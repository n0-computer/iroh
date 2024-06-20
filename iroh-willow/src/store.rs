use anyhow::{anyhow, Result};
use rand_core::CryptoRngCore;

use crate::{
    form::{AuthForm, EntryOrForm},
    proto::{
        keys::{NamespaceId, NamespaceKind, NamespaceSecretKey, UserId},
        meadowcap::AccessMode,
        willow::Entry,
    },
    session::Error,
    store::{
        auth::{AuthError, CapSelector, CapabilityPack, DelegateTo, UserSelector},
        traits::SecretStorage,
    },
};

use self::{auth::AuthStore, traits::Storage};

pub use self::entry::{Origin, WatchableEntryStore};

pub mod auth;
pub mod entry;
pub mod memory;
pub mod traits;

#[derive(Debug, Clone)]
pub struct Store<S: Storage> {
    entries: WatchableEntryStore<S::Entries>,
    secrets: S::Secrets,
    payloads: S::Payloads,
    auth: AuthStore,
}

impl<S: Storage> Store<S> {
    pub fn new(storage: S) -> Self {
        Self {
            entries: WatchableEntryStore::new(storage.entries().clone()),
            secrets: storage.secrets().clone(),
            payloads: storage.payloads().clone(),
            auth: Default::default(),
        }
    }

    pub fn entries(&self) -> &WatchableEntryStore<S::Entries> {
        &self.entries
    }

    pub fn secrets(&self) -> &S::Secrets {
        &self.secrets
    }

    pub fn payloads(&self) -> &S::Payloads {
        &self.payloads
    }

    pub fn auth(&self) -> &AuthStore {
        &self.auth
    }

    pub async fn insert_entry(&self, entry: EntryOrForm, auth: AuthForm) -> Result<(Entry, bool)> {
        let user_id = auth.user_id();
        let entry = match entry {
            EntryOrForm::Entry(entry) => Ok(entry),
            EntryOrForm::Form(form) => form.into_entry(self, user_id).await,
        }?;
        let capability = match auth {
            AuthForm::Exact(cap) => cap,
            AuthForm::Any(user_id) => {
                let selector = CapSelector::for_entry(&entry, UserSelector::Exact(user_id));
                self.auth()
                    .get_write_cap(&selector)?
                    .ok_or_else(|| anyhow!("no write capability available"))?
            }
        };
        let secret_key = self
            .secrets()
            .get_user(&user_id)
            .ok_or(Error::MissingUserKey(user_id))?;
        let authorised_entry = entry.attach_authorisation(capability, &secret_key)?;
        let inserted = self.entries().ingest(&authorised_entry, Origin::Local)?;
        Ok((authorised_entry.into_entry(), inserted))
    }

    pub fn create_namespace(
        &self,
        rng: &mut impl CryptoRngCore,
        kind: NamespaceKind,
        owner: UserId,
    ) -> Result<NamespaceId, AuthError> {
        let namespace_secret = NamespaceSecretKey::generate(rng, kind);
        let namespace_id = namespace_secret.id();
        self.secrets().insert_namespace(namespace_secret)?;
        self.mint_caps(namespace_id, owner)?;
        Ok(namespace_id)
    }

    pub fn delegate_cap(
        &self,
        from: CapSelector,
        access_mode: AccessMode,
        to: DelegateTo,
        store: bool,
    ) -> Result<Vec<CapabilityPack>, AuthError> {
        self.auth()
            .delegate_full_caps(&self.secrets, from, access_mode, to, store)
    }

    pub fn import_caps(&self, caps: Vec<CapabilityPack>) -> Result<(), AuthError> {
        // Only allow importing caps we can use.
        // TODO: Is this what we want?
        for cap in &caps {
            let user_id = cap.receiver();
            if !self.secrets().has_user(&user_id) {
                return Err(AuthError::MissingUserSecret(user_id));
            }
        }
        self.auth().insert_caps(caps);
        Ok(())
    }

    fn mint_caps(&self, namespace_id: NamespaceId, user_id: UserId) -> Result<(), AuthError> {
        self.auth()
            .create_full_caps(&self.secrets, namespace_id, user_id)?;
        Ok(())
    }
}
