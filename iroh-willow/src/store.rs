use anyhow::{anyhow, Result};
use rand_core::CryptoRngCore;

use crate::{
    form::{AuthForm, EntryOrForm},
    proto::{
        grouping::Area,
        keys::{NamespaceId, NamespaceKind, NamespaceSecretKey, UserId},
        meadowcap::AccessMode,
    },
    session::Error,
    store::{
        auth::{AuthError, CapSelector, CapabilityPack},
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

    pub async fn insert_entry(&self, entry: EntryOrForm, auth: AuthForm) -> Result<bool> {
        let user_id = auth.user_id();
        let entry = match entry {
            EntryOrForm::Entry(entry) => Ok(entry),
            EntryOrForm::Form(form) => form.into_entry(self, user_id).await,
        }?;
        let capability = match auth {
            AuthForm::Exact(cap) => cap,
            AuthForm::Find(user_id) => {
                let selector = CapSelector::for_entry(&entry, user_id);
                self.auth()
                    .get_write(selector)?
                    .ok_or_else(|| anyhow!("no write capability available"))?
            }
        };
        let secret_key = self
            .secrets()
            .get_user(&user_id)
            .ok_or(Error::MissingUserKey(user_id))?;
        let authorised_entry = entry.attach_authorisation(capability, &secret_key)?;
        self.entries().ingest(&authorised_entry, Origin::Local)
    }

    pub fn mint_namespace(
        &self,
        rng: &mut impl CryptoRngCore,
        kind: NamespaceKind,
        owner: UserId,
    ) -> Result<NamespaceId, AuthError> {
        let namespace_secret = NamespaceSecretKey::generate(rng, kind);
        let namespace_id = namespace_secret.id();
        self.secrets().insert_namespace(namespace_secret)?;
        self.mint_capabilities(namespace_id, owner)?;
        Ok(namespace_id)
    }

    pub fn delegate_capability(
        &self,
        namespace_id: NamespaceId,
        prev_user: UserId,
        access_mode: AccessMode,
        new_user: UserId,
        new_area: Area,
    ) -> anyhow::Result<Vec<CapabilityPack>> {
        match access_mode {
            AccessMode::Write => {
                let write_cap = self.auth.delegate(
                    &self.secrets,
                    namespace_id,
                    prev_user,
                    AccessMode::Write,
                    new_user,
                    new_area,
                )?;
                Ok(vec![write_cap])
            }
            AccessMode::Read => {
                let write_cap = self.auth.delegate(
                    &self.secrets,
                    namespace_id,
                    prev_user,
                    AccessMode::Write,
                    new_user,
                    new_area.clone(),
                )?;
                let read_cap = self.auth.delegate(
                    &self.secrets,
                    namespace_id,
                    prev_user,
                    AccessMode::Read,
                    new_user,
                    new_area,
                )?;
                Ok(vec![write_cap, read_cap])
            }
        }
    }

    fn mint_capabilities(
        &self,
        namespace_id: NamespaceId,
        user_id: UserId,
    ) -> Result<(), AuthError> {
        self.auth
            .mint(&self.secrets, namespace_id, user_id, AccessMode::Read)?;
        self.auth
            .mint(&self.secrets, namespace_id, user_id, AccessMode::Write)?;
        Ok(())
    }

    // pub fn delegate(
    //     &self,
    //     namespace_id: NamespaceId,
    //     access_mode: AccessMode,
    //     from: UserId,
    //     area: Area,
    //     store: bool,
    // ) -> Option<CapabilityPack> {
    // }
}
