use anyhow::{anyhow, Context, Result};
use rand_core::CryptoRngCore;

use crate::{
    form::{AuthForm, EntryForm, EntryOrForm, SubspaceForm, TimestampForm},
    interest::{CapSelector, ReceiverSelector},
    proto::{
        data_model::Entry,
        data_model::{AuthorisedEntry, PayloadDigest},
        keys::{NamespaceId, NamespaceKind, NamespaceSecretKey, UserId},
    },
    store::traits::SecretStorage,
    util::time::system_time_now,
};

use self::auth::{Auth, AuthError};
use self::traits::Storage;

pub use self::entry::{EntryOrigin, WatchableEntryStore};

pub mod auth;
pub mod entry;
pub mod memory;
pub mod traits;

#[derive(Debug, Clone)]
pub struct Store<S: Storage> {
    entries: WatchableEntryStore<S::Entries>,
    secrets: S::Secrets,
    payloads: S::Payloads,
    auth: Auth<S>,
}

impl<S: Storage> Store<S> {
    pub fn new(storage: S) -> Self {
        Self {
            entries: WatchableEntryStore::new(storage.entries().clone()),
            secrets: storage.secrets().clone(),
            payloads: storage.payloads().clone(),
            auth: Auth::new(storage.secrets().clone(), storage.caps().clone()),
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

    pub fn auth(&self) -> &Auth<S> {
        &self.auth
    }

    pub async fn insert_entry(&self, entry: EntryOrForm, auth: AuthForm) -> Result<(Entry, bool)> {
        let user_id = auth.user_id();
        let entry = match entry {
            EntryOrForm::Entry(entry) => Ok(entry),
            EntryOrForm::Form(form) => self.form_to_entry(form, user_id).await,
        }?;
        let capability = match auth {
            AuthForm::Exact(cap) => cap.0,
            AuthForm::Any(user_id) => {
                let selector = CapSelector::for_entry(&entry, ReceiverSelector::Exact(user_id));
                self.auth()
                    .get_write_cap(&selector)?
                    .ok_or_else(|| anyhow!("no write capability available"))?
            }
        };
        let secret_key = self
            .secrets()
            .get_user(&user_id)
            .context("Missing user keypair")?;

        // TODO(frando): This should use `authorisation_token_unchecked` if we uphold the invariant
        // that `user_id` is a pubkey for `secret_key`. However, that is `unsafe` at the moment
        // (but should not be, IMO).
        // Not using the `_unchecked` variant has the cost of an additional signature verification,
        // so significant.
        let token = capability.authorisation_token(&entry, secret_key)?;
        let authorised_entry = AuthorisedEntry::new_unchecked(entry, token);
        let inserted = self
            .entries()
            .ingest(&authorised_entry, EntryOrigin::Local)?;
        let (entry, _token) = authorised_entry.into_parts();
        Ok((entry, inserted))
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
        self.auth().create_full_caps(namespace_id, owner)?;
        Ok(namespace_id)
    }

    /// Convert the form into an [`Entry`] by filling the fields with data from the environment and
    /// the provided [`Store`].
    ///
    /// `user_id` must be set to the user who is authenticating the entry.
    pub async fn form_to_entry(
        &self,
        form: EntryForm,
        user_id: UserId, // auth: AuthForm,
    ) -> anyhow::Result<Entry> {
        let timestamp = match form.timestamp {
            TimestampForm::Now => system_time_now(),
            TimestampForm::Exact(timestamp) => timestamp,
        };
        let subspace_id = match form.subspace_id {
            SubspaceForm::User => user_id,
            SubspaceForm::Exact(subspace) => subspace,
        };
        let (payload_digest, payload_length) = form.payload.submit(self.payloads()).await?;
        let entry = Entry::new(
            form.namespace_id,
            subspace_id,
            form.path,
            timestamp,
            payload_length,
            PayloadDigest(payload_digest),
        );
        Ok(entry)
    }
}
