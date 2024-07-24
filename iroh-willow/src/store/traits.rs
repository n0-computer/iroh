use std::fmt::Debug;

use anyhow::Result;

use crate::{
    auth::{CapSelector, CapabilityPack},
    proto::{
        grouping::ThreeDRange,
        keys::{NamespaceSecretKey, NamespaceSignature, UserId, UserSecretKey, UserSignature},
        meadowcap,
        sync::{Fingerprint, ReadAuthorisation},
        willow::{AuthorisedEntry, Entry, NamespaceId, WriteCapability},
    },
};

pub trait Storage: Debug + Clone + 'static {
    type Entries: EntryStorage;
    type Secrets: SecretStorage;
    type Payloads: iroh_blobs::store::Store;
    type Caps: CapsStorage;
    fn entries(&self) -> &Self::Entries;
    fn secrets(&self) -> &Self::Secrets;
    fn payloads(&self) -> &Self::Payloads;
    fn caps(&self) -> &Self::Caps;
}

pub trait SecretStorage: Debug + Clone + 'static {
    fn insert(&self, secret: meadowcap::SecretKey) -> Result<(), SecretStoreError>;
    fn get_user(&self, id: &UserId) -> Option<UserSecretKey>;
    fn get_namespace(&self, id: &NamespaceId) -> Option<NamespaceSecretKey>;

    fn has_user(&self, id: &UserId) -> bool {
        self.get_user(id).is_some()
    }

    fn has_namespace(&self, id: &UserId) -> bool {
        self.get_user(id).is_some()
    }

    fn insert_user(&self, secret: UserSecretKey) -> Result<UserId, SecretStoreError> {
        let id = secret.id();
        self.insert(meadowcap::SecretKey::User(secret))?;
        Ok(id)
    }
    fn insert_namespace(
        &self,
        secret: NamespaceSecretKey,
    ) -> Result<NamespaceId, SecretStoreError> {
        let id = secret.id();
        self.insert(meadowcap::SecretKey::Namespace(secret))?;
        Ok(id)
    }

    fn sign_user(&self, id: &UserId, message: &[u8]) -> Result<UserSignature, SecretStoreError> {
        Ok(self
            .get_user(id)
            .ok_or(SecretStoreError::MissingKey)?
            .sign(message))
    }
    fn sign_namespace(
        &self,
        id: &NamespaceId,
        message: &[u8],
    ) -> Result<NamespaceSignature, SecretStoreError> {
        Ok(self
            .get_namespace(id)
            .ok_or(SecretStoreError::MissingKey)?
            .sign(message))
    }
}

pub trait EntryStorage: EntryReader + Clone + Debug + 'static {
    type Reader: EntryReader;
    type Snapshot: EntryReader + Clone;

    fn reader(&self) -> Self::Reader;
    fn snapshot(&self) -> Result<Self::Snapshot>;
    fn ingest_entry(&self, entry: &AuthorisedEntry) -> Result<bool>;
}

pub trait EntryReader: Debug + 'static {
    fn fingerprint(&self, namespace: NamespaceId, range: &ThreeDRange) -> Result<Fingerprint>;

    fn split_range(
        &self,
        namespace: NamespaceId,
        range: &ThreeDRange,
        config: &SplitOpts,
    ) -> Result<impl Iterator<Item = Result<RangeSplit>>>;

    fn count(&self, namespace: NamespaceId, range: &ThreeDRange) -> Result<u64>;

    fn get_entries_with_authorisation<'a>(
        &'a self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> impl Iterator<Item = Result<AuthorisedEntry>> + 'a;

    fn get_entries(
        &self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> impl Iterator<Item = Result<Entry>> {
        self.get_entries_with_authorisation(namespace, range)
            .map(|e| e.map(|e| e.into_entry()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    #[error("store failed: {0}")]
    Store(#[from] anyhow::Error),
    #[error("missing secret key")]
    MissingKey,
}

#[derive(Debug, Copy, Clone)]
pub enum KeyScope {
    Namespace,
    User,
}

pub type RangeSplit = (ThreeDRange, SplitAction);

#[derive(Debug)]
pub enum SplitAction {
    SendFingerprint(Fingerprint),
    SendEntries(u64),
}

#[derive(Debug, Clone, Copy)]
pub struct SplitOpts {
    /// Up to how many values to send immediately, before sending only a fingerprint.
    pub max_set_size: usize,
    /// `k` in the protocol, how many splits to generate. at least 2
    pub split_factor: usize,
}

impl Default for SplitOpts {
    fn default() -> Self {
        SplitOpts {
            max_set_size: 1,
            split_factor: 2,
        }
    }
}

pub trait CapsStorage: Debug + Clone {
    fn insert(&self, cap: CapabilityPack) -> Result<()>;

    fn list_read_caps(
        &self,
        namespace: Option<NamespaceId>,
    ) -> Result<impl Iterator<Item = ReadAuthorisation> + '_>;

    fn list_write_caps(
        &self,
        namespace: Option<NamespaceId>,
    ) -> Result<impl Iterator<Item = WriteCapability> + '_>;

    fn get_write_cap(&self, selector: &CapSelector) -> Result<Option<WriteCapability>>;

    fn get_read_cap(&self, selector: &CapSelector) -> Result<Option<ReadAuthorisation>>;
}
