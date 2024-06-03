use anyhow::Result;

use crate::proto::{
    grouping::ThreeDRange,
    keys::{NamespaceSecretKey, NamespaceSignature, UserId, UserSecretKey, UserSignature},
    meadowcap,
    sync::Fingerprint,
    willow::{AuthorisedEntry, Entry, NamespaceId},
};

pub trait Storage: Clone + 'static {
    type Entries: EntryStorage;
    type Secrets: SecretStorage;
    type Payloads: iroh_blobs::store::Store;
    fn entries(&self) -> &Self::Entries;
    fn secrets(&self) -> &Self::Secrets;
    fn payloads(&self) -> &Self::Payloads;
}

pub trait SecretStorage: std::fmt::Debug + 'static {
    fn insert(&self, secret: meadowcap::SecretKey) -> Result<(), SecretStoreError>;
    fn get_user(&self, id: &UserId) -> Option<UserSecretKey>;
    fn get_namespace(&self, id: &NamespaceId) -> Option<NamespaceSecretKey>;

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

pub trait EntryStorage: EntryReader + Clone + std::fmt::Debug + 'static {
    type Reader: EntryReader;
    type Snapshot: EntryReader + Clone;

    fn reader(&self) -> Self::Reader;
    fn snapshot(&self) -> Result<Self::Snapshot>;
    fn ingest_entry(&self, entry: &AuthorisedEntry) -> Result<bool>;
}

pub trait EntryReader: 'static {
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
