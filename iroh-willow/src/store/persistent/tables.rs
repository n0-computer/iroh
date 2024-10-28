use std::time::Instant;

use anyhow::Result;
use ed25519_dalek::ed25519;
use redb::{
    MultimapTable, MultimapTableDefinition, ReadOnlyMultimapTable, ReadOnlyTable, ReadTransaction,
    Table, TableDefinition, WriteTransaction,
};
use ufotofu::sync::{consumer::IntoVec, producer::FromSlice};
use willow_encoding::sync::{RelativeDecodable, RelativeEncodable};

use crate::proto::{
    grouping::Area,
    meadowcap::{serde_encoding::SerdeReadAuthorisation, McCapability, ReadAuthorisation},
};

// These consts are here so we don't accidentally break the schema!
pub type NamespaceId = [u8; 32];
pub type UserId = [u8; 32];

pub const NAMESPACE_NODES: TableDefinition<NamespaceId, willow_store::NodeId> =
    TableDefinition::new("namespace-nodes-0");

pub const AUTH_TOKENS: TableDefinition<ed25519::SignatureBytes, WriteCap> =
    TableDefinition::new("auth-tokens-0");
pub const AUTH_TOKEN_REFCOUNT: TableDefinition<ed25519::SignatureBytes, u64> =
    TableDefinition::new("auth-token-refcounts-0");

pub const USER_SECRETS: TableDefinition<UserId, [u8; 32]> = TableDefinition::new("user-secrets-0");
pub const NAMESPACE_SECRETS: TableDefinition<NamespaceId, [u8; 32]> =
    TableDefinition::new("namespaces-secrets-0");

pub const READ_CAPS: MultimapTableDefinition<NamespaceId, ReadCap> =
    MultimapTableDefinition::new("read-caps-0");
pub const WRITE_CAPS: MultimapTableDefinition<NamespaceId, WriteCap> =
    MultimapTableDefinition::new("write-caps-0");

self_cell::self_cell! {
    struct OpenWriteInner {
        owner: WriteTransaction,
        #[covariant]
        dependent: Tables,
    }
}

#[derive(derive_more::Debug)]
pub struct OpenWrite {
    #[debug("OpenWriteInner")]
    inner: OpenWriteInner,
    pub since: Instant,
}

impl OpenWrite {
    pub fn new(tx: WriteTransaction) -> Result<Self> {
        Ok(Self {
            inner: OpenWriteInner::try_new(tx, |tx| Tables::new(tx))?,
            since: Instant::now(),
        })
    }

    pub fn read(&self) -> &Tables {
        self.inner.borrow_dependent()
    }

    pub fn modify<T>(&mut self, f: impl FnOnce(&mut Tables) -> Result<T>) -> Result<T> {
        self.inner.with_dependent_mut(|_, t| f(t))
    }

    pub fn commit(self) -> Result<()> {
        self.inner
            .into_owner()
            .commit()
            .map_err(anyhow::Error::from)
    }
}

pub struct Tables<'tx> {
    pub namespace_nodes: Table<'tx, NamespaceId, willow_store::NodeId>,
    pub auth_tokens: Table<'tx, ed25519::SignatureBytes, WriteCap>,
    pub auth_token_refcount: Table<'tx, ed25519::SignatureBytes, u64>,
    pub user_secrets: Table<'tx, UserId, [u8; 32]>,
    pub namespace_secrets: Table<'tx, NamespaceId, [u8; 32]>,
    pub read_caps: MultimapTable<'tx, NamespaceId, ReadCap>,
    pub write_caps: MultimapTable<'tx, NamespaceId, WriteCap>,
    pub node_store: willow_store::Tables<'tx>,
}

impl<'tx> Tables<'tx> {
    pub fn new(tx: &'tx WriteTransaction) -> Result<Self> {
        Ok(Self {
            namespace_nodes: tx.open_table(NAMESPACE_NODES)?,
            auth_tokens: tx.open_table(AUTH_TOKENS)?,
            auth_token_refcount: tx.open_table(AUTH_TOKEN_REFCOUNT)?,
            user_secrets: tx.open_table(USER_SECRETS)?,
            namespace_secrets: tx.open_table(NAMESPACE_SECRETS)?,
            read_caps: tx.open_multimap_table(READ_CAPS)?,
            write_caps: tx.open_multimap_table(WRITE_CAPS)?,
            node_store: willow_store::Tables::open(tx)?,
        })
    }
}

pub struct OpenRead {
    pub namespace_nodes: ReadOnlyTable<NamespaceId, willow_store::NodeId>,
    pub auth_tokens: ReadOnlyTable<ed25519::SignatureBytes, WriteCap>,
    pub read_caps: ReadOnlyMultimapTable<NamespaceId, ReadCap>,
    pub write_caps: ReadOnlyMultimapTable<NamespaceId, WriteCap>,
    pub node_store: willow_store::Snapshot,
}

impl OpenRead {
    pub fn new(tx: &ReadTransaction) -> Result<Self> {
        Ok(Self {
            namespace_nodes: tx.open_table(NAMESPACE_NODES)?,
            auth_tokens: tx.open_table(AUTH_TOKENS)?,
            read_caps: tx.open_multimap_table(READ_CAPS)?,
            write_caps: tx.open_multimap_table(WRITE_CAPS)?,
            node_store: willow_store::Snapshot::open(&tx)?,
        })
    }
}

#[derive(Debug)]
pub struct WriteCap(pub McCapability);

impl redb::Key for WriteCap {
    fn compare(data1: &[u8], data2: &[u8]) -> std::cmp::Ordering {
        data1.cmp(data2)
    }
}

impl redb::Value for WriteCap {
    type SelfType<'a> = Self
        where
            Self: 'a;

    type AsBytes<'a> = Vec<u8>
        where
            Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        let capability =
            McCapability::relative_decode(&Area::new_full(), &mut FromSlice::new(data)).unwrap();
        WriteCap(capability)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        let mut consumer = IntoVec::new();
        value
            .0
            .relative_encode(&Area::new_full(), &mut consumer)
            .unwrap_or_else(|e| match e {}); // infallible
        consumer.into_vec()
    }

    fn type_name() -> redb::TypeName {
        redb::TypeName::new("WriteCap")
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct ReadCap(pub ReadAuthorisation);

impl redb::Key for ReadCap {
    fn compare(data1: &[u8], data2: &[u8]) -> std::cmp::Ordering {
        data1.cmp(data2)
    }
}

impl redb::Value for ReadCap {
    type SelfType<'a> = Self
        where
            Self: 'a;

    type AsBytes<'a> = Vec<u8>
        where
            Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        let capability: SerdeReadAuthorisation = postcard::from_bytes(data).unwrap();
        ReadCap(capability.0)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        // TODO(matheus23): Fewer clones.
        postcard::to_stdvec(&SerdeReadAuthorisation(value.0.clone())).unwrap()
    }

    fn type_name() -> redb::TypeName {
        redb::TypeName::new("ReadCap")
    }
}
