use std::path::{Path, PathBuf};

use anyhow::Result;
use redb_v1::ReadableTable;
use tempfile::NamedTempFile;
use tracing::info;

pub fn run(source: impl AsRef<Path>) -> Result<redb::Database> {
    let source = source.as_ref();
    // create the database to a tempfile
    let target = NamedTempFile::new()?;
    let target = target.into_temp_path();
    info!("migrate {} to {}", source.display(), target.display());
    let old_db = redb_v1::Database::open(source)?;
    let new_db = redb::Database::create(&target)?;

    let rtx = old_db.begin_read()?;
    let wtx = new_db.begin_write()?;

    {
        let old_blobs = rtx.open_table(old::BLOBS_TABLE)?;
        let mut new_blobs = wtx.open_table(new::BLOBS_TABLE)?;
        let len = old_blobs.len()?;
        info!("migrate blobs table ({len} rows)");
        for (i, entry) in old_blobs.iter()?.enumerate() {
            let (key, value) = entry?;
            let key: crate::Hash = key.value().into();
            let value = value.value();
            if i > 0 && i % 100 == 0 {
                info!("    row {i:>6} of {len}");
            }
            new_blobs.insert(key, value)?;
        }
        info!("migrate blobs table done");
        let old_tags = rtx.open_table(old::TAGS_TABLE)?;
        let mut new_tags = wtx.open_table(new::TAGS_TABLE)?;
        let len = old_tags.len()?;
        info!("migrate tags table ({len} rows)");
        for (i, entry) in old_tags.iter()?.enumerate() {
            let (key, value) = entry?;
            let key = key.value();
            let value: crate::HashAndFormat = value.value().into();
            if i > 0 && i % 100 == 0 {
                info!("    row {i:>6} of {len}");
            }
            new_tags.insert(key, value)?;
        }
        info!("migrate tags table done");
        let old_inline_data = rtx.open_table(old::INLINE_DATA_TABLE)?;
        let mut new_inline_data = wtx.open_table(new::INLINE_DATA_TABLE)?;
        let len = old_inline_data.len()?;
        info!("migrate inline data table ({len} rows)");
        for (i, entry) in old_inline_data.iter()?.enumerate() {
            let (key, value) = entry?;
            let key: crate::Hash = key.value().into();
            let value = value.value();
            if i > 0 && i % 100 == 0 {
                info!("    row {i:>6} of {len}");
            }
            new_inline_data.insert(key, value)?;
        }
        info!("migrate inline data table done");
        let old_inline_outboard = rtx.open_table(old::INLINE_OUTBOARD_TABLE)?;
        let mut new_inline_outboard = wtx.open_table(new::INLINE_OUTBOARD_TABLE)?;
        let len = old_inline_outboard.len()?;
        info!("migrate inline outboard table ({len} rows)");
        for (i, entry) in old_inline_outboard.iter()?.enumerate() {
            let (key, value) = entry?;
            let key: crate::Hash = key.value().into();
            let value = value.value();
            if i > 0 && i % 100 == 0 {
                info!("    row {i:>6} of {len}");
            }
            new_inline_outboard.insert(key, value)?;
        }
        info!("migrate inline outboard table done");
    }

    wtx.commit()?;
    drop(rtx);
    drop(old_db);
    drop(new_db);

    let backup_path: PathBuf = {
        let mut p = source.to_owned().into_os_string();
        p.push(".backup-redb-v1");
        p.into()
    };
    info!("rename {} to {}", source.display(), backup_path.display());
    std::fs::rename(source, &backup_path)?;
    info!("rename {} to {}", target.display(), source.display());
    target.persist_noclobber(source)?;
    info!("opening migrated database from {}", source.display());
    let db = redb::Database::open(source)?;
    Ok(db)
}

mod new {
    pub(super) use super::super::tables::*;
}

mod old {
    use super::super::EntryState;
    use crate::util::Tag;
    use bytes::Bytes;
    use iroh_base::hash::BlobFormat;
    use postcard::experimental::max_size::MaxSize;
    use redb_v1::{RedbKey, RedbValue, TableDefinition, TypeName};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use smallvec::SmallVec;

    pub const BLOBS_TABLE: TableDefinition<Hash, EntryState> = TableDefinition::new("blobs-0");

    pub const TAGS_TABLE: TableDefinition<Tag, HashAndFormat> = TableDefinition::new("tags-0");

    pub const INLINE_DATA_TABLE: TableDefinition<Hash, &[u8]> =
        TableDefinition::new("inline-data-0");

    pub const INLINE_OUTBOARD_TABLE: TableDefinition<Hash, &[u8]> =
        TableDefinition::new("inline-outboard-0");

    impl redb_v1::RedbValue for EntryState {
        type SelfType<'a> = EntryState;

        type AsBytes<'a> = SmallVec<[u8; 128]>;

        fn fixed_width() -> Option<usize> {
            None
        }

        fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
        where
            Self: 'a,
        {
            postcard::from_bytes(data).unwrap()
        }

        fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
        where
            Self: 'a,
            Self: 'b,
        {
            postcard::to_extend(value, SmallVec::new()).unwrap()
        }

        fn type_name() -> TypeName {
            TypeName::new("EntryState")
        }
    }

    impl RedbValue for HashAndFormat {
        type SelfType<'a> = Self;

        type AsBytes<'a> = [u8; Self::POSTCARD_MAX_SIZE];

        fn fixed_width() -> Option<usize> {
            Some(Self::POSTCARD_MAX_SIZE)
        }

        fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
        where
            Self: 'a,
        {
            let t: &'a [u8; Self::POSTCARD_MAX_SIZE] = data.try_into().unwrap();
            postcard::from_bytes(t.as_slice()).unwrap()
        }

        fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
        where
            Self: 'a,
            Self: 'b,
        {
            let mut res = [0u8; 33];
            postcard::to_slice(&value, &mut res).unwrap();
            res
        }

        fn type_name() -> TypeName {
            TypeName::new("iroh_base::HashAndFormat")
        }
    }

    impl RedbValue for Tag {
        type SelfType<'a> = Self;

        type AsBytes<'a> = bytes::Bytes;

        fn fixed_width() -> Option<usize> {
            None
        }

        fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
        where
            Self: 'a,
        {
            Self(Bytes::copy_from_slice(data))
        }

        fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
        where
            Self: 'a,
            Self: 'b,
        {
            value.0.clone()
        }

        fn type_name() -> TypeName {
            TypeName::new("Tag")
        }
    }

    impl RedbKey for Tag {
        fn compare(data1: &[u8], data2: &[u8]) -> std::cmp::Ordering {
            data1.cmp(data2)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Hash([u8; 32]);

    impl Serialize for Hash {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            self.0.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Hash {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let data: [u8; 32] = Deserialize::deserialize(deserializer)?;
            Ok(Self(data))
        }
    }

    impl MaxSize for Hash {
        const POSTCARD_MAX_SIZE: usize = 32;
    }

    impl From<Hash> for crate::Hash {
        fn from(value: Hash) -> Self {
            value.0.into()
        }
    }

    impl RedbValue for Hash {
        type SelfType<'a> = Self;

        type AsBytes<'a> = &'a [u8; 32];

        fn fixed_width() -> Option<usize> {
            Some(32)
        }

        fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
        where
            Self: 'a,
        {
            let contents: &'a [u8; 32] = data.try_into().unwrap();
            Hash(*contents)
        }

        fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
        where
            Self: 'a,
            Self: 'b,
        {
            &value.0
        }

        fn type_name() -> TypeName {
            TypeName::new("iroh_base::Hash")
        }
    }

    impl RedbKey for Hash {
        fn compare(data1: &[u8], data2: &[u8]) -> std::cmp::Ordering {
            data1.cmp(data2)
        }
    }

    /// A hash and format pair
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, MaxSize)]
    pub struct HashAndFormat {
        /// The hash
        pub hash: Hash,
        /// The format
        pub format: BlobFormat,
    }

    impl From<HashAndFormat> for crate::HashAndFormat {
        fn from(value: HashAndFormat) -> Self {
            crate::HashAndFormat {
                hash: value.hash.into(),
                format: value.format,
            }
        }
    }
    impl Serialize for HashAndFormat {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            (self.hash, self.format).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for HashAndFormat {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let (hash, format) = <(Hash, BlobFormat)>::deserialize(deserializer)?;
            Ok(Self { hash, format })
        }
    }
}
