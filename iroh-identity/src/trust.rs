use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::Path,
};

use crate::{Error, PeerId};

const HEADER: &str = "iroh trust store v1\n";
const MAX_STORE: usize = 1024 * 1024;
const MAX_NAME: usize = 256;

/// Application-owned pins with explicit compare-and-replace trust migration.
///
/// A successful connection or signature does not mutate this
/// store. The application must approve a replacement ID through an appropriate
/// trusted channel before calling [`Self::migrate`]. Permissions are application
/// state and are not copied by a migration.
#[derive(Clone, Debug, Default)]
pub struct TrustStore {
    pins: BTreeMap<String, PeerId>,
}

impl TrustStore {
    /// Return the currently pinned identity for an application-specific name.
    pub fn get(&self, name: &str) -> Option<PeerId> {
        self.pins.get(name).copied()
    }

    /// Add an initial pin. An existing pin must be changed through `migrate`.
    pub fn trust(&mut self, name: impl Into<String>, id: PeerId) -> Result<(), Error> {
        let name = name.into();
        if name.is_empty() || name.len() > MAX_NAME {
            return Err(Error::Encoding);
        }
        if self.pins.contains_key(&name) {
            return Err(Error::TrustMismatch);
        }
        self.pins.insert(name, id);
        Ok(())
    }

    /// Explicitly replace a pin only if it still matches the approved old identity.
    /// This operation does not infer continuity or transfer application permissions.
    pub fn migrate(
        &mut self,
        name: &str,
        expected_old: PeerId,
        approved_new: PeerId,
    ) -> Result<(), Error> {
        let current = self.pins.get_mut(name).ok_or(Error::TrustMismatch)?;
        if *current != expected_old {
            return Err(Error::TrustMismatch);
        }
        *current = approved_new;
        Ok(())
    }

    /// Revoke a pin only if it still matches the identity selected for revocation.
    pub fn revoke(&mut self, name: &str, expected: PeerId) -> Result<(), Error> {
        if self.get(name) != Some(expected) {
            return Err(Error::TrustMismatch);
        }
        self.pins.remove(name);
        Ok(())
    }

    /// Encode pins in a canonical, bounded local file format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut data = HEADER.to_owned();
        for (name, id) in &self.pins {
            use std::fmt::Write;
            writeln!(
                data,
                "{}\t{}",
                data_encoding::HEXLOWER.encode(name.as_bytes()),
                id
            )
            .expect("writing a string cannot fail");
            if data.len() > MAX_STORE {
                return Err(Error::Encoding);
            }
        }
        Ok(data.into_bytes())
    }

    /// Decode a complete store, rejecting duplicate names and alternate encodings.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        if data.len() > MAX_STORE {
            return Err(Error::Encoding);
        }
        let text = std::str::from_utf8(data).map_err(|_| Error::Encoding)?;
        let records = text.strip_prefix(HEADER).ok_or(Error::Encoding)?;
        let mut store = Self::default();
        for line in records.lines() {
            let (encoded, id) = line.split_once('\t').ok_or(Error::Encoding)?;
            if encoded.len() > 2 * MAX_NAME {
                return Err(Error::Encoding);
            }
            let name = String::from_utf8(
                data_encoding::HEXLOWER
                    .decode(encoded.as_bytes())
                    .map_err(|_| Error::Encoding)?,
            )
            .map_err(|_| Error::Encoding)?;
            store.trust(name, id.parse()?)?;
        }
        if store.to_bytes()? != data {
            return Err(Error::Encoding);
        }
        Ok(store)
    }

    /// Atomically replace the local store, syncing the file and (on Unix) its directory.
    ///
    /// The parent directory must exist and be protected from unauthorized writers.
    /// Concurrent writers require application-level coordination; migration checks
    /// compare the in-memory pin, not another process's state.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(&self.to_bytes()?)?;
        file.as_file().sync_all()?;
        file.persist(path).map_err(|error| Error::Io(error.error))?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    /// Load a bounded local trust store. Trust is only as strong as its storage protection.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take((MAX_STORE + 1) as u64)
            .read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }
}
