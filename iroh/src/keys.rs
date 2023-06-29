//! Handles storage and retrieval of public & private keys.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use ssh_key::LineEnding;
use tracing::warn;
use zeroize::Zeroizing;

/// Supported keypairs.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Keypair {
    Ed25519(ssh_key::private::Ed25519Keypair),
}

impl Keypair {
    /// Encodes the private part of the keypair into the ssh-key file format.
    fn to_private_openssh(&self) -> Result<Zeroizing<String>> {
        match self {
            Keypair::Ed25519(kp) => {
                let res = ssh_key::private::PrivateKey::from(kp.clone())
                    .to_openssh(LineEnding::default())?;
                Ok(res)
            }
        }
    }

    fn algorithm(&self) -> ssh_key::Algorithm {
        match self {
            Keypair::Ed25519(_) => ssh_key::Algorithm::Ed25519,
        }
    }
}

impl TryFrom<&'_ ssh_key::private::PrivateKey> for Keypair {
    type Error = anyhow::Error;

    fn try_from(key: &ssh_key::private::PrivateKey) -> Result<Self, Self::Error> {
        match key.key_data() {
            ssh_key::private::KeypairData::Ed25519(kp) => Ok(Keypair::Ed25519(kp.clone())),
            _ => Err(anyhow!("unsupported key format: {}", key.algorithm())),
        }
    }
}

impl From<Keypair> for iroh_net::tls::Keypair {
    fn from(kp: Keypair) -> Self {
        match kp {
            Keypair::Ed25519(kp) => {
                let secret_key =
                    iroh_net::tls::SecretKey::try_from(kp).expect("should be valid key");
                secret_key.into()
            }
        }
    }
}

/// A keychain to manage your keys.
#[derive(Debug)]
pub struct Keychain<S: Storage> {
    storage: S,
}

impl<S: Storage> Keychain<S> {
    /// Create a keychain based on the provided storage.
    pub fn from_storage(storage: S) -> Self {
        Keychain { storage }
    }

    /// Creates a new Ed25519 based key and stores it.
    pub fn create_ed25519_key(&mut self) -> Result<()> {
        let keypair = ssh_key::private::Ed25519Keypair::random(&mut rand::thread_rng());
        let keypair = Keypair::Ed25519(keypair);

        self.storage.put(keypair)?;

        Ok(())
    }

    /// Returns a stream of all keys stored.
    pub fn keys(&self) -> Result<impl Iterator<Item = Result<Keypair>> + '_> {
        self.storage.keys()
    }

    /// Returns how many keys are stored in this keychain.
    pub fn len(&self) -> Result<usize> {
        self.storage.len()
    }

    /// Returns true if there are no keys stored.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.storage.len()? == 0)
    }
}

impl Default for Keychain<MemoryStorage> {
    fn default() -> Self {
        let storage = MemoryStorage::default();
        Self::from_storage(storage)
    }
}

impl Keychain<MemoryStorage> {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Keychain<DiskStorage> {
    /// Creates a new on disk keychain, with the root defaulting to `.iroh`.
    pub fn new(root: PathBuf) -> Result<Self> {
        Self::with_root(root)
    }

    /// Creates a new on disk keychain, located at the given path.
    ///
    /// If the path does not exist it is created.
    pub fn with_root(root: PathBuf) -> Result<Self> {
        let storage = DiskStorage::new(&root)?;
        Ok(Self::from_storage(storage))
    }
}

/// In memory storage backend for [`Keychain`].
#[derive(Debug, Default)]
pub struct MemoryStorage {
    keys: Vec<Keypair>,
}

/// On disk storage backend for [`Keychain`].
#[derive(Debug)]
pub struct DiskStorage {
    path: PathBuf,
}

impl DiskStorage {
    fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        if !path.exists() {
            fs::create_dir_all(path)?;
        }

        Ok(DiskStorage { path: path.into() })
    }

    fn generate_name(&self, alg: ssh_key::Algorithm) -> Result<String> {
        let count = self.next_count_for_alg(alg)?;
        let name = format!("id_{}_{}", print_algorithm(alg), count);

        Ok(name)
    }

    fn next_count_for_alg(&self, alg: ssh_key::Algorithm) -> Result<usize> {
        let matcher = format!("id_{}", print_algorithm(alg));
        let key_files = self.key_files()?;

        let mut counts = Vec::new();
        for file in key_files {
            if let Ok(file) = file {
                let file_name = file.file_name().unwrap().to_string_lossy();
                if file_name.starts_with(&matcher) {
                    if let Some(raw_count) = file_name.split('_').nth(2) {
                        if let Ok(c) = raw_count.parse::<usize>() {
                            counts.push(c);
                        }
                    }
                }
            }
        }
        counts.sort_unstable();
        Ok(counts.last().map(|c| c + 1).unwrap_or_default())
    }

    fn key_files(&self) -> Result<impl Iterator<Item = Result<PathBuf>> + '_> {
        let reader = fs::read_dir(&self.path)?;
        let reader = reader.filter_map(|entry| match entry {
            Ok(entry) => {
                let path = entry.path();
                if path.extension().is_none()
                    && path.file_name().is_some()
                    && path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("id_")
                {
                    return Some(Ok(PathBuf::from(path.as_path())));
                }
                None
            }
            Err(err) => Some(Err(err.into())),
        });

        Ok(reader)
    }
}

pub trait Storage: std::fmt::Debug {
    fn put(&mut self, keypair: Keypair) -> Result<()>;
    fn len(&self) -> Result<usize>;

    type KeyIterator<'a>: Iterator<Item = Result<Keypair>> + 'a
    where
        Self: 'a;
    fn keys(&self) -> Result<Self::KeyIterator<'_>>;
}

impl Storage for MemoryStorage {
    fn put(&mut self, keypair: Keypair) -> Result<()> {
        self.keys.push(keypair);
        Ok(())
    }

    fn len(&self) -> Result<usize> {
        Ok(self.keys.len())
    }

    type KeyIterator<'a> = MemoryKeyIterator<'a>;

    fn keys(&self) -> Result<Self::KeyIterator<'_>> {
        Ok(MemoryKeyIterator {
            keys: &self.keys,
            index: 0,
        })
    }
}

#[derive(Debug)]
pub struct MemoryKeyIterator<'a> {
    keys: &'a [Keypair],
    index: usize,
}

impl Iterator for MemoryKeyIterator<'_> {
    type Item = Result<Keypair>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.keys.len() {
            return None;
        }
        let index = self.index;
        self.index += 1;

        Some(Ok(self.keys[index].clone()))
    }
}

impl Storage for DiskStorage {
    fn put(&mut self, keypair: Keypair) -> Result<()> {
        let name = self.generate_name(keypair.algorithm())?;
        let path = self.path.join(name);
        let encoded_keypair = keypair.to_private_openssh()?;
        fs::write(path, encoded_keypair.as_bytes())?;

        Ok(())
    }

    fn len(&self) -> Result<usize> {
        let files: Vec<_> = self.key_files()?.collect::<Result<_>>()?;
        Ok(files.len())
    }

    type KeyIterator<'a> = FileKeyIterator;

    fn keys(&self) -> Result<Self::KeyIterator<'_>> {
        let reader = fs::read_dir(&self.path)?;
        Ok(FileKeyIterator { reader })
    }
}

#[derive(Debug)]
pub struct FileKeyIterator {
    reader: fs::ReadDir,
}
impl FileKeyIterator {
    fn next_entry(&self, entry: std::io::Result<fs::DirEntry>) -> Result<Option<Keypair>> {
        let entry = entry?;
        let path = entry.path();
        if path_is_private_key(&path) {
            let content = fs::read_to_string(&path)?;
            let keypair = ssh_key::private::PrivateKey::from_openssh(&content)?;
            let keypair = Keypair::try_from(&keypair)?;
            Ok(Some(keypair))
        } else {
            Ok(None)
        }
    }
}

impl Iterator for FileKeyIterator {
    type Item = Result<Keypair>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.reader.next()?;

        match self.next_entry(entry) {
            Ok(Some(keypair)) => Some(Ok(keypair)),
            Ok(None) => self.next(),
            Err(err) => {
                warn!("invalid keyfile {:?}", err);
                self.next()
            }
        }
    }
}

/// Checks if the provided path is likely to contain a private key of the form
/// `id_<algorithm>_<id>`.
fn path_is_private_key<P: AsRef<Path>>(path: P) -> bool {
    let path = path.as_ref();

    // no extension
    if path.extension().is_some() {
        return false;
    }

    // two `_` and starts with `id_`.
    if let Some(file_name) = path.file_name() {
        let file_name = file_name.to_string_lossy();

        if !file_name.starts_with("id_") {
            return false;
        }

        if file_name.split('_').count() != 3 {
            return false;
        }

        if let Some(raw_count) = file_name.split('_').nth(2) {
            if raw_count.parse::<usize>().is_ok() {
                return true;
            }
        }
    }

    false
}

fn print_algorithm(alg: ssh_key::Algorithm) -> &'static str {
    match alg {
        ssh_key::Algorithm::Ed25519 => "ed25519",
        _ => panic!("unusupported algorithm {alg}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics_memory_keychain() {
        let mut kc = Keychain::<MemoryStorage>::new();
        assert_eq!(kc.len().unwrap(), 0);
        assert!(kc.is_empty().unwrap());
        kc.create_ed25519_key().unwrap();
        kc.create_ed25519_key().unwrap();
        assert_eq!(kc.len().unwrap(), 2);

        let keys: Vec<_> = kc.keys().unwrap().collect::<Result<_>>().unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn basics_disk_keychain() {
        let dir = tempfile::tempdir().unwrap();

        let mut kc = Keychain::<DiskStorage>::with_root(dir.path().into()).unwrap();
        assert_eq!(kc.len().unwrap(), 0);
        assert!(kc.is_empty().unwrap());
        kc.create_ed25519_key().unwrap();
        kc.create_ed25519_key().unwrap();
        assert_eq!(kc.len().unwrap(), 2);

        let next_name = kc
            .storage
            .generate_name(ssh_key::Algorithm::Ed25519)
            .unwrap();
        assert_eq!(next_name, "id_ed25519_2");

        // create some dummy files
        fs::write(dir.path().join("foo"), b"foo").unwrap();
        fs::write(dir.path().join("id_foo"), b"foo").unwrap();
        fs::write(dir.path().join("id_foo.pub"), b"foo").unwrap();
        fs::write(dir.path().join("id_foo.txt"), b"foo").unwrap();
        fs::write(dir.path().join("foo.txt"), b"foo").unwrap();
        // correct name, invalid content, should be ignored
        fs::write(dir.path().join("id_ed25119_4"), b"foo").unwrap();

        let keys: Vec<_> = kc.keys().unwrap().collect::<Result<_>>().unwrap();
        assert_eq!(keys.len(), 2);
    }
}
