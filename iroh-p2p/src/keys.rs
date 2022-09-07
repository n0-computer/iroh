//! Handles storage and retrieval of public & private keys.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::{Stream, StreamExt, TryStreamExt};
use iroh_util::iroh_config_root;
use ssh_key::LineEnding;
use tokio::fs;
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

impl From<Keypair> for libp2p::identity::Keypair {
    fn from(kp: Keypair) -> Self {
        match kp {
            Keypair::Ed25519(kp) => {
                let mut bytes = kp.to_bytes();
                let kp = libp2p::identity::ed25519::Keypair::decode(&mut bytes)
                    .expect("invalid encoding");
                libp2p::identity::Keypair::Ed25519(kp)
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
    pub async fn create_ed25519_key(&mut self) -> Result<()> {
        let keypair = ssh_key::private::Ed25519Keypair::random(rand::thread_rng());
        let keypair = Keypair::Ed25519(keypair);

        self.storage.put(keypair).await?;

        Ok(())
    }

    /// Returns a stream of all keys stored.
    pub fn keys(&self) -> impl Stream<Item = Result<Keypair>> + '_ {
        self.storage.keys()
    }

    /// Returns how many keys are stored in this keychain.
    pub async fn len(&self) -> Result<usize> {
        self.storage.len().await
    }

    /// Returns true if there are no keys stored.
    pub async fn is_empty(&self) -> Result<bool> {
        Ok(self.storage.len().await? == 0)
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
    /// Creates a new on disk keychain, with the root defaulting to the iroh config directory
    pub async fn new() -> Result<Self> {
        let root = iroh_config_root()?;
        Self::with_root(root).await
    }

    /// Creates a new on disk keychain, located at the given path.
    ///
    /// If the path does not exist it is created.
    pub async fn with_root(root: PathBuf) -> Result<Self> {
        let storage = DiskStorage::new(&root).await?;
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
    async fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        if !path.exists() {
            fs::create_dir_all(path).await?;
        }

        Ok(DiskStorage { path: path.into() })
    }

    async fn generate_name(&self, alg: ssh_key::Algorithm) -> Result<String> {
        let count = self.next_count_for_alg(alg).await?;
        let name = format!("id_{}_{}", print_algorithm(alg), count);

        Ok(name)
    }

    async fn next_count_for_alg(&self, alg: ssh_key::Algorithm) -> Result<usize> {
        let matcher = format!("id_{}", print_algorithm(alg));
        let key_files = self.key_files();
        tokio::pin!(key_files);

        let mut counts = Vec::new();
        while let Some(file) = key_files.next().await {
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

    fn key_files(&self) -> impl Stream<Item = Result<PathBuf>> + '_ {
        async_stream::try_stream! {
            let mut reader = fs::read_dir(&self.path).await?;

            while let Some(entry) = reader.next_entry().await? {
                let path = entry.path();
                if path.extension().is_none()
                    && path.file_name().is_some()
                    && path.file_name().unwrap().to_string_lossy().starts_with("id_") {
                        yield path;
                }
            }
        }
    }
}

#[async_trait]
pub trait Storage: std::fmt::Debug {
    async fn put(&mut self, keypair: Keypair) -> Result<()>;
    async fn len(&self) -> Result<usize>;

    fn keys(&self) -> Box<dyn Stream<Item = Result<Keypair>> + Unpin + Send + '_>;
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn put(&mut self, keypair: Keypair) -> Result<()> {
        self.keys.push(keypair);
        Ok(())
    }

    async fn len(&self) -> Result<usize> {
        Ok(self.keys.len())
    }

    fn keys(&self) -> Box<dyn Stream<Item = Result<Keypair>> + Unpin + Send + '_> {
        let s = async_stream::stream! {
            for key in &self.keys {
                yield Ok(key.clone());
            }
        };

        Box::new(Box::pin(s))
    }
}

#[async_trait]
impl Storage for DiskStorage {
    async fn put(&mut self, keypair: Keypair) -> Result<()> {
        let name = self.generate_name(keypair.algorithm()).await?;
        let path = self.path.join(name);
        let encoded_keypair = keypair.to_private_openssh()?;
        fs::write(path, encoded_keypair.as_bytes()).await?;

        Ok(())
    }

    async fn len(&self) -> Result<usize> {
        let files: Vec<_> = self.key_files().try_collect().await?;
        Ok(files.len())
    }

    fn keys(&self) -> Box<dyn Stream<Item = Result<Keypair>> + Unpin + Send + '_> {
        let s = async_stream::try_stream! {
            let mut reader = fs::read_dir(&self.path).await?;

            while let Some(entry) = reader.next_entry().await? {
                let path = entry.path();
                if path_is_private_key(&path) {
                    let content = fs::read_to_string(&path).await?;
                    match ssh_key::private::PrivateKey::from_openssh(&content) {
                        Ok(keypair) => {
                            yield Keypair::try_from(&keypair)?;
                        }
                        Err(err) => {
                            warn!("invalid keyfile at {}: {:?}", path.display(), err);
                        }
                    }
                }
            }
        };

        Box::new(Box::pin(s))
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
        _ => panic!("unusupported algorithm {}", alg),
    }
}

#[cfg(test)]
mod tests {
    use futures::TryStreamExt;

    use super::*;

    #[tokio::test]
    async fn basics_memory_keychain() {
        let mut kc = Keychain::<MemoryStorage>::new();
        assert_eq!(kc.len().await.unwrap(), 0);
        assert!(kc.is_empty().await.unwrap());
        kc.create_ed25519_key().await.unwrap();
        kc.create_ed25519_key().await.unwrap();
        assert_eq!(kc.len().await.unwrap(), 2);

        let keys: Vec<_> = kc.keys().try_collect().await.unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[tokio::test]
    async fn basics_disk_keychain() {
        let dir = tempfile::tempdir().unwrap();

        let mut kc = Keychain::<DiskStorage>::with_root(dir.path().into())
            .await
            .unwrap();
        assert_eq!(kc.len().await.unwrap(), 0);
        assert!(kc.is_empty().await.unwrap());
        kc.create_ed25519_key().await.unwrap();
        kc.create_ed25519_key().await.unwrap();
        assert_eq!(kc.len().await.unwrap(), 2);

        let next_name = kc
            .storage
            .generate_name(ssh_key::Algorithm::Ed25519)
            .await
            .unwrap();
        assert_eq!(next_name, "id_ed25519_2");

        // create some dummy files
        fs::write(dir.path().join("foo"), b"foo").await.unwrap();
        fs::write(dir.path().join("id_foo"), b"foo").await.unwrap();
        fs::write(dir.path().join("id_foo.pub"), b"foo")
            .await
            .unwrap();
        fs::write(dir.path().join("id_foo.txt"), b"foo")
            .await
            .unwrap();
        fs::write(dir.path().join("foo.txt"), b"foo").await.unwrap();
        // correct name, invalid content, should be ignored
        fs::write(dir.path().join("id_ed25119_4"), b"foo")
            .await
            .unwrap();

        let keys: Vec<_> = kc.keys().try_collect().await.unwrap();
        assert_eq!(keys.len(), 2);
    }
}
