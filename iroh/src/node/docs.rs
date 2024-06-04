// use std::{path::PathBuf, sync::RwLock};
//
// use anyhow::bail;
// use iroh_docs::{actor::SyncHandle, Author, AuthorId};
//
// /// Wrapper around [`Engine`] so that we can implement our RPC methods directly.
// ///
// /// See [`crate::node::rpc::docs`]
// #[derive(Debug, Clone)]
// pub(crate) struct DocsEngine {
//     engine: iroh_docs::engine::Engine,
//     default_author: DefaultAuthor
// };
//
// impl std::ops::Deref for DocsEngine {
//     fn deref(&self) -> &Self::Target {
//         &self.engine
//     }
// }
//
// /// Where to persist the default author.
// ///
// /// If set to `Mem`, a new author will be created in the docs store before spawning the sync
// /// engine. Changing the default author will not be persisted.
// ///
// /// If set to `Persistent`, the default author will be loaded from and persisted to the specified
// /// path (as base32 encoded string of the author's public key).
// #[derive(Debug)]
// pub enum DefaultAuthorStorage {
//     /// Memory storage.
//     Mem,
//     /// File based persistent storage.
//     Persistent(PathBuf),
// }
//
// impl DefaultAuthorStorage {
//     /// Load the default author from the storage.
//     ///
//     /// Will create and save a new author if the storage is empty.
//     ///
//     /// Returns an error if the author can't be parsed or if the uathor does not exist in the docs
//     /// store.
//     pub async fn load(&self, docs_store: &SyncHandle) -> anyhow::Result<AuthorId> {
//         match self {
//             Self::Mem => {
//                 let author = Author::new(&mut rand::thread_rng());
//                 let author_id = author.id();
//                 docs_store.import_author(author).await?;
//                 Ok(author_id)
//             }
//             Self::Persistent(ref path) => {
//                 if path.exists() {
//                     let data = tokio::fs::read_to_string(path).await.with_context(|| {
//                         format!(
//                             "Failed to read the default author file at `{}`",
//                             path.to_string_lossy()
//                         )
//                     })?;
//                     let author_id = AuthorId::from_str(&data).with_context(|| {
//                         format!(
//                             "Failed to parse the default author from `{}`",
//                             path.to_string_lossy()
//                         )
//                     })?;
//                     if docs_store.export_author(author_id).await?.is_none() {
//                         bail!("The default author is missing from the docs store. To recover, delete the file `{}`. Then iroh will create a new default author.", path.to_string_lossy())
//                     }
//                     Ok(author_id)
//                 } else {
//                     let author = Author::new(&mut rand::thread_rng());
//                     let author_id = author.id();
//                     docs_store.import_author(author).await?;
//                     self.persist(author_id).await?;
//                     Ok(author_id)
//                 }
//             }
//         }
//     }
//
//     /// Save a new default author.
//     pub async fn persist(&self, author_id: AuthorId) -> anyhow::Result<()> {
//         match self {
//             Self::Mem => {
//                 // persistence is not possible for the mem storage so this is a noop.
//             }
//             Self::Persistent(ref path) => {
//                 tokio::fs::write(path, author_id.to_string())
//                     .await
//                     .with_context(|| {
//                         format!(
//                             "Failed to write the default author to `{}`",
//                             path.to_string_lossy()
//                         )
//                     })?;
//             }
//         }
//         Ok(())
//     }
// }
//
// #[derive(Debug)]
// struct DefaultAuthor {
//     value: RwLock<AuthorId>,
//     storage: DefaultAuthorStorage,
// }
//
// impl DefaultAuthor {
//     async fn load(storage: DefaultAuthorStorage, docs_store: &SyncHandle) -> Result<Self> {
//         let value = storage.load(docs_store).await?;
//         Ok(Self {
//             value: RwLock::new(value),
//             storage,
//         })
//     }
//     fn get(&self) -> AuthorId {
//         *self.value.read().unwrap()
//     }
//     async fn set(&self, author_id: AuthorId, docs_store: &SyncHandle) -> Result<()> {
//         if docs_store.export_author(author_id).await?.is_none() {
//             bail!("The author does not exist");
//         }
//         self.storage.persist(author_id).await?;
//         *self.value.write().unwrap() = author_id;
//         Ok(())
//     }
// }
