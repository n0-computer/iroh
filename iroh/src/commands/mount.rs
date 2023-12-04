use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use iroh::client;
use iroh::{
    client::{Doc, Iroh},
    rpc_protocol::ProviderService,
    sync_engine::LiveEvent,
};
use iroh_sync::{store::Query, AuthorId, NamespaceId};
use nfsserve::nfs::mode3;
use nfsserve::{
    nfs::{
        self, fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, nfstime3, sattr3, specdata3,
    },
    vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities},
};
use quic_rpc::ServiceConnection;
use tokio::sync::{mpsc, RwLock};
use tokio_util::task::LocalPoolHandle;
use tracing::{error, info, warn};

use crate::commands::mount_runner::perform_mount_and_wait_for_ctrlc;

use super::runtime::{self, IrohWrapper};

const HOSTPORT: u32 = 11111;

// schema
//
// Root
// - .fs.iroh
//   - next_id: u64
//
// Directory
// - .dir.iroh
//   - fattr3
//
// File
// - file
// - .file.iroh
//   - fattr3

#[derive(Debug, Clone)]
struct Attrs {
    /// The id of the file
    fileid: fileid3,
    /// Last access time
    atime: nfstime3,
    /// Last modification time
    mtime: nfstime3,
    /// Creation time
    ctime: nfstime3,
    /// size
    size: u64,
    /// Mode
    mode: mode3,
    ftype: FileType,
    /// The name
    name: filename3,
}

#[derive(Debug, Clone)]
enum FileType {
    File,
    Directory,
}

impl From<FileType> for ftype3 {
    fn from(value: FileType) -> Self {
        match value {
            FileType::File => ftype3::NF3REG,
            FileType::Directory => ftype3::NF3DIR,
        }
    }
}

impl TryFrom<ftype3> for FileType {
    type Error = anyhow::Error;

    fn try_from(value: ftype3) -> std::result::Result<Self, Self::Error> {
        match value {
            ftype3::NF3REG => Ok(Self::File),
            ftype3::NF3DIR => Ok(Self::Directory),
            _ => Err(anyhow!("invalid ftype3: {:?}", value)),
        }
    }
}

impl From<Attrs> for fattr3 {
    fn from(value: Attrs) -> Self {
        fattr3 {
            ftype: value.ftype.into(),
            mode: value.mode,
            nlink: 1,
            uid: 507,
            gid: 507,
            size: value.size,
            used: value.size,
            rdev: specdata3::default(),
            fsid: 0,
            fileid: value.fileid,
            atime: value.atime,
            mtime: value.mtime,
            ctime: value.ctime,
        }
    }
}

impl Attrs {
    fn new_file(name: filename3, fileid: fileid3) -> Self {
        Attrs {
            fileid,
            atime: now(),
            mtime: now(),
            ctime: now(),
            size: 0,
            mode: 0o755,
            ftype: FileType::File,
            name,
        }
    }

    fn new_dir(name: filename3, fileid: fileid3) -> Self {
        Attrs {
            fileid,
            atime: now(),
            mtime: now(),
            ctime: now(),
            size: 0,
            mode: 0o777,
            ftype: FileType::Directory,
            name,
        }
    }
}

pub async fn exec<C>(
    iroh: &Iroh<C>,
    doc: NamespaceId,
    path: PathBuf,
    rt: LocalPoolHandle,
) -> Result<()>
where
    C: ServiceConnection<ProviderService>,
{
    let path = path.canonicalize()?;
    println!("mounting {} at {}", doc, path.display());
    let fs = IrohFs::new(iroh.clone(), doc, path.clone(), rt).await?;

    println!("fs prepared");
    let s = fs.ready();
    perform_mount_and_wait_for_ctrlc(
        &path,
        fs,
        true,
        true,
        format!("127.0.0.1:{HOSTPORT}"),
        move || {
            s.try_send(()).ok();
        },
    )
    .await?;

    Ok(())
}

#[derive(Debug, Clone)]
enum FsContents {
    File { key: Bytes, author: AuthorId },
    Directory { content: Vec<fileid3> },
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct FsEntry {
    attr: Attrs,
    parent: fileid3,
    contents: FsContents,
}

impl FsEntry {
    fn new_file(
        name: &str,
        id: fileid3,
        parent: fileid3,
        content_len: u64,
        key: Bytes,
        author: AuthorId,
        ts: Option<nfstime3>,
    ) -> Self {
        let mut attr = Attrs::new_file(name.as_bytes().into(), id);
        if let Some(ts) = ts {
            attr.ctime = ts;
            attr.mtime = ts;
        }
        attr.size = content_len;
        Self {
            attr,
            parent,
            contents: FsContents::File { key, author },
        }
    }

    fn new_dir(name: &str, id: fileid3, parent: fileid3, content: Vec<fileid3>) -> Self {
        Self {
            attr: Attrs::new_dir(name.as_bytes().into(), id),
            parent,
            contents: FsContents::Directory { content },
        }
    }
}

fn now() -> nfstime3 {
    let now = filetime::FileTime::now();
    nfstime3 {
        seconds: now.seconds() as _,
        nseconds: now.nanoseconds(),
    }
}

/// micros to nfstime3
fn ts_to_nfstime(ts: u64) -> nfstime3 {
    let ts = filetime::FileTime::from_unix_time((ts / 1_000_000) as _, (ts * 1000) as _);
    nfstime3 {
        seconds: ts.seconds() as _,
        nseconds: ts.nanoseconds(),
    }
}

#[derive(Debug, Clone)]
pub struct IrohFs<C>
where
    C: ServiceConnection<ProviderService>,
{
    iroh: Iroh<C>,
    doc: Doc<C>,
    fs: Arc<RwLock<BTreeMap<u64, FsEntry>>>,
    next_id: Arc<AtomicU64>,
    rootdir: fileid3,
    author: AuthorId,
    mount_path: PathBuf,
    looper: mpsc::Sender<()>,
}

const MAIN_FILE: &str = "main.js";

impl<C> IrohFs<C>
where
    C: ServiceConnection<ProviderService>,
{
    async fn new(
        iroh: Iroh<C>,
        doc_id: NamespaceId,
        mount_path: PathBuf,
        rt: LocalPoolHandle,
    ) -> Result<Self> {
        let doc = iroh
            .docs
            .open(doc_id)
            .await?
            .ok_or_else(|| anyhow!("unknown document"))?;

        // TODO: better
        let author = iroh.authors.create().await?;

        let mut entries = BTreeMap::new();
        entries.insert(
            0,
            FsEntry::new_file("", 0, 0, 0, Bytes::default(), author, None),
        ); // fileid 0 is special

        let mut root_children = Vec::new();

        let dir_id = 1;
        let mut keys = doc.get_many(Query::single_latest_per_key()).await?;

        let mut current_id = 2;

        while let Some(entry) = keys.next().await {
            let entry = entry?;
            let name = String::from_utf8_lossy(&entry.key()).replace("/", "-");
            let id = current_id;
            current_id += 1;
            root_children.push(id);
            info!("inserting /{}", name);
            entries.insert(
                id,
                FsEntry::new_file(
                    &name,
                    id,
                    dir_id,
                    entry.content_len(),
                    entry.key().to_vec().into(),
                    entry.author(),
                    Some(ts_to_nfstime(entry.timestamp())),
                ),
            );
        }

        let root_dir = FsEntry::new_dir(
            "/",
            dir_id, // current id. Must match position in entries
            0,      // parent id
            root_children,
        );
        entries.insert(1, root_dir);

        let mut sub = doc.subscribe().await?;
        let fs = Arc::new(RwLock::new(entries));
        let sub_fs = fs.clone();
        let next_id = Arc::new(AtomicU64::new(current_id));
        let sub_next_id = next_id.clone();

        let (looper_s, mut looper_r) = mpsc::channel(64);

        let looper = looper_s.clone();
        tokio::task::spawn(async move {
            while let Some(item) = sub.next().await {
                match item {
                    Ok(event) => {
                        match event {
                            LiveEvent::InsertLocal { entry }
                            | LiveEvent::InsertRemote { entry, .. } => {
                                // insert into fs
                                let id = sub_next_id.fetch_add(1, Ordering::Relaxed);
                                let mut fs = sub_fs.write().await;
                                let name = String::from_utf8_lossy(&entry.key()).replace("/", "-");
                                let is_deletion = entry.content_len() == 0;

                                if is_deletion {
                                    // deletion
                                    if let Some(k) = fs
                                        .iter()
                                        .find(|(_, e)| e.attr.name.as_ref() == name.as_bytes())
                                        .map(|(k, _)| *k)
                                    {
                                        fs.remove(&k);
                                    }
                                } else if let Some(fs_entry) = fs
                                    .values_mut()
                                    .find(|e| e.attr.name.as_ref() == name.as_bytes())
                                {
                                    // existing entry, update
                                    fs_entry.attr.mtime = now();
                                    fs_entry.attr.size = entry.content_len();
                                } else {
                                    fs.insert(
                                        id,
                                        FsEntry::new_file(
                                            &name,
                                            id,
                                            dir_id,
                                            entry.content_len(),
                                            entry.key().to_vec().into(),
                                            entry.author(),
                                            Some(ts_to_nfstime(entry.timestamp())),
                                        ),
                                    );

                                    // update root dir
                                    let FsContents::Directory { content } =
                                        &mut fs.get_mut(&1).unwrap().contents
                                    else {
                                        panic!("1 must be the root dir");
                                    };
                                    content.push(id);
                                }
                                // update mtime of parent
                                fs.get_mut(&1).unwrap().attr.mtime = now();

                                if !is_deletion {
                                    looper_s.try_send(()).ok();
                                }

                                info!("inserted {}: {:?}", name, entry);
                            }
                            _ => {}
                        }
                    }
                    Err(err) => {
                        warn!("event failure: {:?}", err);
                    }
                }
            }
        });

        let res = Self {
            fs,
            doc,
            rootdir: 1,
            next_id,
            iroh,
            author,
            mount_path,
            looper,
        };
        let this = res.clone();
        tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    _ = looper_r.recv() => {
                        let fs = this.fs.read().await;

                        if fs
                            .values()
                            .find(|v| v.attr.name.as_ref() == MAIN_FILE.as_bytes())
                            .is_some()
                        {
                            let p = this.mount_path.join(MAIN_FILE);
                            let iroh = this.iroh_wrapper();
                            rt.spawn_pinned(|| async move {
                                if let Err(err) = runtime::exec(iroh, p.clone()).await {
                                    error!("runtime execution failed of {}: {:?}", p.display(), err);
                                }
                            });
                        }
                    }
                }
            }
        });

        Ok(res)
    }
}

impl<C> IrohFs<C>
where
    C: ServiceConnection<ProviderService>,
{
    fn ready(&self) -> mpsc::Sender<()> {
        self.looper.clone()
    }

    fn iroh_wrapper(&self) -> IrohWrapper {
        let any_iroh = (&self.iroh) as &dyn std::any::Any;
        if let Some(iroh) = any_iroh.downcast_ref::<client::mem::Iroh>() {
            return IrohWrapper::Mem(iroh.clone());
        }
        if let Some(iroh) = any_iroh.downcast_ref::<client::quic::Iroh>() {
            return IrohWrapper::Quic(iroh.clone());
        }
        panic!("unsupported iroh client");
    }
}

// For this demo file system we let the handle just be the file
// there is only 1 file. a.txt.
#[async_trait]
impl<C> NFSFileSystem for IrohFs<C>
where
    C: ServiceConnection<ProviderService>,
{
    fn root_dir(&self) -> fileid3 {
        self.rootdir
    }

    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadWrite
    }

    async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
        let mut fs = self.fs.write().await;
        info!("write to {:?}", id);
        let attr = {
            let file = fs.get_mut(&id).ok_or_else(|| {
                error!("missing entry {}", id);
                nfsstat3::NFS3ERR_NOENT
            })?;

            let mut fssize = file.attr.size;
            if let FsContents::File { key, author } = &mut file.contents {
                info!(
                    "writing to {:?} - {} bytes at {}",
                    std::str::from_utf8(key),
                    data.len(),
                    offset,
                );

                // get the full content
                let mut bytes = if let Some(entry) = self
                    .doc
                    .get_exact(*author, &key, true)
                    .await
                    .map_err(|_| nfsstat3::NFS3ERR_SERVERFAULT)?
                {
                    self.iroh
                        .blobs
                        .read_to_bytes(entry.content_hash())
                        .await
                        .map_err(|e| {
                            error!("failed to read {}: {:?}", entry.content_hash(), e);
                            nfsstat3::NFS3ERR_SERVERFAULT
                        })?
                        .to_vec()
                } else {
                    Vec::new()
                };

                let start = offset as usize;
                let end = start + data.len();

                // resize buffer if needed
                if end > bytes.len() {
                    bytes.resize(end, 0);
                }

                bytes[start..end].copy_from_slice(data);
                fssize = bytes.len() as u64;

                // store back
                let _hash = self
                    .doc
                    .set_bytes(self.author, key.clone(), bytes)
                    .await
                    .map_err(|e| {
                        error!(
                            "failed to set bytes {:?}: {:?}",
                            std::str::from_utf8(key),
                            e
                        );
                        nfsstat3::NFS3ERR_SERVERFAULT
                    })?;
                info!(
                    "written {} bytes at offset {}: final size: {}",
                    data.len(),
                    offset,
                    fssize
                );
            }
            file.attr.mtime = now();
            file.attr.size = fssize;

            file.attr.clone()
        };

        // update mtime of the parent
        fs.get_mut(&1).unwrap().attr.mtime = now();

        Ok(attr.into())
    }

    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        _attr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let newid: fileid3;
        let attr = {
            let mut fs = self.fs.write().await;
            newid = self.next_id.fetch_add(1, Ordering::Relaxed) as fileid3;
            let dir = fs.get_mut(&dirid).ok_or_else(|| nfsstat3::NFS3ERR_NOENT)?;
            let FsContents::Directory { content } = &mut dir.contents else {
                warn!("found file, expected directory");
                return Err(nfsstat3::NFS3ERR_NOENT);
            };
            let key: Bytes = filename.as_ref().to_vec().into();

            // Not writing, as we are not storing empty entries
            content.push(newid);
            dir.attr.mtime = now();

            let name = std::string::String::from_utf8_lossy(filename);
            info!("inserting {}: {:?}", newid, name);
            fs.insert(
                newid,
                FsEntry::new_file(&name, newid, dirid, 0, key, self.author, None),
            );
            fs[&newid].attr.clone()
        };

        Ok((newid, attr.into()))
    }

    async fn create_exclusive(
        &self,
        dirid: fileid3,
        filename: &filename3,
    ) -> Result<fileid3, nfsstat3> {
        let newid: fileid3;
        {
            let mut fs = self.fs.write().await;
            newid = self.next_id.fetch_add(1, Ordering::Relaxed) as fileid3;
            let dir = fs.get_mut(&dirid).ok_or_else(|| nfsstat3::NFS3ERR_NOENT)?;
            let FsContents::Directory { content } = &mut dir.contents else {
                return Err(nfsstat3::NFS3ERR_NOENT);
            };
            let key: Bytes = filename.as_ref().to_vec().into();

            let old_entry = self
                .doc
                .get_exact(self.author, &key, false)
                .await
                .map_err(|_| nfsstat3::NFS3ERR_SERVERFAULT)?;

            if old_entry.is_some() {
                error!("already exists: {:?}", std::str::from_utf8(filename));
                return Err(nfsstat3::NFS3ERR_EXIST);
            }

            // Not writing, as we are not storing empty entries
            content.push(newid);
            dir.attr.mtime = now();

            let name = std::string::String::from_utf8_lossy(filename);
            info!("inserting {}: {:?}", newid, name);
            fs.insert(
                newid,
                FsEntry::new_file(&name, newid, dirid, 0, key, self.author, None),
            );
        }
        Ok(newid)
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let fs = self.fs.read().await;
        let entry = fs.get(&dirid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        if let FsContents::File { .. } = entry.contents {
            return Err(nfsstat3::NFS3ERR_NOTDIR);
        } else if let FsContents::Directory { content, .. } = &entry.contents {
            // if looking for dir/. its the current directory
            if filename[..] == [b'.'] {
                return Ok(dirid);
            }
            // if looking for dir/.. its the parent directory
            if filename[..] == [b'.', b'.'] {
                return Ok(entry.parent);
            }
            for i in content {
                if let Some(f) = fs.get(i) {
                    if f.attr.name[..] == filename[..] {
                        return Ok(*i);
                    }
                }
            }
        }
        Err(nfsstat3::NFS3ERR_NOENT)
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        info!("getattr {:?}", id);
        let fs = self.fs.read().await;
        let entry = fs.get(&id).ok_or_else(|| {
            error!("missing entry {}", id);
            nfsstat3::NFS3ERR_NOENT
        })?;

        // update attrs if needed

        if let FsContents::File { author, key } = &entry.contents {
            let author = author.clone();
            let key = key.clone();
            drop(fs);

            let mut fs = self.fs.write().await;
            let fs_entry = fs.get_mut(&id).ok_or_else(|| {
                error!("missing entry {}", id);
                nfsstat3::NFS3ERR_NOENT
            })?;
            if let Some(entry) = self
                .doc
                .get_exact(author, key, true)
                .await
                .map_err(|_| nfsstat3::NFS3ERR_SERVERFAULT)?
            {
                fs_entry.attr.mtime = ts_to_nfstime(entry.timestamp());
            }
            Ok(fs_entry.attr.clone().into())
        } else {
            Ok(entry.attr.clone().into())
        }
    }

    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        let mut fs = self.fs.write().await;
        let entry = fs.get_mut(&id).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        info!(
            "setattr {}:{:?}: {:?}",
            id,
            std::str::from_utf8(entry.attr.name.as_ref()),
            setattr,
        );

        match setattr.atime {
            nfs::set_atime::DONT_CHANGE => {}
            nfs::set_atime::SET_TO_CLIENT_TIME(c) => {
                entry.attr.atime = c;
            }
            nfs::set_atime::SET_TO_SERVER_TIME => {
                let d = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap();
                entry.attr.atime.seconds = d.as_secs() as u32;
                entry.attr.atime.nseconds = d.subsec_nanos();
            }
        };
        match setattr.mtime {
            nfs::set_mtime::DONT_CHANGE => {}
            nfs::set_mtime::SET_TO_CLIENT_TIME(c) => {
                entry.attr.mtime = c;
            }
            nfs::set_mtime::SET_TO_SERVER_TIME => {
                let d = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap();
                entry.attr.mtime.seconds = d.as_secs() as u32;
                entry.attr.mtime.nseconds = d.subsec_nanos();
            }
        };
        match setattr.uid {
            nfs::set_uid3::uid(u) => {
                // TODO:
                // entry.attr.uid = u;
            }
            nfs::set_uid3::Void => {}
        }
        match setattr.gid {
            nfs::set_gid3::gid(u) => {
                // TODO:
                // entry.attr.gid = u;
            }
            nfs::set_gid3::Void => {}
        }
        match setattr.size {
            nfs::set_size3::size(s) => {
                entry.attr.size = s;

                if let FsContents::File { key, author } = &mut entry.contents {
                    if s == 0 {
                        self.doc
                            .del(*author, key.clone())
                            .await
                            .map_err(|_| nfsstat3::NFS3ERR_SERVERFAULT)?;
                    } else {
                        let entry = self
                            .doc
                            .get_exact(*author, &key, true)
                            .await
                            .map_err(|_| nfsstat3::NFS3ERR_SERVERFAULT)?
                            .ok_or(nfsstat3::NFS3ERR_NOENT)?;

                        // get the full content
                        let mut bytes = self
                            .iroh
                            .blobs
                            .read_to_bytes(entry.content_hash())
                            .await
                            .map_err(|err| {
                                error!("read_to_bytes: {:?} {:?}", key, err);
                                nfsstat3::NFS3ERR_SERVERFAULT
                            })?
                            .to_vec();

                        bytes.resize(s as usize, 0);

                        // store back
                        self.doc
                            .set_bytes(self.author, key.clone(), bytes)
                            .await
                            .map_err(|err| {
                                error!("set_bytes: {:?} {:?}", key, err);
                                nfsstat3::NFS3ERR_SERVERFAULT
                            })?;
                    }
                };
            }
            nfs::set_size3::Void => {}
        }
        Ok(entry.attr.clone().into())
    }

    async fn read(
        &self,
        id: fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        info!("reading {}: {} bytes at {}", id, count, offset);
        let fs = self.fs.read().await;
        let entry = fs.get(&id).ok_or(nfsstat3::NFS3ERR_NOENT)?;

        if let FsContents::Directory { .. } = entry.contents {
            return Err(nfsstat3::NFS3ERR_ISDIR);
        } else if let FsContents::File { key, author } = &entry.contents {
            let mut start = offset as usize;
            let mut end = offset as usize + count as usize;

            let entry = self
                .doc
                .get_exact(*author, key, true)
                .await
                .map_err(|_| nfsstat3::NFS3ERR_SERVERFAULT)?
                .ok_or(nfsstat3::NFS3ERR_NOENT)?;

            // TODO: partial reads
            let bytes = self
                .iroh
                .blobs
                .read_to_bytes(entry.content_hash())
                .await
                .map_err(|_| nfsstat3::NFS3ERR_SERVERFAULT)?;
            let eof = end >= bytes.len();
            if start >= bytes.len() {
                start = bytes.len();
            }
            if end > bytes.len() {
                end = bytes.len();
            }
            return Ok((bytes[start..end].to_vec(), eof));
        }
        Err(nfsstat3::NFS3ERR_NOENT)
    }

    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        let fs = self.fs.read().await;
        let entry = fs.get(&dirid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        if let FsContents::File { .. } = entry.contents {
            return Err(nfsstat3::NFS3ERR_NOTDIR);
        } else if let FsContents::Directory { content, .. } = &entry.contents {
            let mut ret = ReadDirResult {
                entries: Vec::new(),
                end: false,
            };
            let mut start_index = 0;
            if start_after > 0 {
                if let Some(pos) = content.iter().position(|&r| r == start_after) {
                    start_index = pos + 1;
                } else {
                    return Err(nfsstat3::NFS3ERR_BAD_COOKIE);
                }
            }
            let remaining_length = content.len() - start_index;

            for i in content[start_index..].iter() {
                let entry = fs.get(i).ok_or(nfsstat3::NFS3ERR_IO)?;
                ret.entries.push(DirEntry {
                    fileid: *i,
                    name: entry.attr.name.clone(),
                    attr: entry.attr.clone().into(),
                });
                if ret.entries.len() >= max_entries {
                    break;
                }
            }
            if ret.entries.len() == remaining_length {
                ret.end = true;
            }
            return Ok(ret);
        }
        Err(nfsstat3::NFS3ERR_NOENT)
    }

    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        info!("remove {:?} from {}", std::str::from_utf8(filename), dirid);
        let mut fs = self.fs.write().await;
        let (fid, _) = fs
            .iter()
            .find(|(_, e)| e.attr.name.as_ref() == filename.as_ref())
            .ok_or(nfsstat3::NFS3ERR_NOENT)?;
        let fid = *fid;
        // Remove entry from the cache
        let entry = fs.remove(&fid);

        // Remove from doc
        if let Some(FsContents::File { key, author }) = entry.map(|e| e.contents) {
            self.doc.del(author, key.clone()).await.map_err(|err| {
                error!("delete {:?}: {:?}", key, err);
                nfsstat3::NFS3ERR_SERVERFAULT
            })?;
        }

        // Update dir
        {
            let entry = fs.get_mut(&dirid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
            if let FsContents::Directory { content, .. } = &mut entry.contents {
                content.retain(|r| *r != fid);
            }
            entry.attr.mtime = now();
        }

        Ok(())
    }

    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        info!(
            "rename {:?} to {:?}",
            std::str::from_utf8(from_filename),
            std::str::from_utf8(to_filename)
        );
        let mut fs = self.fs.write().await;

        if !fs.contains_key(&from_dirid) {
            warn!("missing from: {}", from_dirid);
            return Err(nfsstat3::NFS3ERR_NOENT);
        }

        if !fs.contains_key(&to_dirid) {
            warn!("missing to: {}", to_dirid);
            return Err(nfsstat3::NFS3ERR_NOENT);
        }

        // read entry
        let (fid, _) = fs
            .iter()
            .find(|(_, e)| e.attr.name.as_ref() == from_filename.as_ref())
            .ok_or_else(|| {
                warn!(
                    "no entry found for {:?}",
                    std::str::from_utf8(from_filename)
                );
                nfsstat3::NFS3ERR_NOENT
            })?;
        let fid = *fid;

        let entry = fs.get(&fid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        let FsContents::File { key, author } = &entry.contents else {
            return Err(nfsstat3::NFS3ERR_ISDIR);
        };

        let new_key: Bytes = to_filename.as_ref().to_vec().into();
        if let Some(entry) = self
            .doc
            .get_exact(*author, key, true)
            .await
            .map_err(|_| nfsstat3::NFS3ERR_SERVERFAULT)?
        {
            self.doc
                .set_hash(
                    self.author,
                    new_key,
                    entry.content_hash(),
                    entry.content_len(),
                )
                .await
                .map_err(|_| nfsstat3::NFS3ERR_SERVERFAULT)?;
        } else {
            // assume empty entry, ignore
        }

        // update dir entrires
        if from_dirid == to_dirid {
            let entry = fs.get_mut(&from_dirid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
            entry.attr.mtime = now();
        } else {
            // remove from old
            {
                let entry = fs.get_mut(&from_dirid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
                let FsContents::Directory { content, .. } = &mut entry.contents else {
                    return Err(nfsstat3::NFS3ERR_NOENT);
                };
                content.retain(|v| *v != fid);
                entry.attr.mtime = now();
            }

            // insert into new dir
            {
                let entry = fs.get_mut(&to_dirid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
                let FsContents::Directory { content, .. } = &mut entry.contents else {
                    return Err(nfsstat3::NFS3ERR_NOENT);
                };
                content.push(fid);
                entry.attr.mtime = now();
            }
        }

        Ok(())
    }

    async fn mkdir(
        &self,
        _dirid: fileid3,
        dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        error!("missing mkdir {:?}", std::str::from_utf8(dirname));
        return Err(nfsstat3::NFS3ERR_NOTSUPP);
    }

    async fn symlink(
        &self,
        _dirid: fileid3,
        _linkname: &filename3,
        _symlink: &nfspath3,
        _attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn readlink(&self, _id: fileid3) -> Result<nfspath3, nfsstat3> {
        error!("missing readlink");
        return Err(nfsstat3::NFS3ERR_NOTSUPP);
    }
}
