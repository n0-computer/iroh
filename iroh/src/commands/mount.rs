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
use iroh::{
    client::{Doc, Iroh},
    rpc_protocol::ProviderService,
    sync_engine::LiveEvent,
};
use iroh_sync::{store::Query, AuthorId, NamespaceId};
use nfsserve::{
    nfs::{
        self, fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, nfstime3, sattr3, specdata3,
    },
    vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities},
};
use quic_rpc::ServiceConnection;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::commands::mount_runner::perform_mount_and_wait_for_ctrlc;

const HOSTPORT: u32 = 11111;

pub async fn exec<C>(iroh: &Iroh<C>, doc: NamespaceId, path: PathBuf) -> Result<()>
where
    C: ServiceConnection<ProviderService>,
{
    let path = path.canonicalize()?;
    println!("mounting {} at {}", doc, path.display());
    let fs = IrohFs::new(iroh.clone(), doc).await?;

    println!("fs prepared");
    perform_mount_and_wait_for_ctrlc(
        &path,
        fs,
        true,
        true,
        format!("127.0.0.1:{HOSTPORT}"),
        || {},
    )
    .await?;

    Ok(())
}

#[derive(Debug, Clone)]
enum FSContents {
    File { key: Bytes, author: AuthorId },
    Directory { content: Vec<fileid3> },
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct FSEntry {
    id: fileid3,
    attr: fattr3,
    name: filename3,
    parent: fileid3,
    contents: FSContents,
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

fn make_file(
    name: &str,
    id: fileid3,
    parent: fileid3,
    content_len: u64,
    key: Bytes,
    author: AuthorId,
    ts: nfstime3,
) -> FSEntry {
    let attr = fattr3 {
        ftype: ftype3::NF3REG,
        mode: 0o755,
        nlink: 1,
        uid: 507,
        gid: 507,
        size: content_len,
        used: content_len,
        rdev: specdata3::default(),
        fsid: 0,
        fileid: id,
        atime: nfstime3::default(),
        mtime: ts,
        ctime: ts,
    };
    FSEntry {
        id,
        attr,
        name: name.as_bytes().into(),
        parent,
        contents: FSContents::File { key, author },
    }
}

fn make_dir(name: &str, id: fileid3, parent: fileid3, content: Vec<fileid3>) -> FSEntry {
    let attr = fattr3 {
        ftype: ftype3::NF3DIR,
        mode: 0o777,
        nlink: 1,
        uid: 507,
        gid: 507,
        size: 0,
        used: 0,
        rdev: specdata3::default(),
        fsid: 0,
        fileid: id,
        atime: nfstime3::default(),
        mtime: now(),
        ctime: nfstime3::default(),
    };
    FSEntry {
        id,
        attr,
        name: name.as_bytes().into(),
        parent,
        contents: FSContents::Directory { content },
    }
}

#[derive(Debug)]
pub struct IrohFs<C>
where
    C: ServiceConnection<ProviderService>,
{
    iroh: Iroh<C>,
    doc: Doc<C>,
    fs: Arc<RwLock<BTreeMap<u64, FSEntry>>>,
    next_id: Arc<AtomicU64>,
    rootdir: fileid3,
    author: AuthorId,
}

impl<C> IrohFs<C>
where
    C: ServiceConnection<ProviderService>,
{
    async fn new(iroh: Iroh<C>, doc_id: NamespaceId) -> Result<Self> {
        let doc = iroh
            .docs
            .open(doc_id)
            .await?
            .ok_or_else(|| anyhow!("unknown document"))?;

        // TODO: better
        let author = iroh.authors.create().await?;

        let mut entries = BTreeMap::new();
        entries.insert(0, make_file("", 0, 0, 0, Bytes::default(), author, now())); // fileid 0 is special

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
                make_file(
                    &name,
                    id,
                    dir_id,
                    entry.content_len(),
                    entry.key().to_vec().into(),
                    entry.author(),
                    ts_to_nfstime(entry.timestamp()),
                ),
            );
        }

        let root_dir = make_dir(
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

                                if let Some(fs_entry) =
                                    fs.values_mut().find(|e| e.name.as_ref() == name.as_bytes())
                                {
                                    // existing entry, update
                                    fs_entry.attr.mtime = now();
                                    fs_entry.attr.size = entry.content_len();
                                    fs_entry.attr.used = entry.content_len();
                                } else {
                                    fs.insert(
                                        id,
                                        make_file(
                                            &name,
                                            id,
                                            dir_id,
                                            entry.content_len(),
                                            entry.key().to_vec().into(),
                                            entry.author(),
                                            ts_to_nfstime(entry.timestamp()),
                                        ),
                                    );

                                    // update root dir
                                    let FSContents::Directory { content } =
                                        &mut fs.get_mut(&1).unwrap().contents
                                    else {
                                        panic!("1 must be the root dir");
                                    };
                                    content.push(id);
                                }
                                // update mtime of parent
                                fs.get_mut(&1).unwrap().attr.mtime = now();

                                info!("inserted {}", name);
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

        Ok(Self {
            fs,
            doc,
            rootdir: 1,
            next_id,
            iroh,
            author,
        })
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
            let file = fs.get_mut(&id).ok_or_else(|| nfsstat3::NFS3ERR_NOENT)?;

            let mut fssize = file.attr.size;
            if let FSContents::File { key, author } = &mut file.contents {
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
            file.attr.used = fssize;

            file.attr
        };

        // update mtime of the parent
        fs.get_mut(&1).unwrap().attr.mtime = now();

        Ok(attr)
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
            let FSContents::Directory { content } = &mut dir.contents else {
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
                make_file(&name, newid, dirid, 0, key, self.author, now()),
            );
            fs[&newid].attr
        };

        Ok((newid, attr))
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
            let FSContents::Directory { content } = &mut dir.contents else {
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
                make_file(&name, newid, dirid, 0, key, self.author, now()),
            );
        }
        Ok(newid)
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let fs = self.fs.read().await;
        let entry = fs.get(&dirid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        if let FSContents::File { .. } = entry.contents {
            return Err(nfsstat3::NFS3ERR_NOTDIR);
        } else if let FSContents::Directory { content, .. } = &entry.contents {
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
                    if f.name[..] == filename[..] {
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
        let entry = fs.get(&id).ok_or(nfsstat3::NFS3ERR_NOENT)?;

        // update attrs if needed

        if let FSContents::File { author, key } = &entry.contents {
            let author = author.clone();
            let key = key.clone();
            drop(fs);

            let mut fs = self.fs.write().await;
            let fs_entry = fs.get_mut(&id).ok_or(nfsstat3::NFS3ERR_NOENT)?;
            if let Some(entry) = self
                .doc
                .get_exact(author, key, true)
                .await
                .map_err(|_| nfsstat3::NFS3ERR_SERVERFAULT)?
            {
                fs_entry.attr.mtime = ts_to_nfstime(entry.timestamp());
            }
            Ok(fs_entry.attr)
        } else {
            Ok(entry.attr)
        }
    }

    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        let mut fs = self.fs.write().await;
        let entry = fs.get_mut(&id).ok_or(nfsstat3::NFS3ERR_NOENT)?;
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
                entry.attr.uid = u;
            }
            nfs::set_uid3::Void => {}
        }
        match setattr.gid {
            nfs::set_gid3::gid(u) => {
                entry.attr.gid = u;
            }
            nfs::set_gid3::Void => {}
        }
        match setattr.size {
            nfs::set_size3::size(s) => {
                entry.attr.size = s;
                entry.attr.used = s;

                if let FSContents::File { key, author } = &mut entry.contents {
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
                    if !bytes.is_empty() {
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
        Ok(entry.attr)
    }

    async fn read(
        &self,
        id: fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        let fs = self.fs.read().await;
        let entry = fs.get(&id).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        if let FSContents::Directory { .. } = entry.contents {
            return Err(nfsstat3::NFS3ERR_ISDIR);
        } else if let FSContents::File { key, author } = &entry.contents {
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
        if let FSContents::File { .. } = entry.contents {
            return Err(nfsstat3::NFS3ERR_NOTDIR);
        } else if let FSContents::Directory { content, .. } = &entry.contents {
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
                    name: entry.name.clone(),
                    attr: entry.attr,
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
        let fid = fs
            .values()
            .position(|e| e.name.as_ref() == filename.as_ref())
            .ok_or(nfsstat3::NFS3ERR_NOENT)? as u64;

        // Remove entry from the cache
        let entry = fs.remove(&fid);

        // Remove from doc
        if let Some(FSContents::File { key, author }) = entry.map(|e| e.contents) {
            self.doc.del(author, key.clone()).await.map_err(|err| {
                error!("delete {:?}: {:?}", key, err);
                nfsstat3::NFS3ERR_SERVERFAULT
            })?;
        }

        // Update dir
        {
            let entry = fs.get_mut(&dirid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
            if let FSContents::Directory { content, .. } = &mut entry.contents {
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

        // read entry
        let fid = fs
            .values()
            .position(|e| e.name.as_ref() == from_filename.as_ref())
            .ok_or(nfsstat3::NFS3ERR_NOENT)? as u64;
        let entry = fs.get(&fid).ok_or(nfsstat3::NFS3ERR_NOENT)?;

        let FSContents::File { key, author } = &entry.contents else {
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

        // remove from old
        {
            let entry = fs.get_mut(&from_dirid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
            let FSContents::Directory { content, .. } = &mut entry.contents else {
                return Err(nfsstat3::NFS3ERR_NOENT);
            };
            content.retain(|v| *v != fid);
            entry.attr.mtime = now();
        }

        // insert into new dir
        {
            let entry = fs.get_mut(&to_dirid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
            let FSContents::Directory { content, .. } = &mut entry.contents else {
                return Err(nfsstat3::NFS3ERR_NOENT);
            };
            content.push(fid);
            entry.attr.mtime = now();
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
