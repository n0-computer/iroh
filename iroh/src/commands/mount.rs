use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use iroh::{client::Iroh, rpc_protocol::ProviderService};
use iroh_bytes::Hash;
use iroh_sync::{store::Query, AuthorId, NamespaceId};
use nfsserve::{
    nfs::{
        self, fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, nfstime3, sattr3, specdata3,
    },
    vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities},
};
use quic_rpc::ServiceConnection;
use tokio::sync::Mutex;
use tracing::error;

use crate::commands::mount_runner::perform_mount_and_wait_for_ctrlc;

const HOSTPORT: u32 = 11111;

pub async fn exec<C>(iroh: &Iroh<C>, path: PathBuf) -> Result<()>
where
    C: ServiceConnection<ProviderService>,
{
    let path = path.canonicalize()?;
    println!("mounting {}", path.display());
    let fs = IrohFs::new(iroh.clone()).await?;

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
    File {
        content_hash: Hash,
        content_len: u64,
        author: AuthorId,
        namespace: NamespaceId,
        key: Bytes,
    },
    Directory {
        content: Vec<fileid3>,
        namespace: NamespaceId,
        author: AuthorId,
    },
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

fn make_file(
    name: &str,
    id: fileid3,
    parent: fileid3,
    content_hash: Hash,
    content_len: u64,
    author: AuthorId,
    namespace: NamespaceId,
    key: Bytes,
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
        fileid: 2,
        atime: nfstime3::default(),
        mtime: nfstime3::default(),
        ctime: nfstime3::default(),
    };
    FSEntry {
        id,
        attr,
        name: name.as_bytes().into(),
        parent,
        contents: FSContents::File {
            content_hash,
            content_len,
            namespace,
            author,
            key,
        },
    }
}

fn make_dir(
    name: &str,
    id: fileid3,
    parent: fileid3,
    content: Vec<fileid3>,
    namespace: NamespaceId,
    author: AuthorId,
) -> FSEntry {
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
        fileid: 1,
        atime: nfstime3::default(),
        mtime: nfstime3::default(),
        ctime: nfstime3::default(),
    };
    FSEntry {
        id,
        attr,
        name: name.as_bytes().into(),
        parent,
        contents: FSContents::Directory {
            content,
            namespace,
            author,
        },
    }
}

#[derive(Debug)]
pub struct IrohFs<C>
where
    C: ServiceConnection<ProviderService>,
{
    iroh: Iroh<C>,
    fs: Mutex<Vec<FSEntry>>,
    rootdir: fileid3,
}

impl<C> IrohFs<C>
where
    C: ServiceConnection<ProviderService>,
{
    async fn new(iroh: Iroh<C>) -> Result<Self> {
        // TODO: better
        let author = iroh.authors.create().await?;
        let none_author = AuthorId::default();
        let none_ns = NamespaceId::default();
        let mut entries = vec![
            make_file(
                "",
                0,
                0,
                Hash::EMPTY,
                0,
                none_author,
                none_ns,
                Bytes::default(),
            ), // fileid 0 is special
        ];

        let mut docs = iroh.docs.list().await?;
        let mut current_id = 2;
        let mut root_children = Vec::new();
        while let Some(item) = docs.next().await {
            let (doc_id, cap) = item?;
            let dir_id = current_id;
            current_id += 1;

            let mut children = Vec::new();
            let mut files = Vec::new();

            let doc = iroh.docs.open(doc_id).await?.unwrap();

            let mut keys = doc.get_many(Query::all()).await?;
            while let Some(entry) = keys.next().await {
                let entry = entry?;
                let name = String::from_utf8_lossy(&entry.key()).replace("/", "-");
                let id = current_id;
                current_id += 1;
                children.push(id);
                files.push(make_file(
                    &name,
                    id,
                    dir_id,
                    entry.content_hash(),
                    entry.content_len(),
                    entry.author(),
                    entry.namespace(),
                    entry.key().to_vec().into(),
                ));
            }

            // TODO: store cap to indicate read/write
            entries.push(make_dir(
                &format!("doc:{}", doc_id),
                dir_id, // current id
                1,      // parent id
                children,
                doc_id,
                author,
            ));
            entries.extend(files);
            root_children.push(dir_id);
        }

        let root_dir = make_dir(
            "/",
            1, // current id. Must match position in entries
            1, // parent id
            root_children,
            none_ns,
            none_author,
        );
        entries.insert(1, root_dir);

        Ok(Self {
            fs: Mutex::new(entries),
            rootdir: 1,
            iroh,
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
        {
            let mut fs = self.fs.lock().await;
            let mut fssize = fs[id as usize].attr.size;
            if let FSContents::File {
                content_hash,
                content_len,
                author,
                namespace,
                key,
            } = &mut fs[id as usize].contents
            {
                // get the full content
                let mut bytes = self
                    .iroh
                    .blobs
                    .read_to_bytes(*content_hash)
                    .await
                    .map_err(|_| nfsstat3::NFS3ERR_SERVERFAULT)?
                    .to_vec();
                let offset = offset as usize;
                if offset + data.len() > bytes.len() {
                    bytes.resize(offset + data.len(), 0);
                    bytes[offset..].copy_from_slice(data);
                    fssize = bytes.len() as u64;
                }

                // store back
                let doc = self
                    .iroh
                    .docs
                    .open(*namespace)
                    .await
                    .map_err(|_| nfsstat3::NFS3ERR_SERVERFAULT)?
                    .ok_or(nfsstat3::NFS3ERR_SERVERFAULT)?;

                let hash = doc
                    .set_bytes(*author, key.clone(), bytes)
                    .await
                    .map_err(|_| nfsstat3::NFS3ERR_SERVERFAULT)?;
                *content_hash = hash;
                *content_len = fssize;
            }
            fs[id as usize].attr.size = fssize;
            fs[id as usize].attr.used = fssize;
        }
        self.getattr(id).await
    }

    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        _attr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let newid: fileid3;
        {
            let mut fs = self.fs.lock().await;
            newid = fs.len() as fileid3;
            let file = if let FSContents::Directory {
                content,
                namespace,
                author,
            } = &mut fs[dirid as usize].contents
            {
                let bytes = Bytes::default();
                let doc = self
                    .iroh
                    .docs
                    .open(*namespace)
                    .await
                    .map_err(|err| {
                        error!("open {}: {:?}", namespace, err);
                        nfsstat3::NFS3ERR_SERVERFAULT
                    })?
                    .ok_or(nfsstat3::NFS3ERR_SERVERFAULT)?;

                let key: Bytes = filename.as_ref().to_vec().into();

                // Not writing, as we are not storing empty entries
                let hash = Hash::EMPTY;
                content.push(newid);

                Some(make_file(
                    std::str::from_utf8(filename).unwrap(),
                    newid,
                    dirid,
                    hash,
                    0,
                    *author,
                    *namespace,
                    key,
                ))
            } else {
                None
            };

            if let Some(file) = file {
                fs.push(file);
            }
        }
        Ok((newid, self.getattr(newid).await.unwrap()))
    }

    async fn create_exclusive(
        &self,
        _dirid: fileid3,
        _filename: &filename3,
    ) -> Result<fileid3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_NOTSUPP)
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let fs = self.fs.lock().await;
        let entry = fs.get(dirid as usize).ok_or(nfsstat3::NFS3ERR_NOENT)?;
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
                if let Some(f) = fs.get(*i as usize) {
                    if f.name[..] == filename[..] {
                        return Ok(*i);
                    }
                }
            }
        }
        Err(nfsstat3::NFS3ERR_NOENT)
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        let fs = self.fs.lock().await;
        let entry = fs.get(id as usize).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        Ok(entry.attr)
    }

    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        let mut fs = self.fs.lock().await;
        let entry = fs.get_mut(id as usize).ok_or(nfsstat3::NFS3ERR_NOENT)?;
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

                if let FSContents::File {
                    content_hash,
                    content_len,
                    author,
                    namespace,
                    key,
                } = &mut entry.contents
                {
                    // get the full content
                    let mut bytes = self
                        .iroh
                        .blobs
                        .read_to_bytes(*content_hash)
                        .await
                        .map_err(|err| {
                            error!("read_to_bytes {}: {:?} {:?}", namespace, key, err);
                            nfsstat3::NFS3ERR_SERVERFAULT
                        })?
                        .to_vec();

                    bytes.resize(s as usize, 0);

                    // store back
                    let doc = self
                        .iroh
                        .docs
                        .open(*namespace)
                        .await
                        .map_err(|err| {
                            error!("open {}: {:?}", namespace, err);
                            nfsstat3::NFS3ERR_SERVERFAULT
                        })?
                        .ok_or(nfsstat3::NFS3ERR_SERVERFAULT)?;

                    let hash = if bytes.is_empty() {
                        Hash::EMPTY
                    } else {
                        doc.set_bytes(*author, key.clone(), bytes)
                            .await
                            .map_err(|err| {
                                error!("set_bytes {}: {:?} {:?}", namespace, key, err);
                                nfsstat3::NFS3ERR_SERVERFAULT
                            })?
                    };
                    *content_hash = hash;
                    *content_len = s;
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
        let fs = self.fs.lock().await;
        let entry = fs.get(id as usize).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        if let FSContents::Directory { .. } = entry.contents {
            return Err(nfsstat3::NFS3ERR_ISDIR);
        } else if let FSContents::File { content_hash, .. } = &entry.contents {
            let mut start = offset as usize;
            let mut end = offset as usize + count as usize;

            // TODO: partial reads
            let bytes = self
                .iroh
                .blobs
                .read_to_bytes(*content_hash)
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
        let fs = self.fs.lock().await;
        let entry = fs.get(dirid as usize).ok_or(nfsstat3::NFS3ERR_NOENT)?;
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
                ret.entries.push(DirEntry {
                    fileid: *i,
                    name: fs[(*i) as usize].name.clone(),
                    attr: fs[(*i) as usize].attr,
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

    /// Removes a file.
    /// If not supported dur to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    #[allow(unused)]
    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        return Err(nfsstat3::NFS3ERR_NOTSUPP);
    }

    /// Removes a file.
    /// If not supported dur to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    #[allow(unused)]
    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        return Err(nfsstat3::NFS3ERR_NOTSUPP);
    }

    #[allow(unused)]
    async fn mkdir(
        &self,
        _dirid: fileid3,
        _dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
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
        return Err(nfsstat3::NFS3ERR_NOTSUPP);
    }
}
