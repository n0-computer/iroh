use std::path::{Path, PathBuf};

use anyhow::{anyhow, ensure, Result};
use futures::{Stream, StreamExt};
use relative_path::RelativePathBuf;

use crate::{IpfsPath, OutType};

/// Takes a stream of blocks as from `get` and writes it to the filesystem.
pub async fn write_get_stream(
    ipfs_path: &IpfsPath,
    blocks: impl Stream<Item = Result<(RelativePathBuf, OutType)>>,
    output_path: Option<&Path>,
) -> Result<PathBuf> {
    let root_path = get_root_path(ipfs_path, output_path)
        .ok_or_else(|| anyhow!("IPFS path does not refer to a CID"))?;
    ensure!(
        !root_path.exists(),
        "output path {} already exists",
        root_path.display()
    );

    save_get_stream(&root_path, blocks).await?;
    Ok(root_path)
}

async fn save_get_stream(
    root_path: &Path,
    blocks: impl Stream<Item = Result<(RelativePathBuf, OutType)>>,
) -> Result<()> {
    tokio::pin!(blocks);
    while let Some(block) = blocks.next().await {
        let (path, out) = block?;
        let full_path = path.to_path(root_path);
        println!("full path: {:?}", full_path);
        match out {
            OutType::Dir => {
                tokio::fs::create_dir_all(full_path).await?;
            }
            OutType::Reader(mut reader) => {
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent.to_path(root_path)).await?;
                }
                let mut f = tokio::fs::File::create(full_path).await?;
                tokio::io::copy(&mut reader, &mut f).await?;
            }
            OutType::Symlink(target) => {
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent.to_path(root_path)).await?;
                }
                #[cfg(windows)]
                tokio::task::spawn_blocking(move || {
                    make_windows_symlink(target, full_path).map_err(|e| anyhow::anyhow!(e))
                })
                .await??;

                #[cfg(unix)]
                tokio::fs::symlink(target, full_path).await?;
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn make_windows_symlink(target: PathBuf, path: PathBuf) -> Result<()> {
    if target.is_dir() {
        std::os::windows::fs::symlink_dir(target, path).map_err(|e| anyhow::anyhow!(e))
    } else {
        std::os::windows::fs::symlink_file(target, path).map_err(|e| anyhow::anyhow!(e))
    }
}

/// Given an cid and an optional output path, determine root path
fn get_root_path(ipfs_path: &IpfsPath, output_path: Option<&Path>) -> Option<PathBuf> {
    match output_path {
        Some(path) => Some(path.to_path_buf()),
        None => {
            if ipfs_path.tail().is_empty() {
                ipfs_path.cid().map(|c| PathBuf::from(c.to_string()))
            } else {
                Some(PathBuf::from(ipfs_path.tail().last().unwrap()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_save_get_stream() {
        let stream = Box::pin(futures::stream::iter(vec![
            Ok((RelativePathBuf::from_path("a").unwrap(), OutType::Dir)),
            Ok((
                RelativePathBuf::from_path("a/c").unwrap(),
                OutType::Symlink(PathBuf::from("../b")),
            )),
            Ok((
                RelativePathBuf::from_path("b").unwrap(),
                OutType::Reader(Box::new(std::io::Cursor::new("hello"))),
            )),
        ]));
        let tmp_dir = TempDir::new().unwrap().path().join("test_save_get_stream");
        save_get_stream(&tmp_dir, stream).await.unwrap();
        assert!(tmp_dir.join("a").is_dir());
        assert!(tmp_dir.join("a/c").is_symlink());
        let target = tokio::fs::read_link(tmp_dir.join("a/c"))
            .await
            .expect("file to exist");
        assert_eq!(target, PathBuf::from("../b"));
        assert_eq!(std::fs::read_to_string(tmp_dir.join("b")).unwrap(), "hello");
    }

    #[test]
    fn test_get_root_path() {
        let ipfs_path =
            IpfsPath::from_str("/ipfs/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N").unwrap();
        assert_eq!(
            get_root_path(&ipfs_path, None).unwrap(),
            PathBuf::from("QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N")
        );
        assert_eq!(
            get_root_path(&ipfs_path, Some(Path::new("bar"))).unwrap(),
            PathBuf::from("bar")
        );
    }

    #[test]
    fn test_get_root_path_with_tail() {
        let ipfs_path =
            IpfsPath::from_str("/ipfs/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N/tail")
                .unwrap();
        assert_eq!(
            get_root_path(&ipfs_path, None).unwrap(),
            PathBuf::from("tail")
        );
        assert_eq!(
            get_root_path(&ipfs_path, Some(Path::new("bar"))).unwrap(),
            PathBuf::from("bar")
        );
    }
}
