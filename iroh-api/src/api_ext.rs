use std::path::{Path, PathBuf};

use crate::{Api, IpfsPath, OutType};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::Stream;
use futures::StreamExt;

#[async_trait(?Send)]
pub trait ApiExt: Api {
    /// High level get, equivalent of CLI `iroh get`
    async fn get<'a>(
        &self,
        ipfs_path: &IpfsPath,
        output_path: Option<&'a Path>,
    ) -> Result<PathBuf> {
        ipfs_path
            .cid()
            .ok_or_else(|| anyhow!("IPFS path does not refer to a CID"))?;
        let out_path = get_out_path(ipfs_path, output_path);
        if out_path.exists() {
            return Err(anyhow!("output path {} already exists", out_path.display()));
        }
        let blocks = self.get_stream(ipfs_path);
        save_get_stream(&ipfs_path.to_path_buf(), &out_path, blocks).await?;
        Ok(out_path)
    }
}

impl<T> ApiExt for T where T: Api {}

/// take a stream of blocks as from `get_stream` and write them to the filesystem
async fn save_get_stream(
    root_path: &Path,
    out_path: &Path,
    blocks: impl Stream<Item = Result<(PathBuf, OutType)>>,
) -> Result<()> {
    tokio::pin!(blocks);
    while let Some(block) = blocks.next().await {
        let (path, out) = block?;
        let full_path = replace_with_out_path(root_path, out_path, &path)?;
        match out {
            OutType::Dir => {
                tokio::fs::create_dir_all(full_path).await?;
            }
            OutType::Reader(mut reader) => {
                if let Some(parent) = full_path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                let mut f = tokio::fs::File::create(full_path).await?;
                tokio::io::copy(&mut reader, &mut f).await?;
            }
        }
    }
    Ok(())
}

/// Given the ipfs_path and an optional output path, determine output path
fn get_out_path(ipfs_path: &IpfsPath, output_path: Option<&Path>) -> PathBuf {
    match output_path {
        Some(path) => path.to_path_buf(),
        None => {
            let mut out_path = ipfs_path.to_path_buf();
            if let Some(parent) = out_path.parent() {
                out_path = out_path
                    .strip_prefix(parent)
                    .expect("parent should always be a valid path prefix")
                    .to_path_buf();
            }
            out_path
        }
    }
}

fn replace_with_out_path(root_path: &Path, output_path: &Path, path: &Path) -> Result<PathBuf> {
    if root_path == path {
        return Ok(output_path.to_path_buf());
    }
    let relative = path.strip_prefix(root_path)?;
    Ok(output_path.join(relative))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::Cid;
    use std::str::FromStr;
    use tempdir::TempDir;

    #[tokio::test]
    async fn test_save_get_stream() {
        let stream = Box::pin(futures::stream::iter(vec![
            Ok((PathBuf::from("foo/a"), OutType::Dir)),
            Ok((
                PathBuf::from("foo/b"),
                OutType::Reader(Box::new(std::io::Cursor::new("hello"))),
            )),
        ]));
        let ipfs_path = PathBuf::from("foo");
        let tmp_dir = TempDir::new("test_save_get_stream").unwrap();
        save_get_stream(&ipfs_path, tmp_dir.path(), stream)
            .await
            .unwrap();
        assert!(tmp_dir.path().join("a").is_dir());
        assert_eq!(
            std::fs::read_to_string(tmp_dir.path().join("b")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn test_get_out_path() {
        let cid = Cid::from_str("QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR").unwrap();
        let ipfs_path = IpfsPath::from_cid(cid);
        assert_eq!(
            get_out_path(&ipfs_path, None),
            PathBuf::from("QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR")
        );
        assert_eq!(
            get_out_path(&ipfs_path, Some(Path::new("bar"))),
            PathBuf::from("bar")
        );
    }

    #[test]
    fn test_replace_with_out_path() {
        let got = replace_with_out_path(
            Path::new("foo/bar"),
            Path::new("baz"),
            Path::new("foo/bar/bat"),
        )
        .unwrap();
        let expect = PathBuf::from("baz/bat");
        assert_eq!(expect, got);

        let got =
            replace_with_out_path(Path::new("foo/bar"), Path::new("baz"), Path::new("foo/bar"))
                .unwrap();
        let expect = PathBuf::from("baz");
        assert_eq!(expect, got);
    }
}
