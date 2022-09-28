use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cid::Cid;
use futures::Stream;
use futures::StreamExt;
use iroh_resolver::resolver::Path as IpfsPath;
use iroh_resolver::{resolver, unixfs_builder};
use iroh_rpc_client::Client;

pub async fn get(client: &Client, ipfs_path: &IpfsPath, output: Option<&Path>) -> Result<()> {
    let blocks = get_stream(client.clone(), ipfs_path, output.map(|p| p.to_path_buf()));
    tokio::pin!(blocks);
    while let Some(block) = blocks.next().await {
        let (path, out) = block?;
        match out {
            OutType::Dir => {
                tokio::fs::create_dir_all(path).await?;
            }
            OutType::Reader(mut reader) => {
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                let mut f = tokio::fs::File::create(path).await?;
                tokio::io::copy(&mut reader, &mut f).await?;
            }
        }
    }
    Ok(())
}

pub async fn add(client: &Client, path: &Path, recursive: bool, wrap: bool) -> Result<Cid> {
    let providing_client = iroh_resolver::unixfs_builder::StoreAndProvideClient {
        client: Box::new(client),
    };
    if path.is_dir() {
        unixfs_builder::add_dir(Some(&providing_client), path, wrap, recursive).await
    } else if path.is_file() {
        unixfs_builder::add_file(Some(&providing_client), path, wrap).await
    } else {
        anyhow::bail!("can only add files or directories");
    }
}

pub enum OutType<T: resolver::ContentLoader> {
    Dir,
    Reader(resolver::OutPrettyReader<T>),
}

pub fn get_stream<'a>(
    client: Client,
    root: &'a IpfsPath,
    output: Option<PathBuf>,
) -> impl Stream<Item = Result<(PathBuf, OutType<Client>)>> + 'a {
    tracing::debug!("get {:?}", root);
    let resolver = iroh_resolver::resolver::Resolver::new(client);
    let results = resolver.resolve_recursive_with_paths(root.clone());
    async_stream::try_stream! {
        tokio::pin!(results);
        while let Some(res) = results.next().await {
            let (path, out) = res?;
            let path = make_output_path(path, root.clone(), output.clone())?;
            if out.is_dir() {
                yield (path, OutType::Dir);
            } else {
                let reader = out.pretty(resolver.clone(), Default::default())?;
                yield (path, OutType::Reader(reader));
            }
        }
    }
}

// make_output_path adjusts the full path to replace the root with any given output path
// if it exists
fn make_output_path(full: IpfsPath, root: IpfsPath, output: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(ref output) = output {
        let root_str = &root.to_string()[..];
        let full_as_path = PathBuf::from(full.to_string());
        let path_str = full_as_path.to_str().context("invalid root path")?;
        let output_str = output.to_str().context("invalid output path")?;
        Ok(PathBuf::from(path_str.replace(root_str, output_str)))
    } else {
        // returns path as a string
        Ok(PathBuf::from(full.to_string_without_type()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_make_output_path() {
        // test with output dir
        let root =
            IpfsPath::from_str("/ipfs/QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR").unwrap();
        let full =
            IpfsPath::from_str("/ipfs/QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR/bar.txt")
                .unwrap();
        let output = Some(PathBuf::from("foo"));
        let expect = PathBuf::from("foo/bar.txt");
        let got = make_output_path(full, root, output).unwrap();
        assert_eq!(expect, got);

        // test with output filepath
        let root = resolver::Path::from_str(
            "/ipfs/QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR/bar.txt",
        )
        .unwrap();
        let full = resolver::Path::from_str(
            "/ipfs/QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR/bar.txt",
        )
        .unwrap();
        let output = Some(PathBuf::from("foo/baz.txt"));
        let expect = PathBuf::from("foo/baz.txt");
        let got = make_output_path(full, root, output).unwrap();
        assert_eq!(expect, got);

        // test no output path
        let root = resolver::Path::from_str("/ipfs/QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR")
            .unwrap();
        let full = resolver::Path::from_str(
            "/ipfs/QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR/bar.txt",
        )
        .unwrap();
        let output = None;
        let expect = PathBuf::from("QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR/bar.txt");
        let got = make_output_path(full, root, output).unwrap();
        assert_eq!(expect, got);
    }
}
