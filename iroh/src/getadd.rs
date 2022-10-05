use std::path::{Path, PathBuf};

use crate::api::{Iroh, OutType};
use anyhow::{Context, Result};
use futures::Stream;
use futures::StreamExt;
use iroh_resolver::resolver::Path as IpfsPath;
use iroh_rpc_client::Client;

impl<'a> Iroh<'a> {
    pub fn get_stream<'b>(
        &self,
        root: &'b IpfsPath,
        output: Option<&'b Path>,
    ) -> impl Stream<Item = Result<(PathBuf, OutType<Client>)>> + 'b {
        tracing::debug!("get {:?}", root);
        let resolver = iroh_resolver::resolver::Resolver::new(self.get_client().clone());
        let results = resolver.resolve_recursive_with_paths(root.clone());
        async_stream::try_stream! {
            tokio::pin!(results);
            while let Some(res) = results.next().await {
                let (path, out) = res?;
                let path = Self::make_output_path(path, root.clone(), output.clone())?;
                if out.is_dir() {
                    yield (path, OutType::Dir);
                } else {
                    let reader = out.pretty(resolver.clone(), Default::default())?;
                    yield (path, OutType::Reader(reader));
                }
            }
        }
    }

    /// Adjusts the full path to replace the root with any given output path
    /// if it exists.
    fn make_output_path(full: IpfsPath, root: IpfsPath, output: Option<&Path>) -> Result<PathBuf> {
        if let Some(output) = output {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_resolver::resolver;
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
        let got = Iroh::make_output_path(full, root, output.as_deref()).unwrap();
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
        let got = Iroh::make_output_path(full, root, output.as_deref()).unwrap();
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
        let got = Iroh::make_output_path(full, root, output).unwrap();
        assert_eq!(expect, got);
    }
}
