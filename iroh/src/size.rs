use std::path::{Path, PathBuf};

use async_stream::stream;
use futures::stream::Stream;
use tokio::fs;

#[derive(Debug, PartialEq, Eq)]
pub struct FileInfo {
    pub path: PathBuf,
    pub size: u64,
}

pub fn size_stream(path: &Path) -> impl Stream<Item = FileInfo> + '_ {
    stream! {
        let mut stack = vec![path.to_path_buf()];
        while let Some(path) = stack.pop() {
            if path.is_dir() {
                let mut read_dir = fs::read_dir(&path).await.unwrap();
                while let Some(entry) = read_dir.next_entry().await.unwrap() {
                    stack.push(entry.path());
                }
            } else if path.is_symlink() {
                continue;
            } else {
                let size = fs::metadata(&path).await.unwrap().len();
                let path = path.clone();
                yield FileInfo { path, size };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream::StreamExt;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_read_directory_size() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("fixtures");
        d.push("dir");
        let mut size_info = size_stream(&d).collect::<Vec<FileInfo>>().await;
        // have to sort this for testing purposes as read_dir has no guaranteed
        // order
        size_info.sort_by_key(|info| info.path.clone());
        assert_eq!(
            size_info,
            vec![
                FileInfo {
                    path: d.join("a.txt"),
                    size: 7,
                },
                FileInfo {
                    path: d.join("subdir").join("b.txt"),
                    size: 15
                },
                FileInfo {
                    path: d.join("subdir").join("c.txt"),
                    size: 14,
                },
            ],
        );
    }
}
