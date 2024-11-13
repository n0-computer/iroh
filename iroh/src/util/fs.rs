//! Utilities for filesystem operations.
use std::{
    fs::read_dir,
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, Context};
use bytes::Bytes;
use iroh_net::key::SecretKey;
use tokio::io::AsyncWriteExt;

/// Loads a [`SecretKey`] from the provided file, or stores a newly generated one
/// at the given location.
pub async fn load_secret_key(key_path: PathBuf) -> anyhow::Result<SecretKey> {
    if key_path.exists() {
        let keystr = tokio::fs::read(key_path).await?;
        let secret_key = SecretKey::try_from_openssh(keystr).context("invalid keyfile")?;
        Ok(secret_key)
    } else {
        let secret_key = SecretKey::generate();
        let ser_key = secret_key.to_openssh()?;

        // Try to canonicalize if possible
        let key_path = key_path.canonicalize().unwrap_or(key_path);
        let key_path_parent = key_path.parent().ok_or_else(|| {
            anyhow::anyhow!("no parent directory found for '{}'", key_path.display())
        })?;
        tokio::fs::create_dir_all(&key_path_parent).await?;

        // write to tempfile
        let (file, temp_file_path) = tempfile::NamedTempFile::new_in(key_path_parent)
            .context("unable to create tempfile")?
            .into_parts();
        let mut file = tokio::fs::File::from_std(file);
        file.write_all(ser_key.as_bytes())
            .await
            .context("unable to write keyfile")?;
        file.flush().await?;
        drop(file);

        // move file
        tokio::fs::rename(temp_file_path, key_path)
            .await
            .context("failed to rename keyfile")?;

        Ok(secret_key)
    }
}

/// Information about the content on a path
#[derive(Debug, Clone)]
pub struct PathContent {
    /// total size of all the files in the directory
    pub size: u64,
    /// total number of files in the directory
    pub files: u64,
}

/// Walks the directory to get the total size and number of files in directory or file
// TODO: possible combine with `scan_dir`
pub fn path_content_info(path: impl AsRef<Path>) -> anyhow::Result<PathContent> {
    path_content_info0(path)
}

fn path_content_info0(path: impl AsRef<Path>) -> anyhow::Result<PathContent> {
    let mut files = 0;
    let mut size = 0;
    let path = path.as_ref();

    if path.is_dir() {
        for entry in read_dir(path)? {
            let path0 = entry?.path();

            match path_content_info0(path0) {
                Ok(path_content) => {
                    size += path_content.size;
                    files += path_content.files;
                }
                Err(e) => bail!(e),
            }
        }
    } else {
        match path.try_exists() {
            Ok(true) => {
                size = path
                    .metadata()
                    .context(format!("Error reading metadata for {path:?}"))?
                    .len();
                files = 1;
            }
            Ok(false) => {
                tracing::warn!("Not including broking symlink at {path:?}");
            }
            Err(e) => {
                bail!(e);
            }
        }
    }
    Ok(PathContent { size, files })
}

/// Helper function that translates a key that was derived from the [`path_to_key`] function back
/// into a path.
///
/// If `prefix` exists, it will be stripped before converting back to a path
/// If `root` exists, will add the root as a parent to the created path
/// Removes any null byte that has been appended to the key
pub fn key_to_path(
    key: impl AsRef<[u8]>,
    prefix: Option<String>,
    root: Option<PathBuf>,
) -> anyhow::Result<PathBuf> {
    let mut key = key.as_ref();
    if key.is_empty() {
        return Ok(PathBuf::new());
    }
    // if the last element is the null byte, remove it
    if b'\0' == key[key.len() - 1] {
        key = &key[..key.len() - 1]
    }

    let key = if let Some(prefix) = prefix {
        let prefix = prefix.into_bytes();
        if prefix[..] == key[..prefix.len()] {
            &key[prefix.len()..]
        } else {
            anyhow::bail!("key {:?} does not begin with prefix {:?}", key, prefix);
        }
    } else {
        key
    };

    let mut path = if key[0] == b'/' {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };
    for component in key
        .split(|c| c == &b'/')
        .map(|c| String::from_utf8(c.into()).context("key contains invalid data"))
    {
        let component = component?;
        path = path.join(component);
    }

    // add root if it exists
    let path = if let Some(root) = root {
        root.join(path)
    } else {
        path
    };

    Ok(path)
}

/// Helper function that creates a document key from a canonicalized path, removing the `root` and adding the `prefix`, if they exist
///
/// Appends the null byte to the end of the key.
pub fn path_to_key(
    path: impl AsRef<Path>,
    prefix: Option<String>,
    root: Option<PathBuf>,
) -> anyhow::Result<Bytes> {
    let path = path.as_ref();
    let path = if let Some(root) = root {
        path.strip_prefix(root)?
    } else {
        path
    };
    let suffix = canonicalized_path_to_string(path, false)?.into_bytes();
    let mut key = if let Some(prefix) = prefix {
        prefix.into_bytes().to_vec()
    } else {
        Vec::new()
    };
    key.extend(suffix);
    key.push(b'\0');
    Ok(key.into())
}

/// This function converts an already canonicalized path to a string.
///
/// If `must_be_relative` is true, the function will fail if any component of the path is
/// `Component::RootDir`
///
/// This function will also fail if the path is non canonical, i.e. contains
/// `..` or `.`, or if the path components contain any windows or unix path
/// separators.
pub fn canonicalized_path_to_string(
    path: impl AsRef<Path>,
    must_be_relative: bool,
) -> anyhow::Result<String> {
    let mut path_str = String::new();
    let parts = path
        .as_ref()
        .components()
        .filter_map(|c| match c {
            Component::Normal(x) => {
                let c = match x.to_str() {
                    Some(c) => c,
                    None => return Some(Err(anyhow::anyhow!("invalid character in path"))),
                };

                if !c.contains('/') && !c.contains('\\') {
                    Some(Ok(c))
                } else {
                    Some(Err(anyhow::anyhow!("invalid path component {:?}", c)))
                }
            }
            Component::RootDir => {
                if must_be_relative {
                    Some(Err(anyhow::anyhow!("invalid path component {:?}", c)))
                } else {
                    path_str.push('/');
                    None
                }
            }
            _ => Some(Err(anyhow::anyhow!("invalid path component {:?}", c))),
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let parts = parts.join("/");
    path_str.push_str(&parts);
    Ok(path_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_to_key_roundtrip() {
        let path = PathBuf::from("/foo/bar");
        let expect_path = PathBuf::from("/foo/bar");
        let key = b"/foo/bar\0";
        let expect_key = Bytes::from(&key[..]);

        let got_key = path_to_key(path.clone(), None, None).unwrap();
        let got_path = key_to_path(got_key.clone(), None, None).unwrap();

        assert_eq!(expect_key, got_key);
        assert_eq!(expect_path, got_path);

        // including prefix
        let prefix = String::from("prefix:");
        let key = b"prefix:/foo/bar\0";
        let expect_key = Bytes::from(&key[..]);
        let got_key = path_to_key(path.clone(), Some(prefix.clone()), None).unwrap();
        assert_eq!(expect_key, got_key);
        let got_path = key_to_path(got_key, Some(prefix.clone()), None).unwrap();
        assert_eq!(expect_path, got_path);

        // including root
        let root = PathBuf::from("/foo");
        let key = b"prefix:bar\0";
        let expect_key = Bytes::from(&key[..]);
        let got_key = path_to_key(path, Some(prefix.clone()), Some(root.clone())).unwrap();
        assert_eq!(expect_key, got_key);
        let got_path = key_to_path(got_key, Some(prefix), Some(root)).unwrap();
        assert_eq!(expect_path, got_path);
    }

    #[test]
    fn test_canonicalized_path_to_string() {
        assert_eq!(
            canonicalized_path_to_string("foo/bar", true).unwrap(),
            "foo/bar"
        );
        assert_eq!(canonicalized_path_to_string("", true).unwrap(), "");
        assert_eq!(
            canonicalized_path_to_string("foo bar/baz/bat", true).unwrap(),
            "foo bar/baz/bat"
        );
        assert_eq!(
            canonicalized_path_to_string("/foo/bar", true).map_err(|e| e.to_string()),
            Err("invalid path component RootDir".to_string())
        );

        assert_eq!(
            canonicalized_path_to_string("/foo/bar", false).unwrap(),
            "/foo/bar"
        );
        let path = PathBuf::from("/").join("Ü").join("⁰€™■･�").join("東京");
        assert_eq!(
            canonicalized_path_to_string(path, false).unwrap(),
            "/Ü/⁰€™■･�/東京"
        )
    }

    #[test]
    fn test_get_path_content() {
        let dir = testdir::testdir!();
        let PathContent { size, files } = path_content_info(&dir).unwrap();
        assert_eq!(0, size);
        assert_eq!(0, files);
        let foo = b"hello_world";
        let bar = b"ipsum lorem";
        let bat = b"happy birthday";
        let expect_size = foo.len() + bar.len() + bat.len();
        std::fs::write(dir.join("foo.txt"), foo).unwrap();
        std::fs::write(dir.join("bar.txt"), bar).unwrap();
        std::fs::write(dir.join("bat.txt"), bat).unwrap();
        let PathContent { size, files } = path_content_info(&dir).unwrap();
        assert_eq!(expect_size as u64, size);
        assert_eq!(3, files);

        // create nested empty dirs
        std::fs::create_dir(dir.join("1")).unwrap();
        std::fs::create_dir(dir.join("2")).unwrap();
        let dir3 = dir.join("3");
        std::fs::create_dir(&dir3).unwrap();

        // create a nested dir w/ content
        let dir4 = dir3.join("4");
        std::fs::create_dir(&dir4).unwrap();
        std::fs::write(dir4.join("foo.txt"), foo).unwrap();
        std::fs::write(dir4.join("bar.txt"), bar).unwrap();
        std::fs::write(dir4.join("bat.txt"), bat).unwrap();

        let expect_size = expect_size * 2;
        let PathContent { size, files } = path_content_info(&dir).unwrap();
        assert_eq!(expect_size as u64, size);
        assert_eq!(6, files);
    }
}
