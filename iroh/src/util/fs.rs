//! Utilities for filesystem operations.
use std::{
    borrow::Cow,
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, Context};
use walkdir::WalkDir;

/// A data source
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct DataSource {
    /// Custom name
    name: String,
    /// Path to the file
    path: PathBuf,
}

impl DataSource {
    /// Creates a new [`DataSource`] from a [`PathBuf`].
    pub fn new(path: PathBuf) -> Self {
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        DataSource { path, name }
    }
    /// Creates a new [`DataSource`] from a [`PathBuf`] and a custom name.
    pub fn with_name(path: PathBuf, name: String) -> Self {
        DataSource { path, name }
    }

    /// Returns blob name for this data source.
    ///
    /// If no name was provided when created it is derived from the path name.
    pub fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }

    /// Returns the path of this data source.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl From<PathBuf> for DataSource {
    fn from(value: PathBuf) -> Self {
        DataSource::new(value)
    }
}

impl From<&std::path::Path> for DataSource {
    fn from(value: &std::path::Path) -> Self {
        DataSource::new(value.to_path_buf())
    }
}

/// Create data sources from a path.
pub fn scan_path(root: PathBuf) -> anyhow::Result<Vec<DataSource>> {
    Ok(if root.is_dir() {
        let files = WalkDir::new(&root).into_iter();
        let data_sources = files
            .map(|entry| {
                let entry = entry?;
                let root = root.clone();
                if !entry.file_type().is_file() {
                    // Skip symlinks. Directories are handled by WalkDir.
                    return Ok(None);
                }
                let path = entry.into_path();
                let name = canonicalize_path(path.strip_prefix(&root)?)?;
                anyhow::Ok(Some(DataSource { name, path }))
            })
            .filter_map(Result::transpose);
        let data_sources: Vec<anyhow::Result<DataSource>> = data_sources.collect::<Vec<_>>();
        data_sources
            .into_iter()
            .collect::<anyhow::Result<Vec<_>>>()?
    } else {
        // A single file, use the file name as the name of the blob.
        vec![scan_file(root)?]
    })
}

/// Create a single file data source from a path to a file.
pub fn scan_file(path: PathBuf) -> anyhow::Result<DataSource> {
    if !path.is_file() {
        bail!("Expected {} to be a file", path.to_string_lossy());
    }
    Ok(DataSource {
        name: canonicalize_path(path.file_name().context("path must be a file")?)?,
        path,
    })
}

/// This function converts a canonicalized relative path to a string, returning
/// an error if the path is not valid unicode.
///
/// This function will also fail if the path is non canonical, i.e. contains
/// `..` or `.`, or if the path components contain any windows or unix path
/// separators.
pub fn canonicalize_path(path: impl AsRef<Path>) -> anyhow::Result<String> {
    let parts = path
        .as_ref()
        .components()
        .map(|c| {
            let c = if let Component::Normal(x) = c {
                x.to_str().context("invalid character in path")?
            } else {
                anyhow::bail!("invalid path component {:?}", c)
            };
            anyhow::ensure!(
                !c.contains('/') && !c.contains('\\'),
                "invalid path component {:?}",
                c
            );
            Ok(c)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_canonicalize_path() {
        assert_eq!(super::canonicalize_path("foo/bar").unwrap(), "foo/bar");
    }
}
