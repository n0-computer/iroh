use std::{
    cmp,
    fs::{self, File},
    io::{self, Read},
    num::ParseIntError,
    path::Path,
    str::FromStr,
};

use anyhow::{Context, Result};

const PREFIX: &str = "/repo/flatfs/shard/";
pub const FILE_NAME: &str = "SHARDING";

/// The available sharding functions.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Shard {
    Prefix(usize),
    Suffix(usize),
    NextToLast(usize),
}

impl Default for Shard {
    fn default() -> Self {
        Shard::NextToLast(2)
    }
}

impl Shard {
    /// Ensures that the corresponding sharding file exists on disk.
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = self.to_string();
        let path = path.as_ref().join(FILE_NAME);
        fs::write(&path, content).with_context(|| format!("Failed to write shard to {path:?}"))?;
        Ok(())
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().join(FILE_NAME);
        let file = File::open(&path).with_context(|| format!("Failed to open file {path:?}"))?;
        let mut content = String::with_capacity(50);

        // Protect agains invalid files and unknown formats.
        file.take(100).read_to_string(&mut content)?;
        let res = content.parse()?;
        Ok(res)
    }

    /// The name of the sharding function.
    pub const fn name(&self) -> &'static str {
        match self {
            Shard::Prefix(_) => "prefix",
            Shard::Suffix(_) => "suffix",
            Shard::NextToLast(_) => "next-to-last",
        }
    }

    /// The parameter of the sharding function.
    pub fn param(&self) -> usize {
        match self {
            Shard::Prefix(p) => *p,
            Shard::Suffix(p) => *p,
            Shard::NextToLast(p) => *p,
        }
    }

    /// Returns the shard directory according to the specific strategy.
    pub fn dir<'a>(&self, value: &'a str) -> &'a str {
        match self {
            Shard::Prefix(n) => {
                let n = cmp::min(*n, value.len());
                value.split_at(n).0
            }
            Shard::Suffix(n) => {
                let n = cmp::min(*n, value.len());
                value.split_at(value.len() - n).1
            }
            Shard::NextToLast(n) => {
                let n = cmp::min(*n + 1, value.len());
                let (_, imm) = value.split_at(value.len() - n);
                let n = cmp::min(imm.len(), 1);
                imm.split_at(imm.len() - n).0
            }
        }
    }
}

impl ToString for Shard {
    fn to_string(&self) -> String {
        format!("{PREFIX}v1/{}/{}", self.name(), self.param())
    }
}

impl FromStr for Shard {
    type Err = io::Error;

    fn from_str(input: &str) -> io::Result<Self> {
        let make_err = |msg| Err(io::Error::new(io::ErrorKind::InvalidInput, msg));

        let input = input.trim();
        if input.is_empty() {
            return make_err("empty shard");
        }

        if let Some(no_prefix) = input.strip_prefix(PREFIX) {
            let mut parts = no_prefix.split('/');
            match (parts.next(), parts.next(), parts.next()) {
                (Some(version), Some(name), Some(param)) => {
                    if version.is_empty() {
                        return make_err("missing version");
                    }
                    if name.is_empty() {
                        return make_err("missing name");
                    }
                    if param.is_empty() {
                        return make_err("missing param");
                    }

                    if version != "v1" {
                        return make_err("invalid version");
                    }

                    let param: usize = param.parse().map_err(|err: ParseIntError| {
                        io::Error::new(io::ErrorKind::InvalidInput, err.to_string())
                    })?;
                    match name {
                        "prefix" => Ok(Shard::Prefix(param)),
                        "suffix" => Ok(Shard::Suffix(param)),
                        "next-to-last" => Ok(Shard::NextToLast(param)),
                        _ => make_err("unknown name"),
                    }
                }
                _ => make_err("invalid shard"),
            }
        } else {
            make_err("missing prefix")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_to_string() {
        assert_eq!(
            Shard::Suffix(4).to_string(),
            "/repo/flatfs/shard/v1/suffix/4"
        );

        assert_eq!(
            Shard::Prefix(12).to_string(),
            "/repo/flatfs/shard/v1/prefix/12"
        );

        assert_eq!(
            Shard::NextToLast(4).to_string(),
            "/repo/flatfs/shard/v1/next-to-last/4"
        );
    }

    #[test]
    fn shard_from_string() {
        assert_eq!(
            "/repo/flatfs/shard/v1/suffix/4".parse::<Shard>().unwrap(),
            Shard::Suffix(4)
        );

        assert_eq!(
            "/repo/flatfs/shard/v1/prefix/12".parse::<Shard>().unwrap(),
            Shard::Prefix(12)
        );

        assert_eq!(
            "/repo/flatfs/shard/v1/next-to-last/4"
                .parse::<Shard>()
                .unwrap(),
            Shard::NextToLast(4)
        );

        let match_err = |input: &str, err_msg| {
            let err = input.parse::<Shard>();
            assert!(err.is_err());
            if let Err(err) = err {
                assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
                assert_eq!(format!("{}", err.get_ref().unwrap()), err_msg);
            }
        };

        match_err("/repo/flatfs/shard/v1/next-to-other/4", "unknown name");
        match_err("/repo/flatfs/shard/v1/next-to-last/", "missing param");
        match_err("/repo/flatfs/shard/v1/", "invalid shard");
        match_err("/repo/flatfs/shard/v//4", "missing name");
        match_err("/repo/flatfs/shard/", "invalid shard");
        match_err("/repo/flatfs/shard/v/next-to-last/4", "invalid version");
        match_err("/repo/flatfs/shard//next-to-last/4", "missing version");
        match_err("/v1/next-to-last", "missing prefix");
        match_err("", "empty shard");
    }

    #[test]
    fn test_shard_dir() {
        assert_eq!(Shard::Prefix(2).dir("hello"), "he");
        assert_eq!(Shard::Prefix(2).dir("he"), "he");
        assert_eq!(Shard::Prefix(2).dir("h"), "h");
        assert_eq!(Shard::Prefix(2).dir(""), "");

        assert_eq!(Shard::Suffix(2).dir("hello"), "lo");
        assert_eq!(Shard::Suffix(2).dir("lo"), "lo");
        assert_eq!(Shard::Suffix(2).dir("o"), "o");
        assert_eq!(Shard::Suffix(2).dir(""), "");

        assert_eq!(Shard::NextToLast(2).dir("hello"), "ll");
        assert_eq!(Shard::NextToLast(2).dir("lo"), "l");
        assert_eq!(Shard::NextToLast(2).dir("o"), "");
        assert_eq!(Shard::NextToLast(2).dir(""), "");
    }
}
