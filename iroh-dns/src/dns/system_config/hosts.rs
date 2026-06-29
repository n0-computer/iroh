//! Static name-to-address mappings from the system hosts file.
//!
//! On Unix this is `/etc/hosts`, on Windows the per-system hosts file under
//! `%SystemRoot%`. Entries are consulted ahead of the cache and the network so
//! that an operator can pin a relay or discovery origin to a fixed address, the
//! way the old hickory-backed resolver did via its `use_hosts_file` default.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use tracing::warn;

/// The A and AAAA addresses mapped to a single name.
#[derive(Debug, Default)]
struct Entry {
    a: Vec<Ipv4Addr>,
    aaaa: Vec<Ipv6Addr>,
}

/// Static host-to-address mappings parsed from the system hosts file.
#[derive(Debug, Default)]
pub(crate) struct Hosts {
    by_name: HashMap<String, Entry>,
}

impl Hosts {
    /// Reads and parses the system hosts file.
    ///
    /// Returns an empty mapping when the file is missing, unreadable, or the
    /// platform has no hosts file, so a missing file is never an error.
    pub(crate) fn from_system() -> Self {
        match hosts_path().and_then(|path| std::fs::read_to_string(path).ok()) {
            Some(content) => Self::parse(&content),
            None => Self::default(),
        }
    }

    /// Parses hosts-file content into a name-to-address mapping.
    ///
    /// Each non-comment line has the form `address host [host ...]`. Names are
    /// lowercased; comments (`#` to end of line) and unparsable addresses are
    /// skipped.
    fn parse(content: &str) -> Self {
        let mut by_name: HashMap<String, Entry> = HashMap::new();
        for line in content.lines() {
            let line = match line.split_once('#') {
                Some((before, _)) => before,
                None => line,
            }
            .trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let Some(addr) = fields.next() else {
                continue;
            };
            let Ok(addr) = addr.parse::<IpAddr>() else {
                warn!(%addr, "ignoring unparsable address in hosts file");
                continue;
            };
            for name in fields {
                let entry = by_name.entry(name.to_ascii_lowercase()).or_default();
                match addr {
                    IpAddr::V4(ip) => entry.a.push(ip),
                    IpAddr::V6(ip) => entry.aaaa.push(ip),
                }
            }
        }
        Self { by_name }
    }

    /// Normalizes a query name to the hosts-file key form: lowercased, with any
    /// trailing dot removed.
    fn normalize(name: &str) -> String {
        name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
    }

    /// Returns the mapped IPv4 addresses for `name`, if any.
    pub(crate) fn lookup_ipv4(&self, name: &str) -> Option<Vec<Ipv4Addr>> {
        let entry = self.by_name.get(&Self::normalize(name))?;
        (!entry.a.is_empty()).then(|| entry.a.clone())
    }

    /// Returns the mapped IPv6 addresses for `name`, if any.
    pub(crate) fn lookup_ipv6(&self, name: &str) -> Option<Vec<Ipv6Addr>> {
        let entry = self.by_name.get(&Self::normalize(name))?;
        (!entry.aaaa.is_empty()).then(|| entry.aaaa.clone())
    }

    /// Builds a hosts map directly from file content, for tests.
    #[cfg(test)]
    pub(crate) fn from_content(content: &str) -> Self {
        Self::parse(content)
    }
}

#[cfg(unix)]
fn hosts_path() -> Option<std::path::PathBuf> {
    Some(std::path::PathBuf::from("/etc/hosts"))
}

#[cfg(windows)]
fn hosts_path() -> Option<std::path::PathBuf> {
    let system_root = std::env::var_os("SystemRoot")?;
    Some(std::path::Path::new(&system_root).join("System32\\drivers\\etc\\hosts"))
}

#[cfg(not(any(unix, windows)))]
fn hosts_path() -> Option<std::path::PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_and_lookup() {
        let hosts = Hosts::parse(
            "127.0.0.1 localhost\n10.0.1.10 myrelay.test relay\n::1 localhost myrelay.test\n",
        );
        assert_eq!(
            hosts.lookup_ipv4("myrelay.test"),
            Some(vec![Ipv4Addr::new(10, 0, 1, 10)])
        );
        // Alias on the same line resolves too.
        assert_eq!(
            hosts.lookup_ipv4("relay"),
            Some(vec![Ipv4Addr::new(10, 0, 1, 10)])
        );
        assert_eq!(
            hosts.lookup_ipv6("myrelay.test"),
            Some(vec![Ipv6Addr::LOCALHOST])
        );
        // No AAAA entry for a name that only has an A record.
        assert_eq!(hosts.lookup_ipv6("relay"), None);
    }

    #[test]
    fn lookup_is_case_insensitive_and_fqdn_tolerant() {
        let hosts = Hosts::parse("10.0.1.10 MyRelay.Test\n");
        assert_eq!(
            hosts.lookup_ipv4("myrelay.test."),
            Some(vec![Ipv4Addr::new(10, 0, 1, 10)])
        );
    }

    #[test]
    fn parse_skips_comments_and_garbage() {
        let hosts = Hosts::parse(
            "# a comment\n\n  10.0.1.10  host1  # trailing comment\nnot-an-ip host2\n",
        );
        assert_eq!(
            hosts.lookup_ipv4("host1"),
            Some(vec![Ipv4Addr::new(10, 0, 1, 10)])
        );
        assert_eq!(hosts.lookup_ipv4("host2"), None);
    }

    #[test]
    fn multiple_addresses_accumulate() {
        let hosts = Hosts::parse("10.0.0.1 host\n10.0.0.2 host\n");
        assert_eq!(
            hosts.lookup_ipv4("host"),
            Some(vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)])
        );
    }

    #[test]
    fn empty_lookup_returns_none() {
        let hosts = Hosts::default();
        assert_eq!(hosts.lookup_ipv4("anything"), None);
    }
}
