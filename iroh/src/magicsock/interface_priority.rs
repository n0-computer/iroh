//! Interface-based path prioritization for network paths.
//!
//! Allows preferring certain network interfaces over others when multiple paths
//! to a peer exist. Useful for scenarios like preferring Ethernet over Wi-Fi.

use std::{net::IpAddr, sync::Arc};

use netwatch::netmon;

/// Configuration for prioritizing network interfaces when selecting paths.
///
/// Interfaces are matched using glob-style patterns and assigned priority weights.
/// Higher weights indicate higher priority.
///
/// # Examples
///
/// ```no_run
/// use iroh::magicsock::InterfacePriority;
///
/// // Prefer Infiniband (ib*) over Ethernet (eth*, en*)
/// let priority = InterfacePriority::new(vec![
///     ("ib*".to_string(), 100),
///     ("eth*".to_string(), 50),
///     ("en*".to_string(), 50),
/// ]);
/// ```
#[derive(Debug, Clone)]
pub struct InterfacePriority {
    rules: Arc<Vec<InterfaceRule>>,
}

#[derive(Debug, Clone)]
struct InterfaceRule {
    pattern: Pattern,
    weight: u32,
}

#[derive(Debug, Clone)]
enum Pattern {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Contains(String),
    Wildcard { prefix: String, suffix: String },
}

impl InterfacePriority {
    /// Create a new interface priority configuration.
    ///
    /// # Arguments
    ///
    /// * `patterns` - List of (pattern, weight) tuples. Patterns support:
    ///   - Exact match: `"eth0"` matches only "eth0"
    ///   - Prefix: `"ib*"` matches "ib0", "ib1", etc.
    ///   - Suffix: `"*0"` matches "eth0", "ib0", etc.
    ///   - Contains: `"*eth*"` matches anything containing "eth"
    ///   - Complex: `"eth*0"` matches "eth0", "eth10", etc.
    ///
    /// Higher weights indicate higher priority.
    pub fn new(patterns: Vec<(String, u32)>) -> Self {
        let rules = patterns
            .into_iter()
            .map(|(pattern, weight)| InterfaceRule {
                pattern: Pattern::parse(&pattern),
                weight,
            })
            .collect();

        Self {
            rules: Arc::new(rules),
        }
    }

    /// Parse interface priorities from an environment variable.
    ///
    /// Format: `IROH_INTERFACE_PRIORITY="ib*:100,eth*:50,en*:50"`
    ///
    /// Each entry is `pattern:weight` separated by commas.
    /// Returns `None` if the environment variable is not set.
    /// Returns an error if the format is invalid.
    ///
    /// # Example
    ///
    /// ```bash
    /// export IROH_INTERFACE_PRIORITY="ib*:100,eth*:50"
    /// ```
    pub fn from_env() -> Result<Option<Self>, String> {
        const ENV_VAR: &str = "IROH_INTERFACE_PRIORITY";

        let Some(value) = std::env::var(ENV_VAR).ok() else {
            return Ok(None);
        };

        if value.is_empty() {
            return Ok(None);
        }

        let mut patterns = Vec::new();
        for entry in value.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }

            let parts: Vec<&str> = entry.split(':').collect();
            if parts.len() != 2 {
                return Err(format!(
                    "Invalid format in {}: '{}'. Expected 'pattern:weight'",
                    ENV_VAR, entry
                ));
            }

            let pattern = parts[0].trim().to_string();
            let weight = parts[1].trim().parse::<u32>().map_err(|e| {
                format!(
                    "Invalid weight in {}: '{}'. Expected number, got error: {}",
                    ENV_VAR, parts[1], e
                )
            })?;

            patterns.push((pattern, weight));
        }

        if patterns.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Self::new(patterns)))
        }
    }

    /// Get the priority weight for a given interface name.
    ///
    /// Returns the weight of the first matching pattern, or 0 if no pattern matches.
    pub fn weight(&self, interface_name: &str) -> u32 {
        self.rules
            .iter()
            .find(|rule| rule.pattern.matches(interface_name))
            .map(|rule| rule.weight)
            .unwrap_or(0)
    }

    /// Returns true if this configuration is empty (no rules).
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Detect which network interface would be used for a given local IP address.
///
/// This examines the netmon state to find which interface owns the given IP address.
pub(super) fn detect_interface(local_ip: IpAddr, netmon_state: &netmon::State) -> Option<String> {
    for (iface_name, iface) in &netmon_state.interfaces {
        // Check if any of this interface's addresses match our local IP
        if iface.addrs().any(|addr| addr.addr() == local_ip) {
            return Some(iface_name.clone());
        }
    }
    None
}

/// Build a mapping from bind addresses to interface names.
///
/// This is useful for quickly looking up which interface a socket is bound to.
pub(super) fn build_interface_map(
    bind_addrs: &[std::net::SocketAddr],
    netmon_state: &netmon::State,
) -> std::collections::HashMap<std::net::IpAddr, String> {
    let mut map = std::collections::HashMap::new();
    for bind_addr in bind_addrs {
        if let Some(interface) = detect_interface(bind_addr.ip(), netmon_state) {
            map.insert(bind_addr.ip(), interface);
        }
    }
    map
}

impl Default for InterfacePriority {
    fn default() -> Self {
        Self {
            rules: Arc::new(Vec::new()),
        }
    }
}

impl Pattern {
    fn parse(pattern: &str) -> Self {
        if !pattern.contains('*') {
            return Pattern::Exact(pattern.to_string());
        }

        if pattern == "*" {
            return Pattern::Contains(String::new());
        }

        if pattern.starts_with('*') && pattern.ends_with('*') {
            let middle = &pattern[1..pattern.len() - 1];
            return Pattern::Contains(middle.to_string());
        }

        if let Some(suffix) = pattern.strip_prefix('*') {
            return Pattern::Suffix(suffix.to_string());
        }

        if let Some(prefix) = pattern.strip_suffix('*') {
            return Pattern::Prefix(prefix.to_string());
        }

        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            return Pattern::Wildcard {
                prefix: parts[0].to_string(),
                suffix: parts[1].to_string(),
            };
        }

        Pattern::Exact(pattern.to_string())
    }

    fn matches(&self, s: &str) -> bool {
        match self {
            Pattern::Exact(exact) => s == exact,
            Pattern::Prefix(prefix) => s.starts_with(prefix),
            Pattern::Suffix(suffix) => s.ends_with(suffix),
            Pattern::Contains(substr) => s.contains(substr),
            Pattern::Wildcard { prefix, suffix } => {
                s.starts_with(prefix)
                    && s.ends_with(suffix)
                    && s.len() >= prefix.len() + suffix.len()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let priority = InterfacePriority::new(vec![("eth0".to_string(), 100)]);
        assert_eq!(priority.weight("eth0"), 100);
        assert_eq!(priority.weight("eth1"), 0);
        assert_eq!(priority.weight("ib0"), 0);
    }

    #[test]
    fn test_prefix_match() {
        let priority = InterfacePriority::new(vec![("ib*".to_string(), 100)]);
        assert_eq!(priority.weight("ib0"), 100);
        assert_eq!(priority.weight("ib1"), 100);
        assert_eq!(priority.weight("ib_main"), 100);
        assert_eq!(priority.weight("eth0"), 0);
    }

    #[test]
    fn test_suffix_match() {
        let priority = InterfacePriority::new(vec![("*0".to_string(), 50)]);
        assert_eq!(priority.weight("eth0"), 50);
        assert_eq!(priority.weight("ib0"), 50);
        assert_eq!(priority.weight("eth1"), 0);
    }

    #[test]
    fn test_contains_match() {
        let priority = InterfacePriority::new(vec![("*eth*".to_string(), 50)]);
        assert_eq!(priority.weight("eth0"), 50);
        assert_eq!(priority.weight("myeth"), 50);
        assert_eq!(priority.weight("ethtest"), 50);
        assert_eq!(priority.weight("ib0"), 0);
    }

    #[test]
    fn test_wildcard_match() {
        let priority = InterfacePriority::new(vec![("eth*0".to_string(), 75)]);
        assert_eq!(priority.weight("eth0"), 75);
        assert_eq!(priority.weight("eth10"), 75);
        assert_eq!(priority.weight("eth_test_0"), 75);
        assert_eq!(priority.weight("eth1"), 0);
        assert_eq!(priority.weight("ib0"), 0);
    }

    #[test]
    fn test_first_match_wins() {
        let priority =
            InterfacePriority::new(vec![("ib*".to_string(), 100), ("ib0".to_string(), 50)]);
        assert_eq!(priority.weight("ib0"), 100);
    }

    #[test]
    fn test_multiple_interfaces() {
        let priority = InterfacePriority::new(vec![
            ("ib*".to_string(), 100),
            ("eth*".to_string(), 50),
            ("en*".to_string(), 50),
        ]);
        assert_eq!(priority.weight("ib0"), 100);
        assert_eq!(priority.weight("ib1"), 100);
        assert_eq!(priority.weight("eth0"), 50);
        assert_eq!(priority.weight("enp0s1"), 50);
        assert_eq!(priority.weight("wlan0"), 0);
    }

    #[test]
    fn test_empty_priority() {
        let priority = InterfacePriority::default();
        assert!(priority.is_empty());
        assert_eq!(priority.weight("any"), 0);
    }

    #[test]
    fn test_from_patterns() {
        // Test by directly creating from patterns instead of env var
        let priority =
            InterfacePriority::new(vec![("ib*".to_string(), 100), ("eth*".to_string(), 50)]);
        assert_eq!(priority.weight("ib0"), 100);
        assert_eq!(priority.weight("eth0"), 50);
        assert_eq!(priority.weight("wlan0"), 0);
    }

    #[test]
    fn test_parse_format() {
        // Test the parsing logic without environment variables
        // Valid format
        let patterns = vec![("ib*".to_string(), 100), ("eth*".to_string(), 50)];
        let priority = InterfacePriority::new(patterns);
        assert_eq!(priority.weight("ib0"), 100);

        // Empty is OK
        let empty = InterfacePriority::new(vec![]);
        assert!(empty.is_empty());
        assert_eq!(empty.weight("any"), 0);
    }
}
