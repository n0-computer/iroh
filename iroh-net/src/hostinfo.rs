//! Answers questions about the host environment that we are running on.
//!
//! Based on tailscale/hostinfo

use std::net::IpAddr;

use super::config::NetInfo;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const RUST_VERSION: &str = env!("RUSTC_VERSION");
const GIT_COMMIT: &str = env!("GIT_COMMIT");

/// Contains a summary of the host we are running on.
#[derive(Clone, Debug, PartialEq)]
pub struct Hostinfo {
    /// Version of this code.
    pub version: String,
    /// Git commit of this code.
    pub git_commit: String,
    /// Operating system the client runs on (a version.OS value)
    pub os: String,

    /// OSVersion is the version of the OS, if available.
    pub os_version: String,

    /// Whether the client is running in a container
    pub container: Option<bool>,
    /// a hostinfo.EnvType in string form
    pub env: String,
    /// if a desktop was detected on Linux.
    pub desktop: Option<bool>,
    /// mobile phone model ("Pixel 3a", "iPhone12,3")
    pub device_model: Option<String>,
    /// name of the host the client runs on
    pub hostname: String,
    /// the current host's machine type (uname -m)
    pub machine: String,
    /// ARCH value (of the built binary)
    pub arch: String,
    /// Rust version binary was built with.
    pub rust_version: String,
    /// set of IP ranges this client can route
    pub routable_ips: Vec<IpAddr>,
    /// if advertised,
    pub net_info: Option<NetInfo>,
}

impl Default for Hostinfo {
    fn default() -> Self {
        let hostname = hostname::get()
            .ok()
            .and_then(|s| s.into_string().ok())
            .unwrap_or_default();
        // grab the first label
        let hostname = hostname.split('.').next().unwrap_or_default().to_string();
        let os = os_info::get();

        return Hostinfo {
            version: PKG_VERSION.to_string(),
            git_commit: GIT_COMMIT.to_string(),
            hostname,
            os: os.os_type().to_string(),
            os_version: os.version().to_string(),
            container: None,      //lazyInContainer.Get(),
            env: "".to_string(),  //string(GetEnvType()),
            desktop: None,        //desktop(),
            arch: "".to_string(), //runtime.GOARCH,
            rust_version: RUST_VERSION.to_string(),
            machine: "".to_string(), // TODO
            device_model: None,      //deviceModel(),
            net_info: None,
            routable_ips: Vec::new(),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostinfo() {
        let info = Hostinfo::default();
        println!("{:#?}", info);

        assert!(!info.git_commit.is_empty());
        assert!(!info.rust_version.is_empty());
    }
}
