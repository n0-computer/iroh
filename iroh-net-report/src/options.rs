pub use imp::Options;

#[cfg(not(wasm_browser))]
mod imp {
    use std::{collections::BTreeSet, sync::Arc};

    use netwatch::UdpSocket;

    use crate::{reportgen::ProbeProto, QuicConfig};

    /// Options for running probes
    ///
    /// By default, will run icmp over IPv4, icmp over IPv6, and Https probes.
    ///
    /// Use [`Options::stun_v4`], [`Options::stun_v6`], and [`Options::quic_config`]
    /// to enable STUN over IPv4, STUN over IPv6, and QUIC address discovery.
    #[derive(Debug, Clone)]
    pub struct Options {
        /// Socket to send IPv4 STUN probes from.
        ///
        /// Responses are never read from this socket, they must be passed in via internal
        /// messaging since, when used internally in iroh, the socket is also used to receive
        /// other packets from in the magicsocket (`MagicSock`).
        ///
        /// If not provided, STUN probes will not be sent over IPv4.
        pub(crate) stun_sock_v4: Option<Arc<UdpSocket>>,
        /// Socket to send IPv6 STUN probes from.
        ///
        /// Responses are never read from this socket, they must be passed in via internal
        /// messaging since, when used internally in iroh, the socket is also used to receive
        /// other packets from in the magicsocket (`MagicSock`).
        ///
        /// If not provided, STUN probes will not be sent over IPv6.
        pub(crate) stun_sock_v6: Option<Arc<UdpSocket>>,
        /// The configuration needed to launch QUIC address discovery probes.
        ///
        /// If not provided, will not run QUIC address discovery.
        pub(crate) quic_config: Option<QuicConfig>,
        /// Enable icmp_v4 probes
        ///
        /// On by default
        pub(crate) icmp_v4: bool,
        /// Enable icmp_v6 probes
        ///
        /// On by default
        pub(crate) icmp_v6: bool,
        /// Enable https probes
        ///
        /// On by default
        pub(crate) https: bool,
    }

    impl Default for Options {
        fn default() -> Self {
            Self {
                stun_sock_v4: None,
                stun_sock_v6: None,
                quic_config: None,
                icmp_v4: true,
                icmp_v6: true,
                https: true,
            }
        }
    }

    impl Options {
        /// Create an [`Options`] that disables all probes
        pub fn disabled() -> Self {
            Self {
                stun_sock_v4: None,
                stun_sock_v6: None,
                quic_config: None,
                icmp_v4: false,
                icmp_v6: false,
                https: false,
            }
        }

        /// Set the ipv4 stun socket and enable ipv4 stun probes
        pub fn stun_v4(mut self, sock: Option<Arc<UdpSocket>>) -> Self {
            self.stun_sock_v4 = sock;
            self
        }

        /// Set the ipv6 stun socket and enable ipv6 stun probes
        pub fn stun_v6(mut self, sock: Option<Arc<UdpSocket>>) -> Self {
            self.stun_sock_v6 = sock;
            self
        }

        /// Enable quic probes
        pub fn quic_config(mut self, quic_config: Option<QuicConfig>) -> Self {
            self.quic_config = quic_config;
            self
        }

        /// Enable or disable icmp_v4 probe
        pub fn icmp_v4(mut self, enable: bool) -> Self {
            self.icmp_v4 = enable;
            self
        }

        /// Enable or disable icmp_v6 probe
        pub fn icmp_v6(mut self, enable: bool) -> Self {
            self.icmp_v6 = enable;
            self
        }

        /// Enable or disable https probe
        pub fn https(mut self, enable: bool) -> Self {
            self.https = enable;
            self
        }

        /// Turn the options into set of valid protocols
        pub(crate) fn to_protocols(&self) -> BTreeSet<ProbeProto> {
            let mut protocols = BTreeSet::new();
            if self.stun_sock_v4.is_some() {
                protocols.insert(ProbeProto::StunIpv4);
            }
            if self.stun_sock_v6.is_some() {
                protocols.insert(ProbeProto::StunIpv6);
            }
            if let Some(ref quic) = self.quic_config {
                if quic.ipv4 {
                    protocols.insert(ProbeProto::QuicIpv4);
                }
                if quic.ipv6 {
                    protocols.insert(ProbeProto::QuicIpv6);
                }
            }
            if self.icmp_v4 {
                protocols.insert(ProbeProto::IcmpV4);
            }
            if self.icmp_v6 {
                protocols.insert(ProbeProto::IcmpV6);
            }
            if self.https {
                protocols.insert(ProbeProto::Https);
            }
            protocols
        }
    }
}

#[cfg(wasm_browser)]
mod imp {
    use std::collections::BTreeSet;

    use crate::reportgen::ProbeProto;

    /// Options for running probes (in browsers).
    ///
    /// Only HTTPS probes are supported in browsers.
    /// These are run by default.
    #[derive(Debug, Clone)]
    pub struct Options {
        /// Enable https probes
        ///
        /// On by default
        pub(crate) https: bool,
    }

    impl Default for Options {
        fn default() -> Self {
            Self { https: true }
        }
    }

    impl Options {
        /// Create an [`Options`] that disables all probes
        pub fn disabled() -> Self {
            Self { https: false }
        }

        /// Enable or disable https probe
        pub fn https(mut self, enable: bool) -> Self {
            self.https = enable;
            self
        }

        /// Turn the options into set of valid protocols
        pub(crate) fn to_protocols(&self) -> BTreeSet<ProbeProto> {
            let mut protocols = BTreeSet::new();
            if self.https {
                protocols.insert(ProbeProto::Https);
            }
            protocols
        }
    }
}
