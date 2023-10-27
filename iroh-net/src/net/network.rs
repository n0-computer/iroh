use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Network selection between Ipv4 and Ipv6.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Network {
    /// Ipv4
    Ipv4,
    /// Ipv6
    Ipv6,
}

impl From<IpAddr> for Network {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

impl Network {
    /// Returns the matching default address.
    pub fn default_addr(&self) -> IpAddr {
        match self {
            Self::Ipv4 => Ipv4Addr::UNSPECIFIED.into(),
            Self::Ipv6 => Ipv6Addr::UNSPECIFIED.into(),
        }
    }

    /// Returns the matching localhost address.
    pub fn local_addr(&self) -> IpAddr {
        match self {
            Self::Ipv4 => Ipv4Addr::LOCALHOST.into(),
            Self::Ipv6 => Ipv6Addr::LOCALHOST.into(),
        }
    }
}

impl From<Network> for socket2::Domain {
    fn from(value: Network) -> Self {
        match value {
            Network::Ipv4 => socket2::Domain::IPV4,
            Network::Ipv6 => socket2::Domain::IPV6,
        }
    }
}
