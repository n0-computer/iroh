use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Ip family selection between Ipv4 and Ipv6.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IpFamily {
    /// Ipv4
    V4,
    /// Ipv6
    V6,
}

impl From<IpAddr> for IpFamily {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }
}

impl IpFamily {
    /// Returns the matching default address.
    pub fn unspecified_addr(&self) -> IpAddr {
        match self {
            Self::V4 => Ipv4Addr::UNSPECIFIED.into(),
            Self::V6 => Ipv6Addr::UNSPECIFIED.into(),
        }
    }

    /// Returns the matching localhost address.
    pub fn local_addr(&self) -> IpAddr {
        match self {
            Self::V4 => Ipv4Addr::LOCALHOST.into(),
            Self::V6 => Ipv6Addr::LOCALHOST.into(),
        }
    }
}

impl From<IpFamily> for socket2::Domain {
    fn from(value: IpFamily) -> Self {
        match value {
            IpFamily::V4 => socket2::Domain::IPV4,
            IpFamily::V6 => socket2::Domain::IPV6,
        }
    }
}
