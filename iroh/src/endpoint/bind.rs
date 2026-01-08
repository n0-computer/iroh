use std::{
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use n0_error::stack_error;

/// Options when configuring binding an IP socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindOpts {
    /// Sets the network prefix length which manages route.
    ///
    /// Defaults to `0`.
    ///
    /// Must not be larger than `32`
    prefix_len: u8,
    /// If set, binding this interface is required and any errors will abort the
    /// initialization of the endpoint.
    ///
    /// Defaults to `true`.
    is_required: bool,
}

impl Default for BindOpts {
    fn default() -> Self {
        Self {
            prefix_len: 0,
            is_required: true,
        }
    }
}

impl BindOpts {
    /// Sets the network prefix length which manages route.
    ///
    /// Defaults to `0`.
    ///
    /// Must not be larger than `32`
    pub fn set_prefix_len(mut self, prefix_len: u8) -> Self {
        self.prefix_len = prefix_len;
        self
    }

    /// Returns the `prefix_len`.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// If set, binding this interface is required and any errors will abort the
    /// initialization of the endpoint.
    ///
    /// Defaults to `true`.
    pub fn set_is_required(mut self, is_required: bool) -> Self {
        self.is_required = is_required;
        self
    }

    /// Returns the value for `is_required`.
    pub fn is_required(&self) -> bool {
        self.is_required
    }
}

/// A simpler version of `ToSocketAddrs`, that does not do any DNS resolution.
pub trait ToSocketAddr {
    /// Error type on failed conversion.
    type Err: std::error::Error;

    /// Tries to convert this type to a [`SocketAddr`].
    fn to_socket_addr(&self) -> Result<SocketAddr, Self::Err>;
}

impl ToSocketAddr for SocketAddr {
    type Err = Infallible;

    fn to_socket_addr(&self) -> Result<SocketAddr, Self::Err> {
        Ok(*self)
    }
}

impl ToSocketAddr for SocketAddrV4 {
    type Err = Infallible;

    fn to_socket_addr(&self) -> Result<SocketAddr, Self::Err> {
        Ok(SocketAddr::V4(*self))
    }
}

impl ToSocketAddr for SocketAddrV6 {
    type Err = Infallible;

    fn to_socket_addr(&self) -> Result<SocketAddr, Self::Err> {
        Ok(SocketAddr::V6(*self))
    }
}

impl ToSocketAddr for (IpAddr, u16) {
    type Err = Infallible;

    fn to_socket_addr(&self) -> Result<SocketAddr, Self::Err> {
        let (ip, port) = *self;
        match ip {
            IpAddr::V4(ref a) => (*a, port).to_socket_addr(),
            IpAddr::V6(ref a) => (*a, port).to_socket_addr(),
        }
    }
}

impl ToSocketAddr for (Ipv4Addr, u16) {
    type Err = Infallible;

    fn to_socket_addr(&self) -> Result<SocketAddr, Self::Err> {
        let (ip, port) = *self;
        SocketAddrV4::new(ip, port).to_socket_addr()
    }
}

impl ToSocketAddr for (Ipv6Addr, u16) {
    type Err = Infallible;

    fn to_socket_addr(&self) -> Result<SocketAddr, Self::Err> {
        let (ip, port) = *self;
        SocketAddrV6::new(ip, port, 0, 0).to_socket_addr()
    }
}

impl ToSocketAddr for (&str, u16) {
    type Err = std::net::AddrParseError;

    fn to_socket_addr(&self) -> Result<SocketAddr, Self::Err> {
        let (host, port) = *self;

        let addr = host.parse::<IpAddr>()?;
        let addr = SocketAddr::new(addr, port);
        Ok(addr)
    }
}

impl ToSocketAddr for (String, u16) {
    type Err = std::net::AddrParseError;

    fn to_socket_addr(&self) -> Result<SocketAddr, Self::Err> {
        (&*self.0, self.1).to_socket_addr()
    }
}

impl ToSocketAddr for str {
    type Err = std::net::AddrParseError;

    fn to_socket_addr(&self) -> Result<SocketAddr, Self::Err> {
        let addr = self.parse()?;
        Ok(addr)
    }
}

impl<T: ToSocketAddr + ?Sized> ToSocketAddr for &T {
    type Err = T::Err;

    fn to_socket_addr(&self) -> Result<SocketAddr, Self::Err> {
        (**self).to_socket_addr()
    }
}

impl ToSocketAddr for String {
    type Err = std::net::AddrParseError;

    fn to_socket_addr(&self) -> Result<SocketAddr, Self::Err> {
        (**self).to_socket_addr()
    }
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum InvalidSocketAddr {
    #[error(transparent)]
    AddrParse {
        #[error(std_err)]
        source: std::net::AddrParseError,
    },
    #[error(transparent)]
    InvalidPrefix {
        #[error(std_err)]
        source: netdev::ipnet::PrefixLenError,
    },
    #[error(transparent)]
    Infallible {
        #[error(std_err)]
        source: Infallible,
    },
}
