use std::{
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use n0_error::stack_error;

/// Options when configuring binding an IP socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindOpts {
    /// Sets the network prefix length of the subnet for this interface.
    ///
    /// The prefix length is used in the routing table that is built to decide where
    /// datagrams without a specific source address are sent. If these number of leading
    /// bits in the destination IP address match the same number of leading bits in this
    /// bound socket address, then it matches the subnet and the datagram will be sent
    /// here. Otherwise the next bound sockets will be checked for a subnet match. Sockets
    /// are ordered from longest prefix to shortest prefix.
    ///
    /// If no bound address has a matching subnet, the bind marked with
    /// [`Self::is_default_route`] will be used.
    ///
    /// Note that most datagrams belonging to a traffic flow are in response to an incoming
    /// datagram. Those are usually sent on the same bound socket as they were received and
    /// will not consult the routing table derived from these bound sockets to select the
    /// socket on which they will be sent.
    prefix_len: u8,
    /// If set, binding this interface is required and any errors will abort the
    /// initialization of the endpoint.
    ///
    /// Defaults to `true`.
    is_required: bool,
    /// Whether this socket should be used as default route.
    ///
    /// The default route is used for outgoing datagrams not belonging to an existing
    /// traffic flow, which does not fit in any subnet of the bound sockets. It is assumed
    /// this subnet has a gateway router to route such packets.
    ///
    /// See [`Self::prefix_len`] for details of how such routing works.
    is_default_route: Option<bool>,
}

impl Default for BindOpts {
    fn default() -> Self {
        Self {
            prefix_len: 0,
            is_required: true,
            is_default_route: None,
        }
    }
}

impl BindOpts {
    /// Sets the network prefix length of the subnet this interface is in.
    ///
    ///
    /// The subnets of bound sockets are used to route outgoing datagrams not belonging to
    /// an existing traffic flow to the socket they should be sent on. Subnets are ordered
    /// from longest prefix length to shortest prefix length and the first subnet which
    /// contains the destination IP address will be chosen. If no subnet matches but there
    /// is a bound socket marked with [`Self::set_is_default_route`] then this socket will
    /// be used. In this case it is assumed the attached subnet has a gateway router to
    /// forward the datagram.
    ///
    /// Defaults to `0`, which means *all* IP addresses will belong to the subnet of this
    /// socket's address. If multiple sockets of the same address family (IPv4 or IPv6) are
    /// bound with such a `/0` prefix the socket which will be chosen is undefined.
    ///
    /// For IPv4 sockets the maximum prefix is `32`. For IPv6 the maximum prefix is `128`.
    pub fn set_prefix_len(mut self, prefix_len: u8) -> Self {
        self.prefix_len = prefix_len;
        self
    }

    /// Returns the `prefix_len`, see [`Self::set_prefix_len`].
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Sets whether bind errors are fatal for this socket.
    ///
    /// If `false` and this socket fails to bind, the error will be silently ignored and the
    /// endpoint will still be created.
    ///
    /// Defaults to `true`.
    pub fn set_is_required(mut self, is_required: bool) -> Self {
        self.is_required = is_required;
        self
    }

    /// Returns the value set by [`Self::set_is_required`].
    pub fn is_required(&self) -> bool {
        self.is_required
    }

    /// Sets whether this is a default route.
    ///
    /// The default route is used for outgoing datagrams not belonging to an existing
    /// traffic flow, which does not fit in any subnet of the bound sockets. It is assumed
    /// this subnet has a gateway router to route such packets.
    ///
    /// See [`Self::set_prefix_len`] for details on how this routing works.
    ///
    /// If not set explicitly, then [`Self::is_default_route`] will return `true`
    /// if the prefix length is set to `0` (the default) and `false` otherwise.
    pub fn set_is_default_route(mut self, is_default_route: bool) -> Self {
        self.is_default_route = Some(is_default_route);
        self
    }

    /// Returns whether this is a default route.
    ///
    /// If [`Self::set_is_default_route`] has been called then that value is returned.
    /// Otherwise, returns `true` if the [`prefix_len`][`Self::prefix_len] is `0` and
    /// `false` otherwise.
    pub fn is_default_route(&self) -> bool {
        match self.is_default_route {
            Some(is_default) => is_default,
            None => self.prefix_len() == 0,
        }
    }
}

/// A simpler version of [`ToSocketAddrs`], that does not do any DNS resolution.
///
/// [`ToSocketAddrs`]: std::net::ToSocketAddrs
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
    #[error("Only a single default address can be set per IP family")]
    DuplicateDefaultAddr,
}
