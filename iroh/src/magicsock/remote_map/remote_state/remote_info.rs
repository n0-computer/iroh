use iroh_base::{EndpointId, TransportAddr};

/// Information about a remote endpoint.
///
/// This information is a snapshot in time, i.e. it is not updating and may
/// already be outdated by the time you are reading this. Updated information
/// can only be retrieved by calling [`Endpoint::remote_info`] again.
///
/// [`Endpoint::remote_info`]: crate::Endpoint::remote_info
#[derive(Debug, Clone)]
pub struct RemoteInfo {
    pub(super) endpoint_id: EndpointId,
    pub(super) addrs: Vec<TransportAddrInfo>,
}

impl RemoteInfo {
    /// Returns the remote's endpoint id.
    pub fn id(&self) -> EndpointId {
        self.endpoint_id
    }

    /// Returns an iterator over known all addresses for this remote.
    ///
    /// Note that this may include outdated or unusable addresses.
    pub fn addrs(&self) -> impl Iterator<Item = &TransportAddrInfo> {
        self.addrs.iter()
    }

    /// Converts into an iterator over known all addresses for this remote.
    ///
    /// Note that this may include outdated or unusable addresses. You can use [`TransportAddrInfo::usage`]
    /// to filter for addresses that are actively used.
    ///
    /// You can use this to construct an [`EndpointAddr`] for this remote:
    ///
    /// ```no_run
    /// # use iroh::{Endpoint, EndpointId, EndpointAddr};
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let endpoint = Endpoint::bind().await.unwrap();
    /// # let remote_id = EndpointId::from_bytes(&[0u8; 32]).unwrap();
    /// let info = endpoint.remote_info(remote_id).await.unwrap();
    /// let addr = EndpointAddr::from_parts(info.id(), info.into_addrs().map(|addr| addr.into_addr()));
    /// # }
    /// ```
    ///
    /// [`EndpointAddr`]: crate::EndpointAddr
    pub fn into_addrs(self) -> impl Iterator<Item = TransportAddrInfo> {
        self.addrs.into_iter()
    }
}

/// Address of a remote with some metadata
#[derive(Debug, Clone)]
pub struct TransportAddrInfo {
    pub(super) addr: TransportAddr,
    pub(super) usage: TransportAddrUsage,
}

impl TransportAddrInfo {
    /// Returns the [`TransportAddr`].
    pub fn addr(&self) -> &TransportAddr {
        &self.addr
    }

    /// Converts into [`TransportAddr`].
    pub fn into_addr(self) -> TransportAddr {
        self.addr
    }

    /// Returns information how this address is used.
    pub fn usage(&self) -> TransportAddrUsage {
        self.usage
    }
}

impl From<TransportAddrInfo> for TransportAddr {
    fn from(value: TransportAddrInfo) -> Self {
        value.addr
    }
}

/// Information how a transport address is used.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum TransportAddrUsage {
    /// The address is in active use.
    Active,
    /// The address is not currently used.
    Inactive,
}
