//! A static endpoint discovery to manually add endpoint addressing information.
//!
//! Often an application might get endpoint addressing information out-of-band in an
//! application-specific way.  [`EndpointTicket`]'s are one common way used to achieve this.
//! This "static" addressing information is often only usable for a limited time so needs to
//! be able to be removed again once know it is no longer useful.
//!
//! This is where the [`StaticProvider`] is useful: it allows applications to add and
//! retract endpoint addressing information that is otherwise out-of-band to iroh.
//!
//! [`EndpointTicket`]: https://docs.rs/iroh-base/latest/iroh_base/ticket/struct.EndpointTicket

use std::{
    collections::{BTreeMap, btree_map::Entry},
    sync::{Arc, RwLock},
};

use iroh_base::PublicKey;
use n0_future::{
    boxed::BoxStream,
    stream::{self, StreamExt},
    time::SystemTime,
};

use super::{Discovery, DiscoveryError, DiscoveryItem, EndpointData, EndpointInfo};

/// A static endpoint discovery to manually add endpoint addressing information.
///
/// Often an application might get endpoint addressing information out-of-band in an
/// application-specific way.  [`EndpointTicket`]'s are one common way used to achieve this.
/// This "static" addressing information is often only usable for a limited time so needs to
/// be able to be removed again once know it is no longer useful.
///
/// This is where the [`StaticProvider`] is useful: it allows applications to add and
/// retract endpoint addressing information that is otherwise out-of-band to iroh.
///
/// # Examples
///
/// ```rust
/// use iroh::{Endpoint, EndpointAddr, TransportAddr, discovery::static_provider::StaticProvider};
/// use iroh_base::SecretKey;
///
/// # #[tokio::main]
/// # async fn main() -> n0_error::Result<()> {
/// // Create the discovery service and endpoint.
/// let discovery = StaticProvider::new();
///
/// let _ep = Endpoint::builder()
///     .discovery(discovery.clone())
///     .bind()
///     .await?;
///
/// // Sometime later add a RelayUrl for our endpoint.
/// let id = SecretKey::generate(&mut rand::rng()).public();
/// // You can pass either `EndpointInfo` or `EndpointAddr` to `add_endpoint_info`.
/// discovery.add_endpoint_info(EndpointAddr {
///     id,
///     addrs: [TransportAddr::Relay("https://example.com".parse()?)]
///         .into_iter()
///         .collect(),
/// });
///
/// # Ok(())
/// # }
/// ```
///
/// [`EndpointTicket`]: https://docs.rs/iroh-base/latest/iroh_base/ticket/struct.EndpointTicket
#[derive(Debug, Clone)]
pub struct StaticProvider {
    endpoints: Arc<RwLock<BTreeMap<PublicKey, StoredEndpointInfo>>>,
    provenance: &'static str,
}

impl Default for StaticProvider {
    fn default() -> Self {
        Self {
            endpoints: Default::default(),
            provenance: Self::PROVENANCE,
        }
    }
}

#[derive(Debug)]
struct StoredEndpointInfo {
    data: EndpointData,
    last_updated: SystemTime,
}

impl StaticProvider {
    /// The provenance string for this discovery implementation.
    ///
    /// This is mostly used for debugging information and allows understanding the origin of
    /// addressing information used by an iroh [`Endpoint`].
    ///
    /// [`Endpoint`]: crate::Endpoint
    pub const PROVENANCE: &'static str = "static_discovery";

    /// Creates a new static discovery instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new static discovery instance with the provided `provenance`.
    ///
    /// The provenance is part of [`DiscoveryItem`]s returned from [`Self::resolve`].
    /// It is mostly used for debugging information and allows understanding the origin of
    /// addressing information used by an iroh [`Endpoint`].
    ///
    /// [`Endpoint`]: crate::Endpoint
    pub fn with_provenance(provenance: &'static str) -> Self {
        Self {
            endpoints: Default::default(),
            provenance,
        }
    }

    /// Creates a static discovery instance from endpoint addresses.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::{net::SocketAddr, str::FromStr};
    ///
    /// use iroh::{Endpoint, EndpointAddr, discovery::static_provider::StaticProvider};
    ///
    /// # fn get_addrs() -> Vec<EndpointAddr> {
    /// #     Vec::new()
    /// # }
    /// # #[tokio::main]
    /// # async fn main() -> n0_error::Result<()> {
    /// // get addrs from somewhere
    /// let addrs = get_addrs();
    ///
    /// // create a StaticProvider from the list of addrs.
    /// let discovery = StaticProvider::from_endpoint_info(addrs);
    /// // create an endpoint with the discovery
    /// let endpoint = Endpoint::builder().discovery(discovery).bind().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_endpoint_info(infos: impl IntoIterator<Item = impl Into<EndpointInfo>>) -> Self {
        let res = Self::default();
        for info in infos {
            res.add_endpoint_info(info);
        }
        res
    }

    /// Sets endpoint addressing information for the given endpoint ID.
    ///
    /// This will completely overwrite any existing info for the endpoint.
    ///
    /// Returns the [`EndpointData`] of the previous entry, or `None` if there was no previous
    /// entry for this endpoint ID.
    pub fn set_endpoint_info(
        &self,
        endpoint_info: impl Into<EndpointInfo>,
    ) -> Option<EndpointData> {
        let last_updated = SystemTime::now();
        let EndpointInfo { endpoint_id, data } = endpoint_info.into();
        let mut guard = self.endpoints.write().expect("poisoned");
        let previous = guard.insert(endpoint_id, StoredEndpointInfo { data, last_updated });
        previous.map(|x| x.data)
    }

    /// Augments endpoint addressing information for the given endpoint ID.
    ///
    /// The provided addressing information is combined with the existing info in the static
    /// provider.  Any new direct addresses are added to those already present while the
    /// relay URL is overwritten.
    pub fn add_endpoint_info(&self, endpoint_info: impl Into<EndpointInfo>) {
        let last_updated = SystemTime::now();
        let EndpointInfo { endpoint_id, data } = endpoint_info.into();
        let mut guard = self.endpoints.write().expect("poisoned");
        match guard.entry(endpoint_id) {
            Entry::Occupied(mut entry) => {
                let existing = entry.get_mut();
                existing.data.add_addrs(data.addrs().cloned());
                existing.data.set_user_data(data.user_data().cloned());
                existing.last_updated = last_updated;
            }
            Entry::Vacant(entry) => {
                entry.insert(StoredEndpointInfo { data, last_updated });
            }
        }
    }

    /// Returns endpoint addressing information for the given endpoint ID.
    pub fn get_endpoint_info(&self, endpoint_id: PublicKey) -> Option<EndpointInfo> {
        let guard = self.endpoints.read().expect("poisoned");
        let info = guard.get(&endpoint_id)?;
        Some(EndpointInfo::from_parts(endpoint_id, info.data.clone()))
    }

    /// Removes all endpoint addressing information for the given endpoint ID.
    ///
    /// Any removed information is returned.
    pub fn remove_endpoint_info(&self, endpoint_id: PublicKey) -> Option<EndpointInfo> {
        let mut guard = self.endpoints.write().expect("poisoned");
        let info = guard.remove(&endpoint_id)?;
        Some(EndpointInfo::from_parts(endpoint_id, info.data))
    }
}

impl Discovery for StaticProvider {
    fn publish(&self, _data: &EndpointData) {}

    fn resolve(
        &self,
        endpoint_id: PublicKey,
    ) -> Option<BoxStream<Result<super::DiscoveryItem, DiscoveryError>>> {
        let guard = self.endpoints.read().expect("poisoned");
        let info = guard.get(&endpoint_id);
        match info {
            Some(endpoint_info) => {
                let last_updated = endpoint_info
                    .last_updated
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("time drift")
                    .as_micros() as u64;
                let item = DiscoveryItem::new(
                    EndpointInfo::from_parts(endpoint_id, endpoint_info.data.clone()),
                    self.provenance,
                    Some(last_updated),
                );
                Some(stream::iter(Some(Ok(item))).boxed())
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::{EndpointAddr, SecretKey, TransportAddr};
    use n0_error::{Result, StackResultExt};

    use super::*;
    use crate::{Endpoint, RelayMode};

    #[tokio::test]
    async fn test_basic() -> Result {
        let discovery = StaticProvider::new();

        let _ep = Endpoint::empty_builder(RelayMode::Disabled)
            .discovery(discovery.clone())
            .bind()
            .await?;

        let key = SecretKey::from_bytes(&[0u8; 32]);
        let addr = EndpointAddr {
            id: key.public(),
            addrs: [TransportAddr::Relay("https://example.com".parse()?)]
                .into_iter()
                .collect(),
        };
        let user_data = Some("foobar".parse().unwrap());
        let endpoint_info = EndpointInfo::from(addr.clone()).with_user_data(user_data.clone());
        discovery.add_endpoint_info(endpoint_info.clone());

        let back = discovery
            .get_endpoint_info(key.public())
            .context("no addr")?;

        assert_eq!(back, endpoint_info);
        assert_eq!(back.user_data(), user_data.as_ref());
        assert_eq!(back.into_endpoint_addr(), addr);

        let removed = discovery
            .remove_endpoint_info(key.public())
            .context("nothing removed")?;
        assert_eq!(removed, endpoint_info);
        let res = discovery.get_endpoint_info(key.public());
        assert!(res.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_provenance() -> Result {
        let discovery = StaticProvider::with_provenance("foo");
        let key = SecretKey::from_bytes(&[0u8; 32]);
        let addr = EndpointAddr {
            id: key.public(),
            addrs: [TransportAddr::Relay("https://example.com".parse()?)]
                .into_iter()
                .collect(),
        };
        discovery.add_endpoint_info(addr);
        let mut stream = discovery.resolve(key.public()).unwrap();
        let item = stream.next().await.unwrap()?;
        assert_eq!(item.provenance(), "foo");
        assert_eq!(
            item.relay_urls().next(),
            Some(&("https://example.com".parse()?))
        );

        Ok(())
    }
}
