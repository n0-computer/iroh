//! Pkarr based address lookup for iroh, supporting both relay servers and the DHT.
//!
//! This module contains pkarr-based address lookup for iroh which can use both pkarr
//! relay servers as well as the Mainline DHT directly.  See the [pkarr module] for an
//! overview of pkarr.
//!
//! [pkarr module]: super
use std::sync::{Arc, Mutex};

use iroh_base::{EndpointId, SecretKey};
use iroh_relay::{
    endpoint_info::EndpointIdExt,
    pkarr::{SignedPacket, SignedPacketVerifyError, Timestamp},
};
use mainline::{Dht, DhtBuilder, MutableItem};
use n0_future::{
    boxed::BoxStream,
    stream::StreamExt,
    task::{self, AbortOnDropHandle},
    time::{self, Duration},
};

use crate::{
    Endpoint,
    address_lookup::{
        AddrFilter, AddressLookup, AddressLookupBuilder, AddressLookupBuilderError, EndpointData,
        Error as AddressLookupError, Item as AddressLookupItem, pkarr::DEFAULT_PKARR_TTL,
    },
    endpoint_info::EndpointInfo,
};

/// Republish delay for the DHT.
///
/// This is only for when the info does not change.  If the info changes, it will be
/// published immediately.
const REPUBLISH_DELAY: Duration = Duration::from_secs(60 * 60);

/// Convert a [`SignedPacket`] to a mainline [`MutableItem`].
fn signed_packet_to_mutable_item(packet: &SignedPacket) -> MutableItem {
    MutableItem::new_signed_unchecked(
        *packet.public_key().as_bytes(),
        packet.signature().to_bytes(),
        packet.encoded_packet(),
        packet.timestamp().as_micros() as i64,
        None,
    )
}

/// Convert a mainline [`MutableItem`] to a [`SignedPacket`].
fn mutable_item_to_signed_packet(
    item: &MutableItem,
) -> Result<SignedPacket, SignedPacketVerifyError> {
    SignedPacket::from_parts_unchecked(
        item.key(),
        item.signature(),
        Timestamp::from_micros(item.seq() as u64),
        item.value(),
    )
}

/// Pkarr Mainline DHT and relay server address lookup.
///
/// It stores endpoint addresses in DNS records, signed by the endpoint's private key, and publishes
/// them to the BitTorrent Mainline DHT.  See the [pkarr module] for more details.
///
/// This implements the [`AddressLookup`] trait to be used as an address lookup service which can
/// be used as both a publisher and resolver.  Calling [`DhtAddressLookup::publish`] will start
/// a background task that periodically publishes the endpoint address.
///
/// [`DhtAddressLookup`] filters published addresses: only relay addresses are published by default.
/// To change this behavior, use [`Builder::addr_filter`] and set it to e.g. [`AddrFilter::unfiltered`].
/// This can be useful to enable publishing IP addresses if the iroh endpoint is reachable via public
/// IP addresses.
///
/// [pkarr module]: super
/// [`AddrFilter::relay_only`]: crate::address_lookup::AddrFilter::relay_only
/// [`AddrFilter::unfiltered`]: crate::address_lookup::AddrFilter::unfiltered
#[derive(Debug, Clone)]
pub struct DhtAddressLookup(Arc<Inner>);

#[derive(derive_more::Debug)]
struct Inner {
    /// Mainline DHT node.
    dht: Dht,
    /// The background task that periodically publishes the endpoint address.
    ///
    /// Due to [`AbortOnDropHandle`], this will be aborted when the Address Lookup is dropped.
    task: Mutex<Option<AbortOnDropHandle<()>>>,
    /// Optional keypair for signing the DNS packets.
    ///
    /// If this is None, the endpoint will not publish its address to the DHT.
    secret_key: Option<SecretKey>,
    /// Time-to-live value for the DNS packets.
    ttl: u32,
    /// Republish delay for the DHT.
    republish_delay: Duration,
    /// User supplied filter to filter and reorder addresses for publishing
    filter: AddrFilter,
}

impl Inner {
    async fn resolve_dht(
        &self,
        public_key: EndpointId,
    ) -> Option<Result<AddressLookupItem, AddressLookupError>> {
        tracing::info!("resolving {} from DHT", public_key.to_z32());

        let maybe_item = self
            .dht
            .clone()
            .as_async()
            .get_mutable_most_recent(public_key.as_bytes(), None)
            .await;
        match maybe_item {
            Some(item) => {
                let signed_packet = match mutable_item_to_signed_packet(&item) {
                    Ok(packet) => packet,
                    Err(err) => {
                        tracing::debug!("failed to parse mutable item as signed packet: {err}");
                        return None;
                    }
                };
                match EndpointInfo::from_pkarr_signed_packet(&signed_packet) {
                    Ok(endpoint_info) => {
                        tracing::info!("discovered endpoint info {:?}", endpoint_info);
                        Some(Ok(AddressLookupItem::new(endpoint_info, "pkarr", None)))
                    }
                    Err(_err) => {
                        tracing::debug!("failed to parse signed packet as endpoint info");
                        None
                    }
                }
            }
            None => {
                tracing::debug!("no signed packet found");
                None
            }
        }
    }
}

/// Builder for [`DhtAddressLookup`].
///
/// By default, publishing to the DHT is enabled, and relay publishing is disabled.
#[derive(Debug)]
pub struct Builder {
    dht_builder: Option<DhtBuilder>,
    secret_key: Option<SecretKey>,
    ttl: Option<u32>,
    republish_delay: Duration,
    enable_publish: bool,
    addr_filter: AddrFilter,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            dht_builder: None,
            secret_key: None,
            ttl: None,
            republish_delay: REPUBLISH_DELAY,
            enable_publish: true,
            addr_filter: AddrFilter::relay_only(),
        }
    }
}

impl Builder {
    /// Explicitly sets the DHT builder to use.
    pub fn dht_builder(mut self, builder: DhtBuilder) -> Self {
        self.dht_builder = Some(builder);
        self
    }

    /// Sets the secret key to use for signing the DNS packets.
    ///
    /// Without a secret key, the endpoint will not publish its address to the DHT.
    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    /// Sets the time-to-live value for the DNS packets.
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Sets the republish delay for the DHT.
    pub fn republish_delay(mut self, republish_delay: Duration) -> Self {
        self.republish_delay = republish_delay;
        self
    }

    /// Disables publishing even if a secret key is set.
    pub fn no_publish(mut self) -> Self {
        self.enable_publish = false;
        self
    }

    /// Sets the address filter to control which addresses are published to the DHT.
    ///
    /// By default [`AddrFilter::relay_only`] is used. This avoids leaking IP addresses
    /// to the public DHT.
    ///
    /// It can be useful to override this with [`AddrFilter::unfiltered`], if this is
    /// not a concern, e.g. when this endpoint runs on a machine with public IP
    /// addresses and without a firewall. In such cases connecting to this endpoint
    /// with just an [`EndpointId`] and DHT lookup can become faster and potentially
    /// even bypass a relay connection entirely.
    pub fn addr_filter(mut self, filter: AddrFilter) -> Self {
        self.addr_filter = filter;
        self
    }

    /// Builds the address lookup mechanism.
    pub fn build(self) -> Result<DhtAddressLookup, AddressLookupBuilderError> {
        let dht_builder = self.dht_builder.unwrap_or_default();
        let dht = dht_builder
            .build()
            .map_err(|e| AddressLookupBuilderError::from_err("pkarr-dht", e))?;
        let ttl = self.ttl.unwrap_or(DEFAULT_PKARR_TTL);
        let secret_key = self.secret_key.filter(|_| self.enable_publish);

        Ok(DhtAddressLookup(Arc::new(Inner {
            dht,
            ttl,
            secret_key,
            republish_delay: self.republish_delay,
            task: Default::default(),
            filter: self.addr_filter,
        })))
    }
}

impl AddressLookupBuilder for Builder {
    fn into_address_lookup(
        self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        self.secret_key(endpoint.secret_key().clone()).build()
    }
}

impl DhtAddressLookup {
    /// Creates a new builder for [`DhtAddressLookup`].
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Periodically publishes the endpoint address to the DHT.
    async fn publish_loop(self, signed_packet: SignedPacket) {
        let this = self;
        let z32 = signed_packet.public_key().to_z32();
        let item = signed_packet_to_mutable_item(&signed_packet);
        loop {
            let res = this
                .0
                .dht
                .clone()
                .as_async()
                .put_mutable(item.clone(), None)
                .await;
            match res {
                Ok(_) => {
                    tracing::debug!("pkarr publish success. published under {z32}");
                }
                Err(e) => {
                    // we could do a smaller delay here, but in general DHT publish
                    // not working is due to a network issue, and if the network changes
                    // the task will be restarted anyway.
                    //
                    // Being unable to publish to the DHT is something that is expected
                    // to happen from time to time, so this does not warrant a error log.
                    tracing::warn!("pkarr publish error: {}", e);
                }
            }
            time::sleep(this.0.republish_delay).await;
        }
    }
}

impl AddressLookup for DhtAddressLookup {
    fn publish(&self, data: &EndpointData) {
        let Some(keypair) = &self.0.secret_key else {
            tracing::debug!("no keypair set, not publishing");
            return;
        };

        // apply user-supplied filter
        let data = data.apply_filter(&self.0.filter).into_owned();

        if !data.has_addrs() {
            tracing::debug!("no relay url or direct addresses in endpoint data, not publishing");
            return;
        }

        tracing::debug!("publishing {data:?}");
        let info = EndpointInfo::from_parts(keypair.public(), data);
        let Ok(signed_packet) = info.to_pkarr_signed_packet(keypair, self.0.ttl) else {
            tracing::warn!("failed to create signed packet");
            return;
        };
        let this = self.clone();
        let curr = task::spawn(this.publish_loop(signed_packet));
        let mut task = self.0.task.lock().expect("poisoned");
        *task = Some(AbortOnDropHandle::new(curr));
    }

    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<BoxStream<Result<AddressLookupItem, AddressLookupError>>> {
        let z32 = endpoint_id.to_z32();
        tracing::info!("resolving {} as {}", endpoint_id, z32);
        let address_lookup = self.0.clone();
        let stream =
            n0_future::stream::once_future(
                async move { address_lookup.resolve_dht(endpoint_id).await },
            )
            .filter_map(|x| x)
            .boxed();
        Some(stream)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use iroh_base::{RelayUrl, TransportAddr};
    use mainline::Testnet;
    use n0_error::{Result, StdResultExt};
    use n0_tracing_test::traced_test;
    use url::Url;

    use super::*;

    #[tokio::test]
    #[ignore = "flaky"]
    #[traced_test]
    async fn dht_address_lookup_smoke() -> Result {
        let secret = SecretKey::generate();
        let testnet = Testnet::new_async(3).await.anyerr()?;
        let mut dht_builder = DhtBuilder::default();
        dht_builder.bootstrap(&testnet.bootstrap);
        let address_lookup = DhtAddressLookup::builder()
            .secret_key(secret.clone())
            .dht_builder(dht_builder)
            .addr_filter(AddrFilter::unfiltered())
            .build()?;

        let relay_url: RelayUrl = Url::parse("https://example.com").anyerr()?.into();

        let data = EndpointData::from_iter([TransportAddr::Relay(relay_url.clone())]);
        address_lookup.publish(&data);

        // publish is fire and forget, so we have no way to wait until it is done.
        tokio::time::timeout(Duration::from_secs(30), async move {
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let mut found_relay_urls = BTreeSet::new();
                let items = address_lookup
                    .resolve(secret.public())
                    .unwrap()
                    .collect::<Vec<_>>()
                    .await;
                for item in items.into_iter().flatten() {
                    for url in item.relay_urls() {
                        found_relay_urls.insert(url.clone());
                    }
                }
                if found_relay_urls.contains(&relay_url) {
                    break;
                }
            }
        })
        .await
        .expect("timeout, relay_url not found on DHT");
        Ok(())
    }
}
