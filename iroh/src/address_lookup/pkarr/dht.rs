//! Pkarr based address lookup for iroh, supporting both relay servers and the DHT.
//!
//! This module contains pkarr-based address lookup for iroh which can use both pkarr
//! relay servers as well as the Mainline DHT directly.  See the [pkarr module] for an
//! overview of pkarr.
//!
//! [pkarr module]: super
use std::sync::{Arc, Mutex};

use iroh_base::{EndpointId, SecretKey};
use n0_future::{
    boxed::BoxStream,
    stream::StreamExt,
    task::{self, AbortOnDropHandle},
    time::{self, Duration},
};
use pkarr::{Client as PkarrClient, SignedPacket};
use url::Url;

use crate::{
    Endpoint,
    address_lookup::{
        AddressLookup, EndpointData, Error as AddressLookupError, IntoAddressLookup,
        IntoAddressLookupError, Item as AddressLookupItem,
        pkarr::{DEFAULT_PKARR_TTL, N0_DNS_PKARR_RELAY_PROD, N0_DNS_PKARR_RELAY_STAGING},
    },
    endpoint_info::EndpointInfo,
};

/// Republish delay for the DHT.
///
/// This is only for when the info does not change.  If the info changes, it will be
/// published immediately.
const REPUBLISH_DELAY: Duration = Duration::from_secs(60 * 60);

/// Pkarr Mainline DHT and relay server address lookup.
///
/// It stores endpoint addresses in DNS records, signed by the endpoint's private key, and publishes
/// them to the BitTorrent Mainline DHT.  See the [pkarr module] for more details.
///
/// This implements the [`AddressLookup`] trait to be used as an address lookup service which can
/// be used as both a publisher and resolver.  Calling [`DhtAddressLookup::publish`] will start
/// a background task that periodically publishes the endpoint address.
///
/// [pkarr module]: super
#[derive(Debug, Clone)]
pub struct DhtAddressLookup(Arc<Inner>);

impl Default for DhtAddressLookup {
    fn default() -> Self {
        Self::builder().build().expect("valid builder")
    }
}

#[derive(derive_more::Debug)]
struct Inner {
    /// Pkarr client for interacting with the DHT.
    pkarr: PkarrClient,
    /// The background task that periodically publishes the endpoint address.
    ///
    /// Due to [`AbortOnDropHandle`], this will be aborted when the Address Lookup is dropped.
    task: Mutex<Option<AbortOnDropHandle<()>>>,
    /// Optional keypair for signing the DNS packets.
    ///
    /// If this is None, the endpoint will not publish its address to the DHT.
    secret_key: Option<SecretKey>,
    /// Optional pkarr relay URL to use.
    relay_url: Option<Url>,
    /// Time-to-live value for the DNS packets.
    ttl: u32,
    /// True to include the direct addresses in the DNS packet.
    include_direct_addresses: bool,
    /// Republish delay for the DHT.
    republish_delay: Duration,
}

impl Inner {
    async fn resolve_pkarr(
        &self,
        key: pkarr::PublicKey,
    ) -> Option<Result<AddressLookupItem, AddressLookupError>> {
        tracing::info!(
            "resolving {} from relay and DHT {:?}",
            key.to_z32(),
            self.relay_url
        );

        let maybe_packet = self.pkarr.resolve(&key).await;
        match maybe_packet {
            Some(signed_packet) => match EndpointInfo::from_pkarr_signed_packet(&signed_packet) {
                Ok(endpoint_info) => {
                    tracing::info!("discovered endpoint info {:?}", endpoint_info);
                    Some(Ok(AddressLookupItem::new(endpoint_info, "pkarr", None)))
                }
                Err(_err) => {
                    tracing::debug!("failed to parse signed packet as endpoint info");
                    None
                }
            },
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
    client: Option<PkarrClient>,
    secret_key: Option<SecretKey>,
    ttl: Option<u32>,
    pkarr_relay: Option<Url>,
    dht: bool,
    include_direct_addresses: bool,
    republish_delay: Duration,
    enable_publish: bool,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            client: None,
            secret_key: None,
            ttl: None,
            pkarr_relay: None,
            dht: true,
            include_direct_addresses: false,
            republish_delay: REPUBLISH_DELAY,
            enable_publish: true,
        }
    }
}

impl Builder {
    /// Explicitly sets the pkarr client to use.
    pub fn client(mut self, client: PkarrClient) -> Self {
        self.client = Some(client);
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

    /// Sets the pkarr relay URL to use.
    pub fn pkarr_relay(mut self, pkarr_relay: Url) -> Self {
        self.pkarr_relay = Some(pkarr_relay);
        self
    }

    /// Uses the default [number 0] pkarr relay URL.
    ///
    /// [number 0]: https://n0.computer
    pub fn n0_dns_pkarr_relay(mut self) -> Self {
        let url = if crate::endpoint::force_staging_infra() {
            N0_DNS_PKARR_RELAY_STAGING
        } else {
            N0_DNS_PKARR_RELAY_PROD
        };
        self.pkarr_relay = Some(url.parse().expect("valid URL"));
        self
    }

    /// Sets whether to publish to the Mainline DHT.
    pub fn dht(mut self, dht: bool) -> Self {
        self.dht = dht;
        self
    }

    /// Sets whether to include the direct addresses in the DNS packet.
    pub fn include_direct_addresses(mut self, include_direct_addresses: bool) -> Self {
        self.include_direct_addresses = include_direct_addresses;
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

    /// Builds the address lookup mechanism.
    pub fn build(self) -> Result<DhtAddressLookup, IntoAddressLookupError> {
        if !(self.dht || self.pkarr_relay.is_some()) {
            return Err(IntoAddressLookupError::from_err(
                "pkarr",
                std::io::Error::other("at least one of DHT or relay must be enabled"),
            ));
        }
        let pkarr = match self.client {
            Some(client) => client,
            None => {
                let mut builder = PkarrClient::builder();
                builder.no_default_network();
                if self.dht {
                    builder.dht(|x| x);
                }
                if let Some(url) = &self.pkarr_relay {
                    builder
                        .relays(std::slice::from_ref(url))
                        .map_err(|e| IntoAddressLookupError::from_err("pkarr", e))?;
                }
                builder
                    .build()
                    .map_err(|e| IntoAddressLookupError::from_err("pkarr", e))?
            }
        };
        let ttl = self.ttl.unwrap_or(DEFAULT_PKARR_TTL);
        let include_direct_addresses = self.include_direct_addresses;
        let secret_key = self.secret_key.filter(|_| self.enable_publish);

        Ok(DhtAddressLookup(Arc::new(Inner {
            pkarr,
            ttl,
            relay_url: self.pkarr_relay,
            include_direct_addresses,
            secret_key,
            republish_delay: self.republish_delay,
            task: Default::default(),
        })))
    }
}

impl IntoAddressLookup for Builder {
    fn into_address_lookup(
        self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, IntoAddressLookupError> {
        self.secret_key(endpoint.secret_key().clone()).build()
    }
}

impl DhtAddressLookup {
    /// Creates a new builder for [`DhtAddressLookup`].
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Periodically publishes the endpoint address to the DHT and/or relay.
    async fn publish_loop(self, keypair: SecretKey, signed_packet: SignedPacket) {
        let this = self;
        let public_key =
            pkarr::PublicKey::try_from(keypair.public().as_bytes()).expect("valid public key");
        let z32 = public_key.to_z32();
        loop {
            // If the task gets aborted while doing this lookup, we have not published yet.
            let prev_timestamp = this
                .0
                .pkarr
                .resolve_most_recent(&public_key)
                .await
                .map(|p| p.timestamp());
            let res = this.0.pkarr.publish(&signed_packet, prev_timestamp).await;
            match res {
                Ok(()) => {
                    tracing::debug!("pkarr publish success. published under {z32}",);
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
        if !data.has_addrs() {
            tracing::debug!("no relay url or direct addresses in endpoint data, not publishing");
            return;
        }
        tracing::debug!("publishing {data:?}");
        let mut info = EndpointInfo::from_parts(keypair.public(), data.clone());
        if !self.0.include_direct_addresses {
            info.clear_ip_addrs();
        }
        let Ok(signed_packet) = info.to_pkarr_signed_packet(keypair, self.0.ttl) else {
            tracing::warn!("failed to create signed packet");
            return;
        };
        let this = self.clone();
        let curr = task::spawn(this.publish_loop(keypair.clone(), signed_packet));
        let mut task = self.0.task.lock().expect("poisoned");
        *task = Some(AbortOnDropHandle::new(curr));
    }

    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<BoxStream<Result<AddressLookupItem, AddressLookupError>>> {
        let pkarr_public_key =
            pkarr::PublicKey::try_from(endpoint_id.as_bytes()).expect("valid public key");
        tracing::info!("resolving {} as {}", endpoint_id, pkarr_public_key.to_z32());
        let address_lookup = self.0.clone();
        let stream = n0_future::stream::once_future(async move {
            address_lookup.resolve_pkarr(pkarr_public_key).await
        })
        .filter_map(|x| x)
        .boxed();
        Some(stream)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use iroh_base::RelayUrl;
    use n0_error::{Result, StdResultExt};
    use n0_tracing_test::traced_test;

    use super::*;

    #[tokio::test]
    #[ignore = "flaky"]
    #[traced_test]
    async fn dht_address_lookup_smoke() -> Result {
        let secret = SecretKey::generate(&mut rand::rng());
        let testnet = pkarr::mainline::Testnet::new_async(3).await.anyerr()?;
        let client = pkarr::Client::builder()
            .dht(|builder| builder.bootstrap(&testnet.bootstrap))
            .build()
            .anyerr()?;
        let address_lookup = DhtAddressLookup::builder()
            .secret_key(secret.clone())
            .client(client)
            .build()?;

        let relay_url: RelayUrl = Url::parse("https://example.com").anyerr()?.into();

        let data = EndpointData::default().with_relay_url(Some(relay_url.clone()));
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
