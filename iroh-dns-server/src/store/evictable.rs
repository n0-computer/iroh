use std::{sync::Arc, time::Duration};

use anyhow::Result;
use iroh_metrics::inc;
use pkarr::SignedPacket;
use timedmap::TimedMap;

use crate::{metrics::Metrics, util::PublicKeyBytes};

use super::SignedPacketStore;

#[derive(Debug)]
pub struct EvictableStore {
    store: Arc<TimedMap<PublicKeyBytes, SignedPacket>>,
    max_age: Duration,
}

impl EvictableStore {
    pub fn new(max_age: Duration) -> Self {
        let store = Arc::new(TimedMap::new());
        Self { store, max_age }
    }
}

impl SignedPacketStore for EvictableStore {
    fn upsert(&self, packet: SignedPacket) -> Result<bool> {
        let key = PublicKeyBytes::from_signed_packet(&packet);

        let mut replaced = false;
        if let Some(existing) = self.store.get(&key) {
            if existing.more_recent_than(&packet) {
                return Ok(false);
            } else {
                replaced = true;
            }
        }

        self.store.insert(key, packet, self.max_age);

        if replaced {
            inc!(Metrics, store_packets_updated);
        } else {
            inc!(Metrics, store_packets_inserted);
        }

        Ok(true)
    }

    fn get(&self, key: &PublicKeyBytes) -> Result<Option<SignedPacket>> {
        Ok(self.store.get(key))
    }

    fn remove(&self, key: &PublicKeyBytes) -> Result<bool> {
        let updated = self.store.remove(key).is_some();

        if updated {
            inc!(Metrics, store_packets_removed)
        }

        Ok(updated)
    }
}
