use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::broadcast;

use crate::proto::{
    data_model::{AuthorisedEntry, NamespaceId},
    grouping::Area,
};

pub type SessionId = u64;

use super::traits::EntryStorage;

const BROADCAST_CAP: usize = 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EntryOrigin {
    /// The entry is inserted locally.
    Local,
    /// The entry was received from a peer.
    Remote {
        session: SessionId,
        channel: EntryChannel,
    }, // TODO: Add details.
       // Remote {
       //     peer: NodeId,
       //     channel: EntryChannel,
       // },
}

impl EntryOrigin {
    // pub fn peer(&self) -> Option<NodeId> {
    //     match self {
    //         EntryOrigin::Local => None,
    //         EntryOrigin::Remote { peer, .. } => Some(peer)
    //     }
    // }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EntryChannel {
    Reconciliation,
    Data,
}

#[derive(Debug, Clone)]
pub struct WatchableEntryStore<ES> {
    storage: ES,
    broadcast: Arc<Mutex<Broadcaster>>,
}

impl<ES: EntryStorage> WatchableEntryStore<ES> {
    pub(super) fn new(storage: ES) -> Self {
        Self {
            storage,
            broadcast: Default::default(),
        }
    }

    // /// Returns a store reader.
    // pub fn reader(&self) -> ES::Reader {
    //     self.storage.reader()
    // }

    /// Returns a store snapshot.
    pub fn snapshot(&self) -> anyhow::Result<ES::Snapshot> {
        self.storage.snapshot()
    }

    /// Ingest a new entry.
    ///
    /// Returns `true` if the entry was stored, and `false` if the entry already exists or is
    /// obsoleted by an existing entry.
    pub fn ingest(&self, entry: &AuthorisedEntry, origin: EntryOrigin) -> anyhow::Result<bool> {
        if self.storage.ingest_entry(entry)? {
            self.broadcast.lock().unwrap().broadcast(entry, origin);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Setup a new subscription, identified by `session_id`.
    ///
    /// The subscription will initially be empty. To actually receive newly ingested entries,
    /// add areas to watch with [`Self::watch_area`].
    ///
    /// Returns a [`broadcast::Receiver`].
    pub fn subscribe(&self, session_id: SessionId) -> broadcast::Receiver<AuthorisedEntry> {
        self.broadcast
            .lock()
            .unwrap()
            .subscribe(session_id, BROADCAST_CAP)
    }

    /// Remove a subscription.
    pub fn unsubscribe(&self, session_id: &SessionId) {
        self.broadcast.lock().unwrap().unsubscribe(session_id)
    }

    /// Add an area to the list of watched areas for a subscription.
    ///
    /// The subscription has to be setup with [`Self::subscribe`] to actually receive new entries
    /// that fall within the area.
    pub fn watch_area(&self, session: SessionId, namespace: NamespaceId, area: Area) {
        self.broadcast
            .lock()
            .unwrap()
            .watch_area(session, namespace, area);
    }
}

#[derive(Debug, Default)]
struct Broadcaster {
    senders: HashMap<SessionId, broadcast::Sender<AuthorisedEntry>>,
    watched_areas: HashMap<NamespaceId, HashMap<SessionId, Vec<Area>>>,
}

impl Broadcaster {
    fn subscribe(
        &mut self,
        session: SessionId,
        cap: usize,
    ) -> broadcast::Receiver<AuthorisedEntry> {
        self.senders
            .entry(session)
            .or_insert_with(|| broadcast::Sender::new(cap))
            .subscribe()
    }

    fn unsubscribe(&mut self, session: &SessionId) {
        self.senders.remove(session);
        self.watched_areas.retain(|_namespace, sessions| {
            sessions.remove(session);
            !sessions.is_empty()
        });
    }

    fn watch_area(&mut self, session: SessionId, namespace: NamespaceId, area: Area) {
        self.watched_areas
            .entry(namespace)
            .or_default()
            .entry(session)
            .or_default()
            .push(area)
    }

    fn broadcast(&mut self, entry: &AuthorisedEntry, origin: EntryOrigin) {
        let Some(sessions) = self.watched_areas.get_mut(entry.entry().namespace_id()) else {
            return;
        };
        let mut dropped_receivers = vec![];
        for (session_id, areas) in sessions {
            // Do not broadcast back into sessions where the entry came from.
            if matches!(origin, EntryOrigin::Remote { session, ..} if session == *session_id) {
                continue;
            }
            // Check if the session is watching an area where the entry falls into.
            if areas.iter().any(|area| area.includes_entry(entry.entry())) {
                if let Some(sender) = self.senders.get(session_id) {
                    // Send the entry and mark senders with dropped receivers for removal.
                    if let Err(_err) = sender.send(entry.clone()) {
                        dropped_receivers.push(*session_id);
                    }
                }
            }
        }
        for session_id in dropped_receivers {
            self.unsubscribe(&session_id);
        }
    }
}
