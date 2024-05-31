use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::broadcast;

use crate::{
    proto::{
        grouping::Area,
        willow::{AuthorisedEntry, NamespaceId},
    },
    store::{EntryStore, Shared},
};

use super::SessionId;

const BROADCAST_CAP: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub enum Origin {
    Local,
    Remote(SessionId),
}

#[derive(Debug)]
pub struct Broadcaster<S> {
    store: Shared<S>,
    broadcast: Arc<Mutex<BroadcasterInner>>,
}

impl<S> Clone for Broadcaster<S> {
    fn clone(&self) -> Self {
        Broadcaster {
            store: self.store.clone(),
            broadcast: self.broadcast.clone(),
        }
    }
}

impl<S: EntryStore> std::ops::Deref for Broadcaster<S> {
    type Target = Shared<S>;
    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

impl<S: EntryStore> Broadcaster<S> {
    pub fn new(store: Shared<S>) -> Self {
        Self {
            store,
            broadcast: Default::default(),
        }
    }

    pub fn subscribe(&mut self, session_id: SessionId) -> broadcast::Receiver<AuthorisedEntry> {
        self.broadcast.lock().unwrap().subscribe(session_id)
    }

    pub fn unsubscribe(&mut self, session_id: &SessionId) {
        self.broadcast.lock().unwrap().unsubscribe(session_id)
    }

    pub fn ingest_entry(
        &mut self,
        entry: &AuthorisedEntry,
        origin: Origin,
    ) -> anyhow::Result<bool> {
        if self.store.ingest_entry(entry)? {
            self.broadcast.lock().unwrap().broadcast(entry, origin);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn add_area(&mut self, session: SessionId, namespace: NamespaceId, area: Area) {
        self.broadcast
            .lock()
            .unwrap()
            .add_area(session, namespace, area);
    }
}

#[derive(Debug, Default)]
struct BroadcasterInner {
    senders: HashMap<SessionId, broadcast::Sender<AuthorisedEntry>>,
    areas: HashMap<NamespaceId, HashMap<SessionId, Vec<Area>>>,
}

impl BroadcasterInner {
    fn subscribe(&mut self, session: SessionId) -> broadcast::Receiver<AuthorisedEntry> {
        self.senders
            .entry(session)
            .or_insert_with(|| broadcast::Sender::new(BROADCAST_CAP))
            .subscribe()
    }

    fn unsubscribe(&mut self, session: &SessionId) {
        self.senders.remove(session);
        self.areas.retain(|_namespace, sessions| {
            sessions.remove(session);
            !sessions.is_empty()
        });
    }

    fn add_area(&mut self, session: SessionId, namespace: NamespaceId, area: Area) {
        self.areas
            .entry(namespace)
            .or_default()
            .entry(session)
            .or_default()
            .push(area)
    }

    fn broadcast(&mut self, entry: &AuthorisedEntry, origin: Origin) {
        let Some(sessions) = self.areas.get_mut(&entry.namespace_id()) else {
            return;
        };
        for (session_id, areas) in sessions {
            if let Origin::Remote(origin) = origin {
                if origin == *session_id {
                    continue;
                }
            }
            if areas.iter().any(|area| area.includes_entry(entry.entry())) {
                self.senders
                    .get(session_id)
                    .expect("session sender to exist")
                    .send(entry.clone())
                    .ok();
            }
        }
    }
}
