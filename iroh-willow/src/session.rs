//! The `session` module contains an implementation of the Willow General Purpose Sync Protocol
//! (WGPS).
//!
//! It exposes a few public types used to initiate sessions, and the [`intents`] module which
//! contains handle, event and command types for controlling sessions.
//!
//! Internally, this module contains the full implementation of the protocol, which is started with
//! the `run_session` function (which is not public).

use std::sync::Arc;

use channels::ChannelSenders;
use tokio::sync::mpsc;

use crate::{
    interest::Interests,
    session::{error::ChannelReceiverDropped, intents::Intent},
};

mod aoi_finder;
mod capabilities;
mod challenge;
pub(crate) mod channels;
mod data;
mod error;
pub mod intents;
mod pai_finder;
mod payload;
mod reconciler;
mod resource;
mod run;
mod static_tokens;

pub(crate) use self::challenge::InitialTransmission;
pub(crate) use self::channels::Channels;
pub(crate) use self::error::Error;
pub(crate) use self::run::run_session;

/// Id per session to identify store subscriptions.
pub(crate) type SessionId = u64;

/// To break symmetry, we refer to the peer that initiated the synchronisation session as Alfie,
/// and the other peer as Betty.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Role {
    /// The peer that initiated the synchronisation session.
    Alfie,
    /// The peer that accepted the synchronisation session.
    Betty,
}

impl Role {
    /// Returns `true` if we initiated the session.
    pub fn is_alfie(&self) -> bool {
        matches!(self, Role::Alfie)
    }
    /// Returns `true` if we accepted the session.
    pub fn is_betty(&self) -> bool {
        matches!(self, Role::Betty)
    }
}

/// A session can either run a single reconciliation, or keep open until closed by either peer.
///
/// * [`Self::Continuous`] will enable the live data channels to synchronize updates in real-time.
/// * [`Self::ReconcileOnce`] will run a single reconciliation of the interests declared at session
///   start, and then close the session.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SessionMode {
    /// Run a single, full reconciliation, and then quit.
    ReconcileOnce,
    /// Run reconciliations and data mode, until intentionally closed.
    Continuous,
}

impl SessionMode {
    /// Returns `true` if the session runs in live mode.
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Continuous)
    }
}

/// Options to initialize a session.
#[derive(Debug)]
pub struct SessionInit {
    /// Selects the areas we wish to synchronize.
    pub interests: Interests,
    /// Selects the session mode (once or continuous).
    pub mode: SessionMode,
}

impl SessionInit {
    pub fn new(interests: impl Into<Interests>, mode: SessionMode) -> Self {
        let interests = interests.into();
        Self { interests, mode }
    }

    /// Creates a new [`SessionInit`] with [`SessionMode::Continuous`].
    pub fn continuous(interests: impl Into<Interests>) -> Self {
        Self::new(interests, SessionMode::Continuous)
    }

    /// Creates a new [`SessionInit`] with [`SessionMode::ReconcileOnce`].
    pub fn reconcile_once(interests: impl Into<Interests>) -> Self {
        Self::new(interests, SessionMode::ReconcileOnce)
    }
}

/// Sender for session events
#[derive(Debug, Clone)]
pub(crate) struct EventSender(pub mpsc::Sender<SessionEvent>);

impl EventSender {
    pub(crate) async fn send(&self, event: SessionEvent) -> Result<(), ChannelReceiverDropped> {
        self.0.send(event).await.map_err(|_| ChannelReceiverDropped)
    }
}

/// Events emitted from a session.
///
/// These are handled in the [`PeerManager`](crate::engine::peer_manager::PeerManager).
#[derive(derive_more::Debug)]
pub(crate) enum SessionEvent {
    Established,
    Complete {
        result: Result<(), Arc<Error>>,
        // TODO(Frando): Not sure if we should make use of this somewhere, maybe just remove.
        #[allow(unused)]
        we_cancelled: bool,
        #[debug("ChannelSenders")]
        senders: ChannelSenders,
        remaining_intents: Vec<Intent>,
    },
}

/// Update commands for an active session.
#[derive(Debug)]
pub(crate) enum SessionUpdate {
    SubmitIntent(Intent),
    Abort(Error),
}

/// Handle to an active session.
///
/// This is not made public, the only public interface are [`intents`] handles.
#[derive(Debug)]
pub(crate) struct SessionHandle {
    pub(crate) update_tx: mpsc::Sender<SessionUpdate>,
    pub(crate) event_rx: mpsc::Receiver<SessionEvent>,
}

impl SessionHandle {
    // TODO(Frando): Previously the [`SessionHandle`] was exposed through the `net` module.
    // Now all public interaction goes through the [`Engine`], which does not use the handle as
    // such, but splits into the fields. Leaving this here for the moment in case we decide to
    // expose the session handle (without relying on intents) publicly.

    /// Wait for the session to finish.
    ///
    /// Returns the channel senders and a boolean indicating if we cancelled the session.
    /// Returns an error if the session failed to complete.
    #[cfg(test)]
    pub(crate) async fn complete(&mut self) -> Result<(ChannelSenders, bool), Arc<Error>> {
        while let Some(event) = self.event_rx.recv().await {
            if let SessionEvent::Complete {
                result,
                senders,
                we_cancelled,
                ..
            } = event
            {
                return result.map(|()| (senders, we_cancelled));
            }
        }
        Err(Arc::new(Error::ActorFailed))
    }
}
