use serde::{Deserialize, Serialize};
use strum::{EnumCount, VariantArray};

use super::messages::Message;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, derive_more::TryFrom)]
pub enum Channel {
    Control,
    Logical(LogicalChannel),
}

impl Channel {
    pub const COUNT: usize = LogicalChannel::COUNT + 1;

    pub fn all() -> [Channel; LogicalChannel::COUNT + 1] {
        // TODO: do this without allocation
        // https://users.rust-lang.org/t/how-to-concatenate-array-literals-in-compile-time/21141/3
        [Self::Control]
            .into_iter()
            .chain(LogicalChannel::VARIANTS.iter().copied().map(Self::Logical))
            .collect::<Vec<_>>()
            .try_into()
            .expect("static length")
    }

    pub fn fmt_short(&self) -> &'static str {
        match self {
            Channel::Control => "Ctl",
            Channel::Logical(ch) => ch.fmt_short(),
        }
    }

    pub fn id(&self) -> u8 {
        match self {
            Channel::Control => 0,
            Channel::Logical(ch) => ch.id(),
        }
    }

    pub fn from_id(id: u8) -> Result<Self, InvalidChannelId> {
        match id {
            0 => Ok(Self::Control),
            _ => {
                let ch = LogicalChannel::from_id(id)?;
                Ok(Self::Logical(ch))
            }
        }
    }
}

/// The different logical channels employed by the WGPS.
#[derive(
    Debug,
    Serialize,
    Deserialize,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Hash,
    strum::EnumIter,
    strum::VariantArray,
    strum::EnumCount,
)]
pub enum LogicalChannel {
    /// Logical channel for controlling the binding of new IntersectionHandles.
    Intersection,
    /// Logical channel for controlling the binding of new CapabilityHandles.
    Capability,
    /// Logical channel for controlling the binding of new AreaOfInterestHandles.
    AreaOfInterest,
    /// Logical channel for controlling the binding of new StaticTokenHandles.
    StaticToken,
    /// Logical channel for performing 3d range-based set reconciliation.
    Reconciliation,
    /// Logical channel for transmitting Entries and Payloads outside of 3d range-based set reconciliation.
    Data,
    // /// Logical channel for controlling the binding of new PayloadRequestHandles.
    // PayloadRequest,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid channel id")]
pub struct InvalidChannelId;

impl LogicalChannel {
    pub fn all() -> [LogicalChannel; LogicalChannel::COUNT] {
        LogicalChannel::VARIANTS
            .try_into()
            .expect("statically checked")
    }
    pub fn fmt_short(&self) -> &'static str {
        match self {
            LogicalChannel::Intersection => "Pai",
            LogicalChannel::Reconciliation => "Rec",
            LogicalChannel::StaticToken => "StT",
            LogicalChannel::Capability => "Cap",
            LogicalChannel::AreaOfInterest => "AoI",
            LogicalChannel::Data => "Dat",
        }
    }

    pub fn from_id(id: u8) -> Result<Self, InvalidChannelId> {
        match id {
            2 => Ok(Self::Intersection),
            3 => Ok(Self::AreaOfInterest),
            4 => Ok(Self::Capability),
            5 => Ok(Self::StaticToken),
            6 => Ok(Self::Reconciliation),
            7 => Ok(Self::Data),
            _ => Err(InvalidChannelId),
        }
    }

    pub fn id(&self) -> u8 {
        match self {
            LogicalChannel::Intersection => 2,
            LogicalChannel::AreaOfInterest => 3,
            LogicalChannel::Capability => 4,
            LogicalChannel::StaticToken => 5,
            LogicalChannel::Reconciliation => 6,
            LogicalChannel::Data => 7,
        }
    }
}

impl Message {
    pub fn channel(&self) -> Channel {
        match self {
            Message::PaiBindFragment(_) | Message::PaiReplyFragment(_) => {
                Channel::Logical(LogicalChannel::Intersection)
            }

            Message::SetupBindReadCapability(_) => Channel::Logical(LogicalChannel::Capability),
            Message::SetupBindAreaOfInterest(_) => Channel::Logical(LogicalChannel::AreaOfInterest),
            Message::SetupBindStaticToken(_) => Channel::Logical(LogicalChannel::StaticToken),

            Message::ReconciliationSendFingerprint(_)
            | Message::ReconciliationAnnounceEntries(_)
            | Message::ReconciliationSendEntry(_)
            | Message::ReconciliationSendPayload(_)
            | Message::ReconciliationTerminatePayload(_) => {
                Channel::Logical(LogicalChannel::Reconciliation)
            }

            Message::DataSendEntry(_)
            | Message::DataSendPayload(_)
            | Message::DataSetMetadata(_) => Channel::Logical(LogicalChannel::Data),

            Message::CommitmentReveal(_)
            | Message::PaiRequestSubspaceCapability(_)
            | Message::PaiReplySubspaceCapability(_)
            | Message::ControlIssueGuarantee(_)
            | Message::ControlAbsolve(_)
            | Message::ControlPlead(_)
            | Message::ControlAnnounceDropping(_)
            | Message::ControlApologise(_)
            | Message::ControlFreeHandle(_) => Channel::Control,
        }
    }
}
