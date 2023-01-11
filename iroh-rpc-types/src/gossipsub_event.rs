use futures::stream::BoxStream;
use libp2p::{
    gossipsub::{GossipsubMessage, MessageId, TopicHash},
    PeerId,
};
use serde::{Deserialize, Serialize};

use crate::p2p::GossipsubSubscribeResponse;

pub type GossipsubEventStream = BoxStream<'static, Box<GossipsubSubscribeResponse>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipsubEvent {
    Subscribed {
        peer_id: PeerId,
        #[serde(with = "TopicHashDef")]
        topic: TopicHash,
    },
    Unsubscribed {
        peer_id: PeerId,
        #[serde(with = "TopicHashDef")]
        topic: TopicHash,
    },
    Message {
        from: PeerId,
        id: MessageId,
        #[serde(with = "GossipsubMessageDef")]
        message: GossipsubMessage,
        #[serde(with = "TopicHashDef")]
        topic: TopicHash,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "TopicHash")]
struct TopicHashDef {
    #[serde(getter = "TopicHash::to_string")]
    hash: String,
}

impl From<TopicHashDef> for TopicHash {
    fn from(t: TopicHashDef) -> Self {
        TopicHash::from_raw(t.hash)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "GossipsubMessage")]
struct GossipsubMessageDef {
    source: Option<PeerId>,
    data: Vec<u8>,
    sequence_number: Option<u64>,
    #[serde(with = "TopicHashDef")]
    topic: TopicHash,
}
