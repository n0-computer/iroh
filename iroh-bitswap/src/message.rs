use core::convert::TryFrom;

use ahash::{AHashMap, AHashSet};
use bytes::{Buf, BytesMut};
use cid::Cid;
use prost::Message;

use crate::block::Block;
use crate::error::BitswapError;
use crate::prefix::Prefix;

mod pb {
    include!(concat!(env!("OUT_DIR"), "/bitswap_pb.rs"));
}

/// Priority of a wanted block.
pub type Priority = i32;

#[derive(Default, Clone, Debug, PartialEq)]
pub struct Wantlist {
    /// Wanted blocks.
    want_blocks: AHashMap<Cid, Priority>,
    /// Blocks to cancel.
    cancel_blocks: AHashSet<Cid>,
    /// Blocks this peer provides.
    want_have_blocks: AHashMap<Cid, Priority>,
}

impl Wantlist {
    pub fn is_empty(&self) -> bool {
        self.want_blocks.is_empty()
            && self.cancel_blocks.is_empty()
            && self.want_have_blocks.is_empty()
    }

    /// Returns the list of wanted blocks.
    pub fn blocks(&self) -> impl Iterator<Item = (&Cid, Priority)> {
        self.want_blocks
            .iter()
            .map(|(cid, priority)| (cid, *priority))
    }

    pub fn want_have_blocks(&self) -> impl Iterator<Item = (&Cid, Priority)> {
        self.want_have_blocks
            .iter()
            .map(|(cid, priority)| (cid, *priority))
    }

    /// Returns the list of cancelled blocks.
    pub fn cancels(&self) -> impl Iterator<Item = &Cid> {
        self.cancel_blocks.iter()
    }

    /// Adds a block to the want list.
    pub fn want_block(&mut self, cid: &Cid, priority: Priority) {
        self.cancel_blocks.remove(cid);
        self.want_blocks.insert(*cid, priority);
    }

    /// Adds a block to the have want list.
    pub fn want_have_block(&mut self, cid: &Cid, priority: Priority) {
        self.want_have_blocks.insert(*cid, priority);
    }

    /// Adds a block to the cancel list.
    pub fn cancel_block(&mut self, cid: &Cid) {
        self.want_blocks.remove(cid);
        self.cancel_blocks.insert(*cid);
    }

    fn into_pb(self) -> pb::message::Wantlist {
        use pb::message::wantlist::WantType;

        let mut wantlist = pb::message::Wantlist {
            entries: Vec::with_capacity(self.want_blocks.len() + self.cancel_blocks.len()),
            full: false,
        };

        for (cid, &priority) in &self.want_blocks {
            let entry = pb::message::wantlist::Entry {
                block: cid.to_bytes(),
                priority,
                cancel: false,
                want_type: WantType::Block as _,
                send_dont_have: false,
            };
            wantlist.entries.push(entry);
        }

        for (cid, &priority) in &self.want_have_blocks {
            let entry = pb::message::wantlist::Entry {
                block: cid.to_bytes(),
                priority,
                cancel: false,
                want_type: WantType::Have as _,
                send_dont_have: true,
            };
            wantlist.entries.push(entry);
        }

        for cid in &self.cancel_blocks {
            let entry = pb::message::wantlist::Entry {
                block: cid.to_bytes(),
                priority: 1,
                cancel: true,
                want_type: WantType::Block as _,
                send_dont_have: false,
            };
            wantlist.entries.push(entry);
        }

        wantlist
    }

    fn from_pb(proto: Option<pb::message::Wantlist>) -> Result<Self, BitswapError> {
        let mut wantlist = Wantlist::default();
        let proto = proto.unwrap_or_default();

        for entry in proto.entries {
            let cid = Cid::try_from(entry.block)?;
            match entry.want_type {
                ty if pb::message::wantlist::WantType::Block as i32 == ty => {
                    if entry.cancel {
                        wantlist.cancel_blocks.insert(cid);
                    } else {
                        wantlist.want_blocks.insert(cid, entry.priority);
                    }
                }
                ty if pb::message::wantlist::WantType::Have as i32 == ty => {
                    if !entry.cancel {
                        wantlist.want_have_blocks.insert(cid, entry.priority);
                    }
                }
                _ => {}
            }
        }

        Ok(wantlist)
    }
}

/// A bitswap message.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct BitswapMessage {
    wantlist: Wantlist,
    /// List of blocks to send.
    blocks: Vec<Block>,
    block_presences: Vec<BlockPresence>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BlockPresence {
    pub cid: Cid,
    pub typ: BlockPresenceType,
}

#[derive(Clone, Copy, Debug, PartialEq, num_enum::IntoPrimitive, num_enum::TryFromPrimitive)]
#[repr(i32)]
pub enum BlockPresenceType {
    Have = 0,
    DontHave = 1,
}

impl BlockPresence {
    pub fn have(cid: Cid) -> Self {
        BlockPresence {
            cid,
            typ: BlockPresenceType::Have,
        }
    }

    pub fn is_have(&self) -> bool {
        matches!(self.typ, BlockPresenceType::Have)
    }
}

impl From<BlockPresence> for pb::message::BlockPresence {
    fn from(bp: BlockPresence) -> Self {
        pb::message::BlockPresence {
            cid: bp.cid.to_bytes(),
            r#type: bp.typ.into(),
        }
    }
}

impl From<BlockPresenceType> for pb::message::BlockPresenceType {
    fn from(ty: BlockPresenceType) -> Self {
        match ty {
            BlockPresenceType::Have => pb::message::BlockPresenceType::Have,
            BlockPresenceType::DontHave => pb::message::BlockPresenceType::DontHave,
        }
    }
}

impl BitswapMessage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Is message empty.
    pub fn is_empty(&self) -> bool {
        self.wantlist.is_empty() && self.blocks.is_empty() && self.block_presences.is_empty()
    }

    /// Returns the list of blocks.
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    /// Returns the list of blocks.
    pub fn block_presences(&self) -> &[BlockPresence] {
        &self.block_presences
    }

    pub fn remove_block(&mut self, i: usize) -> Block {
        self.blocks.remove(i)
    }

    /// Pops a block from the message.
    pub fn pop_block(&mut self) -> Option<Block> {
        self.blocks.pop()
    }

    pub fn wantlist(&self) -> &Wantlist {
        &self.wantlist
    }

    pub fn wantlist_mut(&mut self) -> &mut Wantlist {
        &mut self.wantlist
    }

    /// Adds a `Block` to the message.
    pub fn add_block(&mut self, block: Block) {
        self.blocks.push(block);
    }

    /// Adds a `BlockPresence` to the message.
    pub fn add_block_presence(&mut self, bp: BlockPresence) {
        self.block_presences.push(bp);
    }

    /// Turns this `Message` into a message that can be sent to a substream.
    pub fn to_bytes(&self) -> BytesMut {
        self.clone().into_bytes()
    }

    pub fn into_bytes(self) -> BytesMut {
        let mut payload = Vec::with_capacity(self.blocks.len());
        for block in self.blocks.into_iter() {
            let prefix: Prefix = block.cid().into();
            let b = pb::message::Block {
                prefix: prefix.to_bytes(),
                data: block.data,
            };
            payload.push(b);
        }

        let block_presences = self.block_presences.into_iter().map(|p| p.into()).collect();

        let proto = pb::Message {
            wantlist: if self.wantlist.is_empty() {
                None
            } else {
                Some(self.wantlist.into_pb())
            },
            payload,
            block_presences,
            blocks: Default::default(),        // unused
            pending_bytes: Default::default(), // unused
        };

        let mut res = BytesMut::with_capacity(proto.encoded_len());
        proto
            .encode(&mut res)
            .expect("there is no situation in which the protobuf message can be invalid");

        res
    }

    /// Creates a `Message` from bytes that were received from a substream.
    pub fn from_bytes<B: Buf>(bytes: B) -> Result<Self, BitswapError> {
        let proto = pb::Message::decode(bytes)?;
        let wantlist = Wantlist::from_pb(proto.wantlist)?;

        let mut blocks = Vec::with_capacity(proto.payload.len());
        for payload in proto.payload {
            let prefix = Prefix::new(&payload.prefix)?;
            let cid = prefix.to_cid(&payload.data)?;
            let block = Block {
                cid,
                data: payload.data,
            };
            blocks.push(block);
        }

        let mut block_presences = Vec::with_capacity(proto.block_presences.len());
        for bp in proto.block_presences {
            let cid = Cid::try_from(bp.cid)?;
            let entry = BlockPresence {
                cid,
                typ: bp.r#type.try_into()?,
            };
            block_presences.push(entry);
        }

        Ok(BitswapMessage {
            wantlist,
            blocks,
            block_presences,
        })
    }
}
#[cfg(test)]
mod tests {

    use super::*;
    use crate::block::tests::create_block;

    #[test]
    fn test_empty_message_to_from_bytes() {
        let message = BitswapMessage::new();
        let bytes = message.to_bytes();
        let new_message = BitswapMessage::from_bytes(bytes).unwrap();
        assert_eq!(message, new_message);
    }

    #[test]
    fn test_want_message_to_from_bytes() {
        let mut message = BitswapMessage::new();
        let block = create_block(&b"hello world"[..]);
        message.wantlist_mut().want_block(block.cid(), 1);
        let bytes = message.to_bytes();
        let new_message = BitswapMessage::from_bytes(bytes).unwrap();
        assert_eq!(message, new_message);
    }

    #[test]
    fn test_want_have_message_to_from_bytes() {
        let mut message = BitswapMessage::new();
        let block = create_block(&b"hello world"[..]);
        message.wantlist_mut().want_have_block(block.cid(), 1);
        let bytes = message.to_bytes();
        let new_message = BitswapMessage::from_bytes(bytes).unwrap();
        assert_eq!(message, new_message);
    }

    #[test]
    fn test_cancel_message_to_from_bytes() {
        let mut message = BitswapMessage::new();
        let block = create_block(&b"hello world"[..]);
        message.wantlist_mut().cancel_block(block.cid());
        let bytes = message.to_bytes();
        let new_message = BitswapMessage::from_bytes(bytes).unwrap();
        assert_eq!(message, new_message);
    }

    #[test]
    fn test_payload_message_to_from_bytes() {
        let mut message = BitswapMessage::new();
        let block = create_block(&b"hello world"[..]);
        message.add_block(block);
        let bytes = message.to_bytes();
        let new_message = BitswapMessage::from_bytes(bytes).unwrap();
        assert_eq!(message, new_message);
    }
}
