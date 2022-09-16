use cid::Cid;
use libp2p::PeerId;

use crate::{
    client::wantlist::{Entry, Wantlist},
    message::{Priority, WantType},
};

/// Tracks the wantlist for a given partner
#[derive(Debug)]
pub struct Ledger {
    /// The remote peer.
    partner: PeerId,
    wantlist: Wantlist,
}

impl Ledger {
    pub fn wants(&mut self, cid: Cid, priority: Priority, want_type: WantType) {
        self.wantlist.add(cid, priority, want_type);
    }

    pub fn cancel_want(&mut self, cid: &Cid) -> Option<Entry> {
        self.wantlist.remove(cid)
    }

    pub fn wantlist_get(&self, cid: &Cid) -> Option<&Entry> {
        self.wantlist.get(cid)
    }

    pub fn entries(&mut self) -> impl Iterator<Item = Entry> + '_ {
        self.wantlist.entries()
    }
}
