use crate::get::get_response_machine::*;
use crate::Hash;
use iroh_net::tls::PeerId;
use std::collections::BTreeMap;

enum PerPeerFsm {
    Disconnected,
    AtInitial(AtInitial),
    AtConnected(AtConnected),
    AtStartChild(AtStartChild),
    AtStartRoot(AtStartRoot),
    AtBlobHeader(AtBlobHeader),
    AtBlobContent(AtBlobContent),
    AtEndBlob(AtEndBlob),
    AtClosing(AtClosing),
    Busy,
}

impl PerPeerFsm {
    fn take(&mut self) -> Self {
        std::mem::replace(self, PerPeerFsm::Busy)
    }
}

struct DownloadState {
    downloads: BTreeMap<PeerId, PerPeerFsm>,
}

struct DownloadManager {
    current: BTreeMap<Hash, DownloadState>,
}
