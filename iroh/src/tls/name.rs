//! Implementation of encoding iroh NodeIds as domain names.
//!
//! We used to use a constant "localhost" for the TLS server name - however, that affects
//! 0-RTT and would put all of the TLS session tickets we receive into the same bucket in
//! the TLS session ticket cache.
//! So we choose something that'd dependent on the NodeId.
//! We cannot use hex to encode the NodeId, as that'd encode to 64 characters, but we only
//! have 63 maximum per DNS subdomain. Base32 is the next best alternative.
//! We use the `.invalid` TLD, as that's specified (in RFC 2606) to never actually resolve
//! "for real", unlike `.localhost` which is allowed to resolve to `127.0.0.1`.
//! We also add "iroh" as a subdomain, although those 5 bytes might not be necessary.
//! We *could* decide to remove that indicator in the future likely without breakage.

use data_encoding::BASE32_DNSSEC;
use iroh_base::NodeId;

pub(crate) fn encode(node_id: NodeId) -> String {
    format!("{}.iroh.invalid", BASE32_DNSSEC.encode(node_id.as_bytes()))
}

pub(crate) fn decode(name: &str) -> Option<NodeId> {
    let [base32_node_id, "iroh", "invalid"] = name.split(".").collect::<Vec<_>>()[..] else {
        return None;
    };
    NodeId::from_bytes(
        &BASE32_DNSSEC
            .decode(base32_node_id.as_bytes())
            .ok()?
            .try_into()
            .ok()?,
    )
    .ok()
}
