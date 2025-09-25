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

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;

    #[test]
    fn test_roundtrip() {
        let key = SecretKey::generate(rand::rng());
        let node_id = key.public();
        println!("{}", super::encode(node_id));
        assert_eq!(Some(node_id), super::decode(&super::encode(node_id)));
    }

    #[test]
    fn test_snapshot() {
        let key = SecretKey::from_bytes(&[0; 32]);
        assert_eq!(
            super::encode(key.public()),
            "7dl2ff6emqi2qol3l382krodedij45bn3nh479hqo14a32qpr8kg.iroh.invalid",
        );
    }
}
