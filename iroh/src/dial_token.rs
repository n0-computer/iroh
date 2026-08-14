//! Dial tokens: proof of endpoint id knowledge in the initial DCID.
//!
//! A dialer that knows the remote's [`EndpointId`] encodes a MAC keyed on it
//! into the client-chosen destination connection id of its first Initial
//! packet: `nonce(8) || MAC(endpoint_id, nonce)(12)`. An endpoint with
//! [`crate::endpoint::Builder::require_endpoint_id_knowledge`] set verifies
//! the token before doing any handshake work and silently ignores connection
//! attempts without a valid one, making it indistinguishable from a closed
//! port to anyone who merely knows its address.
//!
//! To anyone who does not know the endpoint id, a token is indistinguishable
//! from the random DCID every QUIC client sends, so dialers always send
//! tokens: this is invisible to endpoints that don't require them.
//!
//! The 8 byte nonce keeps the DCID as unpredictable to endpoint id holders as
//! a standard 8 byte random DCID (off-path injection resistance per RFC 9000
//! section 7.2); to anyone else all 20 bytes are unpredictable.

use iroh_base::EndpointId;

/// Domain separation for the token MAC key. A wire-format constant.
const KEY_DOMAIN: &str = "iroh dial token v1";

const NONCE_LEN: usize = 8;
const MAC_LEN: usize = 12;
/// Total token length: the maximum QUIC connection id size.
const TOKEN_LEN: usize = NONCE_LEN + MAC_LEN;

fn mac(endpoint_id: &EndpointId, nonce: &[u8]) -> [u8; MAC_LEN] {
    let key = blake3::derive_key(KEY_DOMAIN, endpoint_id.as_bytes());
    let hash = blake3::keyed_hash(&key, nonce);
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&hash.as_bytes()[..MAC_LEN]);
    out
}

/// Generates a fresh dial token for dialing the given remote endpoint.
pub(crate) fn generate(remote: &EndpointId) -> [u8; TOKEN_LEN] {
    let nonce: [u8; NONCE_LEN] = rand::random();
    let mut token = [0u8; TOKEN_LEN];
    token[..NONCE_LEN].copy_from_slice(&nonce);
    token[NONCE_LEN..].copy_from_slice(&mac(remote, &nonce));
    token
}

/// Verifies a dial token against our own endpoint id.
pub(crate) fn verify(local: &EndpointId, dcid: &[u8]) -> bool {
    if dcid.len() != TOKEN_LEN {
        return false;
    }
    let expected = mac(local, &dcid[..NONCE_LEN]);
    // Constant-time comparison: don't leak matching MAC prefixes via timing.
    dcid[NONCE_LEN..]
        .iter()
        .zip(expected.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;

    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let id = SecretKey::from_bytes(&[1u8; 32]).public();
        let other = SecretKey::from_bytes(&[2u8; 32]).public();

        let token = generate(&id);
        assert!(verify(&id, &token));
        // Wrong endpoint id, tampered MAC, tampered nonce, wrong length.
        assert!(!verify(&other, &token));
        let mut bad = token;
        bad[TOKEN_LEN - 1] ^= 1;
        assert!(!verify(&id, &bad));
        let mut bad = token;
        bad[0] ^= 1;
        assert!(!verify(&id, &bad));
        assert!(!verify(&id, &token[..TOKEN_LEN - 1]));

        // Fresh nonce every time.
        assert_ne!(generate(&id), generate(&id));
    }
}
