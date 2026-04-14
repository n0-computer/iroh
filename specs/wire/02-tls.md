# TLS

**Version:** 1.0

Iroh uses a specific TLS 1.3 profile for endpoint authentication and encryption. This profile replaces X.509 certificate chains with Raw Public Keys.

## TLS Version

Implementations MUST use TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)). Earlier TLS versions MUST NOT be used.

## Raw Public Keys

Iroh uses the Raw Public Keys extension ([RFC 7250](https://www.rfc-editor.org/rfc/rfc7250)) instead of X.509 certificates. Each endpoint presents its Ed25519 public key directly as a SubjectPublicKeyInfo (SPKI) structure.

The SPKI encoding for an Ed25519 public key follows the standard ASN.1 DER format:

```
SEQUENCE {
  SEQUENCE {
    OBJECT IDENTIFIER 1.3.101.112 (Ed25519)
  }
  BIT STRING <32-byte public key>
}
```

This results in a 44-byte DER encoding: a 12-byte ASN.1 prefix followed by the 32-byte Ed25519 public key.

## Signature Scheme

Implementations MUST use Ed25519 as the sole signature scheme (`SignatureScheme::ED25519`). Other signature schemes MUST NOT be offered or accepted.

## Server Name Indication

The TLS ClientHello MUST include a Server Name Indication (SNI) extension containing the target Endpoint ID encoded as a DNS name in the format:

```
{BASE32-DNSSEC(endpoint_id)}.iroh.invalid
```

Where:
- `BASE32-DNSSEC` is the base32 encoding using the alphabet defined in [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) (uppercase, no padding). Specifically the "Extended Hex" variant used by DNSSEC (digits `0-9` followed by letters `A-V`).
- `endpoint_id` is the 32-byte Ed25519 public key.
- `.iroh.invalid` is a fixed suffix using a reserved TLD.

The resulting SNI name is 52 characters of base32 followed by `.iroh.invalid`.

## Peer Verification

### Initiator (Client) Verification of Responder (Server)

The initiator MUST verify the responder's identity as follows:

1. The responder's certificate MUST contain exactly one raw public key (no intermediate certificates).
2. Extract the SPKI bytes from the certificate.
3. Compare the SPKI bytes against the expected Endpoint ID (the 12-byte Ed25519 ASN.1 prefix concatenated with the 32-byte public key).
4. The connection MUST be rejected if the public key does not match the expected Endpoint ID.

### Responder (Server) Verification of Initiator (Client)

The responder MUST require client authentication. Verification is performed by the TLS library through Ed25519 signature verification during the handshake. The responder:

1. MUST verify that no intermediate certificates are present.
2. SHOULD extract the client's Endpoint ID from the verified public key and make it available to the application for authorization decisions.

## Mutual Authentication

Both sides of an iroh connection present raw public keys. Authentication is mutual: the initiator verifies the responder matches the intended Endpoint ID, and the responder verifies the initiator possesses the claimed secret key through the TLS handshake signature.

## Session Resumption

Implementations SHOULD support TLS session resumption via session tickets.

- Session ticket cache: implementations SHOULD cache up to 256 session tickets.
- 0-RTT (early data): implementations SHOULD enable 0-RTT when a valid session ticket is available.

## Certificate Chain Restrictions

Iroh connections MUST NOT include intermediate certificates. If any intermediates are present in a certificate message, the connection MUST be rejected. This ensures that only raw public keys are used for authentication.
