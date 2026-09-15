# Experimental identity encoding and authentication

The `unstable-identity` feature exposes an additive `iroh::identity` API on
native targets. Existing `iroh::Endpoint`, `EndpointId`, `PublicKey`, and legacy
wire formats retain their contracts. New IDs and the new API are unstable.

See the [implementation guide](identity-implementation.md) for API integration
and current limitations.

## Run and verify

```sh
cargo run -p iroh --features unstable-identity --example pluggable-identity --locked
cargo test -p iroh --features unstable-identity --locked \
  --test identity
```

The example binds two loopback IP sockets, mutually authenticates using ML-DSA-65,
prints their IDs, and transfers a message. Its elapsed time is a smoke measurement,
not a benchmark. Tests cover both algorithms, identity pinning, malformed inputs,
policy rejection, invalid signatures, endpoint lifecycle, and interoperability
with the existing `iroh::Endpoint` API in both directions.

## Prototype encoding, version 1

All numbers here are experimental assignments. IDs carry an explicit prototype
prefix; do not distribute these as production iroh identities. The format is
fixed for this experimental API. A change to its meaning requires a new version.

### Identity commitment

For new identities, compute:

```text
SHA-384(
    ASCII("iroh identity prototype v1") || 0x00 ||
    0x01 || suite_u16_be || key_length_u32_be || canonical_raw_public_key
)
```

SHA-384 produces 48 bytes. The extra size avoids inheriting a digest size purely
from the old relay frame. A production security review must establish the
commitment security target and hash choice; this experimental API does not establish a
security level for the full system.

The built-in suite assignments are:

| Suite | Key representation | Signature |
| --- | --- | --- |
| 1 | Existing validated 32-byte Ed25519 key | Existing strict Ed25519 verification |
| 2 | 1952 raw ML-DSA-65 public-key bytes | 3309-byte ML-DSA-65 signature |

Suite 1 retains the public key itself as its legacy ID. It does not hash the key.
Suite 2 derives a new identity commitment. Location information and private key
material do not enter the commitment. Key or suite changes produce a new ID.

During TLS, the public key is carried in canonical DER SubjectPublicKeyInfo
(SPKI), as a raw public key rather than an X.509 certificate. The adapter checks
the exact algorithm identifier, key length, and canonical DER before deriving
the ID. This experimental API does not transmit a separate identity-document envelope:
the registered TLS adapter determines the suite and canonical key bytes.

### New ID envelope

| Identity | Complete binary encoding |
| --- | --- |
| Legacy | `0x00 || 32-byte Ed25519 key` |
| V1 commitment | `0x01 || 0x01 || 48-byte digest` |

The first new-ID byte is the identity version; the next byte selects SHA-384.
Only exact lengths are accepted. Unknown versions and commitment suites fail.
The legacy envelope tag exists only in the new API; existing legacy serialization
remains the original untagged bytes.

Legacy text display and parsing use the existing iroh key implementation. A new
ID is `iroh-pid1-` followed by lowercase hex of its entire 50-byte envelope.
The new parser accepts neither uppercase hex nor trailing data for this format.

For suite 2 with 1952 zero key bytes, the commitment is:

```text
b5eae4b113a1d2556cdf07cf7c0e34d6c7bb2052f1d97e5e8cce6be3b201f8eef116388069ec74903bcfeaebda80d8fc
```

This independently computed test vector exercises encoding; it is not an
authentication fixture or a generated key pair.

## Extension points and policy

- `IdentityAlgorithm` supplies the suite number, TLS signature scheme,
  canonical key parser, and verifier. Implementations are trusted code.
- `Registry::new` installs adapters and a separate remote-peer suite allowlist. Duplicate
  suite numbers and duplicate TLS signature schemes fail registration. Ambiguous
  public-key parsing also fails. Supporting several identity suites under one TLS
  signature scheme requires further protocol design.
- `LocalIdentity::new` takes `Arc<dyn rustls::sign::SigningKey>`. A supplied signer
  need not export or serialize its private key. The convenience ML-DSA generator
  imports an in-memory PKCS#8 key into rustls; that is not a requirement imposed
  on custom signers.
- `IdentityEndpoint::connect(EndpointAddr::new(id, addr), alpn)` verifies the exact remote ID.
  No error initiates an attempt with another identity or algorithm.
- `IdentityEndpoint::accept()` completes client authentication before returning
  the remote ID. Handshakes are verified concurrently on background tasks, so one
  unresponsive peer never delays another. Applications still decide whether that
  ID is authorized.

Both peers must agree on suite assignments and TLS signature schemes. A plugin
cannot make a peer understand an algorithm it does not implement. Suite 1 and
the Ed25519 TLS signature scheme are reserved for legacy semantics.

Local credentials can use any registered adapter, independently of the remote
allowlist. For example, `Registry::builtins(vec![2])` accepts only ML-DSA-65 peers,
while still allowing `LocalIdentity::ed25519(old_key, &registry)` as the local
credential. The reverse arrangement is also possible: a local PQ credential with
`Registry::builtins(vec![1])` accepts only Ed25519 peers. Neither arrangement makes
both sides of the connection PQ-authenticated; each endpoint controls which
remote signatures it accepts.

This separation applies both when constructing an identity and when binding it
to an endpoint. The endpoint registry must still contain the local adapter and
derive the same identity. Registering or selecting a local credential never adds
its suite to the remote allowlist. The remote checks in `Registry::identify`, TLS
signature verification, and `Connection::remote_id()` extraction retain that
allowlist. Exact identity pinning is unchanged.

TLS can complete on the client before it learns that the server rejected its
client credential; server acceptance is the authoritative result of client
authentication. [Policy tests](../tests/identity/policy.rs) cover mixed credentials
in both directions and ensure that a local suite does not become remotely allowed.

## Integrated endpoint behavior

The normal `Endpoint::builder(Empty).credentials(identity, registry)` method
returns a typed builder. It preserves IP bindings, relay configuration, ALPNs,
transport settings, CA trust and the crypto provider. `remote_policy` can further
restrict the remote suites and exact peer IDs independently of local credentials.
Legacy `Endpoint::builder(...).secret_key(...)` remains unchanged.

The typed transport stores full `(PeerId, RelayUrl)` routing keys. Synthetic IPv6
addresses are internal QUIC handles, never surrogate Ed25519 identities. Relays
explicitly enable `/relay/identity-v1` and `iroh-identity-relay/1`; registration
proves possession over a fresh, URL-bound challenge. Legacy `/relay` is unchanged.
A PQ deployment requires relays supporting this new protocol. Existing public
relays are not automatically upgraded by this feature.

Supply the expected identity and its direct or relay locations in `EndpointAddr`.
Signed-contact lookup and publication are deferred to a separate contribution.

QUIC address discovery uses the same UDP sockets and configured relay QAD ports.
NAT traversal exchanges candidates inside the authenticated QUIC connection.
A validated direct path becomes available while the relay remains a backup.
Unsupported address-family probes are dropped rather than closing the connection.
The Linux namespace test covers two port-restricted NATs.

Endpoint clones share their runtime. Connections retain it after endpoint handles
are dropped. Path tasks hold only weak connection handles, so dropping the last
`Connection` closes it implicitly. `close().await` drains QUIC and cancels
managed relay, QAD and path tasks. Relay reconnects retain the credential and
never fall back to Ed25519. Relay and QAD HTTPS use the builder's
crypto provider.

Keys use the versioned `IRID` encoding; Ed25519 retains its raw 32-byte secret,
ML-DSA-65 stores PKCS#8, and custom signers may be non-exportable. Unix key files
are created with mode 0600 and never overwritten. `TrustStore::migrate` explicitly
compares the old pin and replaces it with an application-approved new identity;
network observations cannot change trust.

Resumption, early data and SNI are disabled. SPKI is capped at 8192 bytes and
signatures at 16384 bytes, with exact built-in lengths checked. Rustls 0.23.44 or
later supplies ML-DSA integration. Released-version interoperability is exercised
against the separately built iroh 1.1.0 peer with rustls 0.23.41.

See the [test guide](../tests/identity/README.md) for commands to run the identity,
released-version interoperability, and NAT traversal tests.
