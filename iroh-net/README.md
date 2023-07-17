# iroh-net

This crate contains the networking support for iroh.  Primarily it
implements support for establishing direct peer to peer QUIC
connections using relays and holepunching using the `MagicEndpoint`
entrypoint.

Peer to peer connectivity is established with the help of a DERP
server or derper.  This server provides STUN for the peers as well as
connection coordination using the DERP protocol (Designated Relay for
Encrypted Packets protocol).  If no direct connection can be
established the connection is relayed via the DERP server.

Peers must know and do verify the PeerID of each other before they can
connect.  When using a DERP server to aid the connection establishment
they will register with a home DERP server using their PeerId.  Other
peers which can not establish a direct connection can then establish
connection via this DERP server.  This will try to assist establishing
a direct connection using STUN and holepunching but continue relaying
if not possible.

Peers can also connect directly without using a DERP server.  For this
however the listening peer must be directly reachable by the
connecting peer via one of it's addresses.


# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
