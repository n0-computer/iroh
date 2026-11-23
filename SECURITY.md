# Security considerations for iroh

This document documents some security considerations for iroh. It
exists to help understand how to think about iroh security. It is not
currently a threat model for iroh, and it is a work in progress.

Not that this is **not** a description of how iroh works. Do not read
descriptions here in that sense. Often some subset of behaviour or a
special case is called out, rather than a comprehensive explanation of
iroh's designk.

Neither is this a description of how number 0 or anyone else operates
any infrastructure. It exists to understand what the technical
boundaries are.

## Relay Servers

Iroh uses relay servers to establish connectivity with other peers
that are otherwise unreachable. Two kinds of relay servers are
involved in establishing connections:

- The home relay. This is the relay server on which an iroh endpoint
  will be listening for incoming connections.

- Dialling relays. These are the home relay servers of peers that are
  being dialled.

### Blind relays

Relay servers are considered "blind" as they only see encrypted
traffic. However, they could obtain the following information:

- Each connected EndpointId is known as each iroh endpoint
  authenticates using this.
  
- The IP address of each connected endpoint is known to the relay
  server. It is never shared with any other peers that are connected
  to the relay server.
  
- Datagrams are routed by the relay server based on the destination
  EndpointId. This means the relay server has an idea of flows of
  traffic between connected endpoints.
  
- As the first packet of a QUIC connection is readable by anyone on
  the network path, so can the relay server. Thus it can:
  
  - Detect connection handshakes.
  - Read the client's ClientHello frame, containing at least:
    - The ALPN
    - Client QUIC transport parameters.
    
### Relay manipulation

Based on what relay servers know about endpoints and the observed
traffic they can manipulate traffic to some extend. Most notably relay
servers can block or degrade traffic between all or some connected
endpoints.

To do manipulate the traffic between two endpoints a relay server
needs to be on the path between the two endpoints. Thus the selected
home relay is important as it can disrupt all incoming
connections. The relay servers considered for home relay come from an
explicitly configured set of candidates in the RelayMap, and
connections to them are protected with TLS certificates by default.
