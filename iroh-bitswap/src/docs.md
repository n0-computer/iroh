

## Client Architecture

- `Client`
  - `PeerManager`
    - Per Peer: `MessageQueue`
    - `PeerWantManager`
    - `Network`
  - `ProviderQueryManager`
  - `Network`
  - `Store`
  - `SessionManager`
     - Per Session: `Session`
      - `SessionPeerManager`
      - `SessionWantSender`
        - `PeerManger`
        - `SessionPeerManager`
        - `SessionManager`
        - `BlockPresenceManager`
    - `SessionInterestManager`
    - `BlockPresenceManager`
    - `PeerManager`
    - `ProviderQueryManager`
    - `Network`

