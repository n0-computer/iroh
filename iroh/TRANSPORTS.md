This table contains a mapping from custom address id to the transport type.

If you want to publish a globally available custom transport, choose an id and do a PR against this repo.



| transport id | transport | address format | repo | status |
|--------------|-----------|----------------|------|--------|
| 0x544F52     | Tor       | Ed25519 public key (32 bytes) | [iroh-tor](https://github.com/n0-computer/iroh-tor) | experimental |
| 0x424C45     | BLE       | Bluetooth MAC address (6 bytes) | | reserved |
