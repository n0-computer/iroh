# Iroh Net Report

`iroh-net-report` is a tool for generating detailed reports on network
connectivity and configuration on the current host for nodes powered by [iroh].
`iroh-net-report` evaluates key aspects of network performance and behavior,
including NAT traversal capabilities, protocol availability, and relay server
latencies. Key features include:

- **STUN diagnostics**

  Evaluates the completion of UDP STUN round trips for both IPv4 and IPv6.
  Determine the variability of STUN results based on the destination server.
  This helps understand the type of NAT for this host's network.

- **IPv4 and IPv6 connectivity checks**

  Verifies basic connectivity for IPv4 and IPv6, including the ability to bind
  sockets and send packets.

- **ICMP diagnostics**

  Performs ICMP round trips for IPv4 and IPv6 to assess reachability.

- **Hair-Pinning detection**

  Determines whether the router supports hair-pinning, enabling communication
  between devices on the same NATed network via their public IP.

- **Port Mapping protocol support**

  Detects the presence of port mapping protocols like UPnP, PCP, or NAT-PMP for
  enhanced NAT traversal.

- **Relay Server Latencies**

  Measures latency for the configured relay servers, keeping details about
  IPv4-specific, and IPv6-specific measurements.

- **Global IP Address Discovery**

  Identifies the public (global) IPv4 and IPv6 addresses for the host.

- **Captive Portal Detection**

  Identifies if the network is using a captive portal to intercept HTTP
  traffic.

- **Preferred Relay Identification**

  Detect the best relay server for use.

Used in [iroh], created with love by the [n0 team](https://n0.computer/).

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

[iroh]: https://github.com/n0-computer/iroh
