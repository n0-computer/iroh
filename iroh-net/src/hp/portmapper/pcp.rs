
/// NAT-PMP/PCP Version
pub enum Version {
    /// NAT-PMP Version according to [RFC 6886 1.1 Transition to Port Control Protocol][rfc6886s11]
    /// [rfc6886s11]: https://datatracker.ietf.org/doc/html/rfc6886#section-1.1
    // Version 0
    NatPmp,
    /// PCP Version according to [RFC 6887 9. Version Negotiation][rfc6887s9]
    /// [rfc6887s9]: https://datatracker.ietf.org/doc/html/rfc6887#section-9
    // Version 2
    Pcp,
}

// PCP and NAT-PMP share same ports, reasigned by IANA from the older version to the new one. See
// <https://datatracker.ietf.org/doc/html/rfc6886#section-3.2.1>

/// Port to use when acting as a client. This is the one we bind to.
// TODO(@divma): remember
// > Clients should therefore bind specifically to 224.0.0.1:5350, not to 0.0.0.0:5350.
pub const CLIENT_PORT: u16 = 5350;

/// Port to use when acting as a server. This is the one we direct requests to.
pub const SERVER_PORT: u16 = 5351;
