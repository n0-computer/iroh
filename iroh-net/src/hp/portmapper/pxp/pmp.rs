// 3.5.  Result Codes
pub enum ResultCode {
    Success = 0,
    UnsupportedVersion = 1,
    /// Functionality is suported but not allowerd: e.g. box supports mapping, but user has turned
    /// feature off.
    NotAuthorizedOrRefused = 2,
    /// Netfork failures, e.g. NAT box itself has not obtained a DHCP lease.
    NetworkFailure = 3,
    /// NAT box cannot create any more mappings at this time.
    OutOfResources = 4,
    UnsupportedOpcode = 5,
}
