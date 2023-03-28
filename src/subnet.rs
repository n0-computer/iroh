//! Same subnet logic.
//!
//! Tiny module because left/right shifting confuses emacs' rust-mode.  So sad.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Checks if both addresses are on the same subnet given the `prefix_len`.
pub(crate) fn same_subnet_v4(addr_a: Ipv4Addr, addr_b: Ipv4Addr, prefix_len: u8) -> bool {
    let mask = u32::MAX << (32 - prefix_len);
    let a = u32::from(addr_a) & mask;
    let b = u32::from(addr_b) & mask;
    a == b
}

pub(crate) fn same_subnet_v6(addr_a: Ipv6Addr, addr_b: Ipv6Addr, prefix_len: u8) -> bool {
    let mask = u128::MAX << (128 - prefix_len);
    let a = u128::from(addr_a) & mask;
    let b = u128::from(addr_b) & mask;
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_subnet_v4() {
        let a = Ipv4Addr::new(192, 168, 0, 5);
        let b = Ipv4Addr::new(192, 168, 1, 6);
        assert!(!same_subnet_v4(a, b, 24));
        assert!(same_subnet_v4(a, b, 16));
    }

    #[test]
    fn test_same_subnet_v6() {
        let a = Ipv6Addr::new(0xfd56, 0x5799, 0xd8f6, 0x3cc, 0x0, 0x0, 0x0, 0x1);
        let b = Ipv6Addr::new(0xfd56, 0x5799, 0xd8f6, 0x3cd, 0x0, 0x0, 0x0, 0x2);
        assert!(!same_subnet_v6(a, b, 64));
        assert!(same_subnet_v6(a, b, 48));
    }
}
