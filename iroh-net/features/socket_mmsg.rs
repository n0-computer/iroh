// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Detects platform capability of:
//! * https://linux.die.net/man/2/sendmmsg
//! * https://linux.die.net/man/2/recvmmsg

fn main() {
    println!("sendmmsg {:?}", unsafe { SENDMMSG });
    println!("recvmmsg {:?}", unsafe { RECVMMSG });
}

/// Try to resolve the required references from the linker
///
/// The build will fail if they don't exist.
#[cfg(all(unix, feature = "std"))]
extern "C" {
    #[link_name = "sendmmsg"]
    static SENDMMSG: *const u8;
    #[link_name = "recvmmsg"]
    static RECVMMSG: *const u8;
}
