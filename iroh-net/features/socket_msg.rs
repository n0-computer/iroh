// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Detects platform capability of:
//! * https://linux.die.net/man/2/sendmsg
//! * https://linux.die.net/man/2/recvmsg

fn main() {
    println!("sendmsg {:?}", unsafe { SENDMSG });
    println!("recvmsg {:?}", unsafe { RECVMSG });
}

/// Try to resolve the required references from the linker
///
/// The build will fail if they don't exist.
#[cfg(all(unix, feature = "std"))]
extern "C" {
    #[link_name = "sendmsg"]
    static SENDMSG: *const u8;
    #[link_name = "recvmsg"]
    static RECVMSG: *const u8;
}
