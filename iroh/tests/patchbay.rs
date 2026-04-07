#![cfg(all(target_os = "linux", not(skip_patchbay)))]

#[path = "patchbay/nat.rs"]
mod nat;
#[path = "patchbay/util.rs"]
mod util;

/// Init the user namespace before any threads are spawned.
///
/// This gives us all permissions we need for the patchbay tests.
#[ctor::ctor]
fn userns_ctor() {
    patchbay::init_userns().expect("failed to init userns");
}
