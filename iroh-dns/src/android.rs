//! Android system DNS reader.
//!
//! Forwards to [`hickory_resolver::system_conf::read_system_conf`], which
//! reads `LinkProperties.getDnsServers()` through `ndk_context`. iroh on
//! Android therefore requires `ndk_context` to be initialized before any
//! [`DnsResolver`] is constructed, either by ndk-glue or android-activity
//! (both do this before `main`) or by an explicit
//! [`install_android_jni_context`] call.
//!
//! Without an initialized `ndk_context`, the JNI lookup panics. Debug
//! builds wrap the call in `std::panic::catch_unwind` so unit tests on
//! Android (where no JVM is in scope) fall back to the resolver's
//! default servers instead of aborting the test binary. Release builds
//! let the panic propagate; uninitialized `ndk_context` in production
//! is a programming error and should surface loudly.
//!
//! [`DnsResolver`]: crate::dns::DnsResolver

use std::ffi::c_void;

use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    net::NetError,
};

/// Reads the active network's DNS configuration via JNI.
pub(crate) fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), NetError> {
    #[cfg(debug_assertions)]
    {
        use std::panic::{AssertUnwindSafe, catch_unwind};
        match catch_unwind(AssertUnwindSafe(
            hickory_resolver::system_conf::read_system_conf,
        )) {
            Ok(Ok(conf)) => Ok(conf),
            Ok(Err(err)) => Err(NetError::from(err)),
            Err(_) => Err(NetError::Msg(
                "ndk_context not initialized; call install_android_jni_context".to_string(),
            )),
        }
    }
    #[cfg(not(debug_assertions))]
    Ok(hickory_resolver::system_conf::read_system_conf()?)
}

/// Forwards a `JavaVM` and `Application` `Context` to [`ndk_context`].
///
/// Apps that initialize `ndk_context` directly, via ndk-glue, or via
/// android-activity do not need this; double-initialization panics.
///
/// # Safety
///
/// See [`ndk_context::initialize_android_context`].
pub unsafe fn install_android_jni_context(java_vm: *mut c_void, application_context: *mut c_void) {
    unsafe {
        ndk_context::initialize_android_context(java_vm, application_context);
    }
}
