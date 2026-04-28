//! Android system DNS reader.
//!
//! Forwards to [`hickory_resolver::system_conf::read_system_conf`], which
//! reads `LinkProperties.getDnsServers()` through `ndk_context`. iroh on
//! Android therefore requires `ndk_context` to be initialized before any
//! [`DnsResolver`] is constructed, either by ndk-glue or android-activity
//! (both do this before `main`) or by an explicit
//! [`install_android_jni_context`] call. Without it,
//! `ndk_context::android_context()` panics at the first JNI lookup.
//!
//! [`DnsResolver`]: crate::dns::DnsResolver

use std::ffi::c_void;

use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    net::NetError,
};
use n0_error::e;

use super::SystemConfigError;

/// Reads the active network's DNS configuration via JNI.
pub(super) fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), SystemConfigError> {
    let ctx = ndk_context::android_context();
    if ctx.vm().is_null() {
        return Err(e!(SystemConfigError::PlatformUnsupported));
    }
    Ok(hickory_resolver::system_conf::read_system_conf().map_err(NetError::from)?)
}

/// Test-only workaround: publishes null `ndk_context` handles.
///
/// `ndk_context::android_context()` panics when nothing has been
/// published, so unit tests on Android (where no JVM is in scope)
/// would otherwise be unable to construct a [`DnsResolver`].
/// Publishing nulls makes the call succeed; [`read_system_conf`] then
/// detects the null `JavaVM`, returns
/// [`SystemConfigError::PlatformUnsupported`], and the resolver falls
/// back to public DNS without ever issuing a JNI call.
///
/// Production code must use [`install_android_jni_context`] or rely on
/// ndk-glue / android-activity.
#[doc(hidden)]
pub fn install_test_jni_context_stub() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: the null pointers are never dereferenced because
        // `read_system_conf` rejects a null `vm` up front.
        unsafe {
            ndk_context::initialize_android_context(std::ptr::null_mut(), std::ptr::null_mut());
        }
    });
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
    // SAFETY: forwarded to the caller via the function-level safety contract.
    unsafe {
        ndk_context::initialize_android_context(java_vm, application_context);
    }
}
