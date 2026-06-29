//! Android system DNS reader.
//!
//! Forwards to [`hickory_resolver::system_conf::read_system_conf`], which
//! reads `LinkProperties.getDnsServers()` through [`ndk_context`]. iroh on
//! Android therefore requires [`ndk_context`] to be initialized before any
//! [`DnsResolver`] is constructed, either by ndk-glue or android-activity
//! (both do this before `main`) or by an explicit
//! [`install_android_jni_context`] call.
//!
//! Without an initialized [`ndk_context`], the JNI lookup panics internally.
//! We catch the panic via [`catch_unwind`] and convert the panic into a regular
//! error, which will then make the [`DnsResolver`] use fallback nameservers.
//!
//! This depends on panic unwinding though, so if you set `panic = abort` in
//! your compilation profile, and don't install the JNI context, your app
//! would panic and abort on the first DNS lookup.
//!
//! [`DnsResolver`]: crate::dns::DnsResolver
//! [`ndk_context`]: https://docs.rs/ndk-context
//! [`catch_unwind`]: std::panic::catch_unwind

use std::{
    ffi::c_void,
    panic::{AssertUnwindSafe, catch_unwind},
};

use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    net::NetError,
};

/// Reads the active network's DNS configuration via JNI.
pub(crate) fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), NetError> {
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

/// Exposes a JVM to iroh so that we can read the system's DNS configuration.
///
/// This calls [`ndk_context::initialize_android_context`] to expose a
/// `JavaVM` and Application Context to Rust code so that we can use JNI.
/// This is required to get the configured nameservers on Android.
///
/// If this function is not called, fetching the configured nameservers will fail
/// and the default [`DnsResolver`] will use fallback nameservers instead.
///
/// If you call [`ndk_context::initialize_android_context`] already somewhere
/// up the stack in your app, or use a crate like `ndk-glue` or `android-activity`
/// that do this for you, then there's no need to call this function.
///
/// If you don't use a glue crate, a typical way to initialize the context is
/// via `JNI_OnLoad`:
///
/// *Note: `install_android_jni_context` is reexported from `iroh`, so you can substitute
/// `iroh_dns` for `iroh` below.*
///
/// ```ignore
/// #[cfg(target_os = "android")]
/// #[no_mangle]
/// pub extern "C" fn JNI_OnLoad(
///     vm: jni::JavaVM,
///     res: *mut std::os::raw::c_void,
/// ) -> jni::sys::jint {
///     use std::ffi::c_void;
///
///     let vm = vm.get_java_vm_pointer() as *mut c_void;
///     unsafe {
///         iroh_dns::install_android_jni_context(vm, res);
///     }
///     jni::JNIVersion::V6.into()
/// }
/// ```
///
/// # Safety
///
/// Both the `java_vm` and `context_jobject` pointers must remain valid until the process exits.
/// See also [`ndk_context::initialize_android_context`].
///
/// [`DnsResolver`]: crate::dns::DnsResolver
/// [`ndk_context`]: https://docs.rs/ndk-context
/// [`ndk_context::initialize_android_context`]: https://docs.rs/ndk-context/latest/ndk_context/fn.initialize_android_context.html
pub unsafe fn install_android_jni_context(java_vm: *mut c_void, context_jobject: *mut c_void) {
    unsafe {
        ndk_context::initialize_android_context(java_vm, context_jobject);
    }
}
