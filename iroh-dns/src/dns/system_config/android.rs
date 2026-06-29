//! Android system DNS reader.
//!
//! Android does not use `/etc/resolv.conf`. Instead the active network's DNS
//! servers are read from `LinkProperties.getDnsServers()` over JNI, going
//! through [`ndk_context`]. This requires [`ndk_context`] to be initialized
//! before any [`DnsResolver`] is constructed, either by ndk-glue or
//! android-activity (both do this before `main`) or by an explicit
//! [`install_android_jni_context`] call.
//!
//! Without an initialized [`ndk_context`] the JNI lookup panics. Debug builds
//! wrap the call in `std::panic::catch_unwind` so unit tests on Android (where
//! no JVM is in scope) fall back to the resolver's default servers instead of
//! aborting the test binary. Release builds let the panic propagate;
//! uninitialized [`ndk_context`] in production is a programming error and
//! should surface loudly.
//!
//! The JNI implementation is adapted from `hickory_resolver`.
//!
//! [`DnsResolver`]: crate::dns::DnsResolver
//! [`ndk_context`]: https://docs.rs/ndk-context

use std::ffi::c_void;
#[cfg(target_os = "android")]
use std::{
    net::{IpAddr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind},
};

#[cfg(target_os = "android")]
use jni::{
    jni_sig, jni_str,
    objects::{IntoAuto as _, JByteArray, JList, JObject, JValue},
};
#[cfg(target_os = "android")]
use tracing::{trace, warn};

#[cfg(target_os = "android")]
use super::{DNS_PORT, DnsConfig, DnsProtocol, Nameserver};

/// Read the active network's DNS configuration via JNI.
#[cfg(target_os = "android")]
pub(super) fn read_system_dns() -> Result<DnsConfig, std::io::Error> {
    match catch_unwind(AssertUnwindSafe(read_system_dns_jni)) {
        Ok(res) => res,
        Err(_) => Err(std::io::Error::other(
            "ndk_context not initialized; call install_android_jni_context",
        )),
    }
}

/// Reads the active network's DNS servers through JNI.
#[cfg(target_os = "android")]
fn read_system_dns_jni() -> Result<DnsConfig, std::io::Error> {
    let ctx = ndk_context::android_context();
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) };
    let nameservers = vm
        .attach_current_thread(|env| {
            let activity = unsafe { JObject::from_raw(env, ctx.context().cast()) };

            // https://developer.android.com/reference/android/content/Context#getSystemService(java.lang.String)
            let connectivity_service = env.new_string("connectivity")?;
            let connectivity_manager = env
                .call_method(
                    activity,
                    jni_str!("getSystemService"),
                    jni_sig!("(Ljava/lang/String;)Ljava/lang/Object;"),
                    &[JValue::Object(&connectivity_service)],
                )?
                .l()?;

            // https://developer.android.com/reference/android/net/ConnectivityManager#getActiveNetwork()
            let network = env
                .call_method(
                    &connectivity_manager,
                    jni_str!("getActiveNetwork"),
                    jni_sig!("()Landroid/net/Network;"),
                    &[],
                )?
                .l()?;

            // https://developer.android.com/reference/android/net/ConnectivityManager#getLinkProperties(android.net.Network)
            let link_properties = env
                .call_method(
                    &connectivity_manager,
                    jni_str!("getLinkProperties"),
                    jni_sig!("(Landroid/net/Network;)Landroid/net/LinkProperties;"),
                    &[JValue::Object(&network)],
                )?
                .l()?;

            // https://developer.android.com/reference/android/net/LinkProperties#getDnsServers()
            let dns_servers = env
                .call_method(
                    &link_properties,
                    jni_str!("getDnsServers"),
                    jni_sig!("()Ljava/util/List;"),
                    &[],
                )?
                .l()?;
            let dns_servers = env.cast_local::<JList<'_>>(dns_servers)?;
            let dns_servers = dns_servers.iter(env)?;

            let mut nameservers = Vec::<Nameserver>::new();
            while let Some(server) = dns_servers.next(env)? {
                let server = server.auto();

                // https://developer.android.com/reference/java/net/InetAddress#getAddress()
                let ip_bytes_obj = env
                    .call_method(&server, jni_str!("getAddress"), jni_sig!("()[B"), &[])?
                    .l()?;
                let ip_bytes_arr = env.cast_local::<JByteArray<'_>>(ip_bytes_obj)?;
                let ip_bytes = env.convert_byte_array(ip_bytes_arr)?;

                let ip = match ip_bytes.len() {
                    4 => {
                        let mut arr = [0u8; 4];
                        arr.copy_from_slice(&ip_bytes);
                        IpAddr::from(arr)
                    }
                    16 => {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&ip_bytes);
                        IpAddr::from(arr)
                    }
                    _ => {
                        warn!("Got invalid ip length: {}. Skipping.", ip_bytes.len());
                        continue;
                    }
                };
                nameservers.push(Nameserver::new(
                    SocketAddr::new(ip, DNS_PORT),
                    DnsProtocol::Udp,
                ));
            }

            trace!("Got DNS servers: {:?}", nameservers);
            Ok(nameservers)
        })
        .map_err(|e: jni::errors::Error| std::io::Error::other(e.to_string()))?;

    Ok(DnsConfig {
        nameservers,
        search_domains: Vec::new(),
        ndots: None,
    })
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
pub unsafe fn install_android_jni_context(java_vm: *mut c_void, application_context: *mut c_void) {
    unsafe {
        ndk_context::initialize_android_context(java_vm, application_context);
    }
}
