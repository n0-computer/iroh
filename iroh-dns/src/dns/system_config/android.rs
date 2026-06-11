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

use std::{
    ffi::c_void,
    net::{IpAddr, SocketAddr},
};

use jni::objects::{IntoAuto as _, JByteArray, JList, JObject, JValue};
use jni::{jni_sig, jni_str};
use tracing::{trace, warn};

use super::{DNS_PORT, DnsProtocol, SystemDnsConfig};

/// Read the active network's DNS configuration via JNI.
pub(super) fn read_system_dns() -> Result<SystemDnsConfig, std::io::Error> {
    #[cfg(debug_assertions)]
    {
        use std::panic::{AssertUnwindSafe, catch_unwind};
        match catch_unwind(AssertUnwindSafe(read_system_dns_jni)) {
            Ok(res) => res,
            Err(_) => Err(std::io::Error::other(
                "ndk_context not initialized; call install_android_jni_context",
            )),
        }
    }
    #[cfg(not(debug_assertions))]
    read_system_dns_jni()
}

/// Reads the active network's DNS servers through JNI.
fn read_system_dns_jni() -> Result<SystemDnsConfig, std::io::Error> {
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

            let mut nameservers = Vec::<(SocketAddr, DnsProtocol)>::new();
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
                nameservers.push((SocketAddr::new(ip, DNS_PORT), DnsProtocol::Udp));
            }

            trace!("Got DNS servers: {:?}", nameservers);
            Ok(nameservers)
        })
        .map_err(|e: jni::errors::Error| std::io::Error::other(e.to_string()))?;

    Ok(SystemDnsConfig {
        nameservers,
        search_domains: Vec::new(),
        ndots: None,
    })
}

/// Publishes a `JavaVM` and `Application` `Context` to [`ndk_context`] so
/// iroh's system DNS reader can use JNI.
///
/// The default [`DnsResolver`] reads DNS configuration through JNI and panics
/// if [`ndk_context`] has not been initialized. Apps that already initialize
/// the context (directly, or via ndk-glue or android-activity) do not need
/// this. Apps that don't use either glue crate must call this once at
/// process startup, before any `DnsResolver` or `Endpoint` is constructed.
///
/// Pass the `JavaVM` from `JNI_OnLoad` (or `JNIEnv::GetJavaVM`) and a JNI
/// global reference to the singleton `Application` from
/// `ActivityThread.currentApplication()`. Both pointers must remain valid
/// until the process exits.
///
/// # Safety
///
/// See [`ndk_context::initialize_android_context`].
///
/// [`DnsResolver`]: crate::dns::DnsResolver
/// [`ndk_context`]: https://docs.rs/ndk-context
pub unsafe fn install_android_jni_context(java_vm: *mut c_void, application_context: *mut c_void) {
    unsafe {
        ndk_context::initialize_android_context(java_vm, application_context);
    }
}
