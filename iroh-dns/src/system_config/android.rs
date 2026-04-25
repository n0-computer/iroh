//! Reads the Android system DNS configuration via JNI.
//!
//! This module is the opt-in path enabled by
//! [`install_android_jni_context`]. Without that call, the parent
//! module returns [`super::SystemConfigError::PlatformUnsupported`] and
//! the resolver falls back to the public DNS list.
//!
//! Why we ship our own JNI reader instead of relying on
//! `hickory-resolver`'s `system_conf::android`:
//!
//! - Hickory dereferences `ndk_context::android_context()` with
//!   `.expect()`, panicking when no consumer has initialized the
//!   context. We detect that case explicitly and return an error.
//! - Hickory does not filter unreachable servers. The most painful
//!   case in production is iPhone Personal Hotspot tethering, which
//!   advertises a link-local IPv6 address (often `fe80::1`) as the
//!   network's DNS server. A connected UDP socket cannot route to a
//!   link-local address without a scope ID we do not carry, so the
//!   query times out. We drop those entries here.

use std::{ffi::c_void, net::IpAddr, sync::OnceLock};

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use jni::{
    JavaVM, jni_sig, jni_str,
    objects::{IntoAuto as _, JByteArray, JList, JObject, JValue},
    sys::jobject,
};
use n0_error::{anyerr, e};
use tracing::{trace, warn};

use super::{SystemConfigError, is_usable_nameserver};

/// Holds the JavaVM and Application Context jobject installed by the
/// consumer.
///
/// Both fields are raw pointers obtained from JNI. They must remain
/// valid for the lifetime of the process. The struct is `Send + Sync`
/// because the underlying handles are thread-safe per JNI rules: the
/// JavaVM is shared across threads and a global `Context` reference
/// is too. The pointers are not dereferenced outside JNI calls.
struct JniContext {
    java_vm: *mut c_void,
    context_jobject: *mut c_void,
}

// SAFETY: A `JavaVM` pointer is intended to be shared across threads
// per the JNI spec. The `context_jobject` is expected to be a global
// reference, which is also thread-safe to share.
unsafe impl Send for JniContext {}
unsafe impl Sync for JniContext {}

static JNI_CONTEXT: OnceLock<JniContext> = OnceLock::new();

/// Installs the Android JNI handles used by [`super::read_system_conf`].
///
/// Call this from your library's `JNI_OnLoad` (or otherwise before
/// any iroh component is created) when you want the resolver to honor
/// the device's per-network DNS configuration. Without this call, the
/// resolver uses its built-in public DNS fallback (Cloudflare and
/// Google) and never touches JNI.
///
/// `java_vm` must be a valid [`JavaVM`] pointer; `application_context`
/// must be a valid [`jobject`] pointing to an
/// [`android.content.Context`]. The cleanest source for the context
/// is `ActivityThread.currentApplication()`. Both pointers must
/// outlive the process; promote a local reference to a global
/// reference (see `JNIEnv::new_global_ref`) before forgetting it.
///
/// Calling this more than once is a no-op: the first call wins. This
/// matches the JVM lifecycle, which only loads each `.so` once.
///
/// # Safety
///
/// The caller must guarantee that:
///
/// - `java_vm` is a valid `*mut JavaVM` for the running JVM.
/// - `application_context` is a valid global reference to an
///   `android.content.Context`.
/// - Both remain valid until the process exits.
///
/// Violating any of these invariants leads to undefined behavior the
/// next time the resolver attempts to read system DNS.
///
/// [`JavaVM`]: https://docs.oracle.com/en/java/javase/21/docs/specs/jni/invocation.html#javavm
/// [`jobject`]: https://docs.rs/jni/latest/jni/sys/type.jobject.html
/// [`android.content.Context`]: https://developer.android.com/reference/android/content/Context
pub unsafe fn install_android_jni_context(java_vm: *mut c_void, application_context: *mut c_void) {
    let _ = JNI_CONTEXT.set(JniContext {
        java_vm,
        context_jobject: application_context,
    });
}

/// Reads the system DNS configuration through the consumer-supplied
/// JNI context.
///
/// Returns [`SystemConfigError::PlatformUnsupported`] when no JNI
/// context has been installed. Returns
/// [`SystemConfigError::Hickory`] (despite the name) when the JNI
/// calls themselves fail; the error wraps the underlying JNI error
/// for diagnostics.
pub(super) fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), SystemConfigError> {
    let ctx = JNI_CONTEXT
        .get()
        .ok_or_else(|| e!(SystemConfigError::PlatformUnsupported))?;

    let nameservers =
        read_dns_servers(ctx).map_err(|err| e!(SystemConfigError::Hickory, anyerr!(err)))?;

    let mut config = ResolverConfig::default();
    for ip in nameservers {
        if !is_usable_nameserver(ip) {
            trace!(?ip, "skipping unusable system DNS server");
            continue;
        }
        config.add_name_server(NameServerConfig::udp_and_tcp(ip));
    }
    Ok((config, ResolverOpts::default()))
}

/// Performs the JNI calls that read the active network's DNS server list.
///
/// Mirrors `hickory-resolver`'s Android `read_system_conf`, but with
/// structured errors instead of `expect()` panics, an opt-in install
/// path that does not depend on `ndk-context`, and link-local
/// filtering applied by the caller.
fn read_dns_servers(ctx: &JniContext) -> Result<Vec<IpAddr>, jni::errors::Error> {
    // SAFETY: ctx.java_vm is a JavaVM pointer that the consumer
    // guarantees is valid for the process lifetime via the
    // install_android_jni_context contract.
    let vm = unsafe { JavaVM::from_raw(ctx.java_vm.cast()) };
    vm.attach_current_thread(|env| {
        // SAFETY: ctx.context_jobject is a global Context reference
        // that the consumer guarantees is valid for the process
        // lifetime via the install_android_jni_context contract.
        let activity = unsafe { JObject::from_raw(env, ctx.context_jobject as jobject) };

        let connectivity_service = env.new_string("connectivity")?;
        let connectivity_manager = env
            .call_method(
                activity,
                jni_str!("getSystemService"),
                jni_sig!("(Ljava/lang/String;)Ljava/lang/Object;"),
                &[JValue::Object(&connectivity_service)],
            )?
            .l()?;

        let network = env
            .call_method(
                &connectivity_manager,
                jni_str!("getActiveNetwork"),
                jni_sig!("()Landroid/net/Network;"),
                &[],
            )?
            .l()?;

        let link_properties = env
            .call_method(
                &connectivity_manager,
                jni_str!("getLinkProperties"),
                jni_sig!("(Landroid/net/Network;)Landroid/net/LinkProperties;"),
                &[JValue::Object(&network)],
            )?
            .l()?;

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

        let mut out = Vec::new();
        while let Some(server) = dns_servers.next(env)? {
            let server = server.auto();
            let ip_bytes_obj = env
                .call_method(&server, jni_str!("getAddress"), jni_sig!("()[B"), &[])?
                .l()?;
            let ip_bytes_arr = env.cast_local::<JByteArray<'_>>(ip_bytes_obj)?;
            let bytes = env.convert_byte_array(ip_bytes_arr)?;
            match bytes.len() {
                4 => {
                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(&bytes);
                    out.push(IpAddr::from(arr));
                }
                16 => {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(&bytes);
                    out.push(IpAddr::from(arr));
                }
                other => {
                    warn!(
                        len = other,
                        "skipping DNS server with invalid InetAddress length",
                    );
                }
            }
        }

        trace!(servers = ?out, "read system DNS via JNI");
        Ok(out)
    })
}
