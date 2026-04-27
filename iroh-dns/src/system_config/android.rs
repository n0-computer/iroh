//! Reader for Android's system DNS configuration via JNI.
//!
//! [`install_android_jni_context`] is the opt-in entry point: a
//! caller that wants the device's per-network DNS supplies the
//! `JavaVM` and the `Application` `Context` here, and subsequent
//! [`super::read_system_conf`] calls query
//! `LinkProperties.getDnsServers()` for the active network.
//!
//! This is a small reimplementation of `hickory-resolver`'s Android
//! `system_conf` module, narrowed to return errors instead of
//! panicking when no JNI context is installed and to drop
//! unreachable nameservers (link-local and unspecified addresses)
//! before handing the result back.

use std::{net::IpAddr, sync::OnceLock};

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use jni::{
    JavaVM, jni_sig, jni_str,
    objects::{IntoAuto as _, JByteArray, JList, JObject, JValue},
    sys::{self, jobject},
};
use n0_error::{anyerr, e};
use tracing::{trace, warn};

use super::{SystemConfigError, is_usable_nameserver};

/// Holds the JavaVM and Application Context jobject installed by the
/// consumer.
///
/// Both fields are raw pointers obtained from JNI. They must remain
/// valid for the lifetime of the process. The pointers are not
/// dereferenced outside JNI calls.
struct JniContext {
    java_vm: *mut sys::JavaVM,
    context_jobject: jobject,
}

// SAFETY: a `JavaVM*` is shareable across threads per the JNI
// invocation spec, and a JNI global reference is too. The
// install_android_jni_context contract requires the caller to pass a
// global reference (not a local one) for context_jobject.
unsafe impl Send for JniContext {}
unsafe impl Sync for JniContext {}

static JNI_CONTEXT: OnceLock<JniContext> = OnceLock::new();

/// Installs the JNI handles used to read system DNS on Android.
///
/// Call this once early in your process, typically from `JNI_OnLoad`,
/// to make the resolver honor the device's per-network DNS
/// configuration. Without it the resolver uses its built-in public
/// DNS fallback and never touches JNI.
///
/// Calling this more than once is a no-op; the first call wins.
///
/// # Safety
///
/// - `java_vm` must be a valid [`JavaVM`] pointer for the running
///   JVM. The per-thread `JNIEnv*` is not the same thing.
/// - `application_context` must be a JNI global reference (not a
///   local one) to an [`android.content.Context`]. Promote a local
///   reference with `JNIEnv::NewGlobalRef` and prevent its drop, or
///   the next read dereferences freed memory. Pass the singleton
///   `Application` from `ActivityThread.currentApplication()`
///   rather than an `Activity` or `Service`, since the latter
///   become unusable once their component is destroyed.
/// - Both pointers must remain valid until the process exits.
///
/// [`JavaVM`]: https://docs.oracle.com/en/java/javase/21/docs/specs/jni/invocation.html#javavm
/// [`android.content.Context`]: https://developer.android.com/reference/android/content/Context
pub unsafe fn install_android_jni_context(java_vm: *mut sys::JavaVM, application_context: jobject) {
    if JNI_CONTEXT
        .set(JniContext {
            java_vm,
            context_jobject: application_context,
        })
        .is_err()
    {
        warn!(
            "install_android_jni_context called more than once; \
             keeping the first JavaVM and Context",
        );
    }
}

/// Reads the system DNS configuration through the consumer-supplied
/// JNI context.
///
/// Returns [`SystemConfigError::PlatformUnsupported`] when no JNI
/// context has been installed. Returns [`SystemConfigError::Read`]
/// when the JNI calls themselves fail; the source wraps the
/// underlying JNI error for diagnostics.
pub(super) fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), SystemConfigError> {
    let ctx = JNI_CONTEXT
        .get()
        .ok_or_else(|| e!(SystemConfigError::PlatformUnsupported))?;

    let nameservers =
        read_dns_servers(ctx).map_err(|err| e!(SystemConfigError::Read, anyerr!(err)))?;

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
    let vm = unsafe { JavaVM::from_raw(ctx.java_vm) };
    vm.attach_current_thread(|env| {
        // SAFETY: ctx.context_jobject is a global Context reference
        // that the consumer guarantees is valid for the process
        // lifetime via the install_android_jni_context contract.
        let activity = unsafe { JObject::from_raw(env, ctx.context_jobject) };

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

        // Cap the number of servers we accept. A normal Android stack
        // returns at most a handful; a malicious local app or VPN
        // could in principle inject a much longer list, which we
        // would then probe in parallel. The bound keeps us honest.
        const MAX_SERVERS: usize = 16;
        let mut out = Vec::with_capacity(MAX_SERVERS);
        while let Some(server) = dns_servers.next(env)? {
            if out.len() >= MAX_SERVERS {
                warn!(MAX_SERVERS, "truncating system DNS server list");
                break;
            }
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
