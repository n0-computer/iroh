use cfg_aliases::cfg_aliases;

fn main() {
    // Setup cfg aliases
    cfg_aliases! {
        // Convenience aliases
        wasm_browser: { all(target_family = "wasm", target_os = "unknown") },
        with_crypto_provider: { any(feature = "tls-ring", feature = "tls-aws-lc-rs") },
        // IP (UDP) transports: native, or in the browser with `--cfg webview_sockets`.
        ip_transport: { any(not(wasm_browser), webview_sockets) }
    }
}
