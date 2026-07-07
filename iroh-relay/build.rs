use cfg_aliases::cfg_aliases;
use vergen_gitcl::{Emitter, GitclBuilder};

fn main() {
    // Setup cfg aliases
    cfg_aliases! {
        // Convenience aliases
        wasm_browser: { all(target_family = "wasm", target_os = "unknown") },
        with_crypto_provider: { any(feature = "tls-ring", feature = "tls-aws-lc-rs") }
    }

    // Experimental toggle for benchmarking datagram vs uni-stream relay framing.
    // Build with `RUSTFLAGS="--cfg h3_datagrams"`. See `plans/h3-bench.md`.
    println!("cargo::rustc-check-cfg=cfg(h3_datagrams)");

    // Emit build-time environment variables
    if let Err(e) = emit_vergen() {
        eprintln!("vergen error: {e}");
    }
}

fn emit_vergen() -> Result<(), Box<dyn std::error::Error>> {
    let gitcl = GitclBuilder::default().sha(false).build()?;
    Emitter::default().add_instructions(&gitcl)?.emit()?;
    Ok(())
}
