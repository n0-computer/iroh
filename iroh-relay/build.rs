use cfg_aliases::cfg_aliases;
use vergen_gitcl::{Emitter, GitclBuilder};

fn main() {
    // Setup cfg aliases
    cfg_aliases! {
        // Convenience aliases
        wasm_browser: { all(target_family = "wasm", target_os = "unknown") },
    }

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
