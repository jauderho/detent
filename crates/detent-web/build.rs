//! Writes `OUT_DIR/openapi.min.json`: `docs/openapi.json` with all insignificant
//! whitespace removed. `docs/openapi.json` stays pretty-printed because it is
//! the reviewed artifact; the binary embeds and serves the compact form
//! (see `src/api/openapi.rs`), which saves several KB of whitespace.

use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let source = manifest.join("../../docs/openapi.json");
    let out = PathBuf::from(std::env::var("OUT_DIR")?).join("openapi.min.json");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", source.display());
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&source)?)?;
    std::fs::write(out, serde_json::to_vec(&value)?)?;
    Ok(())
}
