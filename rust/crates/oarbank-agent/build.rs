//! Compile in the Oarbank vendor's TUF root when the build names one (`OARBANK_TUF_ROOT=<path to root.json>`):
//! release builds do, developer builds do not (they then skip the vendor check; tuf.rs).
fn main() {
    println!("cargo:rerun-if-env-changed=OARBANK_TUF_ROOT");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("tuf-root.json");
    match std::env::var("OARBANK_TUF_ROOT") {
        Ok(p) if !p.is_empty() => {
            println!("cargo:rerun-if-changed={p}");
            std::fs::copy(&p, &out).unwrap_or_else(|e| panic!("OARBANK_TUF_ROOT {p}: {e}"));
        }
        _ => std::fs::write(&out, b"").unwrap(),
    }
}
