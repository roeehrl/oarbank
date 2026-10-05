//! On macOS, embed Info.plist in the binary: Local Network privacy names the launcher by it, and reads its usage text
//! and Bonjour service, when the personal scope's LaunchAgent (this launcher) runs the agent.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let plist = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Info.plist");
        println!("cargo:rerun-if-changed={}", plist.display());
        println!("cargo:rustc-link-arg-bins=-Wl,-sectcreate,__TEXT,__info_plist,{}", plist.display());
    }
}
