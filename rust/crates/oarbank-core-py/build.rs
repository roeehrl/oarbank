// Python symbols resolve at import time; macOS needs `-undefined dynamic_lookup` for a plain `cargo build`.
fn main() {
    pyo3_build_config::add_extension_module_link_args();
}
