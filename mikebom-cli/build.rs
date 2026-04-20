fn main() {
    // On Linux, the eBPF bytecode is compiled via `cargo xtask ebpf`
    // and included at compile time via include_bytes_aligned! in loader.rs.
    //
    // The build.rs doesn't need to do anything special — the eBPF binary
    // is a pre-built artifact that the loader references directly.
    //
    // If using aya-build for automatic compilation, uncomment:
    // #[cfg(target_os = "linux")]
    // {
    //     use std::path::PathBuf;
    //     let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    //     // aya-build integration would go here
    // }

    println!("cargo:rerun-if-changed=build.rs");
}
