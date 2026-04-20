use std::process::Command;

use clap::Parser;

#[derive(Parser)]
enum Cli {
    /// Build the eBPF programs
    Ebpf,
}

fn main() {
    let cli = Cli::parse();
    match cli {
        Cli::Ebpf => build_ebpf(),
    }
}

fn build_ebpf() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../mikebom-ebpf");

    let status = Command::new("cargo")
        .current_dir(dir)
        .args([
            "+nightly",
            "build",
            "--target=bpfel-unknown-none",
            "-Z",
            "build-std=core",
            "--release",
        ])
        .status()
        .expect("failed to build eBPF programs");

    if !status.success() {
        eprintln!("eBPF build failed with status: {status}");
        std::process::exit(1);
    }

    println!("eBPF programs built successfully");
}
