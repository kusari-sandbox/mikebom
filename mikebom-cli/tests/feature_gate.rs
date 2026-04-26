//! Integration test for the `ebpf-tracing` feature flag (milestone 020).
//!
//! Verifies the runtime guard contract from
//! `specs/020-ebpf-feature-gate/contracts/feature-flag.md`: when the feature
//! is OFF (the default), invoking `mikebom trace capture` exits non-zero with
//! a stderr message that names both the missing feature and the rebuild
//! instruction.
//!
//! The test itself is gated `cfg(not(feature = "ebpf-tracing"))`, so it runs
//! ONLY in default builds. Under `--features ebpf-tracing` the guard is
//! unreachable (the real Linux execute_scan takes over), and asserting on a
//! feature-off error message would be meaningless — so we compile this file
//! out.

#[cfg(not(feature = "ebpf-tracing"))]
mod common;

#[cfg(not(feature = "ebpf-tracing"))]
#[test]
fn trace_capture_returns_feature_off_error_in_default_build() {
    use std::process::Command;

    let output = Command::new(common::bin())
        .args(["trace", "capture", "--target-pid", "1"])
        .output()
        .expect("spawn mikebom trace capture");

    assert!(
        !output.status.success(),
        "expected non-zero exit; got {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("compiled without eBPF support"),
        "stderr missing 'compiled without eBPF support' substring:\n{stderr}",
    );
    assert!(
        stderr.contains("--features ebpf-tracing"),
        "stderr missing '--features ebpf-tracing' rebuild instruction:\n{stderr}",
    );
}
