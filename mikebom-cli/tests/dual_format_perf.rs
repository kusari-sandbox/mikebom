//! Dual-format wall-clock performance benchmark (milestone 010
//! T049 / SC-009).
//!
//! Spec: a single `mikebom sbom scan --format cyclonedx-json,spdx-2.3-json`
//! invocation MUST complete in **at least 30 % less wall-clock time**
//! than two sequential single-format invocations against the same
//! target — the savings come from running the scan + deep-hash +
//! layer-walk work **once** instead of twice.
//!
//! The spec specifies the benchmark fixture as
//! `mikebom-cli/tests/fixtures/images/debian-12-slim.tar` because it
//! exercises both the deep-hash deb-package path AND the embedded
//! npm path — the two workloads the dual-format optimization is
//! designed to amortize. That fixture is not committed (~30 MB);
//! the `MIKEBOM_PERF_IMAGE` env var can point at any local
//! `docker save` tarball to run the test. The test is
//! `#[ignore]`-gated by default so the standard CI pipeline stays
//! fast; CI enables it via `--include-ignored` in a separate
//! perf-gate job when the fixture is provisioned.
//!
//! Running locally:
//! ```bash
//! docker pull debian:12-slim
//! docker save debian:12-slim -o /tmp/debian-12-slim.tar
//! MIKEBOM_PERF_IMAGE=/tmp/debian-12-slim.tar \
//!   cargo test --release --test dual_format_perf -- --ignored
//! ```

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mikebom")
}

/// Find the image fixture. Precedence:
///   1. `MIKEBOM_PERF_IMAGE` env var (absolute path to a `.tar`).
///   2. The spec's pinned default
///      (`mikebom-cli/tests/fixtures/images/debian-12-slim.tar`).
/// Returns `None` when neither source resolves to an existing file.
fn image_fixture() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("MIKEBOM_PERF_IMAGE") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    let pinned = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/images/debian-12-slim.tar");
    pinned.exists().then_some(pinned)
}

/// One wall-clock measurement of a single `mikebom sbom scan`
/// invocation. Returns the elapsed `Duration`. Uses release-mode
/// mikebom (the CI perf gate runs the test via
/// `cargo test --release`); dev-mode timings are not representative
/// and the test asserts on relative ratios, not absolute times, so
/// either mode produces a signal.
fn time_scan(image: &std::path::Path, formats: &str) -> Duration {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    // Per-format `--output` entries so the dual-format run writes
    // distinct files (no path collision). For single-format runs
    // we still set a bare `--output` so the file lands inside our
    // tempdir.
    let mut cmd = Command::new(bin());
    cmd.env("HOME", fake_home.path())
        .env("M2_REPO", fake_home.path().join("no-m2-repo"))
        .env("MAVEN_HOME", fake_home.path().join("no-maven-home"))
        .env("GOPATH", fake_home.path().join("no-gopath"))
        .env("GOMODCACHE", fake_home.path().join("no-gomodcache"))
        .env("CARGO_HOME", fake_home.path().join("no-cargo-home"))
        .arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--image")
        .arg(image)
        .arg("--format")
        .arg(formats);
    for f in formats.split(',') {
        let ext = match f {
            "cyclonedx-json" => "cdx.json",
            "spdx-2.3-json" => "spdx.json",
            "spdx-3-json-experimental" => "spdx3.json",
            _ => "json",
        };
        cmd.arg("--output").arg(format!(
            "{f}={}",
            tmp.path().join(format!("out.{ext}")).to_string_lossy()
        ));
    }
    let start = Instant::now();
    let out = cmd.output().expect("mikebom runs");
    let elapsed = start.elapsed();
    assert!(
        out.status.success(),
        "perf-measurement scan failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    elapsed
}

#[test]
#[ignore = "requires MIKEBOM_PERF_IMAGE or pinned fixture; run via --include-ignored"]
fn dual_format_is_at_least_30_percent_faster_than_two_sequential_scans() {
    let Some(image) = image_fixture() else {
        panic!(
            "No perf-benchmark image fixture available. Set \
             MIKEBOM_PERF_IMAGE=<absolute-path-to-docker-save-tar> \
             or place debian-12-slim.tar at \
             mikebom-cli/tests/fixtures/images/. See the module \
             docs for the one-time setup command."
        );
    };

    // Warm-cache pass so on-disk page cache is hot for both the
    // cdx-only and dual-format timings — the spec calls for this
    // explicitly so the comparison measures serializer/dispatch
    // overhead, not cold-cache I/O noise.
    let _ = time_scan(&image, "cyclonedx-json");

    // Two sequential single-format runs — the baseline.
    let cdx_time = time_scan(&image, "cyclonedx-json");
    let spdx_time = time_scan(&image, "spdx-2.3-json");
    let sequential_total = cdx_time + spdx_time;

    // One dual-format run.
    let dual_time = time_scan(&image, "cyclonedx-json,spdx-2.3-json");

    // SC-009: dual ≤ 70 % of sequential_total → ≥30 % reduction.
    let max_allowed = sequential_total.mul_f64(0.70);
    assert!(
        dual_time <= max_allowed,
        "SC-009 failure: dual-format scan ({dual_time:?}) should be \
         ≤ 70 % of two-sequential-scan total ({sequential_total:?}; \
         max allowed {max_allowed:?}). CDX-only {cdx_time:?}, \
         SPDX-only {spdx_time:?}."
    );
    eprintln!(
        "dual_format_perf: cdx={cdx_time:?}, spdx={spdx_time:?}, \
         sequential_total={sequential_total:?}, dual={dual_time:?}, \
         reduction = {:.1}%",
        (1.0 - dual_time.as_secs_f64() / sequential_total.as_secs_f64())
            * 100.0
    );
}
