//! Triple-format wall-clock performance benchmark (milestone 011
//! T035 / SC-007).
//!
//! Spec: a single `mikebom sbom scan --format
//! cyclonedx-json,spdx-2.3-json,spdx-3-json` invocation MUST
//! complete in **at least 30 % less wall-clock time** than three
//! sequential single-format invocations against the same target.
//! The savings come from running the scan + deep-hash + layer-walk
//! work **once** instead of three times — the FR-004 single-pass
//! guarantee extended from the milestone-010 dual-format case.
//!
//! CI gate (per research.md §R4 + clarification Q3): enforces
//! ≥25% reduction, 5 points below the spec target. Same noise-budget
//! rationale as milestone 010's `SC009_CI_MIN_REDUCTION`: fixed
//! per-invocation overhead (CLI init + docker-tarball extract +
//! enrichment no-op) caps the achievable reduction at small fixture
//! scales; the 5-point gap absorbs that reliably while still
//! catching real amortization regressions. Any change that breaks
//! single-pass emission drops the reduction to near 0 %, far below
//! the gate.
//!
//! Fixture reuse: mirrors `dual_format_perf.rs`'s synthetic
//! docker-save tarball (500 deb + 1500 npm packages, ~6 MB of
//! package.json content). That's ~1s per single-format scan on
//! GitHub Actions ubuntu-latest — big enough that fixed overhead
//! stays below the amortization margin.
//!
//! When `MIKEBOM_PERF_IMAGE` is set, the benchmark uses that image
//! instead of the synthetic fixture — useful for reviewers who want
//! to verify against a production-scale `debian:12-slim.tar`.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mikebom")
}

struct ImageFile {
    path: &'static str,
    content: Vec<u8>,
}

/// Build a docker-save-format tarball with `files` placed in the
/// rootfs. Identical shape to the `dual_format_perf.rs` helper.
fn build_synthetic_image(files: &[ImageFile]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut layer_bytes = Vec::new();
    {
        let mut layer_tar = tar::Builder::new(&mut layer_bytes);
        for f in files {
            let mut header = tar::Header::new_ustar();
            header.set_path(f.path).expect("set_path");
            header.set_size(f.content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            layer_tar
                .append(&header, f.content.as_slice())
                .expect("tar append");
        }
        layer_tar.finish().expect("layer finish");
    }
    let manifest = r#"[{"Config":"config.json","RepoTags":["mikebom-perf-triple:latest"],"Layers":["layer0/layer.tar"]}]"#;
    let tar_path = dir.path().join("image.tar");
    let file = std::fs::File::create(&tar_path).expect("create image.tar");
    {
        let mut outer = tar::Builder::new(file);
        let mut mh = tar::Header::new_ustar();
        mh.set_path("manifest.json").unwrap();
        mh.set_size(manifest.len() as u64);
        mh.set_mode(0o644);
        mh.set_cksum();
        outer.append(&mh, manifest.as_bytes()).expect("outer append manifest");
        let mut lh = tar::Header::new_ustar();
        lh.set_path("layer0/layer.tar").unwrap();
        lh.set_size(layer_bytes.len() as u64);
        lh.set_mode(0o644);
        lh.set_cksum();
        outer
            .append(&lh, layer_bytes.as_slice())
            .expect("outer append layer");
        outer.into_inner().expect("outer finish").flush().expect("flush");
    }
    (dir, tar_path)
}

/// Build the same synthetic image `dual_format_perf.rs` uses —
/// 500 deb + 1500 npm packages, ~1s per-single-format wall-clock
/// on GitHub Actions runners. Big enough that per-invocation
/// fixed overhead is a small fraction of total work, so the
/// amortization signal stays above noise.
fn build_benchmark_fixture() -> (tempfile::TempDir, PathBuf) {
    let mut files: Vec<ImageFile> = Vec::new();

    files.push(ImageFile {
        path: "etc/os-release",
        content: b"ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n".to_vec(),
    });

    let mut dpkg = String::new();
    for i in 0..500 {
        use std::fmt::Write as _;
        write!(
            dpkg,
            "Package: pkg-{i:04}\n\
             Status: install ok installed\n\
             Version: 1.{i}.0\n\
             Architecture: amd64\n\
             Maintainer: Debian <debian@example.org>\n\n",
        )
        .unwrap();
    }
    files.push(ImageFile {
        path: "var/lib/dpkg/status",
        content: dpkg.into_bytes(),
    });

    for i in 0..1500 {
        let content = format!(
            r#"{{"name":"pkg-{i:04}","version":"2.{i}.0","license":"MIT","description":"{repeat}"}}"#,
            repeat = "x".repeat(4096)
        );
        let path: &'static str = Box::leak(
            format!("usr/lib/node_modules/pkg-{i:04}/package.json").into_boxed_str(),
        );
        files.push(ImageFile {
            path,
            content: content.into_bytes(),
        });
    }

    build_synthetic_image(&files)
}

/// One wall-clock measurement of a single `mikebom sbom scan` run.
/// Handles arbitrary comma-separated `--format` lists by deriving
/// the per-format output path from the id.
fn time_scan(image: &std::path::Path, formats: &str) -> Duration {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
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
            "spdx-3-json" => "spdx3.json",
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

/// Median of three measurements — robust to CI-runner noise.
fn median_of_3(image: &std::path::Path, formats: &str) -> Duration {
    let mut samples = [
        time_scan(image, formats),
        time_scan(image, formats),
        time_scan(image, formats),
    ];
    samples.sort();
    samples[1]
}

#[test]
fn triple_format_is_at_least_25_percent_faster_than_three_sequential_scans() {
    let (_fixture_guard, image) = if let Ok(p) = std::env::var("MIKEBOM_PERF_IMAGE") {
        let p = PathBuf::from(p);
        assert!(
            p.exists(),
            "MIKEBOM_PERF_IMAGE set but {} does not exist",
            p.display()
        );
        (tempfile::tempdir().expect("unused guard"), p)
    } else {
        build_benchmark_fixture()
    };

    // Warm the page cache before the timed measurements so the
    // signal measures serializer/dispatch overhead, not cold-cache
    // I/O noise.
    let _ = time_scan(&image, "cyclonedx-json");

    let cdx = median_of_3(&image, "cyclonedx-json");
    let spdx = median_of_3(&image, "spdx-2.3-json");
    let spdx3 = median_of_3(&image, "spdx-3-json");
    let triple = median_of_3(&image, "cyclonedx-json,spdx-2.3-json,spdx-3-json");
    let sequential = cdx + spdx + spdx3;

    // Spec SC-007 target: triple ≤ 0.70 × sequential (≥ 30 %
    // reduction). Enforced CI threshold is ≥ 25 % per research.md
    // §R4 + clarification Q3. Same noise-budget rationale as the
    // milestone-010 dual-format gate: fixed per-invocation
    // overhead caps the achievable reduction at small fixture
    // scales. 3 invocations × ~50 ms fixed overhead = ~150 ms
    // un-amortizable; at ~1s per-scan synthetic-fixture total,
    // the achievable ceiling is ~45-47%, comfortably above the
    // 25% CI gate.
    const SC007_CI_MIN_REDUCTION: f64 = 0.25;
    let max_allowed = sequential.mul_f64(1.0 - SC007_CI_MIN_REDUCTION);
    let reduction_pct = (1.0
        - triple.as_secs_f64() / sequential.as_secs_f64())
        * 100.0;

    eprintln!(
        "triple_format_perf: cdx={cdx:?}, spdx23={spdx:?}, \
         spdx3={spdx3:?}, sequential_sum={sequential:?}, \
         triple={triple:?}, reduction = {reduction_pct:.1}% \
         (CI gate ≥ {:.0} %, spec target ≥ 30 %)",
        SC007_CI_MIN_REDUCTION * 100.0
    );

    assert!(
        triple <= max_allowed,
        "SC-007 failure: triple-format scan ({triple:?}) should be ≤ \
         {:.0} % of three-sequential-scan total ({sequential:?}; max \
         allowed {max_allowed:?}). Measured reduction: \
         {reduction_pct:.1}% (CI gate ≥ {:.0}%, spec target ≥ 30 %).",
        (1.0 - SC007_CI_MIN_REDUCTION) * 100.0,
        SC007_CI_MIN_REDUCTION * 100.0,
    );
}
