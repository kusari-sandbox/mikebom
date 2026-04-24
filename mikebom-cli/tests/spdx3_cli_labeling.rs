//! SPDX 3 experimental-labeling surfaces (milestone 010 T042 /
//! FR-019b).
//!
//! Three user-visible places where the stub must announce its
//! experimental status so consumers don't mistake it for production
//! SPDX 3 emission:
//!
//!   (a) CLI `--help` text mentions `[EXPERIMENTAL]` next to the
//!       `spdx-3-json-experimental` format id.
//!   (b) Passing `--format spdx-3-json` (no suffix — common typo)
//!       exits non-zero with a "did you mean
//!       `spdx-3-json-experimental`?" hint.
//!   (c) The produced SPDX 3 JSON document's tool-comment contains
//!       the literal substring `experimental` (covered by the
//!       sister test `spdx3_stub.rs`, linked here for surface
//!       completeness).

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mikebom")
}

#[test]
fn help_text_labels_spdx_3_as_experimental() {
    let output = Command::new(bin())
        .arg("sbom")
        .arg("scan")
        .arg("--help")
        .output()
        .expect("mikebom --help runs");
    assert!(output.status.success(), "sbom scan --help must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("spdx-3-json-experimental"),
        "--help text should mention the format id, got:\n{stdout}"
    );
    assert!(
        stdout.contains("[EXPERIMENTAL]"),
        "--help text should label the stub as [EXPERIMENTAL], got:\n{stdout}"
    );
}

#[test]
fn bare_spdx_3_json_offers_did_you_mean_hint() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let output = Command::new(bin())
        .current_dir(tmp.path())
        .env("HOME", fake_home.path())
        .arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("tests/fixtures/npm/node-modules-walk"),
        )
        .arg("--format")
        .arg("spdx-3-json")
        .output()
        .expect("mikebom runs");
    assert!(
        !output.status.success(),
        "bare spdx-3-json must be rejected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("did you mean 'spdx-3-json-experimental'"),
        "rejection should offer a did-you-mean hint, got:\n{stderr}"
    );
}

#[test]
fn unknown_format_error_includes_experimental_label_in_known_list() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let output = Command::new(bin())
        .current_dir(tmp.path())
        .env("HOME", fake_home.path())
        .arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("tests/fixtures/npm/node-modules-walk"),
        )
        .arg("--format")
        .arg("not-a-format")
        .output()
        .expect("mikebom runs");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The error lists every registered id; the experimental one
    // should carry its label so the reader sees what's stable vs
    // not when picking from the list.
    assert!(
        stderr.contains("spdx-3-json-experimental [EXPERIMENTAL]"),
        "unknown-format error's known-id list should label experimental \
         formats, got:\n{stderr}"
    );
}
