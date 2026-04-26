//! Cross-host byte-identity discipline — shared normalization +
//! fake-HOME isolation for golden-comparison tests.
//!
//! mikebom emits byte-stable SBOMs in three formats (CycloneDX 1.6,
//! SPDX 2.3, SPDX 3.0.1). Per-format regression tests pin a committed
//! golden file and assert byte-equality against it on every CI run.
//! Two classes of variability would defeat that guarantee unless
//! actively normalized:
//!
//! 1. **Run-scoped fields** — UUIDs, wall-clock timestamps, and
//!    content-derived hashes that legitimately differ between
//!    invocations of the same scan. Each format has spec-mandated
//!    fields with this property; this module masks them to fixed
//!    placeholders before comparison.
//!
//! 2. **Host-scoped paths** — the absolute path of the workspace
//!    leaks into several SBOM fields (CDX `mikebom:source-files` /
//!    `evidence.occurrences[].location`; SPDX `comment` and
//!    annotation envelope payloads). On macOS dev that prefix is
//!    `/Users/<user>/Projects/mikebom/...`; on Linux CI it's
//!    `/home/runner/work/mikebom/mikebom/...`. Both are rewritten
//!    to `<WORKSPACE>` so a golden pinned on one host matches on
//!    the other.
//!
//! See `specs/017-spdx-byte-identity-goldens/data-model.md` for the
//! authoritative placeholder catalog and strip rules. See
//! `specs/017-spdx-byte-identity-goldens/contracts/golden-regen.md`
//! for the `MIKEBOM_UPDATE_*_GOLDENS=1` regen contract.
//!
//! ## Masked fields by format
//!
//! - **CycloneDX**:
//!   - `serialNumber` → `SERIAL_PLACEHOLDER` — top-level field, fresh
//!     v4 UUID per invocation per the CDX 1.6 spec.
//!   - `metadata.timestamp` → `TIMESTAMP_PLACEHOLDER` — `Utc::now()`
//!     per the CDX 1.6 spec.
//!
//! - **SPDX 2.3**:
//!   - (filled in T007) `creationInfo.created` — wall-clock per SPDX 2.3 spec.
//!
//! - **SPDX 3**:
//!   - (filled in T011) every `@graph[]` element with `type ==
//!     "CreationInfo"`: `created` field — wall-clock per SPDX 3 spec.
//!
//! ## Strip rules by format
//!
//! - **CycloneDX**: `components[].hashes[]` (recursively descending
//!   into nested `components[].components[]` for shade-jar children
//!   and image-layer-owned bundles). For several ecosystems the
//!   scanner derives hashes from local package caches (Maven JARs
//!   from `~/.m2/repository/`, Go module zips from `~/go/pkg/mod/`)
//!   so per-host cache state varies the hash set; stripping makes
//!   the goldens portable. Hash-set parity within a single scan is
//!   still guarded by `spdx_cdx_parity.rs` (in-memory, same host).
//! - **SPDX 2.3**: (filled in T007) `packages[].checksums[]` — same.
//! - **SPDX 3**: (filled in T011) `verifiedUsing[]` on every
//!   `@graph[]` element with `type == "Package"` — same.
//!
//! ## Fake-HOME isolation envvars
//!
//! `apply_fake_home_env` redirects six env vars, each to an
//! (intentionally empty) sub-path under the per-test tempdir so the
//! scanner's home-cache lookups uniformly hit nothing regardless of
//! host:
//!
//! - `HOME` → `fake_home` itself. Generic per-user home dir; touched
//!   by many tools when other env vars are unset.
//! - `M2_REPO` → `fake_home/no-m2-repo`. Maven local-repo cache.
//!   Without isolation, `~/.m2/repository/` on the dev machine seeds
//!   the scanner with packages absent from CI runners (the
//!   commons-text mismatch the user's memory tagged).
//! - `MAVEN_HOME` → `fake_home/no-maven-home`. Maven settings dir.
//! - `GOPATH` → `fake_home/no-gopath`. Go workspace; defaults to
//!   `$HOME/go` when unset, but pinning explicitly insulates against
//!   shells that export it.
//! - `GOMODCACHE` → `fake_home/no-gomodcache`. Go module cache;
//!   defaults to `$GOPATH/pkg/mod`. Module zip metadata seeds the
//!   Go ecosystem reader.
//! - `CARGO_HOME` → `fake_home/no-cargo-home`. Cargo registry +
//!   git clone cache; defaults to `$HOME/.cargo`. Currently rarely
//!   affects output but isolated for future-proofing.

#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

/// CycloneDX `serialNumber` placeholder. Top-level CDX field is a
/// fresh v4 UUID per invocation; mask to a fixed value for
/// byte-identity comparison.
pub const SERIAL_PLACEHOLDER: &str = "urn:uuid:00000000-0000-0000-0000-000000000000";

/// Wall-clock timestamp placeholder. Used for CDX `metadata.timestamp`,
/// SPDX 2.3 `creationInfo.created`, and SPDX 3 `CreationInfo.created`
/// — every format's "when was this generated" field gets the same
/// epoch placeholder.
pub const TIMESTAMP_PLACEHOLDER: &str = "1970-01-01T00:00:00Z";

/// Stand-in for the absolute path of the workspace root. Macs emit
/// `/Users/<user>/Projects/mikebom/...`; CI Linux emits
/// `/home/runner/work/mikebom/mikebom/...`; both rewrite to this
/// literal so a golden pinned on one host matches on the other.
pub const WORKSPACE_PLACEHOLDER: &str = "<WORKSPACE>";

/// Normalize a raw CycloneDX scan output for golden comparison.
///
/// Workspace-path replacement runs as a string-replace on the raw
/// output (catches every leak vector without enumerating fields);
/// UUID/timestamp masking runs on the parsed JSON; hash stripping
/// descends recursively through nested components.
///
/// Returns the normalized JSON re-serialized as pretty-printed string
/// with sorted keys (no trailing newline — matches the on-disk shape
/// produced by `serde_json::to_string_pretty`, which is what every
/// existing committed golden was written with).
pub fn normalize_cdx_for_golden(raw: &str, workspace: &Path) -> String {
    let ws_str = workspace.to_string_lossy().to_string();
    let replaced = raw.replace(ws_str.as_str(), WORKSPACE_PLACEHOLDER);

    let mut json: serde_json::Value = serde_json::from_str(&replaced)
        .expect("produced SBOM is valid JSON after workspace-path rewrite");
    if let Some(obj) = json.as_object_mut() {
        if obj.contains_key("serialNumber") {
            obj.insert(
                "serialNumber".to_string(),
                serde_json::Value::String(SERIAL_PLACEHOLDER.to_string()),
            );
        }
        if let Some(md) = obj.get_mut("metadata").and_then(|v| v.as_object_mut()) {
            if md.contains_key("timestamp") {
                md.insert(
                    "timestamp".to_string(),
                    serde_json::Value::String(TIMESTAMP_PLACEHOLDER.to_string()),
                );
            }
        }
        if let Some(comps) = obj.get_mut("components").and_then(|v| v.as_array_mut()) {
            for c in comps {
                strip_cdx_component_hashes(c);
            }
        }
    }
    serde_json::to_string_pretty(&json).expect("re-serialize")
}

/// Recursively strip `hashes[]` from a CDX component and its nested
/// `components[]` children (CDX 1.6 nests for shade-jar children and
/// image-layer-owned bundles).
fn strip_cdx_component_hashes(c: &mut serde_json::Value) {
    let Some(obj) = c.as_object_mut() else { return };
    obj.remove("hashes");
    if let Some(nested) = obj.get_mut("components").and_then(|v| v.as_array_mut()) {
        for nc in nested {
            strip_cdx_component_hashes(nc);
        }
    }
}

/// Normalize a parsed SPDX 2.3 document for golden comparison.
///
/// Caller MUST have already serialized the document to a string and
/// run workspace-path replacement on it; the input here is the
/// post-string-replace re-parsed Value. UUID/timestamp masking + hash
/// stripping run on this Value. Caller serializes the result for
/// comparison or write.
pub fn normalize_spdx23_for_golden(
    _doc: serde_json::Value,
    _workspace: &Path,
) -> serde_json::Value {
    unimplemented!("T007")
}

/// Normalize a parsed SPDX 3 document for golden comparison.
///
/// Same contract as `normalize_spdx23_for_golden` but for the SPDX 3
/// `@graph`-shaped document. Walks `@graph[]` for `CreationInfo`
/// elements (mask `created`) and `Package` elements (strip
/// `verifiedUsing[]`).
pub fn normalize_spdx3_for_golden(
    _doc: serde_json::Value,
    _workspace: &Path,
) -> serde_json::Value {
    unimplemented!("T011")
}

/// Apply the cross-host fake-HOME env-var isolation to a Command.
///
/// Redirects HOME, M2_REPO, MAVEN_HOME, GOPATH, GOMODCACHE,
/// CARGO_HOME to subdirectories under `fake_home`. The subdirectories
/// don't need to exist; the goal is to point cache lookups at empty
/// paths so the scanner sees no cached metadata regardless of host.
///
/// Caller is responsible for ensuring `fake_home` outlives the
/// Command's execution (typically by holding the source TempDir).
pub fn apply_fake_home_env(cmd: &mut Command, fake_home: &Path) {
    cmd.env("HOME", fake_home)
        .env("M2_REPO", fake_home.join("no-m2-repo"))
        .env("MAVEN_HOME", fake_home.join("no-maven-home"))
        .env("GOPATH", fake_home.join("no-gopath"))
        .env("GOMODCACHE", fake_home.join("no-gomodcache"))
        .env("CARGO_HOME", fake_home.join("no-cargo-home"));
}
