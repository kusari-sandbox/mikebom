# Data Model: SPDX Byte-Identity Goldens + Cross-Host Determinism Parity

**Phase 1 output for** `/specs/017-spdx-byte-identity-goldens/spec.md`

## Scope

This feature has minimal *runtime* data — it's a test-infrastructure milestone. Two persisted artifacts: (a) per-format normalized golden JSON files committed to the repo, (b) the helper module's exported function signatures (the "API" of the test infrastructure). Both are described here.

---

## Golden file (committed JSON)

A pinned reference SBOM document. One file per (format, ecosystem) pair. Stored under `mikebom-cli/tests/fixtures/golden/<format>/`.

### Filesystem layout

```text
mikebom-cli/tests/fixtures/golden/
├── cyclonedx/        # 9 files — UNCHANGED post-#38, byte-stable across the cdx_regression migration
│   ├── apk.cdx.json
│   ├── cargo.cdx.json
│   ├── deb.cdx.json
│   ├── gem.cdx.json
│   ├── golang.cdx.json
│   ├── maven.cdx.json
│   ├── npm.cdx.json
│   ├── pip.cdx.json
│   └── rpm.cdx.json
├── spdx-2.3/         # 9 NEW files — written via MIKEBOM_UPDATE_SPDX_GOLDENS=1
│   ├── apk.spdx.json
│   ├── cargo.spdx.json
│   ├── deb.spdx.json
│   ├── gem.spdx.json
│   ├── golang.spdx.json
│   ├── maven.spdx.json
│   ├── npm.spdx.json
│   ├── pip.spdx.json
│   └── rpm.spdx.json
└── spdx-3/           # 9 NEW files — written via MIKEBOM_UPDATE_SPDX3_GOLDENS=1
    ├── apk.spdx3.json
    ├── cargo.spdx3.json
    ├── deb.spdx3.json
    ├── gem.spdx3.json
    ├── golang.spdx3.json
    ├── maven.spdx3.json
    ├── npm.spdx3.json
    ├── pip.spdx3.json
    └── rpm.spdx3.json
```

### Content rules

A committed golden file:

- Contains the *normalized* output (per `tests/common/normalize.rs`), not the raw scan output.
- Is pretty-printed JSON (`serde_json::to_string_pretty`) with sorted keys at every level. The serializer's default sort makes `git diff` legible.
- Has every `<WORKSPACE>` placeholder substitution applied — no `/Users/...` or `/home/runner/work/...` paths anywhere.
- Has every legitimately-volatile field replaced with the documented placeholder string for that format (see "Placeholder catalog" below).
- Has all "deep hash" content stripped per the format's strip rule (see "Strip rules" below).
- Ends with a single trailing newline (POSIX-standard text-file convention; matches what `serde_json::to_string_pretty` followed by a newline produces).

### Placeholder catalog

| Format | Field | Reason | Placeholder string |
|---|---|---|---|
| All | Workspace path prefix | Host-dependent absolute path leaks into `comment` / annotation envelopes / etc. | `<WORKSPACE>` |
| CDX | `serialNumber` (top-level) | Fresh v4 UUID per invocation per CycloneDX spec. | `urn:uuid:00000000-0000-0000-0000-000000000000` |
| CDX | `metadata.timestamp` | `Utc::now()` per invocation per CycloneDX spec. | `1970-01-01T00:00:00Z` |
| SPDX 2.3 | `creationInfo.created` | Wall-clock timestamp per SPDX spec. | `1970-01-01T00:00:00Z` |
| SPDX 3 | `@graph[].created` on `CreationInfo` element(s) | Wall-clock timestamp per SPDX 3 spec. | `1970-01-01T00:00:00Z` |
| SPDX 3 | Document IRI (`@id` on `SpdxDocument` element) | Currently content-derived (host-stable per `spdx3_determinism.rs:11-13`); placeholder reserved for future regression. | (not masked today; if emitter changes, mask to `<DOCUMENT_IRI>`) |

### Strip rules

| Format | Field path | Reason |
|---|---|---|
| CDX | `components[].hashes[]` | Deep-hash content depends on local filesystem (file-mtime-derived chunking, host-cached fixture state). |
| CDX | `components[].components[].hashes[]` (nested children of nested children, recursively) | Same reason. |
| SPDX 2.3 | `packages[].checksums[]` | Same reason — deep-hash data identical to CDX. |
| SPDX 3 | `@graph[]` elements where `type == "Package"` and the element has `verifiedUsing[]` — strip `verifiedUsing[]`. | Same reason. |

The strip leaves the surrounding fields intact (`Package.name`, `Package.version`, etc. are still in the golden) so that emitter regressions affecting non-hash fields are still caught.

---

## Helper module (`mikebom-cli/tests/common/normalize.rs`)

A new public module under the existing `tests/common/` directory. Exports the four functions named in FR-006.

### Module-doc shape

The first ~30 lines of the file MUST be a `//!` module-doc covering:

1. **What this module is for** — one paragraph. "The cross-host byte-identity discipline."
2. **Why each masked field is masked** — one bullet per (format, field) pair from the placeholder catalog above. Each bullet cites the spec or the leak vector.
3. **Why each strip rule strips what it does** — one bullet per (format, field path) pair.
4. **The fake-HOME isolation envvars** — list of every env var that `apply_fake_home_env` redirects, with one-line "what cache this points at" per envvar.
5. **The regen contract** — one paragraph pointing to `contracts/golden-regen.md`.

A reader of `tests/common/normalize.rs` MUST be able to answer "why is this field masked?" without leaving the file.

### Function signatures

```rust
/// Normalize a raw CycloneDX scan output for golden comparison.
///
/// Workspace-path replacement runs as a string-replace (catches every
/// leak vector); UUID/timestamp masking runs on the parsed JSON; hash
/// stripping descends recursively through nested components.
///
/// Returns the normalized JSON re-serialized as pretty-printed string
/// with sorted keys + trailing newline.
pub fn normalize_cdx_for_golden(raw: &str, workspace: &Path) -> String;

/// Normalize a parsed SPDX 2.3 document for golden comparison.
///
/// Caller MUST have already serialized the document to a string and
/// run workspace-path replacement on it; the input here is the
/// post-string-replace re-parsed Value. UUID/timestamp masking +
/// hash stripping run on this Value. Caller serializes the result
/// for comparison or write.
///
/// Returns the masked Value; serialization is the caller's responsibility.
pub fn normalize_spdx23_for_golden(doc: serde_json::Value, workspace: &Path) -> serde_json::Value;

/// Normalize a parsed SPDX 3 document for golden comparison.
///
/// Same contract as `normalize_spdx23_for_golden` but for the SPDX 3
/// `@graph`-shaped document.
pub fn normalize_spdx3_for_golden(doc: serde_json::Value, workspace: &Path) -> serde_json::Value;

/// Apply the cross-host fake-HOME env-var isolation to a Command.
///
/// Redirects HOME, M2_REPO, MAVEN_HOME, GOPATH, GOMODCACHE, CARGO_HOME
/// to subdirectories under `fake_home`. The subdirectories don't need
/// to exist; the goal is to point cache lookups at empty paths so the
/// scanner sees no cached metadata.
///
/// Caller is responsible for ensuring `fake_home` outlives the
/// Command's execution (typically by holding the source TempDir).
pub fn apply_fake_home_env(cmd: &mut std::process::Command, fake_home: &Path);
```

### Validation rules

- `normalize_*` MUST be pure (no I/O, no env-var reads, no time access). Inputs determine outputs entirely.
- `apply_fake_home_env` MUST be idempotent — calling it twice on the same Command produces the same Command state.
- Test files using these helpers MUST NOT inline any of the masking/redirection logic. The grep `rg 'env\("HOME"' mikebom-cli/tests/ -g '!common/'` returning 0 hits is the FR-008 enforcement signal.

---

## Regen-decision record (in-PR, no runtime persistence)

When a PR regenerates one or more goldens, the PR description MUST include a per-format diff summary:

```markdown
## Goldens regenerated

| Format | Files changed | Reason |
|---|---|---|
| SPDX 2.3 | 9 / 9 | New annotation field on every Package per `<some milestone>` FR-NNN. |
| SPDX 3  | 0 / 9 | (Unchanged.) |
| CDX     | 0 / 9 | (Unchanged.) |
```

A maintainer reviewing the PR can then verify that the golden diff matches the stated reason — e.g., if "new annotation field on every Package" is the claim, every diff hunk should show that field added. Diffs that go beyond the claim are a red flag and must be explained or rolled back.

This record lives only in the PR description; there's no committed file. The merge commit message preserves it.
