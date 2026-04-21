# Phase 0 Research: PURL & Scope Alignment

**Feature**: `005-purl-and-scope-alignment`
**Date**: 2026-04-20

## Approach

This feature is four surgical edits to existing behaviour — not a green-field design. Phase 0 takes the form of a **current-behaviour audit with recorded decisions**, one section per user story. Each decision cites the file/function/line where the change lands.

No "NEEDS CLARIFICATION" markers remain; all ambiguities were resolved in `spec.md::Clarifications` before this phase.

## US1 — Scan-mode-aware npm scoping

### Decision

Add a `ScanMode` enum (`Path | Image`) threaded from `scan_cmd.rs` through `scan_path()` into `package_db::read_all()` into `npm::read()`. In `npm::walk_node_modules`, skip descent into any directory matching the path-glob `**/node_modules/npm/node_modules/**` when `ScanMode::Path`. When `ScanMode::Image`, walk into it as usual.

Tag components originating from inside that glob with a CycloneDX property `{ name: "mikebom:npm-role", value: "internal" }`. Store the flag as a new `npm_role: Option<String>` field on `PackageDbEntry`; emit the property at CycloneDX-builder time when set.

### Rationale

- The spec's Clarification Q1 pinned the matching rule as a literal glob — not a heuristic — so the detection is a pure path-pattern check with no file-content reads.
- `ScanMode` is preferable to reading it from `std::env`-style side channels because it makes the scoping rule testable with synthetic fixtures.
- Per-component property (not per-document) is appropriate because the distinction is per-package, not per-scan.
- Spec Clarification Q2 pinned the exact property name, removing the "which string" design choice.

### Alternatives considered

- **File-content check (reading `package.json` for `"name": "npm"`)**: rejected — spec clarifications explicitly choose path-pattern over content inference.
- **Emit all components always, let consumers filter**: rejected — consumers currently can't distinguish internal from app components without the property.
- **New CLI flag** (`--include-npm-internals`): rejected per FR-003, FR-016 — scan-mode is the sole determinant.

### Code landing sites

| File | Change |
|---|---|
| `mikebom-cli/src/scan_fs/package_db/mod.rs` | Add `npm_role: Option<String>` field to `PackageDbEntry`. |
| `mikebom-cli/src/scan_fs/package_db/npm.rs` | `walk_node_modules` — early-`continue` inside the npm/npm-internal glob match when `ScanMode::Path`. Populate `npm_role = Some("internal")` for entries landing in the glob. |
| `mikebom-cli/src/scan_fs/package_db/mod.rs::read_all` | Accept a `scan_mode: ScanMode` parameter; thread it to `npm::read`. |
| `mikebom-cli/src/scan_fs/mod.rs::scan_path` | Accept + thread `scan_mode`. |
| `mikebom-cli/src/cli/scan_cmd.rs` | Set `scan_mode = ScanMode::Image` when `--image` is specified; else `ScanMode::Path`. |
| `mikebom-cli/src/generate/cyclonedx/builder.rs` | When `entry.npm_role.is_some()`, append the matching CycloneDX property to that component. |

## US2 + US3 — deb PURL format and namespace

### Decision

Rewrite `build_deb_purl` in `mikebom-cli/src/scan_fs/package_db/dpkg.rs` to take:

- `name: &str`
- `version: &str`
- `arch: Option<&str>`
- `namespace: &str` (new — source: `/etc/os-release::ID` lower-cased, or `"debian"` if absent)
- `distro_version: Option<&str>` (new — source: `/etc/os-release::VERSION_ID`, or `None` to omit the qualifier)

Remove the `codename` parameter entirely. `VERSION_CODENAME` becomes unused for PURL construction (still read for logging/diagnostic purposes if desired, but not required).

### Rationale

- `/etc/os-release::ID` is the canonical source per FR-008; lowercase+raw (no lookup rewrites) per FR-010.
- `<ID>-<VERSION_ID>` matches the format already used by apk and rpm readers in mikebom — byte-stable for those two per SC-004.
- `Option<&str>` for `distro_version` encodes the "omit entirely" edge case (FR-006) directly in the type system rather than via a sentinel string.

### Alternatives considered

- **Keep `codename` parameter and derive `VERSION_ID` separately inside the function**: rejected — adds a second piece of ambient state the function must know about. Explicit parameters are clearer.
- **Accept a struct `DebPurlCtx` with all four distro-related fields**: rejected — three `Option`s at the top-level function signature is still manageable; introducing a struct adds ceremony without reducing misuse risk.
- **Apply an `ubuntu` → `debian` lookup table for "derivative" distros**: rejected per FR-010 — raw `ID` is authoritative.

### Code landing sites

| File | Change |
|---|---|
| `mikebom-cli/src/scan_fs/os_release.rs` | No new functions (both `read_id` and `read_version_id` already exist). Only the call pattern changes upstream. |
| `mikebom-cli/src/scan_fs/package_db/dpkg.rs::build_deb_purl` | Signature change: drop `codename`, add `namespace` + `distro_version`. |
| `mikebom-cli/src/scan_fs/package_db/dpkg.rs::read` | Accept `namespace: &str` + `distro_version: Option<&str>`; thread from caller. |
| `mikebom-cli/src/scan_fs/package_db/mod.rs::read_all` | Read `ID` + `VERSION_ID` once from `<rootfs>/etc/os-release`; compute `namespace = id.unwrap_or("debian")`; pass `distro_version = version_id.as_deref()` to `dpkg::read`. |

## US4 — RPM version format alignment

### Decision (investigation phase)

Before the code change, produce a written root-cause analysis comparing `rpm -qa` output on the polyglot-builder-image container to mikebom's current PURL emissions for the same packages. Sample the 93 mismatches and classify them by failure mode:

- **Epoch inline vs qualifier** — if the mismatch is `rpm -qa` reporting `4.19-1.fc40` while mikebom reports `2:4.19-1.fc40` (or vice versa), that's the epoch-placement issue.
- **Release-tag suffix truncation** — e.g., `.fc40` dropped or `.el9_1` re-quoted.
- **Character encoding drift** — tilde/caret/unicode differences.

Expected outcome: the majority of the 93 are one dominant failure mode; the fix is a narrow format change.

### Decision (post-diagnosis)

Once the diagnosis is written:

1. In `PackageDbEntry`, add `raw_version: Option<String>` holding the unmangled `%{VERSION}-%{RELEASE}` from the rpmdb header (or the `.rpm` artefact for `rpm_file.rs`).
2. In `rpm.rs::assemble_entry` and `rpm_file.rs::parse_rpm_file`, ensure the PURL version segment is `VERSION-RELEASE` (no epoch prefix). Epoch is emitted exclusively via the `epoch=` qualifier (already the case in `rpm.rs`, verify `rpm_file.rs` behaves identically — the audit flagged an inconsistency).
3. Emit the raw version as a CycloneDX component property `{ name: "mikebom:raw-version", value: <rawstring> }` when set.

### Rationale

- FR-014 explicitly requires diagnosis before the fix. Earlier rounds of this project showed that format changes without root-cause analysis created cascading debugging cycles.
- `raw-version` as a property (not a PURL qualifier) is correct because it's informational metadata, not an identity component.

### Alternatives considered

- **Emit the raw version as the PURL version segment verbatim**: rejected — that would mean `2:4.19-1.fc40` appears in the PURL version, which purl-spec rpm rules explicitly move to the `epoch=` qualifier.
- **Apply the fix to the current 93 mismatches without diagnosis, trusting that it's epoch handling**: rejected per FR-014.

### Code landing sites

| File | Change |
|---|---|
| Diagnostic output (no code) | A markdown section appended to `research.md` (under this heading) once the diagnosis runs. Pre-code gate. |
| `mikebom-cli/src/scan_fs/package_db/mod.rs` | Add `raw_version: Option<String>` field to `PackageDbEntry`. |
| `mikebom-cli/src/scan_fs/package_db/rpm.rs::assemble_entry` | Populate `raw_version = Some(format!("{version}-{release}"))`. Verify epoch placement (PURL qualifier only). |
| `mikebom-cli/src/scan_fs/package_db/rpm_file.rs::parse_rpm_file` | Same treatment. Resolve the `rpm.rs` vs `rpm_file.rs` inconsistency flagged in the audit. |
| `mikebom-cli/src/generate/cyclonedx/builder.rs` | Emit `mikebom:raw-version` property when set. |

## SC-009 — Os-release missing-fields metadata property

### Decision

Add a `ScanDiagnostics` struct accumulated during `read_all`:

```rust
pub struct ScanDiagnostics {
    pub os_release_missing_fields: Vec<String>,  // e.g., ["ID", "VERSION_ID"]
    // Future: other scan-time diagnostics go here.
}
```

When `read_id()` returns `None`, push `"ID"`. When `read_version_id()` returns `None`, push `"VERSION_ID"`. Dedupe before emitting.

At CycloneDX serialization time in `metadata.rs::build_metadata`, if `os_release_missing_fields` is non-empty, append a property:

```json
{
  "name": "mikebom:os-release-missing-fields",
  "value": "ID,VERSION_ID"   // comma-joined, no spaces
}
```

When the list is empty, the property is omitted entirely (not emitted with an empty value).

### Rationale

- Spec Clarification Q3 pinned this as the shape.
- A single comma-joined property (as opposed to repeated entries) matches CycloneDX convention and keeps the property count low.
- `ScanDiagnostics` as a struct (not a free-floating `Vec<String>`) leaves room for additional scan-time diagnostics without cross-module churn in the future.

### Alternatives considered

- **Multiple property entries with the same name** (`[{"name": "mikebom:os-release-missing-fields", "value": "ID"}, {"name": "...", "value": "VERSION_ID"}]`): rejected — spec pins single-entry comma-joined.
- **A per-component property on each affected deb/apk/rpm component**: rejected — the condition is scan-global, not per-component.
- **Emit the property unconditionally with an empty value when no fields are missing**: rejected per spec FR-006 — the property is absent when all fields present.

### Code landing sites

| File | Change |
|---|---|
| `mikebom-cli/src/scan_fs/package_db/mod.rs` | Add `ScanDiagnostics` struct. `read_all` returns it alongside existing outputs. |
| `mikebom-cli/src/scan_fs/mod.rs` | `scan_path` threads `ScanDiagnostics` to the SBOM builder. |
| `mikebom-cli/src/generate/cyclonedx/metadata.rs::build_metadata` | Accept `&ScanDiagnostics`; append the `mikebom:os-release-missing-fields` property when applicable. |

## Decisions summary

| ID | Decision | Rationale | Alternatives rejected |
|---|---|---|---|
| D1 | Glob-based npm-internals detection via `**/node_modules/npm/node_modules/**` | Spec Clarification Q1; simplest, no file I/O | File-content check, allow-list |
| D2 | `mikebom:npm-role=internal` per-component property | Spec Clarification Q2 | Ecosystem-agnostic scheme (tracked as todo #9) |
| D3 | `ScanMode` enum threaded from CLI to npm reader | Testable with synthetic fixtures; no side-channel state | Env-based, implicit detection |
| D4 | deb namespace from `/etc/os-release::ID`, raw lowercased, no rewrites | FR-008, FR-010 | `ubuntu→debian` rewrites, static namespace map |
| D5 | Drop `codename` from `build_deb_purl`; use `distro_version = VERSION_ID` | FR-005, FR-007 (byte-stable for apk/rpm) | Keep both; derive inside function |
| D6 | RPM diagnosis before fix; `raw_version` property added to `PackageDbEntry` | FR-011, FR-014 | Ad-hoc fix without diagnosis |
| D7 | `ScanDiagnostics` struct; single comma-joined metadata property | Spec Clarification Q3 | Repeated properties, per-component marker |

## Out-of-scope for Phase 0

- The RPM root-cause analysis narrative (FR-014) is NOT produced in Phase 0 — it's produced as part of Phase 3 (implementation) before any `rpm.rs` or `rpm_file.rs` edits. Phase 0 only decides the decision-sequence (diagnose → then fix).
- Task-level breakdown lives in Phase 2 (`tasks.md`, produced by `/speckit.tasks`), not here.
- No migration tooling for consumers of pre-change PURLs — spec explicitly documents the PURL-shape change in release notes and leaves it to consumers to re-key.

---

## US4 RPM Version Root-Cause Analysis

**Phase:** 3 (implementation gate per FR-014)
**Date:** 2026-04-20
**Fixture:** `sbom-fixture-polyglot:latest` (Fedora 40, 529 RPM packages, `aarch64`)

### Data gathered

1. `rpm -qa --queryformat '%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\n'` executed inside a live container → ground truth at `/tmp/polyglot-rpm-qa.tsv` (529 rows).
2. `rpmdb.sqlite` (22 MB) copied out and placed at `/tmp/poly-rootfs/usr/lib/sysimage/rpm/rpmdb.sqlite`.
3. Synthetic minimal rootfs: `/tmp/poly-rootfs/` containing only the rpmdb + `/etc/os-release` (copied verbatim from the image).
4. `mikebom sbom scan --path /tmp/poly-rootfs` (post-Phase 5, so Feature 005 US2/US3 already applied) → `/tmp/poly-sbom.cdx.json`.
5. Syft + Trivy baselines (CycloneDX JSON output) against the same image, for cross-tool comparison.

### Observed per-field mismatch counts (mikebom vs `rpm -qa`)

| Field | Mismatches / 529 | Notes |
|---|---|---|
| `VERSION-RELEASE` string | **0** | Every package's version string round-trips verbatim. The "93 VERSION_MISMATCH" headline was not a version-string parsing bug. |
| `EPOCH` | 26 | mikebom omits the qualifier when the header's `EPOCH` tag value equals 0, even though the tag is **present**. `rpm -qa` renders `0:…` in those cases. |
| `ARCH` | 1 | `gpg-pubkey` only: header reports `arch=(none)` (literal sentinel). mikebom currently omits the `arch=` qualifier for this sentinel; `rpm -qa` prints `(none)` verbatim. |
| `NAME` | 0 | 1-to-1 name coverage (529/529). |

Total distinct components with any mismatch: **27**.

### Interpretation of "93 VERSION_MISMATCH"

The 93-count quoted in the original triage reflected the prior pairing against an `--image` run in which the Fedora tar-extraction permission bug (separately tracked — docker_image.rs Phase N fix) caused only 19 of 529 rpm components to land in the SBOM. The remaining 510 were surfacing as `pkg:generic/<file-sha256>` entries with no version string, and the conformance tool counted each missing pairing-with-divergent-representation as a `VERSION_MISMATCH`. Once the Phase N extraction fix is in place and 529 rpm components actually emit, the real field-level mismatch count drops to the 27 observed above — all EPOCH/ARCH convention differences, no version-string parsing defects.

### Classification of the 27 remaining mismatches

#### Class A — EPOCH=0 omission (26 cases)

**Symptom:** For 26 packages whose rpmdb header stores `EPOCH=0` explicitly, mikebom emits no `epoch=` qualifier. Example packages: `aopalliance`, `perl-AutoLoader`, `perl-B`, `perl-Class-Struct`, 22 more in the perl/java ecosystems. `rpm -qa` on the live image confirms `%{EPOCH}=0, %{EPOCHNUM}=0` for each.

**Root cause:** `mikebom-cli/src/scan_fs/package_db/rpm.rs::assemble_entry` line 413:
```rust
let epoch_seg = if epoch != 0 { format!("&epoch={epoch}") } else { String::new() };
```
The branch collapses two distinct rpmdb-header states into a single output:
- State 1: `EPOCH` tag absent in header (444 packages on this image) — correctly omits qualifier
- State 2: `EPOCH` tag present, value = 0 (26 packages) — incorrectly omits qualifier

The caller path `build_entry_from_header` is the canonical rpmdb source; it extracts via `header.int32_array(TAG_EPOCH).and_then(|v| v.first().copied()).unwrap_or(0)`. When the tag is absent, `unwrap_or(0)` returns 0 — identical numeric to a header that stores 0 explicitly — so the presence information is lost at the moment of decode.

**Cross-tool comparison:** Syft 1.x emits `&epoch=0` on these packages (matches `rpm -qa`). Trivy 0.x omits it (matches mikebom). Neither the PURL spec (PURL-SPECIFICATION.rst §2) nor the rpm-type definition (PURL-TYPES.rst §rpm) settles this explicitly; `rpm -qa`'s display is the authoritative convention for the `%{EPOCH}-present-but-zero` case.

**Decision for US4:** preserve the tag-presence bit. When the rpmdb header has an `EPOCH` tag (regardless of its numeric value), emit `&epoch=<value>`. When the tag is absent, omit. This matches syft + `rpm -qa` and makes mikebom round-trip `rpm -qa` output exactly. Implementation: change `build_entry_from_header` to return `Option<i64>` (`Some(value)` when tag present, `None` when absent) and extend `assemble_entry` to take `Option<i64>` instead of `i64`. Text-columns fixture path (`build_entry_from_text_columns`) — we intentionally keep its `unwrap_or(0)` → `None` semantics unchanged because the synthetic fixture doesn't need to distinguish the two states; but the signature change threads through, so fixture tests pass `None` explicitly.

> **REVERSED 2026-04-20** (sbom-conformance pass): `epoch=0` is now omitted regardless of whether the tag was explicitly present in the header. Rationale: the conformance framework reports 27 exact-match failures from `epoch=0` emission; RPM semantics treat "no epoch" and "epoch = 0" as equivalent for version comparison; `rpm -qa`'s default display omits epoch when 0; the purl-spec rpm example never includes `epoch=0`. The `Some(0)` vs `None` distinction at the tag-presence bit is preserved internally (the option type remains), but `assemble_entry` matches `Some(v) if v != 0` instead of `Some(v)`. Trade-off: lose the ability to round-trip `rpm -qa --queryformat '%{EPOCH}'` exactly. Acceptable because consumer-side SBOM tools (vuln matchers, license scanners) treat the two states identically.

#### Class B — gpg-pubkey arch=`(none)` (1 case)

**Symptom:** Ground truth: `gpg-pubkey\t(None):a15b79cc-63d04c2c\t(none)`. mikebom emits `pkg:rpm/fedora/gpg-pubkey@a15b79cc-63d04c2c?distro=fedora-40` (no `arch=` qualifier). The current `assemble_entry` drops the arch qualifier when arch is empty, and the header for `gpg-pubkey` stores the literal four-character string `(none)` — mikebom treats that as a sentinel and omits.

**Decision:** leave as-is. The PURL-spec guidance for qualifier values is that they carry meaningful strings; emitting `arch=(none)` as a URL qualifier would normalize to `arch=%28none%29` under percent-encoding, which is strictly worse than omission for any downstream PURL-aware matcher. `rpm -qa`'s column format is a human-facing display convention, not a PURL convention. Documented in release notes; no code change.

### US4 scope, finalized

1. **T040** (no-op audit): Verify `rpm_file::parse_rpm_file` handles epoch with the same `Option<i64>` semantics chosen for `rpm.rs`. (Audit expected to find inline-prefix or identical-branch code; remediation in-task if divergent.)
2. **T041**: `assemble_entry` input changes from `epoch: i64` to `epoch: Option<i64>`. When `Some(v)` (tag present) → emit `&epoch=<v>` including `v == 0`. When `None` (tag absent) → omit. Populate `raw_version = Some(format!("{version}-{release}"))` on the emitted entry.
3. **T042**: Same change for `rpm_file::parse_rpm_file` epoch path + raw_version.
4. **T043**: CycloneDX builder emits `mikebom:raw-version` property when `entry.raw_version.is_some()`. Ordering: immediately after `mikebom:evidence-kind` when both present; otherwise at the same insertion point as today's property list.
5. **T044–T047**: unit tests covering (a) EPOCH tag present with value 0 preserves qualifier, (b) EPOCH absent omits qualifier (regression guard), (c) special chars in release survive (tilde, caret), (d) non-zero epoch always round-trips.
6. **T048**: integration test against a real rpmdb fixture that every emitted rpm component carries `mikebom:raw-version`.

### Expected SC-006 result

Post-US4, re-running the polyglot comparison:

- VERSION_MISMATCH count (field-level): **from 27 down to at most 1** (the `gpg-pubkey` arch case we're intentionally leaving).
- Under the SC-006 tolerance `< 5`, the post-US4 state passes.
- Release note adds two lines: (1) "`&epoch=0` is now emitted when the rpmdb header carries an explicit 0 value" and (2) "`mikebom:raw-version` property is now available on every rpm component and records the verbatim `VERSION-RELEASE` string from the rpmdb header".

### Artefacts

- `/tmp/polyglot-rpm-qa.tsv` — 529 ground-truth rows from `rpm -qa`.
- `/tmp/poly-sbom.cdx.json` — mikebom output on synthetic rootfs (post-Phase 5, pre-US4).
- `/tmp/fedora40-rpmdb.sqlite` — the rpmdb used for the synthetic rootfs.
- `/tmp/poly-rootfs/` — synthetic rootfs (rpmdb + os-release only) used by this analysis.

These four artefacts are non-authoritative scratch; they're not committed to the repo.
