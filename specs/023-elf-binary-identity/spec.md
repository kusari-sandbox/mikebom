---
description: "Extract ELF NT_GNU_BUILD_ID, DT_RPATH/DT_RUNPATH, and .gnu_debuglink to fill the binary-identity + runtime-linkage gap"
status: spec
milestone: 023
---

# Spec: ELF binary identity

## Background

mikebom's ELF binary scanner already reads systemd FDO Packaging Metadata via the
`object` crate's note-walking API (`mikebom-cli/src/scan_fs/binary/elf.rs:43-79`).
It does NOT read three other near-universal ELF identity / linkage signals that
the same primitives could surface:

- **NT_GNU_BUILD_ID** — 20-byte SHA-1-derived note (`.note.gnu.build-id` section)
  emitted by every modern toolchain (gcc, clang, rustc, golang). Deterministic per
  compile output. The canonical binary identity used by `eu-unstrip`,
  `coredumpctl`, `debuginfod`, kernel oops decoders, and every Linux
  debuginfo-package convention. Without it, mikebom cannot dedupe "same binary in
  two container layers" or correlate to a `*-dbgsym` package.

- **DT_RPATH / DT_RUNPATH** — dynamic-section tags listing extra library search
  paths the binary's loader will consult. Today mikebom's `linkage.rs:23-32`
  hardcodes a small set of standard library directories and skips RPATH; this
  causes false-negative library resolution when binaries ship with embedded
  search paths (very common for vendored Rust/C++ binaries, Java JNI libraries,
  and bundled application stacks).

- **.gnu_debuglink** — a section name + CRC32 pointing at a sibling stripped-debug
  file (typically `<basename>.debug` under `/usr/lib/debug/.build-id/`). Captures
  the "this binary's debug symbols live in package X" relationship.

These three together establish ELF binary identity in a way mikebom currently
lacks. They are independent of milestones 1-22 — pure additive scanning.

External callers are unaffected; the changes manifest as new annotation rows in
all three SBOM formats (CDX/SPDX 2.3/SPDX 3) via the established
`mikebom:elf-build-id`, `mikebom:elf-runpath`, `mikebom:elf-debuglink` envelope.

## User story (US1, P1)

**As an SBOM consumer correlating a binary across container layers or to its
debuginfo package**, I want each ELF component in mikebom output to carry its
NT_GNU_BUILD_ID, RPATH/RUNPATH list, and .gnu_debuglink reference (when present)
so that downstream tools can stable-identify the binary, resolve runtime linkage
correctly, and locate the matching debug-symbol package.

**Why P1 (not P2):** this is correctness-flavored, not hygiene. Until build-id
lands, mikebom's binary identity is "absolute path on disk" — which doesn't
deduplicate across layers and doesn't survive renames. That's a real
data-quality gap, not just a polish item.

### Independent test

After implementation:
- `target/debug/mikebom sbom scan --path tests/fixtures/binaries/elf/with-build-id`
  emits CDX with property `name: mikebom:elf-build-id`, value matching the
  fixture's known 40-hex-char build-id.
- Same scan emits SPDX 2.3 annotation envelope with `field: mikebom:elf-build-id`.
- Same scan emits SPDX 3 annotation envelope with same field.
- Three new catalog rows (C24, C25, C26 — or whatever IDs the catalog parser
  assigns next) appear in the C section of `docs/reference/sbom-format-mapping.md`,
  and `holistic_parity` test asserts SymmetricEqual on all three.
- `tests/scan_binary.rs` gains assertions that the three fields populate when the
  fixture has them and are absent when not.
- 27 byte-identity goldens regen with deltas only in the new fields (existing
  fields untouched).

## Acceptance scenarios

**Scenario 1: Build-id round-trip across formats**
```
Given: an ELF binary with NT_GNU_BUILD_ID = 40-hex-char value X
When:  mikebom emits CDX + SPDX 2.3 + SPDX 3 from a single scan
Then:  all three contain a `mikebom:elf-build-id` annotation/property whose
       canonical-flatten value equals X, AND `holistic_parity` agrees on
       SymmetricEqual.
```

**Scenario 2: Multi-RPATH binary**
```
Given: an ELF binary with DT_RUNPATH = "$ORIGIN/../lib:/opt/vendor/lib"
When:  mikebom scans it
Then:  the emitted `mikebom:elf-runpath` annotation contains a JSON array of
       the two unexpanded path entries (mikebom does NOT expand $ORIGIN; the
       raw string is what consumers want).
```

**Scenario 3: Stripped binary with debuglink**
```
Given: an ELF binary with .gnu_debuglink = "foo.debug" + CRC32 = 0xDEADBEEF
When:  mikebom scans it
Then:  the emitted `mikebom:elf-debuglink` annotation has shape
       {"file": "foo.debug", "crc32": "0xdeadbeef"} canonicalized.
```

**Scenario 4: Absent fields don't produce empty annotations**
```
Given: an ELF binary built with `-Wl,--build-id=none` (no build-id note)
When:  mikebom scans it
Then:  no `mikebom:elf-build-id` annotation is emitted (vs an annotation with
       empty value). Same for absent runpath / debuglink.
```

## Edge cases

- **Build-id formats:** NT_GNU_BUILD_ID notes can be SHA-1 (20 bytes, the gcc/
  clang default), MD5 (16 bytes, rare), or other lengths. Emit as lowercase
  hex regardless of length. `object::read::elf::NoteIterator` provides the raw
  bytes; we hex-encode.
- **Both DT_RPATH and DT_RUNPATH present:** emit both, deduplicated. The runtime
  loader honors RUNPATH over RPATH when both exist; mikebom records what the
  binary declares without interpretation.
- **`$ORIGIN`, `$LIB`, `$PLATFORM` substitutions:** record the unexpanded string.
  Expansion is runtime-context-dependent; consumers can re-expand if needed.
- **CRC32 in .gnu_debuglink:** record as 8-hex-char lowercase string (matches
  `eu-readelf` convention). Don't validate that the referenced .debug file
  exists — that's a separate "debuglink-hits-debuginfod" concern.
- **Fat / multi-arch ELF:** doesn't exist (ELF is always single-arch). No
  per-slice handling needed.
- **Non-readable note section (corrupt binary):** silently skip. Same defensive
  posture as `extract_note_package` already takes (`elf.rs:43-79` returns None
  on parse failure).

## Functional requirements

- **FR-001**: `mikebom-cli/src/scan_fs/binary/elf.rs` gains three new
  `pub(super) fn` extractors: `extract_gnu_build_id(file) -> Option<String>`,
  `extract_runpath_entries(file) -> Vec<String>`, `extract_debuglink(file) ->
  Option<DebuglinkEntry>`. Each follows the same shape as the existing
  `extract_note_package`: parse via `object::read::elf::*`, return `None` on
  any parse failure, no panics.

- **FR-002**: `mikebom-cli/src/scan_fs/binary/entry.rs::BinaryScan` gains three
  new fields: `build_id: Option<String>`, `runpath: Vec<String>`,
  `debuglink: Option<DebuglinkEntry>` where `DebuglinkEntry { file: String,
  crc32: u32 }`. Defaults are None / empty Vec / None.

- **FR-003**: `mikebom-cli/src/scan_fs/binary/scan.rs::scan_binary` populates
  the three new fields by calling the FR-001 extractors when the binary is
  ELF. Non-ELF (Mach-O, PE) leaves the fields at their default values.

- **FR-004**: `mikebom-cli/src/scan_fs/binary/mod.rs` emits three new
  annotations on the binary's `PackageDbEntry` when each field is populated:
  - `mikebom:elf-build-id` with a string value (the hex-encoded build-id).
  - `mikebom:elf-runpath` with a JSON array value.
  - `mikebom:elf-debuglink` with a JSON object value `{"file": ..., "crc32": ...}`.
  Empty/None fields skip emission per Scenario 4.

- **FR-005**: `docs/reference/sbom-format-mapping.md` gains three new C-section
  rows (next available IDs after C23) for the three annotations. All three
  classified `Present` × 3 formats × `SymmetricEqual`.

- **FR-006**: `mikebom-cli/src/parity/extractors/{cdx,spdx2,spdx3}.rs` each
  gain three new annotation extractors via the established `*_anno!` macros,
  one line per extractor. The `EXTRACTORS` table in `parity/extractors/mod.rs`
  gains three new `ParityExtractor` rows.

- **FR-007**: `mikebom-cli/tests/fixtures/binaries/elf/` gains at least three
  fixtures: (a) one with build-id + RPATH + debuglink, (b) one with build-id
  only, (c) one with no build-id (`-Wl,--build-id=none`). Fixtures are
  small (< 64 KB), deterministically built, checked in.

- **FR-008**: `mikebom-cli/tests/scan_binary.rs` gains assertions that exercise
  the three fixtures and verify the three new fields populate / don't populate
  as expected.

- **FR-009**: `mikebom-cli/tests/holistic_parity.rs` continues to pass — the
  three new C-section rows are SymmetricEqual across formats.

- **FR-010**: 27 byte-identity goldens regen produces deltas only on fixtures
  that contain ELF binaries. Non-binary fixtures (cargo, npm, pip, deb, rpm,
  apk, gem, golang, synthetic-container-image) emit zero diff.

## Success criteria

- **SC-001**: All four standard verification gates green:
  - `./scripts/pre-pr.sh` clean (default lane).
  - `cargo +stable test -p mikebom --test scan_binary` includes the three new
    assertions and they pass.
  - `cargo +stable test -p mikebom --test holistic_parity` green.
  - 27-golden regen (`MIKEBOM_UPDATE_*_GOLDENS=1`) shows deltas only in
    binary-fixture goldens, no diff in non-binary.

- **SC-002**: SC-001's `scan_binary` test exercises a real-world ELF binary
  (`/bin/ls` already used by the existing test) and asserts that
  `build_id.is_some()` (every modern Linux distro ships build-ids).

- **SC-003**: `git diff main..023-elf-binary-identity -- mikebom-cli/src/scan_fs/binary/macho.rs mikebom-cli/src/scan_fs/binary/pe.rs` is empty.
  Mach-O / PE stubs are out of scope.

- **SC-004**: `wc -l mikebom-cli/src/scan_fs/binary/elf.rs` increases by no
  more than 250 LOC. (Current: ~170. Budget: ≤ 420.)

- **SC-005**: `git diff main..HEAD -- mikebom-cli/src/cli/ mikebom-cli/src/generate/ mikebom-cli/src/resolve/` is empty.
  No CLI / generator / resolver changes.

- **SC-006**: All 3 CI lanes (Linux default + Linux ebpf + macOS) green on the
  milestone PR.

## Clarifications

- **Annotations, not first-class fields**: `build_id` etc. are emitted as
  `mikebom:*` annotations rather than CDX-native or SPDX-native fields because
  none of the three formats has a standardized place for them. CycloneDX has
  a `bom-ref`-style identifier but it's local to the document; SPDX has SPDXID
  but same. The mikebom annotation envelope is the right level — consumers can
  promote to native fields downstream if/when standards catch up.

- **Don't expand `$ORIGIN`**: the runpath value is recorded raw. Expansion is
  runtime-context-dependent (depends on the actual binary path) and would
  require mikebom to embed loader semantics, which is out of scope.

- **No CRC32 verification of debuglink**: mikebom records the declared CRC32;
  it does not chase the .debug file or verify the CRC matches.

- **No build-id → debuginfod lookup**: mikebom records the build-id; downstream
  tools can use it to fetch debuginfo from a debuginfod server. mikebom doesn't
  do network lookups.

## Out of scope

- Mach-O LC_UUID / codesign / entitlements (deferred to milestone 024).
- PE Delay-Load / subsystem / machine-type (deferred to milestone 028).
- Go VCS metadata extraction (deferred to milestone 025).
- Rust `cargo-auditable` detection (separate net-new feature).
- Container layer attribution (deferred to milestone 027).
- Build-id-based cross-binary dedup at scan time (downstream concern; mikebom
  records the field but doesn't act on it).
