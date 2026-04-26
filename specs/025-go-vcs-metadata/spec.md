---
description: "Surface Go BuildInfo VCS metadata (commit SHA, build timestamp, dirty flag) on the main-module PackageDbEntry via the milestone-023 extra_annotations bag"
status: spec
milestone: 025
---

# Spec: Go VCS metadata to entry

## Background

Go's `runtime/debug.BuildInfo` carries more than just the module list mikebom
already extracts — it also records the VCS state of the source tree at build
time. When a Go binary is built with `go build -buildvcs=true` (the default
since Go 1.18), the toolchain stamps the binary with:

- `vcs` — VCS system used (typically `"git"`)
- `vcs.revision` — commit SHA of the source tree
- `vcs.time` — RFC 3339 timestamp of the commit
- `vcs.modified` — `"true"` or `"false"` (was the working tree dirty?)

These show up as TAB-separated `key<TAB>value` lines in the BuildInfo
**vers_info blob** alongside the Go version. mikebom's parser
(`mikebom-cli/src/scan_fs/package_db/go_binary.rs::parse_go_version_from_build_info`,
line 346) reads only the FIRST line of that blob (the Go version) and
discards the rest:

```rust
fn parse_go_version_from_build_info(s: &str) -> Option<String> {
    let trimmed = s.trim();
    let first_line = trimmed.lines().next()?.trim();
    Some(first_line.to_string())
}
```

The VCS lines are present in `s` but never read. Confirmed by inspecting
the byte path through `decode_buildinfo` (line 179): `vers_bytes` →
`vers_info: String` → `parse_go_version_from_build_info` → only
`go_version: Option<String>` lands on `GoBinaryInfo`.

This is data mikebom already has but doesn't surface — pure data plumbing
gap, no new parsers needed beyond a few-line addition that splits the
remaining lines into key-value pairs.

This is the **first follow-on consumer** of the milestone-023 generic
`extra_annotations` bag. Adding three new keys to the bag from the
main-module `PackageDbEntry` requires zero PackageDbEntry-init-site churn
and zero `generate/` plumbing changes — exactly the amortization payoff
the bag was designed for.

## User story (US1, P2)

**As an SBOM consumer auditing a Go binary**, I want each Go-binary-derived
component in mikebom output to carry the source-tree VCS state recorded
at build time (commit SHA, build timestamp, dirty flag) so that I can
correlate the binary back to its exact source revision and confirm
build-tree cleanliness.

**Why P2 (not P1):** the data is recoverable today via `go version -m`
on the binary, so consumers aren't completely blocked. But surfacing it
in the SBOM removes a manual step and makes Go binaries first-class
citizens of the mikebom audit trail. Real value, low risk, fast scope.

### Independent test

After implementation:

- A Go binary built with `-buildvcs=true` (or built from inside a git
  worktree — Go's default) emits a CDX component with three new
  properties: `mikebom:go-vcs-revision`, `mikebom:go-vcs-time`,
  `mikebom:go-vcs-modified`.
- Same scan emits SPDX 2.3 + SPDX 3 annotation envelopes for each of
  the three.
- The annotations attach to the **main-module** Go entry (the
  `pkg:golang/<module-path>@<version>` row), not to dep entries — VCS
  metadata is for the binary's primary module, not its dependencies.
- A Go binary built with `-buildvcs=false` (or with no git worktree at
  build time) emits no `mikebom:go-vcs-*` annotations — the bag stays
  empty for those keys.
- The 27 byte-identity goldens regen with deltas only on Go-binary
  fixtures whose BuildInfo carries VCS metadata.

## Acceptance scenarios

**Scenario 1: Clean build with VCS metadata**
```
Given: a Go binary built with `go build -buildvcs=true` from a clean git
       worktree at commit X, build time T
When:  mikebom scans it
Then:  the main-module CDX component has properties:
         mikebom:go-vcs-revision = X
         mikebom:go-vcs-time     = T (RFC 3339)
         mikebom:go-vcs-modified = "false"
       AND the same three annotations land in SPDX 2.3 + SPDX 3 outputs
```

**Scenario 2: Dirty build**
```
Given: a Go binary built from a worktree with uncommitted changes
When:  mikebom scans it
Then:  the main-module entry's mikebom:go-vcs-modified = "true"
```

**Scenario 3: VCS-disabled build**
```
Given: a Go binary built with `-buildvcs=false` (no VCS keys in BuildInfo)
When:  mikebom scans it
Then:  no mikebom:go-vcs-* annotations are emitted on any component
       (empty bag for those keys; existing mikebom:* annotations
       unaffected)
```

**Scenario 4: Dep entries don't carry VCS metadata**
```
Given: a Go binary with main module M and 3 deps D1, D2, D3
When:  mikebom scans it
Then:  the main-module entry M carries the mikebom:go-vcs-* annotations;
       D1, D2, D3 entries do NOT (their VCS info isn't in this binary's
       BuildInfo)
```

## Edge cases

- **Mixed VCS systems**: Go also supports `hg` (Mercurial). The `vcs`
  key value passes through verbatim — mikebom doesn't validate the
  enum. The `mikebom:go-vcs-system` key is **explicitly out of scope**
  for this milestone (almost always `"git"`; can land later if needed).
- **Truncated BuildInfo**: if the vers_info blob is malformed, only the
  Go version is parsed (existing behavior); VCS keys absent silently.
- **TAB vs space separators**: Go writes `key<TAB>value`. The parser
  only splits on TAB; spaces in values pass through verbatim.
- **Non-ASCII timestamps**: Go's `vcs.time` is always RFC 3339 ASCII.
  The parser uses `lines()` + `splitn(2, '\t')` — handles UTF-8
  anywhere in the value safely.
- **Trailing whitespace / multiline values**: Go writes one line per
  key with `\n` separators. Parser trims whitespace per line before
  matching.
- **Multiple `vcs.*` lines for same key**: shouldn't happen per Go's
  output convention. If it does, last value wins (single-pass parse).

## Functional requirements

- **FR-001**: `mikebom-cli/src/scan_fs/package_db/go_binary.rs` adds a
  new `pub struct GoVcsInfo` with optional fields `revision: Option<String>`,
  `time: Option<String>`, `modified: Option<bool>`. (The `vcs` system
  key — typically "git" — is not surfaced this milestone per spec
  Edge Cases.)
- **FR-002**: `GoBinaryInfo` (line 64) gains `pub vcs: Option<GoVcsInfo>`
  field. `None` when no VCS keys present in BuildInfo; `Some(GoVcsInfo)`
  when at least one VCS key is parsed.
- **FR-003**: `parse_go_version_from_build_info` is renamed (or paired
  with) `parse_vers_info` that returns `(Option<String>, Option<GoVcsInfo>)`
  — the Go version + the VCS metadata. The existing single-line behavior
  for the version stays; the new code walks lines >= 2 looking for
  `vcs.*` keys.
- **FR-004**: `decode_buildinfo` (line 179) populates the new field on
  `GoBinaryInfo`.
- **FR-005**: The main-module `PackageDbEntry` construction in
  `go_binary.rs` (line ~587) populates `extra_annotations` from
  `info.vcs`:
  - `mikebom:go-vcs-revision` ← `vcs.revision` (if Some)
  - `mikebom:go-vcs-time` ← `vcs.time` (if Some)
  - `mikebom:go-vcs-modified` ← `vcs.modified.map(|b| if b { "true" } else { "false" })` (if Some)
  Empty/None values skip insertion (per spec Scenario 3).
- **FR-006**: The dep `PackageDbEntry` construction (line ~623) does
  NOT populate VCS annotations on dep entries. Per Scenario 4, VCS is a
  main-module concern.
- **FR-007**: 3 new C-section catalog rows in
  `docs/reference/sbom-format-mapping.md` (next available IDs after
  C26, so C27/C28/C29) for the three annotations. All three classified
  `Present` × 3 formats × `SymmetricEqual`.
- **FR-008**: `mikebom-cli/src/parity/extractors/{cdx,spdx2,spdx3}.rs`
  each gain three new `*_anno!` invocations. The `EXTRACTORS` table in
  `parity/extractors/mod.rs` gains three new `ParityExtractor` rows + 9
  fn imports.
- **FR-009**: 3 new inline tests in
  `mikebom-cli/src/scan_fs/package_db/go_binary.rs::tests` exercising
  the `parse_vers_info` extension: with-all-three-vcs-keys,
  with-only-revision, with-no-vcs-keys.
- **FR-010**: Each commit in the milestone leaves
  `./scripts/pre-pr.sh` clean (per-commit-clean discipline from
  milestones 018-023).

## Success criteria

- **SC-001**: All four standard verification gates green:
  - `./scripts/pre-pr.sh` clean.
  - `cargo +stable test -p mikebom --lib scan_fs::package_db::go_binary` includes the 3 new
    inline tests + they pass.
  - `cargo +stable test -p mikebom --test holistic_parity` green.
  - 27-golden regen produces no diff on existing fixtures (the
    canonical Cargo/npm/pip/etc. fixtures don't include Go binaries
    with VCS metadata; the synthetic-container-image fixture might —
    will see and document either way).
- **SC-002**: A Go binary built with VCS metadata embedded — verified
  via the `build_inline_buildinfo` test helper — emits all three
  annotations on the main-module entry.
- **SC-003**: A Go binary without VCS metadata — verified the same way
  with no `vcs.*` lines in the build_info blob — emits zero
  `mikebom:go-vcs-*` annotations.
- **SC-004**: `wc -l mikebom-cli/src/scan_fs/package_db/go_binary.rs`
  increases by ≤ 200 LOC. (Current: ~1400. Budget: ≤ 1600.)
- **SC-005**: `git diff main..HEAD -- mikebom-common/ mikebom-cli/src/cli/ mikebom-cli/src/resolve/ mikebom-cli/src/generate/`
  is empty. The bag absorbs the new keys; no other plumbing.
- **SC-006**: All 3 CI lanes green.
- **SC-007**: Bag amortization proof: `git diff main..HEAD --
  mikebom-cli/src/scan_fs/package_db/{apk,cargo,dpkg,gem,golang,maven,npm,pip,rpm}.rs`
  is empty (the 30 PackageDbEntry-init sites NOT touched — the bag
  did its job).

## Clarifications

- **Annotations, not first-class fields**: `mikebom:go-vcs-*` lands
  in the `extra_annotations` bag (milestone 023). No PackageDbEntry
  schema change. Future milestones (024 Mach-O LC_UUID, 026 version
  strings, 027 layer attribution) follow the same pattern.
- **`vcs.modified` as string "true"/"false"**: matches Go's own wire
  format (Go writes the literal string in BuildInfo). Consumers can
  parse if needed; mikebom preserves the surface.
- **`vcs.system` (typically "git") deferred**: low signal — almost
  always `"git"`. If an `hg` or other-VCS use case emerges later,
  add it as `mikebom:go-vcs-system` in a follow-up.
- **Main-module-only emission**: Dep modules don't carry VCS info in
  the parent binary's BuildInfo (their VCS is their own go.mod, not
  the binary's). Emitting on every dep would be misleading.
- **No git-history walking, no upstream lookups**: mikebom records
  what BuildInfo declares; it doesn't verify against the actual
  repo or chase the commit.

## Out of scope

- `mikebom:go-vcs-system` (deferred).
- Validating commit-SHA format (could be 7-char short hash, full
  40-char SHA-1, or something else — record verbatim).
- Resolving dirty trees to specific changed files.
- Mach-O LC_UUID / codesign (milestone 024).
- ELF binary metadata expansion beyond what milestone 023 already did.
- Container layer attribution (milestone 027).
