# Contract: SBOM Schema Deltas

Captures milestone-004's deltas to the emitted CycloneDX 1.6 JSON document at the document-level — property vocabulary extensions, compositions changes, and invariants across the full SBOM. Per-component shape is in `component-output.md`; this file covers the envelope.

---

## New `mikebom:*` property names

Alphabetised (property ordering within a component is covered in `component-output.md`):

| Property | Introduced by | Appears on | Value type |
|---|---|---|---|
| `mikebom:binary-class` | FR-021 | BinaryFileComponent | Enum: `elf`, `macho`, `pe` |
| `mikebom:binary-packed` | FR-021 | BinaryFileComponent (when detected) | Enum: `upx` |
| `mikebom:binary-parse-limit` | FR-007 | BinaryFileComponent (when cap fired) | Short string: `size-cap`, `section-count-cap`, `string-region-cap`, `iteration-budget` |
| `mikebom:binary-stripped` | FR-027 | BinaryFileComponent | Bool-as-string: `true`, `false` |
| `mikebom:confidence` | FR-025 | EmbeddedVersionMatch components | Enum: `heuristic` |
| `mikebom:detected-go` | R8, FR-026 | BinaryFileComponent (when Go BuildInfo succeeded) | Bool-as-string: `true` |
| `mikebom:elf-note-package-type` | FR-024 | ElfNotePackage-derived components with unknown `type` | Raw string from the `.note.package` payload |
| `mikebom:evidence-kind` | FR-004, Q7 | Every new component AND retrofit onto milestone-003 rpm-sqlite components | Enum: `rpm-file`, `rpmdb-sqlite`, `rpmdb-bdb`, `dynamic-linkage`, `elf-note-package`, `embedded-version-string` |
| `mikebom:linkage-kind` | FR-021 | BinaryFileComponent | Enum: `dynamic`, `static`, `mixed` |
| `mikebom:vendor-source` | FR-013 | RPM components (sqlite / bdb / rpm-file) | Enum: `header`, `os-release`, `fallback` |

Unchanged / pre-existing: see milestone 002 / 003 schema.md for the full existing vocabulary.

---

## Evidence-kind / sbom-tier matrix (invariant)

The serializer MUST enforce these pairings. Any other combination is a spec violation and fails `debug_assert!` at test time.

| `mikebom:evidence-kind` | `mikebom:sbom-tier` (MUST) |
|---|---|
| `rpm-file` | `source` |
| `rpmdb-sqlite` | `deployed` |
| `rpmdb-bdb` | `deployed` |
| `dynamic-linkage` | `analyzed` |
| `elf-note-package` | `source` |
| `embedded-version-string` | `analyzed` |

---

## Compositions

### RPM

- `rpmdb.sqlite` read successfully → `{"aggregate": "complete", "assemblies": [<all rpm purls>]}`. Unchanged from milestone 003.
- `--include-legacy-rpmdb` set AND `Packages` BDB read successfully (and no sqlite to conflict) → same `{"aggregate": "complete"}` record as the sqlite case.
- Only `.rpm` files observed (no rpmdb read) → `{"aggregate": "incomplete_first_party_only", "assemblies": [<rpm-file purls>]}` (FR-029, US3 AS-2).
- Mixed (rpmdb entry + `.rpm` files dedup to the same PURL) → one `aggregate: complete` record; the `.rpm`-file evidence is captured as an occurrence, not a separate assembly reference.

### deb / apk / alpm from ELF-note-package

When `.note.package`-sourced components are the ONLY deb/apk/alpm evidence in the scan:

- `aggregate: incomplete_first_party_only` (binary-note-based evidence is self-identification, which is authoritative per-component but doesn't mean the SBOM covers the whole ecosystem).

When `.note.package` + an installed-db of the same ecosystem coexist (rare but possible — a Fedora image with RPM-installed Fedora binaries embedding redundant `.note.package` metadata):

- Components dedup by PURL. Composition uses the installed-db's `aggregate: complete` (installed-db is the authoritative "we read the whole thing" signal).

### Binary / generic-linkage-evidence

**No composition record emitted** under any circumstances (FR-029). Linkage evidence is intrinsically heuristic; declaring aggregate state would be false transparency.

---

## Top-level SBOM invariants

Extends the milestone-002/003 invariants. An SBOM produced by milestone 004 MUST satisfy all of:

1. **No duplicate `bom-ref`**: every component's `bom-ref` is unique within `components[]`.
2. **No duplicate `purl`**: every component's `purl` is unique within `components[]` (follows from FR-008 / FR-028a PURL-first dedup).
3. **Every `dependencies[].dependsOn[]` entry resolves**: references a `bom-ref` present in `components[]` (scan_fs edge resolver drops dangling targets before emission — FR-015).
4. **Every `evidence.occurrences[]` `location`** is an absolute path that exists within the scan root at the time of scanning.
5. **Property ordering** (see `component-output.md`) is deterministic across runs on the same input — SBOMs are bit-for-bit reproducible when scan input is unchanged.
6. **Metadata block** carries the same `metadata.component` + `metadata.tools.components` + `metadata.properties.mikebom:generation-context` entries as milestones 001–003; no deltas.

---

## Backward compatibility

**Additive-only delta**. Every invariant and field present in a milestone-003 SBOM remains present in a milestone-004 SBOM of the same target, with the same value.

One meaningful behaviour change **for rpm-sqlite components only**: they now carry `mikebom:evidence-kind = "rpmdb-sqlite"` (Q7 canonicalization). Consumers that don't know the property ignore it per CycloneDX's forward-compatibility rules. Consumers that DO care about `evidence-kind` can now filter `rpmdb-*` across the ecosystem.

No breaking changes. No JSON-schema deletions. No reordering of pre-existing properties.
