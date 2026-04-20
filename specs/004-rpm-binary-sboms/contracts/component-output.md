# Contract: Per-Evidence-Kind CycloneDX Component Shape

One exemplar per evidence-kind. Every new reader MUST produce components conforming to the shapes below; deviations are blocking bugs. Keys marked **REQUIRED** are non-negotiable; `null` / missing is a test failure.

---

## `evidence-kind = "rpm-file"` (US1 — standalone `.rpm` artefact)

```json
{
  "bom-ref": "pkg:rpm/redhat/openssl-libs@3.0.7-28.el9_4?arch=x86_64",
  "type": "library",
  "name": "openssl-libs",
  "version": "3.0.7-28.el9_4",
  "purl": "pkg:rpm/redhat/openssl-libs@3.0.7-28.el9_4?arch=x86_64",
  "licenses": [
    { "expression": "OpenSSL-3.0 OR ASL-2.0" }
  ],
  "supplier": { "name": "Red Hat, Inc." },
  "author": "Red Hat Engineering",
  "description": "Libraries for programs that use OpenSSL cryptography …",
  "hashes": [
    { "alg": "SHA-256", "content": "<file sha of the .rpm>" }
  ],
  "properties": [
    { "name": "mikebom:evidence-kind",    "value": "rpm-file" },
    { "name": "mikebom:sbom-tier",        "value": "source" },
    { "name": "mikebom:vendor-source",    "value": "header" },
    { "name": "mikebom:source-files",     "value": "<abs path to .rpm file>" }
  ]
}
```

**REQUIRED**:

- `purl` canonical (round-trips through packageurl-python — FR-002, SC-001, SC-007).
- `supplier.name` non-empty (SC-001).
- `licenses[0]` non-empty when `License:` header tag was present (SC-001).
- `properties[].name == "mikebom:evidence-kind"` with value `"rpm-file"`.

**SRPM variant**: arch is `"src"`, PURL becomes `pkg:rpm/redhat/openssl@3.0.7-28.el9?arch=src` (FR-016).

**Missing `Vendor:` header**: `mikebom:vendor-source = "os-release"` or `"fallback"`; `supplier.name` may be absent in the fallback case.

---

## `evidence-kind = "rpmdb-sqlite"` (milestone-003 retrofit)

```json
{
  "bom-ref": "pkg:rpm/redhat/openssl-libs@3.0.7-28.el9_4?arch=x86_64",
  "type": "library",
  "name": "openssl-libs",
  "version": "3.0.7-28.el9_4",
  "purl": "pkg:rpm/redhat/openssl-libs@3.0.7-28.el9_4?arch=x86_64",
  "licenses": [ { "expression": "OpenSSL-3.0 OR ASL-2.0" } ],
  "supplier": { "name": "Red Hat, Inc." },
  "properties": [
    { "name": "mikebom:evidence-kind", "value": "rpmdb-sqlite" },
    { "name": "mikebom:sbom-tier",     "value": "deployed" }
  ]
}
```

**REQUIRED**: `mikebom:evidence-kind = "rpmdb-sqlite"` on every rpm component emitted via the milestone-003 sqlite path. Retrofit is a one-field addition to `rpm.rs::row_to_entry`.

**No other field changes** from milestone 003 — this is strictly a property addition.

---

## `evidence-kind = "rpmdb-bdb"` (US4 — opt-in legacy BDB)

Identical shape to `rpmdb-sqlite` except `mikebom:evidence-kind = "rpmdb-bdb"`. All other fields populated from the same HeaderBlob tag set, via the shared `rpm_header::HeaderBlob::parse` (R2).

```json
{
  "bom-ref": "pkg:rpm/amazon/glibc@2.26-64.amzn2?arch=x86_64",
  "type": "library",
  "name": "glibc",
  "version": "2.26-64.amzn2",
  "purl": "pkg:rpm/amazon/glibc@2.26-64.amzn2?arch=x86_64",
  "licenses": [ { "expression": "LGPL-2.1-or-later WITH GCC-exception-2.0" } ],
  "supplier": { "name": "Amazon Linux" },
  "properties": [
    { "name": "mikebom:evidence-kind", "value": "rpmdb-bdb" },
    { "name": "mikebom:sbom-tier",     "value": "deployed" }
  ]
}
```

---

## `evidence-kind = "dynamic-linkage"` (US2 — ELF / Mach-O / PE)

```json
{
  "bom-ref": "pkg:generic/libssl.so.3",
  "type": "library",
  "name": "libssl.so.3",
  "purl": "pkg:generic/libssl.so.3",
  "properties": [
    { "name": "mikebom:evidence-kind", "value": "dynamic-linkage" },
    { "name": "mikebom:sbom-tier",     "value": "analyzed" }
  ],
  "evidence": {
    "occurrences": [
      { "location": "<abs path to parent binary 1>" },
      { "location": "<abs path to parent binary 2>" }
    ]
  }
}
```

**REQUIRED**:

- `purl` form is `pkg:generic/<raw-linkage-name>` — soname for ELF, install-name for Mach-O (full path retained: `pkg:generic/@rpath%2Flibssl.48.dylib` with URL-encoded `/`), DLL name for PE.
- `evidence.occurrences[]` has at least one entry; every entry's `location` is the absolute path to a parent binary observed in the scan.
- When the same linkage target is referenced by multiple parent binaries in the scan, there is still exactly ONE component (FR-028a / Q5); occurrences accumulate.
- `version` field is absent (the binary alone doesn't tell us the installed version).

**No `hashes[]`** — the linkage target isn't a file on disk from our perspective; it's an identifier.

---

## `evidence-kind = "elf-note-package"` (US2 — distro self-identification)

Mapped to the target ecosystem's canonical PURL (R4 / FR-024). Example — Fedora-built curl binary:

```json
{
  "bom-ref": "pkg:rpm/fedora/curl@8.2.1?arch=x86_64",
  "type": "library",
  "name": "curl",
  "version": "8.2.1",
  "purl": "pkg:rpm/fedora/curl@8.2.1?arch=x86_64",
  "properties": [
    { "name": "mikebom:evidence-kind", "value": "elf-note-package" },
    { "name": "mikebom:sbom-tier",     "value": "source" }
  ],
  "evidence": {
    "occurrences": [
      { "location": "<abs path to the curl binary>" }
    ]
  }
}
```

**REQUIRED**: `sbom-tier = "source"` — distro self-identification is authoritative.

**Unknown `type`** (e.g. a new distro-specific value): PURL falls back to `pkg:generic/<name>@<version>`, and `properties[]` adds `mikebom:elf-note-package-type = <raw-type>`.

**Composition impact**: ELF-note-package components count toward their ecosystem's composition record — a scan containing ten `type=rpm` notes AND the installed rpmdb tallies both as evidence of RPM coverage (FR-029).

---

## `evidence-kind = "embedded-version-string"` (US2 — heuristic curated scanner)

```json
{
  "bom-ref": "pkg:generic/openssl@3.0.11",
  "type": "library",
  "name": "openssl",
  "version": "3.0.11",
  "purl": "pkg:generic/openssl@3.0.11",
  "properties": [
    { "name": "mikebom:evidence-kind", "value": "embedded-version-string" },
    { "name": "mikebom:sbom-tier",     "value": "analyzed" },
    { "name": "mikebom:confidence",    "value": "heuristic" }
  ],
  "evidence": {
    "occurrences": [
      { "location": "<abs path to parent binary>" }
    ]
  }
}
```

**REQUIRED**: `mikebom:confidence = "heuristic"` (FR-025). The property makes the low-confidence nature of this evidence explicit for downstream filtering.

**PURL dedup**: if ten binaries all embed the same OpenSSL version, one component with ten occurrences (parallels linkage-evidence dedup).

**Control set**: per SC-005, scanning ten Go/Rust binaries with no actual OpenSSL dependency MUST emit zero `pkg:generic/openssl@*` components via this path.

---

## Binary file-level component

Emitted one per binary scanned, regardless of format. Anchors `evidence.occurrences[]` pointers back to the physical file.

```json
{
  "bom-ref": "file:sha256:<hex>",
  "type": "file",
  "name": "<relative path from scan root>",
  "hashes": [
    { "alg": "SHA-256", "content": "<hex>" },
    { "alg": "SHA-1",   "content": "<hex>" }
  ],
  "properties": [
    { "name": "mikebom:binary-class",   "value": "elf" },
    { "name": "mikebom:binary-stripped","value": "true" },
    { "name": "mikebom:linkage-kind",   "value": "dynamic" },
    { "name": "mikebom:detected-go",    "value": "true" }
  ]
}
```

**REQUIRED**: `hashes[]` contains both SHA-256 and SHA-1 (Principle XI — multiple algorithms), `mikebom:binary-class` set to one of `{elf, macho, pe}`, `mikebom:binary-stripped` set to `true` or `false`.

**`mikebom:detected-go` appears ONLY when the Go BuildInfo extractor succeeded** (R8). Its absence is informational ("this is not a Go binary").

**`mikebom:binary-packed`** appears only when a packer signature was detected (FR-021, R7).

**`mikebom:binary-parse-limit`** appears only when a defense-in-depth cap fired during parsing (FR-007).

---

## Dependencies (edges)

### `.rpm`-file requires → same-scan targets

Per FR-015:

```json
{
  "ref": "pkg:rpm/redhat/openssl-libs@3.0.7-28.el9_4?arch=x86_64",
  "dependsOn": [
    "pkg:rpm/redhat/zlib@1.2.13-5.el9?arch=x86_64"
  ]
}
```

- Emitted only when the required target resolves to another RPM component observed in the same scan (either another `.rpm` file, a rpmdb-sqlite entry, or a rpmdb-bdb entry).
- Dangling requires (soname provides like `libc.so.6()(64bit)`, or targets not observed) drop silently — FR-015.

### BDB requires → same-scan targets

Identical shape to sqlite-rpmdb requires (milestone 003). The shared HeaderBlob parser feeds the same `depends: Vec<String>` into `PackageDbEntry`; the existing scan_fs edge resolver emits edges.

### Linkage-evidence components have no outgoing edges

By design: a `pkg:generic/libssl.so.3` linkage-evidence component has NO `dependsOn` list, because the binary alone doesn't tell us what `libssl.so.3` itself depends on. Transitive linkage resolution is not part of this milestone.

---

## Compositions

Per FR-029:

- **rpm**: `aggregate: complete` when an rpmdb (sqlite OR BDB) was read successfully; else `aggregate: incomplete_first_party_only` when only `.rpm` files were observed; else omit entirely.
- **deb**, **apk**, **alpm**: participate in the relevant ecosystem's composition tally when ELF-note-package emits a component of that ecosystem (FR-029).
- **Binary / generic-linkage-evidence**: NO composition record. Explicitly never `aggregate: complete` — binary analysis is intrinsically heuristic.

---

## Property-order stability

Properties within a single component's `properties[]` array are emitted in deterministic order:

1. `mikebom:evidence-kind`
2. `mikebom:sbom-tier`
3. `mikebom:confidence` (when present)
4. `mikebom:binary-class` (when present)
5. `mikebom:binary-stripped` (when present)
6. `mikebom:linkage-kind` (when present)
7. `mikebom:binary-packed` (when present)
8. `mikebom:detected-go` (when present)
9. `mikebom:vendor-source` (when present)
10. `mikebom:elf-note-package-type` (when present)
11. `mikebom:binary-parse-limit` (when present)
12. All pre-existing milestone-001/002/003 properties (unchanged order).

This is an additive extension of milestone-003's serializer order — no existing property moves.
