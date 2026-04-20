# CycloneDX Output Contract: PURL & Scope Alignment

**Feature**: `005-purl-and-scope-alignment`

This contract specifies the exact SBOM output-shape changes this feature introduces. It is the binding reference for acceptance testing (SC-001 through SC-009).

## PURL shapes

### deb PURLs (changed)

**Before (current behaviour)**:

```text
pkg:deb/debian/libc6@2.36-9+deb12u7?arch=amd64&distro=bookworm
pkg:deb/debian/libssl3@3.0.14-1~deb12u2?arch=amd64&distro=bookworm
pkg:deb/debian/libssl3@3.0.13-0ubuntu3.4?arch=amd64&distro=noble       ← Ubuntu image, wrong namespace
```

**After (this feature)**:

```text
pkg:deb/debian/libc6@2.36-9+deb12u7?arch=amd64&distro=debian-12
pkg:deb/debian/libssl3@3.0.14-1~deb12u2?arch=amd64&distro=debian-12
pkg:deb/ubuntu/libssl3@3.0.13-0ubuntu3.4?arch=amd64&distro=ubuntu-24.04 ← correct namespace
```

Qualifier ordering: `arch` precedes `distro`. Other qualifiers (not introduced here, e.g. `epoch`) retain their pre-change order per purl-spec conventions.

### apk PURLs (unchanged)

```text
pkg:apk/alpine/busybox@1.36.1-r31?arch=aarch64&distro=alpine-3.20.9
```

The `<ID>-<VERSION_ID>` format was already correct. SC-004 requires byte-for-byte stability here.

### rpm PURLs (unchanged format; version segment handling clarified)

```text
pkg:rpm/fedora/bash@5.2.15-5.fc40?arch=aarch64&epoch=0&distro=fedora-40
pkg:rpm/rocky/bash@5.1.8-6.el9_1?arch=aarch64&distro=rocky-9.3
```

Invariants:

- Version segment is `VERSION-RELEASE` only. Never `EPOCH:VERSION-RELEASE`.
- Epoch appears exclusively as the `epoch=` qualifier. When epoch is 0, the qualifier may be omitted (retains pre-change behaviour).
- SC-004 requires byte-for-byte stability for fixtures where the above was already correct. The fix in US4 targets specific malformed emissions (the 93 mismatches on polyglot-builder-image).

## Component properties

### `mikebom:npm-role` (new)

Applied to: components whose source path matches `**/node_modules/npm/node_modules/**`.
Scan-mode requirement: only emitted on `--image` scans (where such components exist at all).

```json
{
  "type": "library",
  "name": "@npmcli/arborist",
  "version": "...",
  "purl": "pkg:npm/%40npmcli/arborist@...",
  "properties": [
    { "name": "mikebom:npm-role", "value": "internal" }
  ]
}
```

Consumer filtering:

- Exclude npm tool internals: drop components where `properties` contains `{name: "mikebom:npm-role", value: "internal"}`.
- Include only internals: inverse.

Future values: additional role strings may be added in later releases. Consumers SHOULD treat unknown values as "not app-dependency" for filtering purposes.

### `mikebom:raw-version` (new, rpm only)

Applied to: every rpm component emitted by `rpm.rs` or `rpm_file.rs`.
Value: the unmangled `%{VERSION}-%{RELEASE}` from the rpmdb header or `.rpm` artefact.

```json
{
  "name": "bash",
  "version": "5.2.15-5.fc40",
  "purl": "pkg:rpm/fedora/bash@5.2.15-5.fc40?arch=aarch64&epoch=0&distro=fedora-40",
  "properties": [
    { "name": "mikebom:raw-version", "value": "5.2.15-5.fc40" }
  ]
}
```

When PURL version and raw version are byte-identical (most cases), the property is still emitted — it guarantees round-trippability even when purl-spec encoding rules kick in for unusual characters.

## Document-level metadata properties

### `mikebom:os-release-missing-fields` (new)

Emitted as an entry in `metadata.properties` of the CycloneDX document when one or more `/etc/os-release` fields expected by this feature are missing.

Emitted example (both fields missing):

```json
{
  "metadata": {
    "properties": [
      { "name": "mikebom:generation-context", "value": "..." },
      { "name": "mikebom:os-release-missing-fields", "value": "ID,VERSION_ID" }
    ]
  }
}
```

Emitted example (only `VERSION_ID` missing):

```json
{
  "metadata": {
    "properties": [
      { "name": "mikebom:generation-context", "value": "..." },
      { "name": "mikebom:os-release-missing-fields", "value": "VERSION_ID" }
    ]
  }
}
```

Omitted entirely when all fields are present (clean case).

Value format:

- Comma-separated, no spaces (`"ID,VERSION_ID"`, not `"ID, VERSION_ID"`).
- Field names in the case they appear in `/etc/os-release` (uppercase).
- Stable ordering: the order fields are read/tested during scan (currently `ID` then `VERSION_ID`).
- Deduplicated: each field name appears at most once.

Consumer usage:

- A consumer seeing `VERSION_ID` in the value knows deb/apk/rpm PURLs from this scan OMIT the `distro=` qualifier.
- A consumer seeing `ID` in the value knows deb PURLs fell back to `pkg:deb/debian/` regardless of the actual distro.
- Absence of the property means every PURL's namespace and `distro=` qualifier is authoritative.

## Component-count contracts (regression guards)

For each fixture in the sbom-conformance suite, the post-feature component count per ecosystem MUST satisfy:

| Fixture | Ecosystem | Pre-feature count | Post-feature requirement |
|---|---|---|---|
| comprehensive | npm | (current baseline) | +172 (close to ground-truth expected count) |
| debian-bookworm-minimal | deb | N | **exactly N** (byte-stable on deb PURL namespace, only qualifier value changes) |
| ubuntu-24.04-minimal | deb | N | **exactly N** |
| alpine-3.20-minimal | apk | N | **exactly N** (SC-004 byte-stable) |
| rocky-9-minimal | rpm | N | **exactly N** (SC-004 byte-stable) |
| polyglot-builder-image | rpm | N | **exactly N** (version-format fix; count unchanged) |

No fixture's non-targeted-ecosystem count may change by more than 2% (SC-007).

## Ordering guarantees

- **Within a component**: properties are emitted in insertion order. For rpm components, `mikebom:raw-version` comes after any pre-existing property (e.g. `mikebom:evidence-kind`).
- **Within `metadata.properties`**: `mikebom:generation-context` (if present) before `mikebom:os-release-missing-fields`.
- **Within the SBOM document**: no ordering changes to components. Existing sort order preserved.

## Field encoding

- PURL qualifiers: percent-encoded per purl-spec rules. No mikebom-side double-encoding.
- Property values: emitted as-is (plain strings). No URL encoding, no base64.
- Version strings in `mikebom:raw-version`: emitted as-is, preserving any special characters from the rpmdb header (tilde, caret, etc.). Consumers that need spec-compliant encoding apply it themselves.
