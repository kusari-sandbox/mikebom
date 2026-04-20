# Feature Specification: PURL & Scope Alignment

**Feature Branch**: `005-purl-and-scope-alignment`
**Created**: 2026-04-20
**Status**: Draft
**Input**: User description: "Update mikebom to align four PURL and scoping behaviors with current spec direction and industry practice — (1) adopt {ID}-{VERSION_ID} distro qualifier format sourced from `/etc/os-release`; (2) derive the deb PURL namespace from the distro ID rather than hardcoding `debian`; (3) make npm-internals inclusion depend on scan mode (image vs project directory); (4) investigate and resolve RPM version-string mismatches against `rpm -qa`."

## Clarifications

### Session 2026-04-20

- Q: Which path pattern identifies npm internals for the scan-mode-aware scoping (US1 / FR-001 / FR-002)? → A: Path glob `**/node_modules/npm/node_modules/**` — any path with `npm` as an intermediate directory whose grandparent is `node_modules`. Simple, canonical, matches npm v7+ install shape.
- Q: What property name should tag npm-internal components so consumers can filter them (FR-004)? → A: `mikebom:npm-role=internal` — hardcoded, ecosystem-specific; matches the FR-004 example verbatim. A separate todo tracks the possibility of an ecosystem-agnostic scheme (`mikebom:scope=tool-internal` or similar) if future ecosystems develop the same tool-vs-app distinction.
- Q: How should os-release read failures (missing ID / VERSION_ID) be surfaced to SBOM consumers beyond the per-scan log warning (FR-006, FR-009)? → A: Granular SBOM-level properties recording which fields were missing — e.g., a CycloneDX `metadata.properties` entry `mikebom:os-release-missing-fields` with a comma-joined list of missing field names. Consumers parsing the SBOM later can detect degraded PURLs without needing scanner logs. A separate todo tracks whether a standard CycloneDX/SPDX field is a better home for this than a `mikebom:` namespace property.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Image scans report everything installed in the image (Priority: P1)

An operator is producing an SBOM for a Docker image that will be deployed to production. They run mikebom against the image tarball. They need the SBOM to include every package that a vulnerability scanner might plausibly flag — including npm's own internals (`@npmcli/*`, `semver`, `chalk`, etc.) because those packages ship inside the container and a CVE in any of them is exploitable by anyone who can invoke the image's entrypoint.

Separately, the same operator is producing an SBOM for a project source tree before it's packaged into any image. In that context, npm's own installer binaries are NOT dependencies of the application — they're part of the tooling used to install the application's dependencies, and should not appear in the SBOM.

**Why this priority**: This is the single largest conformance gap today. On the comprehensive-ground-truth fixture, the current always-exclude behaviour produces 172 MISSING npm components. Aligning with syft/trivy for image scans and keeping application scoping for directory scans closes that gap without making either scan mode wrong in a different way.

**Independent Test**: Scan a Node.js container image that includes npm installed globally; verify the output contains components for npm's internal packages (any one of `@npmcli/arborist`, `@npmcli/config`, `@npmcli/fs`, etc.). Separately, scan the same application's source directory (without any installed `node_modules/npm/`); verify no npm-internal components appear.

**Acceptance Scenarios**:

1. **Given** a Docker image scanned with `mikebom sbom scan --image <tarball>`, **When** the image contains `/usr/lib/node_modules/npm/node_modules/` (or any variant: `/usr/local/lib/...`, `/opt/node/lib/...`), **Then** components for the packages inside that directory appear in the output with `pkg:npm/...` PURLs.
2. **Given** a project directory scanned with `mikebom sbom scan --path <dir>`, **When** the directory happens to also contain an npm-internals-shaped layout (e.g., a vendored toolchain under `node_modules/npm/node_modules/`), **Then** those npm-internal components are NOT emitted.
3. **Given** an image scan where both application dependencies AND npm internals are present, **When** the scan completes, **Then** both sets of components appear as distinct PURLs (no collision, no dedup-loss between the two groups).

---

### User Story 2 - PURL distro qualifier uses the ID-VERSION_ID format across all ecosystems (Priority: P2)

A consumer is matching mikebom's output against a vulnerability feed keyed on `pkg:deb/debian/<name>@<version>?distro=debian-12`. Today mikebom emits `pkg:deb/debian/<name>@<version>?distro=bookworm` for the same package. The consumer can't match, so they either miss vulnerabilities or have to add a codename-to-version lookup table per distro.

mikebom should emit the `{ID}-{VERSION_ID}` format everywhere — for deb, rpm, and apk — sourced from `/etc/os-release` in the scanned rootfs.

**Why this priority**: Current alpine (`distro=alpine-3.20.9`) and rpm (`distro=rocky-9.3`) PURLs already follow this convention — they were correct from the start. Only the deb path emits codenames today (`distro=bookworm`, `distro=noble`). This story is specifically about bringing deb into line. Impact is every deb component on every Debian/Ubuntu fixture.

**Independent Test**: Scan any Debian or Ubuntu image. Every emitted `pkg:deb/...` PURL's `distro=` qualifier value must match `<os-release::ID>-<os-release::VERSION_ID>` exactly (e.g., `debian-12`, `ubuntu-24.04`).

**Acceptance Scenarios**:

1. **Given** a Debian 12 image with `/etc/os-release` containing `ID=debian` and `VERSION_ID="12"`, **When** scanned, **Then** every deb PURL includes `&distro=debian-12`.
2. **Given** an Ubuntu 24.04 image with `ID=ubuntu` and `VERSION_ID="24.04"`, **When** scanned, **Then** every deb PURL includes `&distro=ubuntu-24.04`.
3. **Given** an image where `/etc/os-release` is absent or malformed, **When** scanned, **Then** deb PURLs are emitted WITHOUT the `distro=` qualifier (rather than with a bogus value), and a warning is logged once per scan.
4. **Given** existing alpine and rpm PURLs that already use the `{ID}-{VERSION_ID}` format, **When** this change lands, **Then** those PURLs are unchanged byte-for-byte.

---

### User Story 3 - deb PURL namespace reflects the actual distro ID (Priority: P2)

A consumer scans an Ubuntu image and expects `pkg:deb/ubuntu/libssl3@...`, matching the purl-spec's deb-definition examples and matching what syft/trivy/cdxgen produce. Today mikebom emits `pkg:deb/debian/libssl3@...` regardless of whether the image is actually Debian or Ubuntu. This makes tool-to-tool SBOM diff noisy and can cause vulnerability feeds keyed on `pkg:deb/ubuntu/*` to miss matches.

mikebom should populate the PURL namespace segment from `/etc/os-release::ID` directly.

**Why this priority**: Matches spec intent and industry convention. Narrower scope than US2 (only affects deb; apk and rpm already use the correct namespace per their type definitions). High correctness value for every Ubuntu consumer.

**Independent Test**: Scan an Ubuntu image. Every `pkg:deb/...` PURL must start with `pkg:deb/ubuntu/`. Scan a Debian image. Every `pkg:deb/...` PURL must start with `pkg:deb/debian/`.

**Acceptance Scenarios**:

1. **Given** an Ubuntu image, **When** scanned, **Then** all deb PURLs have `ubuntu` as the namespace segment.
2. **Given** a Debian image, **When** scanned, **Then** all deb PURLs have `debian` as the namespace segment.
3. **Given** a derivative distro (Kali, Linux Mint, Pop!_OS, etc.) whose `/etc/os-release::ID` is not `debian` or `ubuntu`, **When** scanned, **Then** the namespace is the raw `ID` value (e.g., `pkg:deb/kali/...`) without silently rewriting it.
4. **Given** an image with no `/etc/os-release`, **When** scanned, **Then** deb PURLs fall back to `pkg:deb/debian/` (current behaviour) and a warning is logged once per scan.

---

### User Story 4 - RPM version strings match the output of `rpm -qa` (Priority: P3)

A consumer runs `rpm -qa` on a scanned image and expects the versions from the mikebom SBOM to match byte-for-byte. Today, on the polyglot-builder-image fixture, 93 RPM components have version strings that differ from `rpm -qa` output. The consumer can't reliably cross-reference mikebom's output against the actual package manager.

mikebom should emit RPM version strings that match `rpm -qa`'s output format. The likely culprit is epoch-prefix handling or the release-tag formatting; the exact root cause needs investigation before a fix.

**Why this priority**: Correctness, but lower blast radius than US1–US3 — it's a comparison accuracy issue on RPM fixtures specifically, and 93 mismatches on one fixture is smaller than the 172-MISSING gap in US1. Also, this is partially investigative — the fix shape depends on what the root cause turns out to be (epoch stripping, release-tag quoting, etc.).

**Independent Test**: On a Fedora or Rocky image, for each rpm package in mikebom's SBOM output, find the matching line in `rpm -qa --queryformat '%{NAME}|%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}\n'` and verify the version string is equivalent when normalised to purl-spec rpm version conventions.

**Acceptance Scenarios**:

1. **Given** a scanned Fedora or Rocky image, **When** each rpm PURL's version is compared to the corresponding `rpm -qa` line's `%{VERSION}-%{RELEASE}`, **Then** the strings are equivalent after applying a documented normalisation (e.g., epoch prefix handling per purl-spec rpm rules).
2. **Given** a package with a non-zero epoch, **When** the PURL is constructed, **Then** the epoch appears in the `epoch=` qualifier per purl-spec convention, NOT inline in the version segment.
3. **Given** a package whose version contains characters that purl-spec rules require to be percent-encoded, **When** the PURL is constructed, **Then** those characters are encoded correctly AND the raw version string is preserved in a mikebom-specific property so consumers can round-trip back to it.

---

### Edge Cases

- **Image with no `/etc/os-release` at all** (distroless, scratch, some minimal Alpine variants): The distro qualifier and deb namespace fall back to current defaults (`pkg:deb/debian/`, no `distro=` qualifier). A single warning is logged per scan. The scan does not fail.
- **`/etc/os-release` present but missing `VERSION_ID`**: Treat the same as "missing os-release" for the purposes of the `distro=` qualifier — omit the qualifier rather than emit a half-built value.
- **A scan root that contains multiple conflicting `/etc/os-release` files** (e.g., a multi-stage build tarball that somehow retains both stages): Use the top-level rootfs os-release; don't scan deeper.
- **npm internals detection on unusual layouts**: Images may ship npm at non-standard paths (`/opt/node/lib/node_modules/npm/`, vendored copies inside application directories, etc.). The detection heuristic must be explicit about which paths it considers "npm internals"; matching should be path-pattern-based and documented.
- **Project directory scan that includes a directory literally named `node_modules/npm/`** (e.g., a Node developer has vendored npm for some reason, or a monorepo's packaging build artifact): The exclusion MUST still apply — the scoping decision is by path shape, not by heuristic intent inference.
- **RPM package with an unusual character in the version string** (tilde for pre-release, caret for post-release, non-ASCII codepoint): The purl-spec version encoding rules still apply. Document any edge cases where we deviate.
- **Consumer depending on the pre-change PURL strings**: Every PURL change breaks consumers who've pinned against the old strings. This spec is silent on migration beyond "document the change" — consumers are expected to re-key against the new PURLs.

## Requirements *(mandatory)*

### Functional Requirements

**Scan-mode-aware npm scoping (US1)**:

- **FR-001**: System MUST include npm internals in image-scan output (`--image`). "npm internals" is defined as any filesystem path matching the glob `**/node_modules/npm/node_modules/**` — i.e. any package whose immediate parent directory is `npm/node_modules/` where that `npm/` lives under a `node_modules/` directory. This is the canonical layout installed by npm v7+.
- **FR-002**: System MUST exclude npm internals (same glob as FR-001) from project-directory scan output (`--path`).
- **FR-003**: System MUST use the CLI invocation (`--image` vs `--path`) as the sole determinant of which scoping rule applies. No additional flags are introduced for this behaviour.
- **FR-004**: When npm internals are included, System MUST tag those components with a CycloneDX property named exactly `mikebom:npm-role` with value `internal`. This is the stable, normative identifier consumers filter on — no synonyms, no alternate spellings.

**PURL `distro=` qualifier format (US2)**:

- **FR-005**: System MUST construct the `distro=` qualifier value as `<os-release::ID>-<os-release::VERSION_ID>` for deb, apk, and rpm PURLs emitted from an image or rootfs scan.
- **FR-006**: System MUST omit the `distro=` qualifier entirely when either `ID` or `VERSION_ID` is absent or empty in the scanned rootfs's `/etc/os-release`. System MUST log a single warning per scan when omission occurs, identifying which field was missing, AND record the missing field names in a CycloneDX `metadata.properties` entry named `mikebom:os-release-missing-fields` with a comma-joined value (e.g. `VERSION_ID` or `ID,VERSION_ID`). The property is absent from the SBOM when no fields were missing.
- **FR-007**: Alpine PURLs (which already use the `distro=<ID>-<VERSION_ID>` format) MUST be emitted byte-for-byte identically after this feature lands. RPM PURLs MUST be emitted byte-for-byte identically EXCEPT where US4's version-format fix (FR-011, FR-012, FR-013) deliberately changes an individual PURL to bring it into alignment with `rpm -qa` output. The exempted set is bounded to the PURLs enumerated in the T039 root-cause analysis and numerically bounded by SC-006.

**deb PURL namespace (US3)**:

- **FR-008**: System MUST use the raw lowercased `/etc/os-release::ID` value as the namespace segment of every `pkg:deb/...` PURL emitted from a scanned rootfs.
- **FR-009**: System MUST fall back to `pkg:deb/debian/` when `/etc/os-release` is absent or `ID` is empty, log a single warning per scan when the fallback is used, AND reflect the condition in the same `mikebom:os-release-missing-fields` CycloneDX `metadata.properties` entry introduced by FR-006 (the `ID` field name appearing in the comma-joined value is the consumer's signal that the deb-namespace fallback fired).
- **FR-010**: System MUST NOT apply any lookup-table rewriting to the `ID` value (e.g., no `ubuntu→debian`, no `kali→debian`) — the raw `ID` is authoritative.

**RPM version format alignment (US4)**:

- **FR-011**: System MUST emit RPM PURL version strings equivalent to `rpm -qa --queryformat '%{VERSION}-%{RELEASE}'` after applying the rpm-type encoding rules defined in the PURL specification (`package-url/purl-spec` repository, `PURL-TYPES.rst` §rpm and `PURL-SPECIFICATION.rst` §2):
  (a) The version segment is the combined `<VERSION>-<RELEASE>` string from the rpmdb header, with no `<epoch>:` prefix.
  (b) Epoch appears exclusively in the `epoch=` qualifier (see FR-012); omitted when the package's epoch is zero.
  (c) Character encoding within the version segment follows the PURL general rules in `PURL-SPECIFICATION.rst` §2 — PURL-reserved characters are percent-encoded; all other characters (including tilde, caret, and non-ASCII glyphs legal in RPM version strings) pass through unchanged.
  (d) The `mikebom:raw-version` property (FR-013) preserves the exact pre-encoding `<VERSION>-<RELEASE>` string so consumers can round-trip to the rpmdb header's native representation.
  No other mikebom-specific transformation is applied.
- **FR-012**: System MUST represent a package's epoch exclusively via the `epoch=` PURL qualifier. The version segment MUST NOT carry an inline `<epoch>:` prefix.
- **FR-013**: System MUST preserve the exact raw `<VERSION>-<RELEASE>` string from the rpmdb header as a CycloneDX component property named exactly `mikebom:raw-version`. No synonyms, no alternate spellings. The value is the verbatim string before any PURL encoding (FR-011(c)) so consumers can round-trip to the rpmdb header's native representation.
- **FR-014**: Before implementing the fix, the implementer MUST produce a written root-cause analysis identifying the specific format difference(s) driving the current 93 mismatches on the polyglot-builder-image fixture. Ad-hoc fixes without diagnosis are out of scope.

**Cross-cutting**:

- **FR-015**: System MUST produce deterministic PURLs across repeated scans of the same input. PURL strings are user-facing identifiers; flakiness here is a correctness regression.
- **FR-016**: The changes in this spec MUST NOT be gated behind a CLI flag. They are correctness fixes; consumers should receive the corrected output by default.
- **FR-017**: Release notes for the version introducing these changes MUST call out every PURL-shape change (distro-qualifier format, deb namespace, rpm version format) so consumers of mikebom output can update their keying.

### Key Entities

- **os-release fields (`ID`, `VERSION_ID`, `VERSION_CODENAME`)**: The three fields that together drive distro-qualifier and namespace decisions. `ID` is required for FR-008 and FR-005. `VERSION_ID` is required for FR-005. `VERSION_CODENAME` becomes advisory-only after this change (previously it was the sole source of the deb `distro=` value).
- **npm-internals path pattern**: The set of filesystem path patterns that identify npm's own package tree. Used by FR-002 to exclude these paths during `--path` scans. The pattern set must be explicit and documented (not heuristic).
- **PURL shape**: The composition of an emitted Package URL — `pkg:<type>/<namespace>/<name>@<version>?<qualifiers>`. This feature changes shape for the deb type (namespace + qualifier) and the rpm type (version segment + epoch qualifier), and for apk + rpm the qualifier format is reaffirmed.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On the comprehensive-ground-truth fixture, npm MISSING count drops from 172 to under 5. (Targets US1.)
- **SC-002**: A project-directory scan of a repository whose top-level `node_modules/npm/` layout is vendored emits zero components sourced from that layout (no regression on source-scan scoping). (Targets US1.)
- **SC-003**: On every Debian and Ubuntu fixture in the conformance suite, 100% of emitted deb PURLs' `distro=` qualifier values match the regex `^<ID>-<VERSION_ID>$` sourced from that fixture's `/etc/os-release`. (Targets US2.)
- **SC-004**: On every Alpine fixture, 0% of emitted PURLs change byte-for-byte after this feature lands. On every RPM fixture EXCEPT polyglot-builder-image, 0% of emitted PURLs change byte-for-byte. On polyglot-builder-image, the only PURLs permitted to change are those enumerated in the T039 root-cause analysis as targets of the US4 version-format fix; any other rpm PURL change is a regression. (Regression guard, scoped per FR-007.)
- **SC-005**: On every Ubuntu fixture, 100% of emitted deb PURLs start with `pkg:deb/ubuntu/`. On every Debian fixture, 100% start with `pkg:deb/debian/`. (Targets US3.)
- **SC-006**: On polyglot-builder-image, the count of rpm components whose version string does not match `rpm -qa` output drops from 93 to under 5. (Targets US4.)
- **SC-007**: No fixture's total-component-count decreases by more than 2% from these changes. (Regression guard — we should not silently lose components while "fixing" PURL shapes.)
- **SC-008**: The scan CLI surface remains unchanged — no new flags, no new environment variables required for the correct behaviour. Existing `--image` / `--path` invocations produce the corrected output without modification. (Targets FR-003, FR-016.)
- **SC-009**: When a scan's rootfs is missing `/etc/os-release::ID` and/or `VERSION_ID`, the emitted SBOM's `metadata.properties` contains exactly one entry named `mikebom:os-release-missing-fields` whose value is a comma-joined list of the missing field names. When both fields are present, the property is absent. (Targets FR-006, FR-009.)

## Assumptions

- `/etc/os-release` is the canonical source of distro identity across the Linux distros this project targets (Debian, Ubuntu, Alpine, Fedora, Rocky, RHEL, AlmaLinux, openSUSE, Amazon Linux, Oracle Linux). Derivative distros (Kali, Mint, Pop!_OS, etc.) are expected to follow the same convention and emit honest `ID` values.
- The purl-spec issue #423 resolution is converging on `{ID}-{VERSION_ID}`, and the tools this project is compared against (syft, trivy, cdxgen) all use this format today. If #423 resolves differently (e.g., mandates codenames for deb), the mikebom implementation is expected to track the spec and update — this spec is not a permanent contract.
- npm's internal package layout is identifiable by the presence of `node_modules/npm/` as a parent of `node_modules/<dep>/`. This is the layout npm has shipped since v7 and is expected to remain stable for the foreseeable future.
- Scan mode (`--image` vs `--path`) is a sufficient signal for scoping decisions. There is no plausible "I want to scan a directory as if it were an image" use case that warrants a third mode today.
- Existing consumers of mikebom SBOMs are not running in production with pinned PURL strings. Every change here is a breaking PURL-shape change by design; we communicate it in release notes rather than gating behind a flag.
- RPM version-format divergence is investigable via existing tooling (`rpm -qa` on a running container built from the fixture image, plus mikebom's own SBOM output). No new tooling is required to diagnose the 93 mismatches.
- macOS host, docker-image-scan fixtures, and the existing sbom-conformance harness are available for integration testing and provide sufficient signal on each success criterion.
