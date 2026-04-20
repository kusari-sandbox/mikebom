# Feature 005: PURL & Scope Alignment — Release Notes

**Milestone**: 005
**Status**: Implementation complete (pending T053 conformance-suite rerun)
**Date**: 2026-04-20

## Summary

Four correctness fixes to mikebom's SBOM emissions to align with PURL spec conventions and industry-tooling baselines (syft, trivy, cdxgen). No new CLI flags or environment variables. PURL shape changes affect deb and rpm components and are breaking for consumers that match on exact PURL strings — see migration notes below.

## Functional changes

### 1. npm scoping is now scan-mode-aware (US1 — MVP)

`--image` scans now emit npm's own bundled packages from
`**/node_modules/npm/node_modules/**`. Each carries a new property:

```json
{ "name": "mikebom:npm-role", "value": "internal" }
```

`--path` scans continue to exclude those packages entirely — the
operator is scanning an application source tree; npm's own tooling is
out of scope.

Rationale: image SBOMs cover the entire filesystem (a vuln in an npm
internal package is as real as any other); project SBOMs cover the
application. This matches the SBOM generation-context distinction
already exposed via `--image` / `--path`.

Matches syft/trivy behaviour on image scans; mikebom's `--path` mode
remains intentionally tighter than syft/trivy (they include internals
in directory scans too; mikebom treats a directory scan as a project
scan).

### 2. deb PURL namespace is now `/etc/os-release::ID` (US3)

Ubuntu rootfs scans now emit `pkg:deb/ubuntu/…`. Debian still emits
`pkg:deb/debian/…`. Derivative distros (Kali, Pop!_OS, Raspbian) get
their own raw `ID` value — no silent rewrite to `debian`.

**Migration:** consumers that matched Ubuntu PURLs with the hardcoded
`pkg:deb/debian/` prefix must re-key. This is the correct shape per
`deb-definition.json` in the PURL spec; mikebom was previously
non-compliant.

### 3. deb PURL `distro=` qualifier uses `<ID>-<VERSION_ID>` (US2)

Was: `?arch=amd64&distro=bookworm`
Now: `?arch=amd64&distro=debian-12`

Applies across every deb-producing rootfs:
- Debian 12 → `distro=debian-12`
- Ubuntu 24.04 → `distro=ubuntu-24.04`
- Derivative distros → `distro=<id>-<version_id>`

Matches rpm/apk convention already in place (`distro=fedora-40`,
`distro=alpine-3.20.9`) and the emerging packaging-purl consensus
(syft, trivy, cdxgen all emit this format). `purl-spec#423` is still
open; this implementation choice will be revisited if the upstream
resolution goes differently.

### 4. rpm PURL epoch is always a qualifier, never inline (US4)

`rpm_file.rs` previously emitted `pkg:rpm/fedora/foo@7:1.0-2?arch=…`
(inline epoch). This was a divergence from `rpm.rs` (rpmdb reader),
from the PURL-TYPES.rst §rpm examples, and from syft/trivy. Unified:
all rpm PURLs now use `@<VERSION>-<RELEASE>?…&epoch=<N>`.

**Migration:** consumers matching on `@N:VERSION` inline epoch shapes
must re-key to the qualifier form.

### 5. rpm `&epoch=0` is now preserved when the header tag is present (US4)

The rpmdb distinguishes "EPOCH tag absent" (e.g. `tzdata`: 444 of 529
packages on stock Fedora 40) from "EPOCH tag present, value=0" (e.g.
`aopalliance`: 26 of 529 packages). Previously mikebom collapsed both
to "no qualifier". Now:

- Header has EPOCH tag (any value, including 0) → emit `&epoch=<v>`
- Header has no EPOCH tag → omit

Matches `rpm -qa`'s display convention and syft's emission; lets
downstream consumers round-trip the rpmdb state exactly.

### 6. Every rpm component carries `mikebom:raw-version` (US4)

New property exposing the verbatim `%{VERSION}-%{RELEASE}` string:

```json
{ "name": "mikebom:raw-version", "value": "5.2.15-1.fc40" }
```

Covers both rpmdb-sourced (`rpm.rs`) and standalone artefact-sourced
(`rpm_file.rs`) components. Consumers can cross-reference `rpm -qa`
output without re-parsing the PURL.

### 7. Diagnostic: missing `/etc/os-release` fields (US2/US3)

When a scanned rootfs is missing `ID` and/or `VERSION_ID`, the CDX
metadata now carries:

```json
{ "name": "mikebom:os-release-missing-fields", "value": "ID,VERSION_ID" }
```

When both fields are present, the property is absent. The deb reader
falls back to namespace `debian` when ID is missing (noted in the
diagnostic); no distro qualifier is emitted when VERSION_ID is
missing.

## Success criteria results

| SC | Description | Result |
|---|---|---|
| SC-001 | Image scans surface npm internals tagged `internal` | ✅ T021 integration test |
| SC-002 | Path scans exclude npm internals | ✅ T019/T022 |
| SC-003 | Debian fixtures: every deb PURL carries `distro=debian-<N>` | ✅ T031 |
| SC-004 | Alpine/apk + rpm baseline PURLs byte-stable (except feature-005 changes) | 🟡 T050–T052 (regression guards deferred pending T053 sbom-conformance rerun) |
| SC-005 | Ubuntu rootfs emits `pkg:deb/ubuntu/…` with no rewrite | ✅ T036 |
| SC-006 | Polyglot RPM VERSION_MISMATCH count < 5 | ✅ Verified: 1 residual (gpg-pubkey arch sentinel, intentional) — down from 27 |
| SC-007 | Component counts stable within ±2% outside documented US1 / US4 deltas | 🟡 T052 deferred |
| SC-008 | No new CLI flags, no new env vars | ✅ T054 `scan --help` diff confirms |
| SC-009 | `mikebom:os-release-missing-fields` metadata property present when fields missing | ✅ T037 |

## Non-behaviour (intentionally unchanged)

- **`gpg-pubkey` arch qualifier**: rpmdb stores `arch=(none)` as a
  literal sentinel. mikebom continues to omit the `arch=` qualifier
  for this value — emitting `arch=%28none%29` would be worse per PURL
  spec conventions. Documented per US4 RCA.
- **`--deb-codename` CLI flag**: preserved on the command line for
  backward compatibility with existing scripts; no longer affects
  dpkg PURL generation (the distro qualifier is now always derived
  from `/etc/os-release::VERSION_ID`). The flag is still wired into
  `resolve::path_resolver::resolve_deb_path` for the
  `docker-buildkit` trace path, which is out of scope for this
  feature.

## Test coverage delta

| Suite | Pre-005 | Post-005 | Added |
|---|---|---|---|
| Binary unit tests | 632 | 648 | +16 |
| Binary integration tests | 20 | 25 | +5 |
| Image integration tests | 4 | 5 | +1 |

Total: +22 new tests. All pass on every workspace crate.

## Deferred to follow-up

- **T050–T053a** regression-guard baselines: captured in
  `specs/005-purl-and-scope-alignment/baselines/` but the automated
  diff-against-baseline tests are NOT wired up; the baselines exist
  as reference artefacts. Rationale: T053 (full sbom-conformance
  suite) covers the same ground holistically; the guard tests would
  duplicate work and require careful exemption lists for the
  intentional US2/US3/US4 shape changes.
- **T053** full sbom-conformance suite rerun: depends on the external
  `sbom-conformance` repository and is an operator task rather than
  an in-tree automated test.

Implementer notes on deferrals are in `tasks.md`; none block the
feature from shipping.
