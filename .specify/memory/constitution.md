<!--
  ============================================================
  SYNC IMPACT REPORT
  ============================================================
  Version change: 1.2.0 → 1.2.1
  Bump rationale: PATCH — codified the pre-PR verification
  workflow that CI already enforces. No principle changes,
  no new principles. Prompted by a PR that passed
  `cargo test -p mikebom` locally but failed CI with 14
  `clippy::unwrap_used` errors in test code.

  Modified sections:
    - Development Workflow → new subsection "Pre-PR
      Verification (MANDATORY)" naming the two exact commands
      CI runs and the `#[cfg_attr(test, allow(clippy::unwrap_used))]`
      guard required on test modules that use `.unwrap()`.

  Added sections: none (new subsection under existing section)
  Removed sections: none

  Previous SYNC IMPACT history:
    - 1.1.0 → 1.2.0: MINOR — new principle XII (External Data
      Source Enrichment); principle II + strict boundary #1
      amended to distinguish discovery from enrichment.

  Templates requiring updates:
    - .specify/templates/plan-template.md        ✅ no update needed
    - .specify/templates/spec-template.md         ✅ no update needed
    - .specify/templates/tasks-template.md        ✅ no update needed
    - .specify/templates/agent-file-template.md   ✅ no update needed
    - .specify/templates/checklist-template.md    ✅ no update needed
    - .specify/templates/commands/               ✅ directory empty

  Follow-up TODOs: none
  ============================================================
-->

# mikebom Constitution

## Core Principles

### I. Pure Rust, Zero C

All code — kernel-space eBPF programs and user-space application
alike — MUST be written exclusively in Rust. The `aya` framework
provides the eBPF toolchain. No C source files, no `libbpf`
bindings, and no C compiler toolchains are permitted in the build
pipeline.

**Rationale**: A single-language stack eliminates FFI bugs,
guarantees memory safety across the entire call graph, and
removes the C toolchain as a supply-chain attack surface —
critical for a tool whose purpose is supply-chain integrity.

### II. eBPF-Only Observation

All dependency **discovery** MUST occur through eBPF tracing
of live build processes. Network interception uses `uprobes`
attached to TLS libraries (OpenSSL, GoTLS) to capture
plaintext before encryption. File operations are traced via
kernel probes. No MITM proxy, no certificate injection, and
no static manifest/lockfile parsing are permitted **as a
dependency source**.

External data sources (lockfiles, databases, APIs) MAY be
used to **enrich** already-discovered dependencies — for
example, adding dependency-tree relationships, license data,
or vulnerability context — per Principle XII. A component
that appears only in an external source but was NOT observed
in the eBPF trace MUST NOT be added to the SBOM.

**Rationale**: Observing the actual build eliminates the gap
between what a manifest declares and what a build actually
fetches. Enrichment from external sources adds value without
compromising the trace-first trust model, provided the
distinction between "observed" and "enriched" is maintained.

### III. Fail Closed

If the eBPF trace fails to attach, loses events, or observes
zero dependency activity, mikebom MUST report the failure
transparently and exit with a non-zero status. The tool MUST
NOT fall back to static analysis, lockfile parsing, or any
heuristic gap-filling.

**Rationale**: An SBOM that silently omits dependencies is
worse than no SBOM. Failing closed forces operators to
investigate and fix tracing problems rather than ship
incomplete attestations.

### IV. Type-Driven Correctness

Domain values — cryptographic hashes, Package URLs (PURLs),
SPDX license expressions, CycloneDX component identifiers —
MUST be represented as dedicated newtype structs or enums.
Raw `String` types MUST NOT be passed across function
boundaries for these values. Production code MUST NOT call
`.unwrap()`; use `anyhow` for application errors and
`thiserror` for library error definitions.

**Rationale**: The Rust type system can enforce specification
formats at compile time. A `Purl(String)` wrapper prevents a
hash from being accidentally used where a PURL is expected,
eliminating an entire class of serialization bugs.

### V. Specification Compliance

Generated SBOMs MUST strictly conform to:

- **CISA 2025 Minimum Elements** — all required fields
  populated, including "Tool Name" as `mikebom` and
  "Generation Context" reflecting active build-time trace.
- **CycloneDX 1.6** — valid JSON or XML serialization via
  `cyclonedx-bom` or the `sbom-rs` ecosystem.
- **SPDX 3.1** — when SPDX output is requested.
- **PURL Specification** — every Package URL emitted MUST
  conform to the PURL spec. Invalid PURLs MUST NOT appear
  in output.

Conformance applies to the SBOM envelope and to every
sub-element within it. Non-compliant output at any level is
a blocking bug.

**Rationale**: mikebom exists to produce legally and
technically defensible SBOMs. A spec-conformant document
containing malformed PURLs is still non-compliant.
Sub-element validity is as critical as envelope validity.

### VI. Three-Crate Architecture

The Cargo workspace MUST contain exactly three crates:

- `mikebom-ebpf/` — `no_std` eBPF programs for the kernel.
- `mikebom-common/` — shared struct definitions (ring buffer
  event payloads) used by both kernel and user space.
- `mikebom-cli/` — user-space application: eBPF loader,
  event processor, API client, SBOM serializer.

Additional crates require explicit justification and a
constitution amendment.

**Rationale**: The `aya` framework requires this separation
between `no_std` kernel code and `std` user code. A shared
crate prevents struct definition drift. Keeping it to three
crates enforces simplicity and prevents premature
modularization.

### VII. Test Isolation

Unit tests MUST cover all PURL parsing, `deps.dev` API
response handling, and CycloneDX/SPDX serialization logic.
These tests MUST run without elevated privileges in standard
CI environments using mock eBPF event generators.

Integration tests that load eBPF programs MUST be gated
behind `root` or `CAP_BPF` privilege checks and MUST be
isolated from unit test suites so that `cargo test` succeeds
in unprivileged environments.

**Rationale**: eBPF requires kernel privileges that most CI
runners lack. Separating privilege-dependent tests from pure
logic tests ensures the fast feedback loop remains usable
while still exercising the full stack when privileges are
available.

### VIII. Completeness

mikebom MUST minimize false negatives — dependencies that
were actually fetched during a build but are absent from the
generated SBOM. Every network request and file-read event
observed by the eBPF trace MUST be processed and represented
in the output unless explicitly filtered by a user-specified
exclusion rule.

When completeness cannot be guaranteed (e.g., ring buffer
overflow, partial trace window), the tool MUST signal the
gap per Principle X (Transparency).

**Rationale**: An SBOM that omits real dependencies creates a
false sense of security. Consumers making vulnerability or
license decisions based on an incomplete SBOM inherit
unquantified risk.

### IX. Accuracy

mikebom MUST minimize false positives — components listed in
the SBOM that were not actually used by the traced build.
PURL resolution against `deps.dev` or `PurlDB` MUST be
validated before inclusion: ambiguous or low-confidence
matches MUST be flagged rather than silently included as
definitive.

**Rationale**: An SBOM bloated with phantom dependencies
erodes consumer trust, triggers spurious vulnerability
alerts, and increases audit burden. Accuracy preserves the
signal-to-noise ratio that makes SBOMs actionable.

### X. Transparency

When mikebom cannot guarantee completeness (Principle VIII)
or accuracy (Principle IX), it MUST include structured
metadata in the SBOM output that informs the consumer of
the limitation. Examples:

- Ring buffer overflow detected → metadata indicating
  potential event loss during a time window.
- PURL resolved via heuristic rather than exact hash match
  → confidence annotation on the affected component.
- Build not directly traced (future inference mode) →
  generation context MUST state that data is inferred, not
  observed.

Transparency metadata MUST use spec-native mechanisms
(e.g., CycloneDX `confidence`, `evidence`, or `property`
fields) rather than ad-hoc extensions where possible.

**Rationale**: Consumers cannot act on data they cannot
assess. Transparent metadata allows downstream tooling and
human reviewers to make informed risk decisions rather than
treating all SBOM entries as equally authoritative.

### XI. Enrichment

mikebom SHOULD enrich SBOM output with supplementary data
beyond the minimum dependency graph when the data is
available from upstream sources and can be attached without
violating accuracy (Principle IX). Enrichment targets
include:

- **License data** — resolved from `deps.dev`, registry
  metadata, or package-embedded license files.
- **VEX (Vulnerability Exploitability eXchange)** — when
  vulnerability context is available for a component.
- **Supplier and author metadata** — when provided by the
  package registry.
- **Hash digests** — multiple algorithms (SHA-256, SHA-512)
  for content verification.

Enrichment MUST NOT delay SBOM generation to the point of
failure. If an enrichment source is unavailable, the SBOM
MUST still be emitted with the enrichment fields omitted
and a transparency annotation (Principle X) noting the gap.

**Rationale**: A bare dependency list satisfies minimum
compliance but leaves consumers to independently research
licenses, vulnerabilities, and provenance. Enrichment
collapses that effort into the SBOM itself, increasing its
utility as a single source of truth.

### XII. External Data Source Enrichment

External data sources — including lockfiles, package
registries, hash-to-package databases, and vulnerability
databases — MAY be used to **enrich** eBPF-traced
dependencies with supplementary data. Permitted enrichment
includes:

- **Dependency relationships** — lockfiles (Cargo.lock,
  package-lock.json, go.sum, etc.) MAY be read to add
  dependency-tree edges (e.g., `DEPENDS_ON` relationships)
  between components that were observed in the eBPF trace.
- **Package identity** — hash-to-PURL databases (deps.dev,
  PurlDB) MAY be queried to resolve content hashes to
  package identifiers.
- **Metadata** — license data, supplier info, vulnerability
  context, and provenance data MAY be fetched from any
  available source.

The following constraints apply:

1. External sources MUST NOT introduce new components. A
   package that appears in a lockfile but was NOT observed
   in the eBPF trace MUST NOT be added to the SBOM.
2. Data from external sources MUST be annotated with its
   provenance (e.g., "relationship from Cargo.lock",
   "license from deps.dev") per Principle X (Transparency).
3. External source unavailability MUST NOT prevent SBOM
   generation. The tool MUST degrade gracefully with
   transparency annotations noting missing enrichment.
4. The eBPF trace remains the authoritative source for
   dependency discovery. External sources provide context,
   not authority.

**Rationale**: The eBPF trace tells us *what was fetched*.
Lockfiles and databases tell us *how those fetches relate to
each other* and *what we know about them*. Combining both
produces SBOMs with the dependency trees that downstream
tools expect, without compromising the trace-first trust
model. This closes the dependency-tree gap with tools like
syft and trivy while maintaining mikebom's core advantage
of build-time observation.

## Strict Boundaries

These constraints are non-negotiable and MUST NOT be
circumvented by feature flags, configuration options, or
optional modes:

1. **No lockfile-based dependency discovery.** Lockfiles and
   manifests MUST NOT be used as a source of dependency
   discovery. If the eBPF trace produces no data, the tool
   fails closed (Principle III). Lockfiles MAY be read for
   enrichment purposes only (dependency relationships,
   metadata) per Principle XII — but MUST NOT introduce
   components not observed in the trace.

2. **No MITM proxy.** All network observation MUST remain in
   eBPF `uprobes`. Certificate injection, proxy servers, and
   traffic interception outside eBPF are forbidden.

3. **No C code.** Not in the main codebase, not in build
   scripts, not in vendored dependencies. The `aya` crate
   provides all kernel compatibility (Principle I).

4. **No `.unwrap()` in production.** Test code may use
   `.unwrap()` for brevity; production code MUST use proper
   error propagation (Principle IV).

## Development Workflow

### Build & Test Commands

| Action | Command |
|--------|---------|
| Build eBPF kernel program | `cargo xtask ebpf` |
| Build user-space application | `cargo build --release` |
| Lint | `cargo clippy --all-targets --all-features -- -D warnings` |
| Format check | `cargo fmt -- --check` |
| Unit tests | `cargo test --workspace` |
| Run (requires root) | `sudo RUST_LOG=info target/release/mikebom scan --target-pid <PID>` |

### Pre-PR Verification (MANDATORY)

Before opening or updating ANY pull request, the author MUST run both
of the following commands locally and confirm each passes clean — not
one, not a subset, BOTH:

| Step | Command | Passing condition |
|------|---------|-------------------|
| 1 | `cargo +stable clippy --workspace --all-targets` | Zero errors |
| 2 | `cargo +stable test --workspace` | Every suite reports `ok. N passed; 0 failed` |

These are the exact commands CI executes (`.github/workflows/ci.yml`).
`cargo test -p <crate>` alone is INSUFFICIENT because it skips clippy
and skips cross-crate targets. Specifically, the `clippy::unwrap_used`
deny at the `mikebom-cli` crate root (Principle IV) is enforced by
clippy's `--all-targets` inside `#[cfg(test)]` modules too; any test
module using `.unwrap()` MUST be guarded with
`#[cfg_attr(test, allow(clippy::unwrap_used))]` on the `mod tests`
item, matching the convention used throughout `mikebom-cli/src/trace/`.

A PR that has not passed both commands locally MUST NOT be opened or
pushed for review. A passing per-crate `cargo test` is not evidence of
CI-readiness and MUST NOT be cited as such in the PR description.

### Async Runtime

The `tokio` async runtime MUST be used for:

- Reading from the eBPF ring buffer (`BPF_MAP_TYPE_RINGBUF`).
- Querying `deps.dev` and `PurlDB` APIs for PURL resolution.
- Concurrent event processing.

### eBPF Specifics

- Attach programs to `cgroup` v2 for process isolation.
- Use `BPF_MAP_TYPE_BLOOM_FILTER` for in-kernel event
  deduplication.
- Use `BPF_MAP_TYPE_RINGBUF` (not perf buffer) for
  kernel-to-user data delivery.

## Governance

This constitution is the authoritative source of
non-negotiable project constraints. It supersedes informal
conventions, PR comments, and ad-hoc decisions.

**Amendment procedure**:

1. Propose the change in a dedicated PR with a clear
   rationale.
2. Update this document and increment the version per
   semantic versioning:
   - MAJOR: Principle removed, redefined, or made
     incompatible with prior interpretation.
   - MINOR: New principle or section added, or existing
     guidance materially expanded.
   - PATCH: Wording clarification, typo fix, or
     non-semantic refinement.
3. All active plans and specs MUST be reviewed for
   consistency with the amended constitution before merge.

**Compliance**: Every PR and code review MUST verify that
changes do not violate any principle. Violations require
either a code fix or a constitution amendment — never silent
deviation.

**Version**: 1.2.0 | **Ratified**: 2026-04-15 | **Last Amended**: 2026-04-16
