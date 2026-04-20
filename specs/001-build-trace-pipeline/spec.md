# Feature Specification: Build-Trace-to-SBOM Pipeline

**Feature Branch**: `001-build-trace-pipeline`
**Created**: 2026-04-15
**Status**: Draft
**Input**: User description: "eBPF build-trace to SBOM generation pipeline following the SBOMit attestation-first pattern"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Trace a Build and Produce an Attestation (Priority: P1)

A build pipeline operator wants to observe a software build process
and capture a complete, tamper-evident record of every network
request and file operation that occurred. They run the tracing tool
against a build command and receive a structured attestation file
that serves as the authoritative evidence of what happened during
the build.

**Why this priority**: Without the trace-and-attest step, no
downstream SBOM generation is possible. This is the foundational
capability that differentiates mikebom from manifest-parsing tools.

**Independent Test**: Can be fully tested by tracing a `curl`
command that downloads a known file from a known URL, and verifying
the attestation contains the correct destination hostname, HTTP
path, and content hash.

**Acceptance Scenarios**:

1. **Given** a running build process (identified by PID), **When**
   the operator runs the scan command targeting that PID, **Then**
   the tool produces a valid attestation file containing every
   observed network connection and file operation with timestamps,
   process info, and content hashes.

2. **Given** a build command provided inline (e.g., `-- cargo build`),
   **When** the operator runs the scan command with that build command,
   **Then** the tool spawns the build in an isolated context, traces
   it from start to finish, and produces an attestation after the
   build completes.

3. **Given** a build process that makes TLS-encrypted network
   requests, **When** the tool traces those requests, **Then** the
   attestation contains the plaintext HTTP method, path, host
   header, response status code, and a SHA-256 hash of the response
   body for each connection.

4. **Given** a build process that writes downloaded files to disk,
   **When** the tool traces those writes, **Then** the attestation
   contains the file path, size, and content hash for each write,
   and the content hash matches the corresponding network download
   hash.

5. **Given** a trace where the tool cannot attach to the target
   process or loses events, **When** the trace completes, **Then**
   the tool exits with a non-zero status and a clear error message
   explaining what failed. It does NOT produce a partial attestation
   silently.

---

### User Story 2 - Generate SBOM from Attestation (Priority: P2)

A security analyst receives an attestation file produced by the
tracing tool and wants to generate a standards-compliant SBOM from
it. They run the generation command and receive a CycloneDX or SPDX
document with resolved package identifiers, confidence annotations,
and completeness metadata.

**Why this priority**: The SBOM is the deliverable that downstream
consumers (vulnerability scanners, license auditors, compliance
systems) actually ingest. Without generation, the attestation has
no interoperable value.

**Independent Test**: Can be fully tested with a pre-recorded
attestation file (no eBPF or root privileges needed). Feed the
attestation in, verify the SBOM output against the CycloneDX JSON
schema, and confirm every expected package is present with a valid
PURL.

**Acceptance Scenarios**:

1. **Given** a valid attestation file containing network connections
   to known package registries, **When** the operator runs the
   generate command, **Then** the tool produces a CycloneDX 1.6 JSON
   file where each observed dependency has a valid, spec-conformant
   PURL.

2. **Given** an attestation with connections to crates.io, PyPI, npm,
   and Maven Central, **When** the tool resolves packages, **Then**
   each component in the SBOM includes the resolution method used
   (URL pattern match, hash lookup, file path match) and a
   confidence score.

3. **Given** an attestation where some network connections cannot be
   mapped to a known package, **When** the tool generates the SBOM,
   **Then** low-confidence or unresolvable entries are flagged
   (not silently included as definitive), and the SBOM's
   completeness metadata reflects the gap.

4. **Given** an attestation whose trace integrity section reports
   dropped events, **When** the tool generates the SBOM, **Then**
   the SBOM includes completeness metadata indicating that the
   dependency list may be incomplete, using the standard's native
   mechanisms (e.g., CycloneDX `compositions`).

5. **Given** a valid attestation, **When** the operator requests SPDX
   output format, **Then** the tool produces a valid SPDX document
   with equivalent content.

---

### User Story 3 - End-to-End Trace and SBOM Generation (Priority: P3)

A CI/CD pipeline operator wants a single command that traces a
build and produces both an attestation and a finished SBOM. They
integrate this command into their build pipeline so that every
build automatically produces supply chain documentation.

**Why this priority**: While the separate scan/generate steps
provide flexibility, most users will want a single-command
workflow for CI integration. This is the convenience layer.

**Independent Test**: Can be tested by running the combined
command against a small project build and verifying both the
attestation file and SBOM file are produced, and the SBOM
validates against the relevant schema.

**Acceptance Scenarios**:

1. **Given** a build command, **When** the operator runs the
   combined run command, **Then** both an attestation file and an
   SBOM file are produced, and the SBOM content is identical to
   what would be produced by running scan then generate separately.

2. **Given** a CI environment, **When** the run command is executed
   as part of the pipeline, **Then** the build's exit code is
   preserved (a build failure still fails the pipeline), and the
   tracing tool's own exit code reflects whether the trace and
   SBOM generation succeeded.

---

### User Story 4 - Enrich SBOM with License and Vulnerability Data (Priority: P4)

A compliance officer has an SBOM and wants it enriched with license
information and known vulnerability data before distributing it to
customers or auditors. They run the enrichment command and receive
an SBOM with license expressions, vulnerability entries (VEX), and
supplier metadata populated from upstream sources.

**Why this priority**: Enrichment transforms a dependency list into
an actionable compliance document. It's high value but can be
layered on after the core trace-generate pipeline works.

**Independent Test**: Can be tested with a pre-existing SBOM file
(no eBPF needed). Feed the SBOM in, verify that components now
have license fields, vulnerability entries, and supplier metadata
where available.

**Acceptance Scenarios**:

1. **Given** an SBOM with resolved PURLs, **When** the operator
   runs the enrich command, **Then** each component is augmented
   with license expressions from upstream registry data where
   available.

2. **Given** an SBOM containing a component with a known
   vulnerability, **When** enrichment runs, **Then** the SBOM
   includes a VEX entry for that vulnerability with severity,
   advisory source, and a default triage state of "in triage"
   (not "not affected" — the tool does not make exploitability
   judgments).

3. **Given** an enrichment source that is temporarily unavailable,
   **When** enrichment runs, **Then** the SBOM is still produced
   with the enrichment fields omitted for affected components, and
   a transparency annotation notes which enrichment sources were
   unavailable.

---

### User Story 5 - Validate Attestation or SBOM Conformance (Priority: P5)

A quality engineer wants to verify that a generated attestation or
SBOM conforms to its respective specification before publishing it.
They run the validation command and receive a pass/fail report
with details on any conformance issues.

**Why this priority**: Validation is the quality gate that prevents
non-conformant output from reaching consumers. Important but can
be developed after the core generation pipeline.

**Independent Test**: Can be tested with known-good and known-bad
sample files. Verify that valid files pass and invalid files are
rejected with specific error descriptions.

**Acceptance Scenarios**:

1. **Given** a valid CycloneDX 1.6 SBOM file, **When** the
   operator runs validation, **Then** the tool reports that all
   checks pass, including PURL conformance for every component.

2. **Given** an SBOM containing a malformed PURL, **When**
   validation runs, **Then** the tool reports the specific
   component and the PURL conformance violation.

3. **Given** an SBOM missing a CISA 2025 required field, **When**
   validation runs, **Then** the tool reports which required
   field is absent and which CISA element it maps to.

---

### Edge Cases

- What happens when the traced build makes zero network requests
  (e.g., fully offline build from local cache)? The tool MUST fail
  closed with a clear message that no dependency activity was
  observed, rather than producing an empty SBOM.

- What happens when the ring buffer overflows due to a build with
  extremely high I/O? The attestation MUST record the overflow
  count in its integrity section, and the generated SBOM MUST
  include a completeness annotation indicating potential event loss.

- What happens when a single network download matches multiple
  packages in the registry (hash collision or shared artifact)?
  The resolver MUST flag the ambiguity and include all candidates
  with individual confidence scores rather than silently picking one.

- What happens when the tool cannot attach probes to the TLS
  library (e.g., statically linked binary, unsupported library)?
  The tool MUST report which probes failed to attach and exit with
  an error. It MUST NOT silently produce an attestation that
  appears complete but is missing all encrypted traffic.

- What happens when deps.dev rate-limits or times out during
  resolution or enrichment? Resolution MUST still produce results
  for URL-pattern-based matches (which don't require API calls),
  and unresolved components MUST be flagged. Enrichment failures
  MUST NOT prevent SBOM generation.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The tool MUST observe network connections made by a
  target build process and record the destination IP, port, and
  hostname (from TLS SNI or HTTP Host header) for each connection.

- **FR-002**: The tool MUST intercept plaintext HTTP request and
  response data from TLS-encrypted connections and extract the
  method, path, host header, response status code, content length,
  and a SHA-256 hash of the response body.

- **FR-003**: The tool MUST observe file write operations by the
  target build process and record the file path, size, and a
  SHA-256 content hash.

- **FR-004**: The tool MUST correlate network downloads with file
  writes by matching content hashes, enabling cross-referencing
  between "what was downloaded" and "what was written to disk."

- **FR-005**: The tool MUST produce an attestation file conforming
  to the in-toto Statement v1 envelope format with a structured
  predicate containing network trace, file access, and trace
  integrity sections.

- **FR-006**: The tool MUST record trace integrity metadata
  including ring buffer overflow counts, dropped event counts,
  and probe attachment failures, so consumers can assess the
  completeness of the captured data.

- **FR-007**: The tool MUST resolve observed network connections
  and file paths into Package URLs (PURLs) using a multi-strategy
  pipeline: URL pattern matching, content hash lookup, file path
  pattern matching, and hostname heuristics.

- **FR-008**: Every PURL emitted by the tool MUST conform to the
  PURL specification. Malformed PURLs MUST NOT appear in any
  output.

- **FR-009**: Each resolved component MUST carry evidence metadata
  recording which resolution technique was used and the associated
  confidence level.

- **FR-010**: The tool MUST generate CycloneDX 1.6 SBOMs that
  validate against the official CycloneDX JSON schema, including
  the `compositions` section for completeness signaling and
  `evidence.identity` per component for detection method tracking.

- **FR-011**: The tool MUST generate SPDX SBOMs that validate
  against the official SPDX schema when SPDX output is requested.

- **FR-012**: Every generated SBOM MUST include the CISA 2025
  Minimum Elements: tool name (`mikebom`), generation timestamp,
  generation context (`build-time-trace`), component names,
  versions, PURLs, hashes, and supplier data where available.

- **FR-013**: The tool MUST support enrichment of SBOM components
  with license expressions, vulnerability data (VEX entries), and
  supplier metadata from upstream package registry APIs.

- **FR-014**: The tool MUST exit with a non-zero status and a
  descriptive error when: no dependency activity is observed, the
  eBPF trace fails to attach, or critical events are lost. It MUST
  NOT produce output that appears complete when data is missing.

- **FR-015**: The tool MUST isolate its observation to the target
  build process (and optionally its child processes) so that host
  background activity does not contaminate the attestation.

- **FR-016**: The tool MUST support validation of attestation files
  (schema conformance, trace integrity checks) and SBOM files
  (schema conformance, PURL conformance per component, CISA 2025
  field presence).

### Key Entities

- **Attestation**: A cryptographically structured record of all
  network and file activity observed during a build. Contains
  metadata (tool, timestamps, target process), network trace
  (connections with HTTP details and content hashes), file access
  (operations with paths and content hashes), and trace integrity
  (event loss counters and probe status). Primary output of the
  trace phase.

- **Connection**: A single observed network interaction during the
  build. Attributes: destination (IP, port, hostname), protocol,
  TLS details (SNI, capture method), HTTP request/response, content
  hash, timing, bytes transferred, originating process.

- **File Operation**: A single observed file read or write during
  the build. Attributes: path, operation type, content hash, size,
  timestamp, originating process.

- **Resolved Component**: A dependency identified from attestation
  data. Attributes: PURL, name, version, resolution evidence
  (technique, confidence, source connections/files), licenses,
  hashes, supplier, advisory references.

- **SBOM**: A standards-compliant document derived from resolved
  components. Contains components with PURLs and evidence,
  completeness metadata, vulnerability entries (VEX), and tool/
  generation metadata. Conforms to CycloneDX 1.6 or SPDX.

- **Trace Integrity**: Metadata about the quality of the
  observation itself. Attributes: ring buffer overflow count,
  events dropped count, probe attach failures, partial captures.
  Consumed by the SBOM generator to set completeness annotations.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: When tracing a build that downloads 50+ known
  dependencies, the generated SBOM contains 95%+ of those
  dependencies with valid PURLs (minimizing false negatives).

- **SC-002**: Fewer than 2% of components in a generated SBOM
  are false positives (packages listed that were not actually
  fetched by the build).

- **SC-003**: 100% of PURLs in generated SBOMs pass validation
  against the PURL specification (zero conformance failures).

- **SC-004**: Generated CycloneDX SBOMs validate against the
  official CycloneDX 1.6 JSON schema with zero errors.

- **SC-005**: Generated SBOMs include all CISA 2025 Minimum
  Elements (tool name, timestamp, generation context, component
  identifiers, hashes) with zero omissions.

- **SC-006**: Every component in the SBOM includes evidence
  metadata indicating how it was detected and at what confidence
  level (100% evidence coverage).

- **SC-007**: The SBOM includes a completeness declaration
  (e.g., CycloneDX `compositions`) that accurately reflects
  whether any trace data was lost.

- **SC-008**: When enrichment sources are available, 80%+ of
  components include license data and 100% of components with
  known advisories include VEX entries.

- **SC-009**: The combined trace-and-generate workflow adds less
  than 30 seconds of overhead to a 5-minute build (excluding
  network time for resolution API calls).

- **SC-010**: When the tool encounters a tracing failure, it
  exits with a non-zero status 100% of the time (zero silent
  failures).

## Assumptions

- Users run mikebom on Linux systems with kernel 5.8+ (minimum
  for ring buffer and modern eBPF features).
- Users have root or CAP_BPF privileges when running the trace
  (scan/run) commands. Generation, enrichment, and validation
  commands do not require elevated privileges.
- Target build processes use dynamically linked OpenSSL (libssl)
  or Go's standard TLS library. Builds using other TLS libraries
  (e.g., BoringSSL, rustls) are out of scope for v1 but the
  architecture supports adding probes for them later.
- The deps.dev API is the primary source for hash-to-package
  resolution and enrichment. PurlDB is a secondary source. Both
  require internet access during the generate/enrich phase (but
  NOT during the trace phase).
- SPDX output targets version 3.1 if available at implementation
  time; otherwise 3.0.1 with a migration path.
- macOS and Windows are out of scope (eBPF is Linux-only). The
  generate, enrich, and validate commands may work cross-platform
  since they don't use eBPF. TODO: Future macOS tracing support
  via DYLD_INSERT_LIBRARIES interposition (SSL_read/SSL_write)
  + EndpointSecurity.framework (file ops). Same attestation
  format, different capture backend behind a trait abstraction.
- v1 targets the Cargo, pip/PyPI, npm, Go modules, Maven Central,
  and RubyGems ecosystems for URL pattern resolution. Other
  ecosystems fall back to hash-based or heuristic resolution.
