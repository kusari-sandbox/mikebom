# Research: Build-Trace-to-SBOM Pipeline

**Branch**: `001-build-trace-pipeline` | **Date**: 2026-04-15

## R1: Attestation Intermediate Format

**Decision**: Use in-toto Statement v1 envelope with a custom
`build-trace/v1` predicate as the primary trace artifact.

**Rationale**: in-toto is the CNCF standard for supply chain
attestation (ITE-5/6/7). Using it as the intermediate format gives
mikebom interoperability with the witness ecosystem and SBOMit
tooling. The attestation-first pattern decouples tracing from SBOM
generation, enabling re-generation without re-tracing.

**Alternatives considered**:
- Raw JSON event log (no standard envelope) — rejected: no
  interoperability, no subject/predicate structure for verification
- SLSA Provenance v1 predicate — rejected: designed for build
  provenance, not network/file trace data; would require
  shoehorning trace data into an ill-fitting schema
- Witness-native attestation format — rejected: Go-specific
  tooling, would create a hard dependency on the witness ecosystem
  rather than using the portable in-toto standard

## R2: eBPF TLS Interception Approach

**Decision**: Use `uprobes` attached to `SSL_read`/`SSL_write` in
OpenSSL and `crypto/tls.(*Conn).Read`/`Write` in Go binaries to
capture plaintext HTTP data before/after encryption.

**Rationale**: uprobes provide kernel-level visibility into
function calls with zero modification to the target binary.
Capturing at the TLS library level yields plaintext HTTP data
(method, path, headers, response bodies) without certificate
injection or connection interception.

**Alternatives considered**:
- Transparent proxy with eBPF redirect (go-witness approach) —
  rejected: constitution Principle II prohibits proxies; proxy
  adds latency and a failure point; proxy complicates cgroup
  isolation
- MITM proxy with CA injection — rejected: constitution strictly
  prohibits; changes TLS trust chain; breaks certificate pinning
- kprobe on `sendmsg`/`recvmsg` — rejected: captures ciphertext
  after encryption; unusable for HTTP parsing

## R3: PURL Resolution Strategy

**Decision**: Multi-strategy pipeline with confidence scoring:
URL pattern (0.95) → hash match (0.90) → file path (0.70) →
hostname heuristic (0.40).

**Rationale**: No single strategy covers all ecosystems. URL
patterns are most reliable for known registries. Hash-based lookup
via deps.dev covers cases where URL parsing fails. File path
patterns (SBOMit approach) cover locally cached packages. Hostname
heuristics provide a last-resort fallback. Confidence scoring
ensures the SBOM consumer knows how each component was identified.

**Alternatives considered**:
- URL parsing only — rejected: some registries use opaque URLs
  or redirects that don't encode package name/version
- Hash lookup only — rejected: requires network access; rate-limited;
  some packages not indexed by deps.dev
- Single-strategy with no confidence — rejected: violates
  Principle IX (accuracy) and Principle X (transparency)

## R4: CycloneDX Completeness Signaling

**Decision**: Use CycloneDX `compositions` with conservative
aggregate values. Best case: `incomplete_first_party_only` (not
`complete`). With data loss: `incomplete` or `unknown`.

**Rationale**: eBPF tracing observes direct downloads but cannot
guarantee it captured every transitive dependency relationship.
Claiming `complete` would be dishonest. Using `compositions` is
the spec-native mechanism that no existing tool uses (per the
test report benchmarking 9 tools).

**Alternatives considered**:
- Claim `complete` when trace_integrity shows no event loss —
  rejected: even a clean trace cannot guarantee transitive
  completeness; honest signaling is a core value
- Use custom properties instead of compositions — rejected:
  non-standard; downstream tools won't understand it
- Omit completeness metadata entirely — rejected: violates
  Principle X (transparency)

## R5: VEX Integration Approach

**Decision**: Populate VEX entries from deps.dev `GetAdvisory`
data with a default analysis state of `in_triage`.

**Rationale**: mikebom can identify that a component has known
advisories but cannot determine exploitability in the user's
context. Setting `in_triage` is honest and actionable: it tells
consumers "this advisory exists, you should assess it." Users
can supply a VEX override file to set `not_affected` or other
states after manual review.

**Alternatives considered**:
- Default to `not_affected` — rejected: dangerous assumption
  that contradicts Principle IX
- Omit VEX entirely — rejected: leaves consumers to independently
  discover vulnerabilities; contradicts Principle XI (enrichment)
- Integrate with OSV directly — considered as future enhancement;
  deps.dev already aggregates OSV data

## R6: deps.dev API Usage

**Decision**: Use deps.dev v3 API as primary resolution and
enrichment source. Three endpoints:
- `GET /v3/query?hash.type=SHA256&hash.value={base64}` for hash resolution
- `GET /v3/purl/{encoded_purl}` for PURL existence validation
- `GET /v3/systems/{system}/packages/{name}/versions/{version}` for enrichment

**Rationale**: deps.dev is the largest cross-ecosystem package
metadata API, supporting SHA-256 hash-to-package lookups that no
other public API offers. It aggregates license, advisory, and
provenance data from multiple registries.

**Alternatives considered**:
- PurlDB as primary — rejected: smaller coverage; deps.dev is
  more authoritative; PurlDB remains as secondary fallback
- Direct registry APIs (crates.io, PyPI, npm) — rejected:
  per-registry clients increase complexity; deps.dev normalizes
  across registries
- Offline-only resolution — rejected: limits resolution to URL
  and file path patterns only; hash-based resolution requires
  network access

## R7: eBPF Map Design for Event Delivery

**Decision**: Two separate ring buffers (NETWORK_EVENTS 8MB,
FILE_EVENTS 4MB) with a bloom filter for in-kernel deduplication.

**Rationale**: Separate ring buffers prevent high-volume file I/O
from starving network event delivery. The bloom filter drops
duplicate events (same content hash) in kernel space, reducing
context-switch overhead. Ring buffer (not perf buffer) provides
guaranteed ordering and no event loss below capacity.

**Alternatives considered**:
- Single ring buffer for all events — rejected: file events
  vastly outnumber network events; could cause network event
  starvation
- Perf buffer — rejected: per-CPU buffers with potential
  reordering; ring buffer is the modern replacement with better
  guarantees
- No dedup (bloom filter) — rejected: builds produce many
  duplicate file reads; without dedup, ring buffer overflow is
  more likely

## R8: SPDX Version

**Decision**: Target SPDX 3.1 per constitution. If still in RC
at implementation time, implement 3.0.1 with a version-abstract
trait to swap in 3.1 at GA.

**Rationale**: Constitution Principle V mandates SPDX 3.1. If
the spec hasn't reached GA, we implement the closest stable
version (3.0.1) behind an abstraction that makes the upgrade
mechanical.

**Alternatives considered**:
- Wait for SPDX 3.1 GA before implementing SPDX — rejected:
  blocks the entire SPDX output; CycloneDX is primary output
  anyway
- SPDX 2.3 only — rejected: 2.x lacks the expressiveness
  needed for annotations and relationships
