# Data Model: Build-Trace-to-SBOM Pipeline

**Branch**: `001-build-trace-pipeline` | **Date**: 2026-04-15

## Entity Relationship Overview

```
                    ┌─────────────────────┐
                    │    Attestation       │
                    │  (InTotoStatement)   │
                    └──────┬──────────────┘
                           │ contains
              ┌────────────┼────────────┐
              ▼            ▼            ▼
    ┌─────────────┐ ┌───────────┐ ┌───────────────┐
    │ NetworkTrace│ │FileAccess │ │TraceIntegrity │
    └──────┬──────┘ └─────┬─────┘ └───────────────┘
           │ has many      │ has many
           ▼               ▼
    ┌────────────┐  ┌──────────────┐
    │ Connection │  │FileOperation │
    └──────┬─────┘  └──────┬───────┘
           │               │
           └───────┬───────┘
                   │ resolved into
                   ▼
          ┌─────────────────┐
          │ResolvedComponent│
          └────────┬────────┘
                   │ serialized into
                   ▼
             ┌──────────┐
             │   SBOM   │
             │(CycloneDX│
             │ or SPDX) │
             └──────────┘
```

## Entities

### Attestation (InTotoStatement)

The top-level in-toto envelope wrapping all trace data.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| _type | String (constant) | Yes | `"https://in-toto.io/Statement/v1"` |
| subject | List\<ResourceDescriptor> | Yes | Build output artifacts with digests |
| predicateType | String (constant) | Yes | `"https://mikebom.dev/attestation/build-trace/v1"` |
| predicate | BuildTracePredicate | Yes | Contains all trace data sections |

### BuildTracePredicate

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| metadata | TraceMetadata | Yes | Tool, timing, target, host info |
| network_trace | NetworkTrace | Yes | All observed network connections |
| file_access | FileAccess | Yes | All observed file operations |
| trace_integrity | TraceIntegrity | Yes | Data quality/completeness metadata |

### TraceMetadata

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| tool | ToolInfo | Yes | Name (`mikebom`) and version |
| trace_start | Timestamp | Yes | UTC timestamp when trace began |
| trace_end | Timestamp | Yes | UTC timestamp when trace ended |
| target_process | ProcessInfo | Yes | PID, command, cgroup_id of traced process |
| host | HostInfo | Yes | OS, kernel version, architecture |
| generation_context | GenerationContext | Yes | Always `build-time-trace` for v1 |

### Connection

A single observed network interaction during the build.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | String | Yes | Unique identifier (socket cookie + timestamp) |
| protocol | Protocol | Yes | `tcp`, `http`, or `https` |
| process | ProcessRef | Yes | PID, TID, command name |
| destination | Destination | Yes | IP, port, hostname (from SNI/Host) |
| tls | TlsInfo | No | SNI value, capture method (e.g., `openssl_uprobe`) |
| request | HttpRequest | No | Method, path, host header |
| response | HttpResponse | No | Status code, content length, content hash |
| timing | TimingInfo | Yes | Start and end timestamps |
| bytes_sent | Integer | Yes | Total bytes from client to server |
| bytes_received | Integer | Yes | Total bytes from server to client |

**Validation rules**:
- `id` must be unique within the attestation
- `destination.hostname` populated from SNI or Host header; null if neither available
- `response.content_hash` required when response body is captured
- `protocol` is `https` when TLS info is present, `http` for plaintext HTTP, `tcp` for non-HTTP

### FileOperation

A single observed file read or write during the build.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| path | String | Yes | Absolute file path |
| operation | FileOpType | Yes | `read`, `write`, or `create` |
| process | ProcessRef | Yes | PID, TID, command name |
| content_hash | ContentHash | No | SHA-256 of content (when computable) |
| size | Integer | Yes | Bytes read or written |
| timestamp | Timestamp | Yes | UTC timestamp of operation |

**Validation rules**:
- `path` must be absolute
- `content_hash` present for write operations; best-effort for reads
- `size` must be non-negative

### TraceIntegrity

Metadata about the quality of the observation itself.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| ring_buffer_overflows | Integer | Yes | Count of ring buffer overflow events |
| events_dropped | Integer | Yes | Count of events dropped for any reason |
| uprobe_attach_failures | List\<String> | Yes | Functions where uprobe attachment failed |
| kprobe_attach_failures | List\<String> | Yes | Functions where kprobe attachment failed |
| partial_captures | List\<PartialCapture> | Yes | Events with incomplete data |
| bloom_filter_capacity | Integer | Yes | Configured bloom filter size |
| bloom_filter_false_positive_rate | Float | Yes | Configured false positive rate |

**State transitions**: Not applicable — TraceIntegrity is immutable once
the attestation is finalized.

### ResolvedComponent

A dependency identified from attestation data via the resolution pipeline.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| purl | Purl | Yes | Validated Package URL |
| name | String | Yes | Package name |
| version | String | Yes | Package version |
| evidence | ResolutionEvidence | Yes | How this component was identified |
| licenses | List\<SpdxExpression> | No | License expressions from enrichment |
| hashes | List\<ContentHash> | Yes | At least one SHA-256 hash |
| supplier | String | No | Supplier/author from enrichment |
| advisories | List\<AdvisoryRef> | No | Vulnerability references from enrichment |

### ResolutionEvidence

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| technique | ResolutionTechnique | Yes | Primary resolution method |
| confidence | Float | Yes | 0.0 – 1.0 confidence score |
| source_connection_ids | List\<String> | No | Attestation connection IDs that contributed |
| source_file_paths | List\<String> | No | Attestation file paths that contributed |
| deps_dev_match | DepsDevMatch | No | deps.dev lookup result details |

### Enumerations

**Protocol**: `tcp` | `http` | `https`

**FileOpType**: `read` | `write` | `create`

**GenerationContext**: `build-time-trace` (v1 only)

**ResolutionTechnique**: `url_pattern` | `hash_match` | `file_path_pattern` | `hostname_heuristic`

**HashAlgorithm**: `sha256` | `sha512` | `sha1` | `md5`

## Newtype Constraints

| Type | Underlying | Validation |
|------|-----------|------------|
| Purl | String | Must parse via PURL spec; ecosystem, name required |
| ContentHash | {algorithm, value} | `value` must be valid hex encoding for algorithm |
| SpdxExpression | String | Must be valid SPDX license expression syntax |
| BomRef | String | Non-empty, unique within SBOM |
| Timestamp | DateTime\<Utc> | Must be valid UTC timestamp |
| HexString | String | Must contain only hex characters [0-9a-f] |

## Cross-Entity Correlations

- **Network → File**: A Connection's `response.content_hash` may match
  a FileOperation's `content_hash`, indicating the network download was
  written to that file path.
- **Connection → ResolvedComponent**: The `evidence.source_connection_ids`
  links a resolved package back to the specific connections that identified it.
- **FileOperation → ResolvedComponent**: The `evidence.source_file_paths`
  links a resolved package back to file operations (e.g., path-based resolution).
- **TraceIntegrity → SBOM compositions**: Ring buffer overflows and dropped
  events map to CycloneDX `compositions.aggregate` values.
- **ResolutionEvidence → SBOM evidence**: The technique and confidence
  map to CycloneDX `evidence.identity.methods[]`.
