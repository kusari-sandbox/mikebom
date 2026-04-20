# Attestation Schema Contract

**Predicate Type**: `https://mikebom.dev/attestation/build-trace/v1`
**Envelope**: in-toto Statement v1

## Full Schema

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "<build-output-name>",
      "digest": { "sha256": "<hex-encoded>" }
    }
  ],
  "predicateType": "https://mikebom.dev/attestation/build-trace/v1",
  "predicate": {
    "metadata": {
      "tool": {
        "name": "mikebom",
        "version": "<semver>"
      },
      "trace_start": "<ISO-8601 UTC>",
      "trace_end": "<ISO-8601 UTC>",
      "target_process": {
        "pid": 12345,
        "command": "<full command line>",
        "cgroup_id": 999
      },
      "host": {
        "os": "linux",
        "kernel_version": "<uname -r>",
        "arch": "<x86_64|aarch64>"
      },
      "generation_context": "build-time-trace"
    },

    "network_trace": {
      "connections": [
        {
          "id": "<socket_cookie>_<timestamp_ns>",
          "protocol": "tcp|http|https",
          "process": {
            "pid": 12345,
            "tid": 12350,
            "comm": "<process name>"
          },
          "destination": {
            "ip": "<IPv4 or IPv6>",
            "port": 443,
            "hostname": "<from SNI or Host header, nullable>"
          },
          "tls": {
            "sni": "<Server Name Indication value>",
            "captured_via": "openssl_uprobe|go_tls_uprobe"
          },
          "request": {
            "method": "GET|POST|...",
            "path": "</url/path>",
            "host_header": "<Host header value>"
          },
          "response": {
            "status_code": 200,
            "content_length": 82451,
            "content_hash": {
              "algorithm": "sha256",
              "value": "<hex-encoded>"
            }
          },
          "timing": {
            "start": "<ISO-8601 UTC>",
            "end": "<ISO-8601 UTC>"
          },
          "bytes_sent": 342,
          "bytes_received": 82451
        }
      ],
      "summary": {
        "total_connections": 47,
        "unique_hosts": ["<hostname>", "..."],
        "unique_ips": ["<ip>", "..."],
        "protocol_counts": { "https": 45, "http": 2 },
        "total_bytes_received": 12543210
      }
    },

    "file_access": {
      "operations": [
        {
          "path": "</absolute/file/path>",
          "operation": "read|write|create",
          "process": {
            "pid": 12345,
            "tid": 12350,
            "comm": "<process name>"
          },
          "content_hash": {
            "algorithm": "sha256",
            "value": "<hex-encoded>"
          },
          "size": 82451,
          "timestamp": "<ISO-8601 UTC>"
        }
      ],
      "summary": {
        "total_operations": 1523,
        "unique_paths": 847,
        "operations_by_type": { "read": 1200, "write": 312, "create": 11 }
      }
    },

    "trace_integrity": {
      "ring_buffer_overflows": 0,
      "events_dropped": 0,
      "uprobe_attach_failures": [],
      "kprobe_attach_failures": [],
      "partial_captures": [
        {
          "event_type": "network|file",
          "reason": "<description of what was incomplete>",
          "timestamp": "<ISO-8601 UTC>"
        }
      ],
      "bloom_filter_capacity": 65536,
      "bloom_filter_false_positive_rate": 0.01
    }
  }
}
```

## Field Constraints

### Required vs Optional

| Section | Required Fields | Optional Fields |
|---------|----------------|-----------------|
| metadata | all | none |
| connection | id, protocol, process, destination, timing, bytes_* | tls, request, response |
| file_operation | path, operation, process, size, timestamp | content_hash |
| trace_integrity | all | partial_captures may be empty list |

### Nullable Fields

- `connection.destination.hostname` — null when neither SNI nor Host header available
- `connection.tls` — null for non-TLS connections
- `connection.request` / `connection.response` — null for non-HTTP connections
- `connection.response.content_hash` — null when response body not captured
- `file_operation.content_hash` — null when hash computation not possible

### Timestamp Format

All timestamps MUST be ISO-8601 UTC format: `YYYY-MM-DDTHH:MM:SS.sssZ`

### Hash Format

All content hashes use `{ "algorithm": "<name>", "value": "<hex>" }` format.
The `value` field MUST be lowercase hex-encoded.

## Completeness-to-Compositions Mapping

| trace_integrity State | CycloneDX compositions.aggregate |
|----------------------|----------------------------------|
| All zeros, no failures | `incomplete_first_party_only` |
| ring_buffer_overflows > 0 | `incomplete` |
| events_dropped > 0 | `incomplete` |
| Any uprobe_attach_failures | `unknown` |
| Any kprobe_attach_failures | `unknown` |

The SBOM generator MUST use the most conservative (least complete)
aggregate value when multiple conditions apply.
