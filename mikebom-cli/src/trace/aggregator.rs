//! Event aggregator: correlates raw eBPF events into attestation-level
//! Connection and FileOperation objects.

use std::collections::HashMap;

use mikebom_common::attestation::file::{FileAccess, FileAccessSummary, FileOperation, FileOpType};
use mikebom_common::attestation::integrity::TraceIntegrity;
use mikebom_common::attestation::network::{
    Connection, Destination, HttpRequest, HttpResponse, NetworkSummary, NetworkTrace, ProcessRef,
    Protocol, TimingInfo, TlsInfo,
};
use mikebom_common::events::{FileEvent, FileEventType, NetworkEvent, NetworkEventType};
use mikebom_common::types::hash::ContentHash;
use mikebom_common::types::timestamp::Timestamp;

use super::http_parser;
use super::processor::TraceStats;
use super::sni_extractor;

/// Aggregated trace results ready for attestation building.
pub struct AggregatedTrace {
    pub network_trace: NetworkTrace,
    pub file_access: FileAccess,
    pub trace_integrity: TraceIntegrity,
}

/// Intermediate state for a connection being assembled from multiple events.
///
/// We deliberately do NOT accumulate response bytes here — a TLS capture only
/// ever sees the first ~512 bytes of each TLS record, so the concatenation
/// is not the real file content. Hashes for SBOM components are computed
/// from the actual files on disk after the traced command exits (see
/// `scan::hash_captured_files`).
struct ConnectionBuilder {
    id: String,
    process: ProcessRef,
    dst_ip: String,
    dst_port: u16,
    hostname: Option<String>,
    tls_sni: Option<String>,
    tls_captured_via: Option<String>,
    request: Option<HttpRequest>,
    response: Option<HttpResponse>,
    start_ns: u64,
    end_ns: u64,
    bytes_sent: u64,
    bytes_received: u64,
}

/// Aggregates raw eBPF events into attestation-level structures.
pub struct EventAggregator {
    connections: HashMap<u64, ConnectionBuilder>,
    /// TLS connections where we've seen multiple HTTP requests (keep-alive).
    /// When a second request lands on a connection whose builder already
    /// has `request` populated, we flush the current builder here and
    /// start a fresh one so each request becomes its own logical
    /// connection in the final attestation.
    completed: Vec<ConnectionBuilder>,
    file_ops: Vec<FileOperation>,
    /// Nanoseconds to add to each `bpf_ktime_get_ns` timestamp to convert
    /// from CLOCK_BOOTTIME (what BPF returns) to Unix epoch wall time.
    /// Zero means "treat timestamps as already absolute" — only correct
    /// for synthetic fixtures.
    boot_offset_ns: u64,
}

impl EventAggregator {
    pub fn new() -> Self {
        Self::with_boot_offset(0)
    }

    /// Create an aggregator with a known boot-time→wall-time offset.
    /// Callers should compute this as `CLOCK_REALTIME - CLOCK_BOOTTIME`
    /// (both sampled as nanoseconds) at the start of tracing.
    pub fn with_boot_offset(boot_offset_ns: u64) -> Self {
        Self {
            connections: HashMap::new(),
            completed: Vec::new(),
            file_ops: Vec::new(),
            boot_offset_ns,
        }
    }

    fn wall_time(&self, monotonic_ns: u64) -> chrono::DateTime<chrono::Utc> {
        let wall_ns = monotonic_ns.saturating_add(self.boot_offset_ns);
        let secs = (wall_ns / 1_000_000_000) as i64;
        let nanos = (wall_ns % 1_000_000_000) as u32;
        chrono::DateTime::from_timestamp(secs, nanos).unwrap_or_else(chrono::Utc::now)
    }

    /// Unique set of captured file paths. Useful for the post-trace SHA-256
    /// pass, which hashes each captured artifact file still on disk.
    pub fn captured_paths(&self) -> std::collections::BTreeSet<&str> {
        self.file_ops.iter().map(|op| op.path.as_str()).collect()
    }

    /// Inject hashes computed by userspace (e.g. `hasher::sha256_file_hex`)
    /// back into every `FileOperation` whose path is a key in `hashes`.
    /// Replaces any existing in-kernel hash — userspace sees the whole file
    /// and is authoritative.
    pub fn apply_file_hashes(
        &mut self,
        hashes: &std::collections::HashMap<String, ContentHash>,
    ) {
        for op in &mut self.file_ops {
            if let Some(h) = hashes.get(&op.path) {
                op.content_hash = Some(h.clone());
            }
        }
    }

    /// Record a `FileOperation` synthesised from a post-trace directory
    /// scan. These entries fill in for files we know landed on disk
    /// during the build but whose kernel-side open event was not
    /// captured by the file kprobes (observed with curl's -O and
    /// cargo's .crate writes). Paths show up in file-pattern resolution
    /// and URL-pattern hash correlation just like probe-sourced ops.
    pub fn record_synthetic_file_op(
        &mut self,
        path: String,
        size: u64,
        content_hash: Option<ContentHash>,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) {
        self.file_ops.push(FileOperation {
            path,
            operation: FileOpType::Write,
            process: ProcessRef {
                pid: 0,
                tid: 0,
                comm: "post-trace-scan".to_string(),
            },
            content_hash,
            size,
            timestamp: Timestamp::from_datetime(timestamp),
        });
    }

    /// Process a network event from the ring buffer.
    pub fn handle_network_event(&mut self, event: &NetworkEvent) {
        let conn_id = event.conn_id;
        let pid = event.pid;
        let tid = event.tid;
        let comm = comm_to_string(&event.comm);

        match event.event_type {
            NetworkEventType::ConnEstablished => {
                let dst_ip = std::net::IpAddr::from(event.dst_addr).to_string();
                let builder = ConnectionBuilder {
                    id: format!("{}_{}", conn_id, event.timestamp_ns),
                    process: ProcessRef { pid, tid, comm },
                    dst_ip,
                    dst_port: event.dst_port,
                    hostname: None,
                    tls_sni: None,
                    tls_captured_via: None,
                    request: None,
                    response: None,
                    start_ns: event.timestamp_ns,
                    end_ns: event.timestamp_ns,
                    bytes_sent: 0,
                    bytes_received: 0,
                };
                self.connections.insert(conn_id, builder);
            }
            NetworkEventType::TlsWrite => {
                // Parse the fragment up front — we need to know whether this
                // is a new request to decide between "merge into current
                // builder" and "flush + start fresh" (HTTP keep-alive).
                let fragment = &event.payload_fragment[..std::cmp::min(
                    event.payload_size as usize,
                    512,
                )];
                let parsed_request = http_parser::parse_request(fragment);
                let fragment_host = scan_fragment_for_hostname(fragment);
                let fragment_sni = sni_extractor::extract_sni(fragment);

                // If this fragment starts a new HTTP request and the current
                // builder already has one populated (keep-alive scenario:
                // curl --remote-name-all, cargo fetch, apt), flush the old
                // one and start a fresh builder so each request becomes its
                // own Connection in the attestation.
                if parsed_request.is_some() {
                    if let Some(existing) = self.connections.get(&conn_id) {
                        if existing.request.is_some() {
                            if let Some(old) = self.connections.remove(&conn_id) {
                                self.completed.push(old);
                            }
                        }
                    }
                }

                let conn = self.connections.entry(conn_id).or_insert_with(|| {
                    ConnectionBuilder {
                        id: format!("ssl_{}_{}", conn_id, event.timestamp_ns),
                        process: ProcessRef { pid, tid, comm: comm.clone() },
                        dst_ip: String::new(),
                        dst_port: 0,
                        hostname: None,
                        tls_sni: None,
                        tls_captured_via: None,
                        request: None,
                        response: None,
                        start_ns: event.timestamp_ns,
                        end_ns: event.timestamp_ns,
                        bytes_sent: 0,
                        bytes_received: 0,
                    }
                });
                conn.tls_captured_via = Some("openssl_uprobe".to_string());
                conn.bytes_sent += event.payload_size as u64;
                conn.end_ns = event.timestamp_ns;

                if conn.request.is_none() {
                    if let Some(req) = parsed_request {
                        conn.request = Some(req);
                    }
                }

                if conn.tls_sni.is_none() {
                    if let Some(sni) = fragment_sni {
                        conn.tls_sni = Some(sni);
                    }
                }

                if conn.hostname.is_none() {
                    conn.hostname = conn
                        .request
                        .as_ref()
                        .and_then(|r| r.host_header.clone())
                        .or_else(|| conn.tls_sni.clone())
                        .or_else(|| fragment_host);
                }
            }
            NetworkEventType::TlsRead => {
                // A TlsRead arriving for a ssl_ptr whose current builder
                // was already flushed (keep-alive split) is an orphan —
                // there is no request context to attach it to, and
                // fabricating a new Connection with only a response body
                // produces a meaningless entry (no hostname, no path).
                // Merge the read into the existing builder if one is
                // present; otherwise drop it.
                let Some(conn) = self.connections.get_mut(&conn_id) else {
                    return;
                };
                conn.tls_captured_via = Some("openssl_uprobe".to_string());
                conn.bytes_received += event.payload_size as u64;
                conn.end_ns = event.timestamp_ns;

                let fragment = &event.payload_fragment[..std::cmp::min(
                    event.payload_size as usize,
                    512,
                )];

                if conn.response.is_none() {
                    conn.response = http_parser::parse_response(fragment);
                }

                if conn.hostname.is_none() {
                    if let Some(host) = scan_fragment_for_hostname(fragment) {
                        conn.hostname = Some(host);
                    }
                }
            }
            NetworkEventType::ConnClosed => {
                if let Some(conn) = self.connections.get_mut(&conn_id) {
                    conn.end_ns = event.timestamp_ns;
                }
            }
        }
    }

    /// Process a file event from the ring buffer.
    pub fn handle_file_event(&mut self, event: &FileEvent) {
        let path = event.path_str().to_string();
        if path.is_empty() {
            return; // Skip events with empty paths
        }

        let operation = match event.event_type {
            FileEventType::Read => FileOpType::Read,
            FileEventType::Write => FileOpType::Write,
            // Opens carry the only reliable path (openat2 captures the
            // filename arg) — treat them as reads until vfs_read/write
            // path resolution lands.
            FileEventType::Open => FileOpType::Read,
            FileEventType::Close => return,
        };

        let content_hash = if event.content_hash != [0u8; 32] {
            let hex: String = event.content_hash.iter().map(|b| format!("{b:02x}")).collect();
            ContentHash::sha256(&hex).ok()
        } else {
            None
        };

        let dt = self.wall_time(event.timestamp_ns);

        self.file_ops.push(FileOperation {
            path,
            operation,
            process: ProcessRef {
                pid: event.pid,
                tid: event.tid,
                comm: event.comm_str().to_string(),
            },
            content_hash,
            size: event.bytes_transferred,
            timestamp: Timestamp::from_datetime(dt),
        });
    }

    /// Finalize aggregation and produce attestation-ready structures.
    pub fn finalize(self, stats: &TraceStats) -> AggregatedTrace {
        let boot_offset_ns = self.boot_offset_ns;
        let to_wall = |ns: u64| -> chrono::DateTime<chrono::Utc> {
            let wall = ns.saturating_add(boot_offset_ns);
            let secs = (wall / 1_000_000_000) as i64;
            let nanos = (wall % 1_000_000_000) as u32;
            chrono::DateTime::from_timestamp(secs, nanos).unwrap_or_else(chrono::Utc::now)
        };
        let all_builders: Vec<ConnectionBuilder> = self
            .connections
            .into_values()
            .chain(self.completed)
            .collect();
        let connections: Vec<Connection> = all_builders
            .into_iter()
            .map(|b| {
                // Content hashes intentionally left unset here. The SSL
                // uprobes only capture the first ~512 bytes of each TLS
                // record, so hashing what we saw would produce a value
                // that does not match the downloaded file. Correct hashes
                // are populated from `file_access.operations[].content_hash`
                // later in the pipeline when the traced command finishes
                // and we can hash the landed files on disk.
                let response = b.response;

                let protocol = if b.tls_captured_via.is_some() {
                    if b.request.is_some() {
                        Protocol::Https
                    } else {
                        Protocol::Tcp
                    }
                } else if b.request.is_some() {
                    Protocol::Http
                } else {
                    Protocol::Tcp
                };

                let tls = b.tls_captured_via.map(|via| TlsInfo {
                    sni: b.tls_sni,
                    captured_via: via,
                });

                let start_dt = to_wall(b.start_ns);
                let end_dt = to_wall(b.end_ns);

                Connection {
                    id: b.id,
                    protocol,
                    process: b.process,
                    destination: Destination {
                        ip: b.dst_ip,
                        port: b.dst_port,
                        hostname: b.hostname,
                    },
                    tls,
                    request: b.request,
                    response,
                    timing: TimingInfo {
                        start: Timestamp::from_datetime(start_dt),
                        end: Timestamp::from_datetime(end_dt),
                    },
                    bytes_sent: b.bytes_sent,
                    bytes_received: b.bytes_received,
                }
            })
            .collect();

        // Build summaries
        let unique_hosts: Vec<String> = {
            let mut hosts: Vec<String> = connections
                .iter()
                .filter_map(|c| c.destination.hostname.clone())
                .collect();
            hosts.sort();
            hosts.dedup();
            hosts
        };
        let unique_ips: Vec<String> = {
            let mut ips: Vec<String> = connections.iter().map(|c| c.destination.ip.clone()).collect();
            ips.sort();
            ips.dedup();
            ips
        };
        let mut protocol_counts = std::collections::BTreeMap::new();
        for conn in &connections {
            let key = serde_json::to_string(&conn.protocol)
                .unwrap_or_else(|_| "unknown".to_string())
                .trim_matches('"')
                .to_string();
            *protocol_counts.entry(key).or_insert(0u64) += 1;
        }
        let total_bytes_received: u64 = connections.iter().map(|c| c.bytes_received).sum();

        let total_connections = connections.len() as u64;
        let network_trace = NetworkTrace {
            connections,
            summary: NetworkSummary {
                total_connections,
                unique_hosts,
                unique_ips,
                protocol_counts,
                total_bytes_received,
            },
        };

        // File access summary
        let mut ops_by_type = std::collections::BTreeMap::new();
        for op in &self.file_ops {
            let key = serde_json::to_string(&op.operation)
                .unwrap_or_else(|_| "unknown".to_string())
                .trim_matches('"')
                .to_string();
            *ops_by_type.entry(key).or_insert(0u64) += 1;
        }
        let unique_paths = {
            let mut paths: Vec<&str> = self.file_ops.iter().map(|o| o.path.as_str()).collect();
            paths.sort();
            paths.dedup();
            paths.len() as u64
        };

        let total_file_ops = self.file_ops.len() as u64;
        let file_access = FileAccess {
            operations: self.file_ops,
            summary: FileAccessSummary {
                total_operations: total_file_ops,
                unique_paths,
                operations_by_type: ops_by_type,
            },
        };

        let trace_integrity = TraceIntegrity {
            ring_buffer_overflows: stats.ring_buffer_overflows,
            events_dropped: stats.events_dropped,
            uprobe_attach_failures: Vec::new(),
            kprobe_attach_failures: Vec::new(),
            partial_captures: Vec::new(),
            bloom_filter_capacity: 65536,
            bloom_filter_false_positive_rate: 0.01,
        };

        AggregatedTrace {
            network_trace,
            file_access,
            trace_integrity,
        }
    }
}

fn comm_to_string(comm: &[u8; 16]) -> String {
    let len = comm.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&comm[..len]).to_string()
}

/// Known package-registry hostnames. Matched as substrings of TLS plaintext
/// as a last-resort fallback when the HTTP parser fails (HTTP/2 HPACK frames)
/// and SNI isn't visible in SSL_write. Keep this list in sync with the
/// ecosystems supported by `resolve::url_resolver`.
const KNOWN_REGISTRY_HOSTNAMES: &[&str] = &[
    "static.crates.io",
    "crates.io",
    "index.crates.io",
    "files.pythonhosted.org",
    "pypi.org",
    "registry.npmjs.org",
    "proxy.golang.org",
    "sum.golang.org",
    "repo1.maven.org",
    "repo.maven.apache.org",
    "central.maven.org",
    "rubygems.org",
    "deb.debian.org",
    "security.debian.org",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "ports.ubuntu.com",
];

/// Scan a TLS plaintext fragment for a known registry hostname substring.
/// Returns the first match, so earlier (more specific) entries in the list
/// win over broader ones.
fn scan_fragment_for_hostname(fragment: &[u8]) -> Option<String> {
    if fragment.is_empty() {
        return None;
    }
    for host in KNOWN_REGISTRY_HOSTNAMES {
        if find_subslice(fragment, host.as_bytes()).is_some() {
            return Some((*host).to_string());
        }
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::ip::IpAddr;

    fn make_network_event(
        event_type: NetworkEventType,
        conn_id: u64,
        dst_port: u16,
        payload: &[u8],
    ) -> NetworkEvent {
        let mut fragment = [0u8; 512];
        let len = std::cmp::min(payload.len(), 512);
        fragment[..len].copy_from_slice(&payload[..len]);

        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"curl");

        NetworkEvent {
            event_type,
            timestamp_ns: 1000000000,
            pid: 100,
            tid: 100,
            comm,
            conn_id,
            src_addr: IpAddr::new_v4(127, 0, 0, 1),
            src_port: 12345,
            dst_addr: IpAddr::new_v4(93, 184, 216, 34),
            dst_port,
            payload_size: len as u32,
            payload_hash: [0; 32],
            payload_fragment: fragment,
            payload_truncated: 0,
            _padding: [0; 3],
        }
    }

    #[test]
    fn aggregates_connection_established() {
        let mut agg = EventAggregator::new();
        let event = make_network_event(NetworkEventType::ConnEstablished, 1, 443, b"");
        agg.handle_network_event(&event);
        assert_eq!(agg.connections.len(), 1);
    }

    #[test]
    fn aggregates_tls_write_parses_http_request() {
        let mut agg = EventAggregator::new();
        let conn_event = make_network_event(NetworkEventType::ConnEstablished, 1, 443, b"");
        agg.handle_network_event(&conn_event);

        let req = b"GET /api/v1/crates/serde/1.0.197/download HTTP/1.1\r\nHost: crates.io\r\n\r\n";
        let write_event = make_network_event(NetworkEventType::TlsWrite, 1, 443, req);
        agg.handle_network_event(&write_event);

        let conn = agg.connections.get(&1).expect("connection exists");
        assert!(conn.request.is_some());
        let http_req = conn.request.as_ref().expect("has request");
        assert_eq!(http_req.method, "GET");
        assert_eq!(http_req.path, "/api/v1/crates/serde/1.0.197/download");
        assert_eq!(conn.hostname.as_deref(), Some("crates.io"));
    }
}
