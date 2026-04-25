//! Build a witness-compatible attestation-collection Statement from
//! the same `AggregatedTrace` that powers the mikebom-native builder.
//!
//! Maps mikebom's trace data into four inner attestations:
//! - `material/v0.1` = pre-exec file reads (attestable build inputs)
//! - `command-run/v0.1` = the traced process + its exit code
//! - `product/v0.1` = subject-resolver output (real artifact hashes)
//! - `network-trace/v0.1` = every observed outbound connection
//!
//! Output is an in-toto Statement **v0.1** whose `predicate` is the
//! collection — consumable by `sbomit generate` and any witness-aware
//! verifier.

// Witness-builder is invoked from `cli/scan.rs::execute_scan` Linux-
// only trace flow; on macOS the file compiles but is unreachable.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::BTreeMap;

use mikebom_common::attestation::file::{FileOpType, FileOperation};
use mikebom_common::attestation::network::{Connection as MikebomConnection, Protocol};
use mikebom_common::attestation::witness::{
    self, Collection, CollectionEntry, CommandRunAttestation, Connection as WitnessConnection,
    ConnectionProcess, DigestSet, Endpoint, MaterialAttestation, NetworkConfig, NetworkSummary,
    NetworkTrace, NetworkTraceAttestation, ProcessInfo, Product, ProductAttestation,
    WitnessStatement, WitnessSubject,
};
use mikebom_common::types::hash::HashAlgorithm;
use mikebom_common::types::timestamp::Timestamp;

use crate::attestation::subject::{Subject, SubjectResolver};
use crate::trace::aggregator::AggregatedTrace;

/// Configuration for the witness-format builder.
pub struct WitnessBuildConfig {
    pub target_pid: u32,
    pub target_command: String,
    pub cgroup_id: u64,
    pub subject_resolver: Option<SubjectResolver>,
    pub collection_name: String,
}

/// Build an in-toto Statement v0.1 carrying a witness
/// attestation-collection predicate.
pub fn build_witness_statement(
    trace: AggregatedTrace,
    cfg: &WitnessBuildConfig,
    trace_start: Timestamp,
    trace_end: Timestamp,
) -> anyhow::Result<WitnessStatement> {
    let subjects = resolve_subjects(cfg);
    let subject_list = subjects.iter().map(subject_to_witness).collect();

    let start_dt = *trace_start.as_datetime();
    let end_dt = *trace_end.as_datetime();

    // Build entries in declaration order (material → command-run →
    // product → network-trace). Each entry's starttime/endtime span
    // the full trace for now — mikebom doesn't split attestors into
    // sub-phases the way go-witness does when wrapping a command.
    let mut entries: Vec<CollectionEntry> = Vec::new();

    let materials = build_material_attestation(&trace.file_access.operations);
    entries.push(CollectionEntry {
        attestor_type: witness::MATERIAL_TYPE.to_string(),
        attestation: serde_json::to_value(&materials)?,
        starttime: start_dt,
        endtime: end_dt,
    });

    // Capture all write ops with content hashes BEFORE moving
    // `trace.file_access` into the native builder — these are the real
    // build outputs (cargo cached .crate files, compiler artifacts,
    // etc.) that sbomit's resolvers key off.
    let write_products = build_product_attestation_from_writes(&trace.file_access.operations);

    let command_run = build_command_run_attestation(cfg);
    entries.push(CollectionEntry {
        attestor_type: witness::COMMAND_RUN_TYPE.to_string(),
        attestation: serde_json::to_value(&command_run)?,
        starttime: start_dt,
        endtime: end_dt,
    });

    // Build the product attestation from two sources:
    //   1. Subject-resolver output (operator-specified or magic-byte
    //      detected artifacts — what `sbom verify` will bind to)
    //   2. Every observed file write with a content hash (the real
    //      files the traced command created; sbomit's resolvers map
    //      paths like ~/.cargo/registry/cache/*.crate → cargo pkgs)
    // When both sources name the same path the subject entry wins
    // because it may carry a more precise MIME type.
    let mut products = write_products;
    for (path, p) in build_product_attestation(&subjects) {
        products.insert(path, p);
    }
    entries.push(CollectionEntry {
        attestor_type: witness::PRODUCT_TYPE.to_string(),
        attestation: serde_json::to_value(&products)?,
        starttime: start_dt,
        endtime: end_dt,
    });

    let network = build_network_trace_attestation(
        &trace.network_trace.connections,
        start_dt,
        end_dt,
        cfg.target_pid,
        cfg.cgroup_id,
    );
    entries.push(CollectionEntry {
        attestor_type: witness::NETWORK_TRACE_TYPE.to_string(),
        attestation: serde_json::to_value(&network)?,
        starttime: start_dt,
        endtime: end_dt,
    });

    Ok(WitnessStatement {
        statement_type: witness::STATEMENT_TYPE_V01.to_string(),
        subject: subject_list,
        predicate_type: witness::COLLECTION_PREDICATE_TYPE.to_string(),
        predicate: Collection {
            name: cfg.collection_name.clone(),
            attestations: entries,
        },
    })
}

// ---------------------------------------------------------------------
// Per-attestor builders
// ---------------------------------------------------------------------

fn resolve_subjects(cfg: &WitnessBuildConfig) -> Vec<Subject> {
    match &cfg.subject_resolver {
        Some(r) => r.resolve(),
        None => Vec::new(),
    }
}

fn subject_to_witness(s: &Subject) -> WitnessSubject {
    match s {
        Subject::Artifact { name, digest } => WitnessSubject {
            name: name.clone(),
            digest: witness::sha256_digest(&digest.sha256_hex),
        },
        Subject::Synthetic {
            command_summary,
            synthetic_digest,
        } => {
            // Synthetic subjects use a non-real algorithm key so
            // verifiers see the degraded binding immediately.
            let mut m = DigestSet::new();
            m.insert("synthetic".to_string(), synthetic_digest.clone());
            WitnessSubject {
                name: command_summary.clone(),
                digest: m,
            }
        }
    }
}

/// Build the material attestation: pre-exec (Read) file ops with a
/// captured content hash become attestable build inputs.
///
/// Files with no hash or Write/Create ops are excluded — material means
/// "inputs observed before or during the build"; outputs live in the
/// product attestor. When a path is read multiple times only the last
/// observed hash is kept (map semantics).
fn build_material_attestation(ops: &[FileOperation]) -> MaterialAttestation {
    let mut out = MaterialAttestation::new();
    for op in ops {
        if !matches!(op.operation, FileOpType::Read) {
            continue;
        }
        let Some(hash) = op.content_hash.as_ref() else {
            continue;
        };
        let mut ds = DigestSet::new();
        ds.insert(
            algorithm_key(&hash.algorithm).to_string(),
            hash.value.as_str().to_string(),
        );
        out.insert(op.path.clone(), ds);
    }
    out
}

fn algorithm_key(alg: &HashAlgorithm) -> &'static str {
    // Map mikebom's HashAlgorithm enum to go-witness's string keys.
    // go-witness spells these "sha256", "sha1", "sha512", "md5".
    match alg {
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Sha1 => "sha1",
        HashAlgorithm::Sha512 => "sha512",
        HashAlgorithm::Md5 => "md5",
    }
}

fn build_command_run_attestation(cfg: &WitnessBuildConfig) -> CommandRunAttestation {
    // mikebom's current aggregator doesn't split `target_command` back
    // into argv, so emit as a single-element vec carrying the raw
    // command line. Downstream consumers that care (sbomit doesn't)
    // can re-parse via shell-splitting rules. Exit code is unknown at
    // attestation time — mikebom does not currently wait on the traced
    // command's return value. Default to 0.
    let cmd_vec: Vec<String> = shell_split(&cfg.target_command);
    let processes = if cfg.target_pid > 0 {
        vec![ProcessInfo {
            program: cmd_vec.first().cloned().unwrap_or_default(),
            processid: cfg.target_pid as i32,
            parentpid: 0,
            programdigest: None,
            comm: cmd_vec
                .first()
                .map(|s| s.rsplit(['/', '\\']).next().unwrap_or("").to_string())
                .unwrap_or_default(),
            cmdline: cfg.target_command.clone(),
            exedigest: None,
            openedfiles: None,
            environ: String::new(),
            specbypassisvuln: false,
        }]
    } else {
        Vec::new()
    };
    CommandRunAttestation {
        cmd: cmd_vec,
        stdout: String::new(),
        stderr: String::new(),
        exitcode: 0,
        processes,
    }
}

/// Very small shell-style splitter — whitespace separation is enough
/// for mikebom's use case because we're re-inflating the argv the
/// operator passed after `--`.
fn shell_split(cmd: &str) -> Vec<String> {
    cmd.split_whitespace().map(|s| s.to_string()).collect()
}

/// Build product entries from every observed write op that has a
/// content hash. These are the real files the traced command created —
/// cargo cache `.crate` files, wheels, compiled libraries, etc.
fn build_product_attestation_from_writes(ops: &[FileOperation]) -> ProductAttestation {
    let mut out = ProductAttestation::new();
    for op in ops {
        if !matches!(op.operation, FileOpType::Write | FileOpType::Create) {
            continue;
        }
        let Some(hash) = op.content_hash.as_ref() else {
            continue;
        };
        let mut ds = DigestSet::new();
        ds.insert(
            algorithm_key(&hash.algorithm).to_string(),
            hash.value.as_str().to_string(),
        );
        out.insert(
            op.path.clone(),
            Product {
                mime_type: guess_mime_type(&op.path),
                digest: ds,
            },
        );
    }
    out
}

fn build_product_attestation(subjects: &[Subject]) -> ProductAttestation {
    let mut out = ProductAttestation::new();
    for s in subjects {
        if let Subject::Artifact { name, digest } = s {
            out.insert(
                name.clone(),
                Product {
                    mime_type: guess_mime_type(name),
                    digest: witness::sha256_digest(&digest.sha256_hex),
                },
            );
        }
    }
    out
}

fn guess_mime_type(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".whl") || lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        "application/gzip".to_string()
    } else if lower.ends_with(".zip") || lower.ends_with(".jar") || lower.ends_with(".war") {
        "application/zip".to_string()
    } else if lower.ends_with(".deb") || lower.ends_with(".rpm") {
        "application/octet-stream".to_string()
    } else if lower.ends_with(".so") || lower.ends_with(".dylib") || lower.ends_with(".dll") {
        "application/x-sharedlib".to_string()
    } else {
        "application/x-executable".to_string()
    }
}

fn build_network_trace_attestation(
    connections: &[MikebomConnection],
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
    target_pid: u32,
    cgroup_id: u64,
) -> NetworkTraceAttestation {
    let mut unique_ips: std::collections::BTreeSet<String> = Default::default();
    let mut unique_hosts: std::collections::BTreeSet<String> = Default::default();
    let mut protocol_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut total_bytes_sent: u64 = 0;
    let mut total_bytes_received: u64 = 0;
    let mut out_connections: Vec<WitnessConnection> = Vec::with_capacity(connections.len());

    for c in connections {
        unique_ips.insert(c.destination.ip.clone());
        if let Some(host) = &c.destination.hostname {
            unique_hosts.insert(host.clone());
        }
        let proto_str = protocol_to_string(&c.protocol);
        *protocol_counts.entry(proto_str.clone()).or_insert(0) += 1;
        total_bytes_sent = total_bytes_sent.saturating_add(c.bytes_sent);
        total_bytes_received = total_bytes_received.saturating_add(c.bytes_received);

        out_connections.push(WitnessConnection {
            id: c.id.clone(),
            protocol: proto_str,
            start_time: *c.timing.start.as_datetime(),
            end_time: Some(*c.timing.end.as_datetime()),
            process: ConnectionProcess {
                pid: c.process.pid,
                comm: c.process.comm.clone(),
                cgroup_id,
            },
            destination: Endpoint {
                ip: c.destination.ip.clone(),
                port: c.destination.port,
                hostname: c.destination.hostname.clone().unwrap_or_default(),
            },
            tcp_payloads: Vec::new(),
            bytes_sent: c.bytes_sent,
            bytes_received: c.bytes_received,
            error: String::new(),
        });
    }

    NetworkTraceAttestation {
        network_trace: NetworkTrace {
            start_time: start,
            end_time: end,
            connections: out_connections,
            summary: NetworkSummary {
                total_connections: connections.len() as u64,
                protocol_counts,
                unique_hosts: unique_hosts.into_iter().collect(),
                unique_ips: unique_ips.into_iter().collect(),
                total_bytes_sent,
                total_bytes_received,
            },
            config: NetworkConfig {
                observe_pids: if target_pid > 0 {
                    vec![target_pid]
                } else {
                    Vec::new()
                },
                observe_child_tree: true,
                proxy_port: 0,
                proxy_bind_ipv4: String::new(),
                ..Default::default()
            },
        },
    }
}

fn protocol_to_string(p: &Protocol) -> String {
    match p {
        Protocol::Tcp => "tcp".to_string(),
        Protocol::Http => "http".to_string(),
        Protocol::Https => "https".to_string(),
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::attestation::file::{FileAccess, FileAccessSummary, FileOperation};
    use mikebom_common::attestation::integrity::TraceIntegrity;
    use mikebom_common::attestation::network::{
        Connection as MbConn, Destination, NetworkSummary as MbSum, NetworkTrace as MbNet,
        ProcessRef, Protocol, TimingInfo,
    };
    use mikebom_common::types::hash::ContentHash;
    use mikebom_common::types::timestamp::Timestamp;

    fn trace_with_one_read() -> AggregatedTrace {
        AggregatedTrace {
            network_trace: MbNet {
                connections: vec![],
                summary: MbSum {
                    total_connections: 0,
                    unique_hosts: vec![],
                    unique_ips: vec![],
                    protocol_counts: BTreeMap::new(),
                    total_bytes_received: 0,
                },
            },
            file_access: FileAccess {
                operations: vec![FileOperation {
                    path: "/workspace/src/main.rs".to_string(),
                    operation: FileOpType::Read,
                    process: ProcessRef {
                        pid: 100,
                        tid: 100,
                        comm: "rustc".to_string(),
                    },
                    content_hash: Some(ContentHash::sha256(&"a".repeat(64)).unwrap()),
                    size: 1024,
                    timestamp: Timestamp::now(),
                }],
                summary: FileAccessSummary {
                    total_operations: 1,
                    unique_paths: 1,
                    operations_by_type: BTreeMap::new(),
                },
            },
            trace_integrity: TraceIntegrity {
                ring_buffer_overflows: 0,
                events_dropped: 0,
                uprobe_attach_failures: vec![],
                kprobe_attach_failures: vec![],
                partial_captures: vec![],
                bloom_filter_capacity: 100_000,
                bloom_filter_false_positive_rate: 0.01,
            },
        }
    }

    #[test]
    fn material_includes_only_reads_with_hashes() {
        let ops = vec![
            FileOperation {
                path: "/w/read-hashed.rs".to_string(),
                operation: FileOpType::Read,
                process: ProcessRef {
                    pid: 1,
                    tid: 1,
                    comm: "x".to_string(),
                },
                content_hash: Some(ContentHash::sha256(&"a".repeat(64)).unwrap()),
                size: 100,
                timestamp: Timestamp::now(),
            },
            FileOperation {
                path: "/w/read-unhashed.rs".to_string(),
                operation: FileOpType::Read,
                process: ProcessRef {
                    pid: 1,
                    tid: 1,
                    comm: "x".to_string(),
                },
                content_hash: None,
                size: 100,
                timestamp: Timestamp::now(),
            },
            FileOperation {
                path: "/w/write.o".to_string(),
                operation: FileOpType::Write,
                process: ProcessRef {
                    pid: 1,
                    tid: 1,
                    comm: "x".to_string(),
                },
                content_hash: Some(ContentHash::sha256(&"b".repeat(64)).unwrap()),
                size: 100,
                timestamp: Timestamp::now(),
            },
        ];
        let m = build_material_attestation(&ops);
        assert_eq!(m.len(), 1);
        assert!(m.contains_key("/w/read-hashed.rs"));
        assert!(!m.contains_key("/w/read-unhashed.rs"));
        assert!(!m.contains_key("/w/write.o"));
    }

    #[test]
    fn command_run_splits_argv_and_attaches_pid() {
        let cfg = WitnessBuildConfig {
            target_pid: 4242,
            target_command: "cargo install ripgrep".to_string(),
            cgroup_id: 0,
            subject_resolver: None,
            collection_name: "build".to_string(),
        };
        let cr = build_command_run_attestation(&cfg);
        assert_eq!(cr.cmd, vec!["cargo", "install", "ripgrep"]);
        assert_eq!(cr.exitcode, 0);
        assert_eq!(cr.processes.len(), 1);
        assert_eq!(cr.processes[0].processid, 4242);
        assert_eq!(cr.processes[0].comm, "cargo");
        assert_eq!(cr.processes[0].cmdline, "cargo install ripgrep");
    }

    #[test]
    fn product_mime_types_cover_common_extensions() {
        assert_eq!(guess_mime_type("foo.whl"), "application/gzip");
        assert_eq!(guess_mime_type("FOO.TAR.GZ"), "application/gzip");
        assert_eq!(guess_mime_type("bar.jar"), "application/zip");
        assert_eq!(guess_mime_type("lib.so"), "application/x-sharedlib");
        assert_eq!(guess_mime_type("lib.dylib"), "application/x-sharedlib");
        assert_eq!(guess_mime_type("a.deb"), "application/octet-stream");
        assert_eq!(guess_mime_type("/some/binary"), "application/x-executable");
    }

    #[test]
    fn network_trace_aggregates_protocol_counts_and_unique_hosts() {
        let conns = vec![
            MbConn {
                id: "c1".to_string(),
                protocol: Protocol::Https,
                process: ProcessRef {
                    pid: 1,
                    tid: 1,
                    comm: "curl".to_string(),
                },
                destination: Destination {
                    ip: "1.1.1.1".to_string(),
                    port: 443,
                    hostname: Some("example.com".to_string()),
                },
                tls: None,
                request: None,
                response: None,
                timing: TimingInfo {
                    start: Timestamp::now(),
                    end: Timestamp::now(),
                },
                bytes_sent: 100,
                bytes_received: 200,
            },
            MbConn {
                id: "c2".to_string(),
                protocol: Protocol::Https,
                process: ProcessRef {
                    pid: 1,
                    tid: 1,
                    comm: "curl".to_string(),
                },
                destination: Destination {
                    ip: "2.2.2.2".to_string(),
                    port: 443,
                    hostname: Some("example.com".to_string()),
                },
                tls: None,
                request: None,
                response: None,
                timing: TimingInfo {
                    start: Timestamp::now(),
                    end: Timestamp::now(),
                },
                bytes_sent: 50,
                bytes_received: 500,
            },
            MbConn {
                id: "c3".to_string(),
                protocol: Protocol::Tcp,
                process: ProcessRef {
                    pid: 1,
                    tid: 1,
                    comm: "git".to_string(),
                },
                destination: Destination {
                    ip: "3.3.3.3".to_string(),
                    port: 22,
                    hostname: None,
                },
                tls: None,
                request: None,
                response: None,
                timing: TimingInfo {
                    start: Timestamp::now(),
                    end: Timestamp::now(),
                },
                bytes_sent: 10,
                bytes_received: 10,
            },
        ];
        let now = chrono::Utc::now();
        let nt = build_network_trace_attestation(&conns, now, now, 42, 100);
        assert_eq!(nt.network_trace.summary.total_connections, 3);
        assert_eq!(
            nt.network_trace.summary.protocol_counts.get("https"),
            Some(&2)
        );
        assert_eq!(
            nt.network_trace.summary.protocol_counts.get("tcp"),
            Some(&1)
        );
        assert_eq!(nt.network_trace.summary.unique_ips.len(), 3);
        assert_eq!(nt.network_trace.summary.unique_hosts, vec!["example.com"]);
        assert_eq!(nt.network_trace.summary.total_bytes_sent, 160);
        assert_eq!(nt.network_trace.summary.total_bytes_received, 710);
        assert_eq!(nt.network_trace.config.observe_pids, vec![42]);
    }

    #[test]
    fn build_witness_statement_wraps_all_four_attestors() {
        let trace = trace_with_one_read();
        let cfg = WitnessBuildConfig {
            target_pid: 1,
            target_command: "echo hi".to_string(),
            cgroup_id: 0,
            subject_resolver: None,
            collection_name: "test-collection".to_string(),
        };
        let stmt = build_witness_statement(trace, &cfg, Timestamp::now(), Timestamp::now())
            .expect("build should succeed");
        assert_eq!(stmt.statement_type, witness::STATEMENT_TYPE_V01);
        assert_eq!(stmt.predicate_type, witness::COLLECTION_PREDICATE_TYPE);
        assert_eq!(stmt.predicate.attestations.len(), 4);
        let types: Vec<&str> = stmt
            .predicate
            .attestations
            .iter()
            .map(|e| e.attestor_type.as_str())
            .collect();
        assert_eq!(
            types,
            vec![
                witness::MATERIAL_TYPE,
                witness::COMMAND_RUN_TYPE,
                witness::PRODUCT_TYPE,
                witness::NETWORK_TRACE_TYPE,
            ]
        );
    }
}
