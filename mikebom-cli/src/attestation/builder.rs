//! Builds an InTotoStatement from aggregated trace data.

use std::collections::BTreeMap;

use mikebom_common::attestation::metadata::{
    GenerationContext, HostInfo, ProcessInfo, ToolInfo, TraceMetadata,
};
use mikebom_common::attestation::statement::{
    BuildTracePredicate, InTotoStatement, ResourceDescriptor,
};
use mikebom_common::types::timestamp::Timestamp;

use crate::config;
use crate::trace::aggregator::AggregatedTrace;

/// Configuration for building an attestation.
pub struct AttestationConfig {
    pub target_pid: u32,
    pub target_command: String,
    pub cgroup_id: u64,
    pub subject_name: String,
    pub subject_digest: Option<String>,
}

/// Build an InTotoStatement from aggregated trace results.
pub fn build_attestation(
    trace: AggregatedTrace,
    cfg: &AttestationConfig,
    trace_start: Timestamp,
    trace_end: Timestamp,
) -> anyhow::Result<InTotoStatement> {
    let host = detect_host_info();

    let metadata = TraceMetadata {
        tool: ToolInfo {
            name: config::TOOL_NAME.to_string(),
            version: config::TOOL_VERSION.to_string(),
        },
        trace_start,
        trace_end,
        target_process: ProcessInfo {
            pid: cfg.target_pid,
            command: cfg.target_command.clone(),
            cgroup_id: cfg.cgroup_id,
        },
        host,
        generation_context: GenerationContext::BuildTimeTrace,
    };

    let predicate = BuildTracePredicate {
        metadata,
        network_trace: trace.network_trace,
        file_access: trace.file_access,
        trace_integrity: trace.trace_integrity,
    };

    // Build subject descriptor
    let mut digest = BTreeMap::new();
    if let Some(ref hash) = cfg.subject_digest {
        digest.insert("sha256".to_string(), hash.clone());
    }

    let subject = vec![ResourceDescriptor {
        name: cfg.subject_name.clone(),
        digest,
    }];

    Ok(InTotoStatement {
        statement_type: InTotoStatement::STATEMENT_TYPE.to_string(),
        subject,
        predicate_type: InTotoStatement::PREDICATE_TYPE.to_string(),
        predicate,
    })
}

fn detect_host_info() -> HostInfo {
    HostInfo {
        os: std::env::consts::OS.to_string(),
        kernel_version: detect_kernel_version(),
        arch: std::env::consts::ARCH.to_string(),
        distro_codename: detect_distro_codename(),
    }
}

#[cfg(target_os = "linux")]
fn detect_kernel_version() -> String {
    std::fs::read_to_string("/proc/version")
        .ok()
        .and_then(|v| v.split_whitespace().nth(2).map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(not(target_os = "linux"))]
fn detect_kernel_version() -> String {
    "unknown".to_string()
}

/// Read the distro codename from the trace host's own `/etc/os-release`.
/// Delegates to the shared scan_fs helper so scan-mode and build-time
/// paths parse the file identically.
fn detect_distro_codename() -> Option<String> {
    crate::scan_fs::os_release::detect_host_codename()
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::attestation::file::{FileAccess, FileAccessSummary};
    use mikebom_common::attestation::integrity::TraceIntegrity;
    use mikebom_common::attestation::network::{NetworkSummary, NetworkTrace};
    use crate::trace::aggregator::AggregatedTrace;

    #[test]
    fn builds_valid_attestation() {
        let trace = AggregatedTrace {
            network_trace: NetworkTrace {
                connections: vec![],
                summary: NetworkSummary {
                    total_connections: 0,
                    unique_hosts: vec![],
                    unique_ips: vec![],
                    protocol_counts: BTreeMap::new(),
                    total_bytes_received: 0,
                },
            },
            file_access: FileAccess {
                operations: vec![],
                summary: FileAccessSummary {
                    total_operations: 0,
                    unique_paths: 0,
                    operations_by_type: BTreeMap::new(),
                },
            },
            trace_integrity: TraceIntegrity {
                ring_buffer_overflows: 0,
                events_dropped: 0,
                uprobe_attach_failures: vec![],
                kprobe_attach_failures: vec![],
                partial_captures: vec![],
                bloom_filter_capacity: 65536,
                bloom_filter_false_positive_rate: 0.01,
            },
        };

        let cfg = AttestationConfig {
            target_pid: 1234,
            target_command: "cargo build".to_string(),
            cgroup_id: 999,
            subject_name: "test-output".to_string(),
            subject_digest: None,
        };

        let stmt = build_attestation(
            trace,
            &cfg,
            Timestamp::now(),
            Timestamp::now(),
        )
        .expect("should build attestation");

        assert_eq!(stmt.statement_type, InTotoStatement::STATEMENT_TYPE);
        assert_eq!(stmt.predicate_type, InTotoStatement::PREDICATE_TYPE);
        assert_eq!(stmt.predicate.metadata.tool.name, "mikebom");
        assert_eq!(
            stmt.predicate.metadata.generation_context,
            GenerationContext::BuildTimeTrace
        );
    }
}
