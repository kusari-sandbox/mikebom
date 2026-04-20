use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::file::FileAccess;
use super::integrity::TraceIntegrity;
use super::metadata::TraceMetadata;
use super::network::NetworkTrace;

/// In-toto Statement v1 envelope for a mikebom build-trace attestation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InTotoStatement {
    /// Always `"https://in-toto.io/Statement/v1"`.
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<ResourceDescriptor>,
    /// Always `"https://mikebom.dev/attestation/build-trace/v1"`.
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: BuildTracePredicate,
}

/// An in-toto resource descriptor identifying a build subject by name and digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceDescriptor {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

/// The mikebom build-trace predicate containing all traced activity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BuildTracePredicate {
    pub metadata: TraceMetadata,
    pub network_trace: NetworkTrace,
    pub file_access: FileAccess,
    pub trace_integrity: TraceIntegrity,
}

impl InTotoStatement {
    /// The in-toto statement type URI.
    pub const STATEMENT_TYPE: &'static str = "https://in-toto.io/Statement/v1";

    /// The mikebom build-trace predicate type URI.
    pub const PREDICATE_TYPE: &'static str =
        "https://mikebom.dev/attestation/build-trace/v1";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::file::{FileAccess, FileAccessSummary};
    use crate::attestation::integrity::TraceIntegrity;
    use crate::attestation::metadata::{
        GenerationContext, HostInfo, ProcessInfo, ToolInfo, TraceMetadata,
    };
    use crate::attestation::network::{NetworkSummary, NetworkTrace};
    use crate::types::timestamp::Timestamp;

    fn sample_statement() -> InTotoStatement {
        let mut digest = BTreeMap::new();
        digest.insert(
            "sha256".to_string(),
            "abc123def456abc123def456abc123def456abc123def456abc123def456abcd".to_string(),
        );

        InTotoStatement {
            statement_type: InTotoStatement::STATEMENT_TYPE.to_string(),
            subject: vec![ResourceDescriptor {
                name: "my-artifact".to_string(),
                digest,
            }],
            predicate_type: InTotoStatement::PREDICATE_TYPE.to_string(),
            predicate: BuildTracePredicate {
                metadata: TraceMetadata {
                    tool: ToolInfo {
                        name: "mikebom".to_string(),
                        version: "0.1.0".to_string(),
                    },
                    trace_start: Timestamp::now(),
                    trace_end: Timestamp::now(),
                    target_process: ProcessInfo {
                        pid: 1,
                        command: "cargo build".to_string(),
                        cgroup_id: 100,
                    },
                    host: HostInfo {
                        os: "linux".to_string(),
                        kernel_version: "6.5.0".to_string(),
                        arch: "x86_64".to_string(),
                        distro_codename: None,
                    },
                    generation_context: GenerationContext::BuildTimeTrace,
                },
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
                    bloom_filter_capacity: 100_000,
                    bloom_filter_false_positive_rate: 0.01,
                },
            },
        }
    }

    #[test]
    fn statement_type_field_renamed() {
        let stmt = sample_statement();
        let json = serde_json::to_string(&stmt).expect("serialize statement");
        assert!(json.contains("\"_type\""));
        assert!(!json.contains("\"statement_type\""));
    }

    #[test]
    fn predicate_type_field_renamed() {
        let stmt = sample_statement();
        let json = serde_json::to_string(&stmt).expect("serialize statement");
        assert!(json.contains("\"predicateType\""));
        assert!(!json.contains("\"predicate_type\""));
    }

    #[test]
    fn serde_round_trip() {
        let stmt = sample_statement();
        let json = serde_json::to_string(&stmt).expect("serialize statement");
        let back: InTotoStatement = serde_json::from_str(&json).expect("deserialize statement");
        assert_eq!(stmt.statement_type, back.statement_type);
        assert_eq!(stmt.predicate_type, back.predicate_type);
        assert_eq!(stmt.subject.len(), back.subject.len());
    }
}
