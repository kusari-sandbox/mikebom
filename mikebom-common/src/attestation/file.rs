use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::types::hash::ContentHash;
use crate::types::timestamp::Timestamp;

use super::network::ProcessRef;

/// Aggregated file-system activity captured during a build trace.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileAccess {
    pub operations: Vec<FileOperation>,
    pub summary: FileAccessSummary,
}

/// High-level summary statistics for file access during the trace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileAccessSummary {
    pub total_operations: u64,
    pub unique_paths: u64,
    pub operations_by_type: BTreeMap<String, u64>,
}

/// A single observed file-system operation during the build.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileOperation {
    pub path: String,
    pub operation: FileOpType,
    pub process: ProcessRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<ContentHash>,
    pub size: u64,
    pub timestamp: Timestamp,
}

/// Classification of a file-system operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOpType {
    Read,
    Write,
    Create,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_op_type_serde_snake_case() {
        let json = serde_json::to_string(&FileOpType::Create).expect("serialize file op type");
        assert_eq!(json, "\"create\"");

        let back: FileOpType = serde_json::from_str("\"write\"").expect("deserialize file op type");
        assert_eq!(back, FileOpType::Write);
    }

    #[test]
    fn file_operation_omits_none_hash() {
        let op = FileOperation {
            path: "/tmp/build/out.o".to_string(),
            operation: FileOpType::Write,
            process: ProcessRef {
                pid: 100,
                tid: 100,
                comm: "gcc".to_string(),
            },
            content_hash: None,
            size: 4096,
            timestamp: Timestamp::now(),
        };
        let json = serde_json::to_string(&op).expect("serialize file operation");
        assert!(!json.contains("\"content_hash\""));
    }
}
