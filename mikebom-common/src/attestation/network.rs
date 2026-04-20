use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::types::hash::ContentHash;
use crate::types::timestamp::Timestamp;

/// Aggregated network activity captured during a build trace.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkTrace {
    pub connections: Vec<Connection>,
    pub summary: NetworkSummary,
}

/// High-level summary statistics for the network trace.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub total_connections: u64,
    pub unique_hosts: Vec<String>,
    pub unique_ips: Vec<String>,
    pub protocol_counts: BTreeMap<String, u64>,
    pub total_bytes_received: u64,
}

/// A single observed network connection during the build.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Connection {
    pub id: String,
    pub protocol: Protocol,
    pub process: ProcessRef,
    pub destination: Destination,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<HttpRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<HttpResponse>,
    pub timing: TimingInfo,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Network protocol classification.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Http,
    Https,
}

/// Reference to the process that initiated a connection or file operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessRef {
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
}

/// Network destination for a connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    pub ip: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

/// TLS metadata captured for encrypted connections.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    pub captured_via: String,
}

/// HTTP request metadata observed on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_header: Option<String>,
}

/// HTTP response metadata observed on the wire.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<ContentHash>,
}

/// Start and end timestamps for a traced event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimingInfo {
    pub start: Timestamp,
    pub end: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_serde_snake_case() {
        let json = serde_json::to_string(&Protocol::Https).expect("serialize protocol");
        assert_eq!(json, "\"https\"");

        let back: Protocol = serde_json::from_str(&json).expect("deserialize protocol");
        assert_eq!(back, Protocol::Https);
    }

    #[test]
    fn connection_omits_none_fields() {
        let conn = Connection {
            id: "conn-1".to_string(),
            protocol: Protocol::Tcp,
            process: ProcessRef {
                pid: 1234,
                tid: 1234,
                comm: "curl".to_string(),
            },
            destination: Destination {
                ip: "93.184.216.34".to_string(),
                port: 443,
                hostname: None,
            },
            tls: None,
            request: None,
            response: None,
            timing: TimingInfo {
                start: Timestamp::now(),
                end: Timestamp::now(),
            },
            bytes_sent: 0,
            bytes_received: 0,
        };
        let json = serde_json::to_string(&conn).expect("serialize connection");
        assert!(!json.contains("\"tls\""));
        assert!(!json.contains("\"request\""));
        assert!(!json.contains("\"response\""));
        assert!(!json.contains("\"hostname\""));
    }
}
