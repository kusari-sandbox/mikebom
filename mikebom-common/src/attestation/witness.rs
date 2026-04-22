//! Witness-compatible attestation types.
//!
//! Mirrors the wire format produced by [`go-witness`](https://github.com/in-toto/go-witness)
//! + the network-trace attestor from the Vyom-Yadav fork
//! (branch `add-networktrace-attestor` @ `23a67367`). Emitting this
//! shape makes mikebom attestations directly consumable by
//! `sbomit generate` and any other witness-aware tool.
//!
//! Key constants:
//! - Statement type: `https://in-toto.io/Statement/v0.1` (v0.1, NOT v1)
//! - Collection predicate:
//!   `https://witness.testifysec.com/attestation-collection/v0.1`
//! - Inner attestor types (each on its own `CollectionEntry`):
//!   - `https://witness.dev/attestations/material/v0.1`
//!   - `https://witness.dev/attestations/command-run/v0.1`
//!   - `https://witness.dev/attestations/product/v0.1`
//!   - `https://witness.dev/attestations/network-trace/v0.1`
//!
//! Wire-format subtlety: the `CollectionEntry.starttime` / `endtime`
//! fields are single words (matching `go-witness`), while the inner
//! `NetworkTrace.start_time` / `end_time` fields carry underscores
//! (matching the Vyom-Yadav fork). Getting either wrong means consumers
//! won't parse our output.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// in-toto Statement v0.1 — what `go-witness` emits. Unlike v1 the
/// `_type` URI ends in `/v0.1`, the `subject` entries use legacy shape,
/// and the predicate can be any JSON object the type URI names.
pub const STATEMENT_TYPE_V01: &str = "https://in-toto.io/Statement/v0.1";

/// Witness attestation-collection predicate type.
pub const COLLECTION_PREDICATE_TYPE: &str =
    "https://witness.testifysec.com/attestation-collection/v0.1";

/// Witness material attestor type.
pub const MATERIAL_TYPE: &str = "https://witness.dev/attestations/material/v0.1";

/// Witness command-run attestor type.
pub const COMMAND_RUN_TYPE: &str = "https://witness.dev/attestations/command-run/v0.1";

/// Witness product attestor type.
pub const PRODUCT_TYPE: &str = "https://witness.dev/attestations/product/v0.1";

/// Vyom-Yadav fork network-trace attestor type.
pub const NETWORK_TRACE_TYPE: &str = "https://witness.dev/attestations/network-trace/v0.1";

// ---------------------------------------------------------------------
// Statement + Collection
// ---------------------------------------------------------------------

/// Top-level in-toto Statement v0.1 wrapping a witness collection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WitnessStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<WitnessSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: Collection,
}

/// Statement v0.1 subject entry: `{name, digest: {algo -> hex}}`.
/// (Structurally identical to the v1 shape; separated only to keep
/// the two statement versions decoupled in the type system.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessSubject {
    pub name: String,
    pub digest: DigestSet,
}

/// Witness attestation-collection predicate body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Collection {
    pub name: String,
    pub attestations: Vec<CollectionEntry>,
}

/// One entry in `Collection.attestations[]`.
///
/// **Wire-format note**: `starttime` / `endtime` are single words in
/// go-witness; the inner attestation body uses different conventions
/// (e.g. network-trace uses `start_time` with underscore).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CollectionEntry {
    #[serde(rename = "type")]
    pub attestor_type: String,
    /// The attestor payload. Opaque `serde_json::Value` so we can mix
    /// strongly-typed attestors (defined below) with any extension
    /// type a future fork of witness adds.
    pub attestation: serde_json::Value,
    pub starttime: DateTime<Utc>,
    pub endtime: DateTime<Utc>,
}

// ---------------------------------------------------------------------
// DigestSet — the flat JSON shape shared by every attestor
// ---------------------------------------------------------------------

/// `{algo -> hex}` — what `cryptoutil.DigestSet` marshals to in
/// go-witness. Algorithm names per `cryptoutil/digestset.go:30-56`:
/// `sha256`, `sha1`, `sha512`, `md5`, `gitoid:sha1`, `gitoid:sha256`,
/// `dirHash`. mikebom emits `sha256` exclusively for v1 of the
/// witness-format support.
pub type DigestSet = BTreeMap<String, String>;

// ---------------------------------------------------------------------
// Material attestor — {<file-path>: {<algo>: <hex>}}
// ---------------------------------------------------------------------

/// `MaterialAttestation` is a flat map of path → DigestSet, serialized
/// directly as the object payload (matches go-witness
/// `attestation/material/material.go:102` custom MarshalJSON).
pub type MaterialAttestation = BTreeMap<String, DigestSet>;

// ---------------------------------------------------------------------
// Command-run attestor
// ---------------------------------------------------------------------

/// Payload for `https://witness.dev/attestations/command-run/v0.1`.
/// Mirrors go-witness `attestation/commandrun/commandrun.go:109-120`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommandRunAttestation {
    pub cmd: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub stdout: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub stderr: String,
    pub exitcode: i32,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub processes: Vec<ProcessInfo>,
}

/// Mirrors go-witness `ProcessInfo` at `commandrun.go:96-107`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProcessInfo {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub program: String,
    pub processid: i32,
    pub parentpid: i32,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub programdigest: Option<DigestSet>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub comm: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub cmdline: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exedigest: Option<DigestSet>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub openedfiles: Option<BTreeMap<String, DigestSet>>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub environ: String,
    #[serde(default)]
    pub specbypassisvuln: bool,
}

// ---------------------------------------------------------------------
// Product attestor
// ---------------------------------------------------------------------

/// `ProductAttestation` is a flat map of path → Product, matching
/// go-witness `attestation/product/product.go` MarshalJSON (the inner
/// `Product` type lives in `attestation/context.go:152-155`).
pub type ProductAttestation = BTreeMap<String, Product>;

/// Single product entry: `{mime_type, digest}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Product {
    pub mime_type: String,
    pub digest: DigestSet,
}

// ---------------------------------------------------------------------
// Network-trace attestor — Vyom-Yadav fork
// ---------------------------------------------------------------------

/// Payload for `https://witness.dev/attestations/network-trace/v0.1`.
///
/// Matches the Vyom-Yadav fork at
/// `attestation/networktrace/networktrace.go:49-63` (outer `Attestor`
/// marshals via `NetworkTrace NetworkTrace \`json:"network_trace"\``).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkTraceAttestation {
    pub network_trace: NetworkTrace,
}

/// The `network_trace` payload body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkTrace {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub connections: Vec<Connection>,
    pub summary: NetworkSummary,
    pub config: NetworkConfig,
}

/// A single connection. Mirrors
/// `attestation/networktrace/types/types.go:114-141`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Connection {
    pub id: String,
    pub protocol: String,
    pub start_time: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub end_time: Option<DateTime<Utc>>,
    pub process: ConnectionProcess,
    pub destination: Endpoint,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tcp_payloads: Vec<TcpPayload>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub error: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConnectionProcess {
    pub pid: u32,
    pub comm: String,
    pub cgroup_id: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: String,
    pub port: u16,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub hostname: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TcpPayload {
    pub timestamp: DateTime<Utc>,
    pub direction: String,
    pub payload: Payload,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Payload {
    pub size: u64,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub data: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub hash: String,
    #[serde(default)]
    pub truncated: bool,
}

/// Network summary. Mirrors
/// `attestation/networktrace/types/types.go:144-151`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub total_connections: u64,
    pub protocol_counts: BTreeMap<String, u64>,
    pub unique_hosts: Vec<String>,
    pub unique_ips: Vec<String>,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

/// Network-trace attestor config. Mirrors
/// `attestation/networktrace/types/config.go:25-38`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub observe_pids: Vec<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub observe_cgroups: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub observe_commands: Vec<String>,
    pub observe_child_tree: bool,
    pub proxy_port: u16,
    pub proxy_bind_ipv4: String,
    pub payload: PayloadConfig,
}

/// Payload-recording config. Mirrors
/// `attestation/networktrace/types/types.go:27-36`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PayloadConfig {
    pub record_payload: bool,
    pub record_payload_hash: bool,
    pub max_payload_size: u64,
}

impl Default for PayloadConfig {
    fn default() -> Self {
        Self {
            record_payload: false,
            record_payload_hash: false,
            max_payload_size: 0,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            observe_pids: Vec::new(),
            observe_cgroups: Vec::new(),
            observe_commands: Vec::new(),
            observe_child_tree: false,
            proxy_port: 0,
            proxy_bind_ipv4: String::new(),
            payload: PayloadConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Build a single-entry [`DigestSet`] with SHA-256.
pub fn sha256_digest(hex: impl Into<String>) -> DigestSet {
    let mut m = DigestSet::new();
    m.insert("sha256".to_string(), hex.into());
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
    }

    #[test]
    fn statement_serializes_with_v01_type_and_collection_predicate_uri() {
        let stmt = WitnessStatement {
            statement_type: STATEMENT_TYPE_V01.to_string(),
            subject: vec![WitnessSubject {
                name: "target/release/app".to_string(),
                digest: sha256_digest("abc"),
            }],
            predicate_type: COLLECTION_PREDICATE_TYPE.to_string(),
            predicate: Collection {
                name: "build".to_string(),
                attestations: vec![],
            },
        };
        let json = serde_json::to_string(&stmt).expect("serialize");
        assert!(json.contains("\"_type\":\"https://in-toto.io/Statement/v0.1\""));
        assert!(json.contains(
            "\"predicateType\":\"https://witness.testifysec.com/attestation-collection/v0.1\""
        ));
    }

    #[test]
    fn collection_entry_uses_one_word_starttime_endtime() {
        let entry = CollectionEntry {
            attestor_type: MATERIAL_TYPE.to_string(),
            attestation: serde_json::json!({}),
            starttime: t(1_700_000_000),
            endtime: t(1_700_000_001),
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(json.contains("\"starttime\""));
        assert!(json.contains("\"endtime\""));
        assert!(!json.contains("\"start_time\""));
        assert!(!json.contains("\"end_time\""));
    }

    #[test]
    fn material_attestation_is_flat_path_to_digestset() {
        let mut m: MaterialAttestation = BTreeMap::new();
        m.insert("src/main.rs".to_string(), sha256_digest("aaa"));
        m.insert("Cargo.toml".to_string(), sha256_digest("bbb"));
        let json = serde_json::to_string(&m).expect("serialize");
        // Top-level keys are the file paths.
        assert!(json.contains("\"Cargo.toml\":{\"sha256\":\"bbb\"}"));
        assert!(json.contains("\"src/main.rs\":{\"sha256\":\"aaa\"}"));
    }

    #[test]
    fn product_attestation_values_are_objects_with_mime_type() {
        let mut p: ProductAttestation = BTreeMap::new();
        p.insert(
            "target/release/app".to_string(),
            Product {
                mime_type: "application/x-executable".to_string(),
                digest: sha256_digest("deadbeef"),
            },
        );
        let json = serde_json::to_string(&p).expect("serialize");
        assert!(json.contains("\"mime_type\":\"application/x-executable\""));
        assert!(json.contains("\"digest\":{\"sha256\":\"deadbeef\"}"));
    }

    #[test]
    fn command_run_round_trips() {
        let c = CommandRunAttestation {
            cmd: vec!["cargo".to_string(), "install".to_string(), "ripgrep".to_string()],
            stdout: "ok".to_string(),
            stderr: String::new(),
            exitcode: 0,
            processes: vec![ProcessInfo {
                program: "cargo".to_string(),
                processid: 1234,
                parentpid: 1,
                programdigest: Some(sha256_digest("aa")),
                comm: "cargo".to_string(),
                cmdline: String::new(),
                exedigest: None,
                openedfiles: None,
                environ: String::new(),
                specbypassisvuln: false,
            }],
        };
        let json = serde_json::to_string(&c).expect("serialize");
        let back: CommandRunAttestation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(c, back);
        assert!(json.contains("\"exitcode\":0"));
        assert!(json.contains("\"processid\":1234"));
        assert!(json.contains("\"parentpid\":1"));
    }

    #[test]
    fn command_run_omits_empty_optional_fields() {
        let c = CommandRunAttestation {
            cmd: vec!["echo".to_string()],
            stdout: String::new(),
            stderr: String::new(),
            exitcode: 0,
            processes: vec![],
        };
        let json = serde_json::to_string(&c).expect("serialize");
        assert!(!json.contains("stdout"));
        assert!(!json.contains("stderr"));
        assert!(!json.contains("processes"));
    }

    #[test]
    fn network_trace_uses_underscored_start_time() {
        let nt = NetworkTraceAttestation {
            network_trace: NetworkTrace {
                start_time: t(1_700_000_000),
                end_time: t(1_700_000_001),
                connections: vec![],
                summary: NetworkSummary {
                    total_connections: 0,
                    protocol_counts: BTreeMap::new(),
                    unique_hosts: vec![],
                    unique_ips: vec![],
                    total_bytes_sent: 0,
                    total_bytes_received: 0,
                },
                config: NetworkConfig::default(),
            },
        };
        let json = serde_json::to_string(&nt).expect("serialize");
        assert!(json.contains("\"network_trace\""));
        assert!(json.contains("\"start_time\""));
        assert!(json.contains("\"end_time\""));
        // Confirm the OUTER collection wrapper's one-word tags aren't
        // accidentally leaking into the inner shape.
        assert!(!json.contains("\"starttime\""));
        assert!(!json.contains("\"endtime\""));
    }

    #[test]
    fn network_trace_connection_serializes_endpoint_ip_as_string() {
        let conn = Connection {
            id: "conn-1".to_string(),
            protocol: "tcp".to_string(),
            start_time: t(1_700_000_000),
            end_time: Some(t(1_700_000_001)),
            process: ConnectionProcess {
                pid: 42,
                comm: "curl".to_string(),
                cgroup_id: 100,
            },
            destination: Endpoint {
                ip: "93.184.216.34".to_string(),
                port: 443,
                hostname: "example.com".to_string(),
            },
            tcp_payloads: vec![],
            bytes_sent: 128,
            bytes_received: 2048,
            error: String::new(),
        };
        let json = serde_json::to_string(&conn).expect("serialize");
        assert!(json.contains("\"ip\":\"93.184.216.34\""));
        assert!(json.contains("\"port\":443"));
        assert!(json.contains("\"hostname\":\"example.com\""));
        assert!(!json.contains("tcp_payloads"), "empty tcp_payloads should be omitted");
        assert!(!json.contains("\"error\""), "empty error should be omitted");
    }

    #[test]
    fn full_collection_round_trips_through_serde() {
        let mut materials: MaterialAttestation = BTreeMap::new();
        materials.insert("src/main.rs".to_string(), sha256_digest("aaa"));

        let cmd = CommandRunAttestation {
            cmd: vec!["cargo".to_string(), "build".to_string()],
            stdout: String::new(),
            stderr: String::new(),
            exitcode: 0,
            processes: vec![],
        };

        let mut products: ProductAttestation = BTreeMap::new();
        products.insert(
            "target/release/app".to_string(),
            Product {
                mime_type: "application/x-executable".to_string(),
                digest: sha256_digest("bbb"),
            },
        );

        let stmt = WitnessStatement {
            statement_type: STATEMENT_TYPE_V01.to_string(),
            subject: vec![WitnessSubject {
                name: "target/release/app".to_string(),
                digest: sha256_digest("bbb"),
            }],
            predicate_type: COLLECTION_PREDICATE_TYPE.to_string(),
            predicate: Collection {
                name: "build".to_string(),
                attestations: vec![
                    CollectionEntry {
                        attestor_type: MATERIAL_TYPE.to_string(),
                        attestation: serde_json::to_value(&materials).unwrap(),
                        starttime: t(1_700_000_000),
                        endtime: t(1_700_000_001),
                    },
                    CollectionEntry {
                        attestor_type: COMMAND_RUN_TYPE.to_string(),
                        attestation: serde_json::to_value(&cmd).unwrap(),
                        starttime: t(1_700_000_001),
                        endtime: t(1_700_000_005),
                    },
                    CollectionEntry {
                        attestor_type: PRODUCT_TYPE.to_string(),
                        attestation: serde_json::to_value(&products).unwrap(),
                        starttime: t(1_700_000_005),
                        endtime: t(1_700_000_006),
                    },
                ],
            },
        };
        let json = serde_json::to_string(&stmt).unwrap();
        let back: WitnessStatement = serde_json::from_str(&json).unwrap();
        assert_eq!(stmt, back);
    }
}
