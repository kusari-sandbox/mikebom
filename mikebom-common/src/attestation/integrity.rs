use serde::{Deserialize, Serialize};

use crate::types::timestamp::Timestamp;

/// Diagnostic information about the fidelity of the trace capture.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TraceIntegrity {
    pub ring_buffer_overflows: u64,
    pub events_dropped: u64,
    pub uprobe_attach_failures: Vec<String>,
    pub kprobe_attach_failures: Vec<String>,
    pub partial_captures: Vec<PartialCapture>,
    pub bloom_filter_capacity: u64,
    pub bloom_filter_false_positive_rate: f64,
}

/// Record of an event that was only partially captured.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PartialCapture {
    pub event_type: String,
    pub reason: String,
    pub timestamp: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_integrity_serde_round_trip() {
        let integrity = TraceIntegrity {
            ring_buffer_overflows: 0,
            events_dropped: 2,
            uprobe_attach_failures: vec!["libssl.so:SSL_write".to_string()],
            kprobe_attach_failures: vec![],
            partial_captures: vec![PartialCapture {
                event_type: "tls_handshake".to_string(),
                reason: "buffer too small".to_string(),
                timestamp: Timestamp::now(),
            }],
            bloom_filter_capacity: 100_000,
            bloom_filter_false_positive_rate: 0.01,
        };

        let json = serde_json::to_string(&integrity).expect("serialize integrity");
        let back: TraceIntegrity = serde_json::from_str(&json).expect("deserialize integrity");
        assert_eq!(integrity.events_dropped, back.events_dropped);
        assert_eq!(integrity.uprobe_attach_failures, back.uprobe_attach_failures);
    }
}
