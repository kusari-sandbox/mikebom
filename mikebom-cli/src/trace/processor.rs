//! Async ring buffer consumer for eBPF events.
//!
//! On Linux, this module reads `NetworkEvent` and `FileEvent` structs from
//! aya ring buffers and forwards them through tokio channels to the
//! aggregator stage.
//!
//! On non-Linux platforms, a stub implementation is provided that
//! immediately returns an error.

use std::sync::atomic::{AtomicU64, Ordering};

/// Statistics collected during a trace session.
#[derive(Clone, Debug, Default)]
pub struct TraceStats {
    /// Total network events consumed from the ring buffer.
    pub network_events: u64,
    /// Total file events consumed from the ring buffer.
    pub file_events: u64,
    /// Number of ring buffer overflow events detected.
    pub ring_buffer_overflows: u64,
    /// Events dropped due to channel back-pressure or decode errors.
    pub events_dropped: u64,
}

/// Shared, atomically-updated counters for real-time stats access.
#[derive(Debug)]
pub struct LiveStats {
    pub network_events: AtomicU64,
    pub file_events: AtomicU64,
    pub ring_buffer_overflows: AtomicU64,
    pub events_dropped: AtomicU64,
}

impl LiveStats {
    pub fn new() -> Self {
        Self {
            network_events: AtomicU64::new(0),
            file_events: AtomicU64::new(0),
            ring_buffer_overflows: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
        }
    }

    /// Snapshot the current counters into a `TraceStats`.
    pub fn snapshot(&self) -> TraceStats {
        TraceStats {
            network_events: self.network_events.load(Ordering::Relaxed),
            file_events: self.file_events.load(Ordering::Relaxed),
            ring_buffer_overflows: self.ring_buffer_overflows.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
        }
    }
}

impl Default for LiveStats {
    fn default() -> Self {
        Self::new()
    }
}

// ── Linux implementation ──────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod inner {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use anyhow::{Context, Result};
    use aya::maps::RingBuf;
    use tokio::sync::mpsc;
    use tracing::{debug, trace, warn};

    use mikebom_common::events::{FileEvent, NetworkEvent};

    use super::{LiveStats, TraceStats};

    /// Async processor that drains eBPF ring buffers and forwards events.
    pub struct TraceProcessor;

    impl TraceProcessor {
        /// Run the event processing loop until the stop signal is received.
        ///
        /// Reads from `network_rb` and `file_rb`, sending decoded events
        /// through the provided channels. Returns final stats on completion.
        pub async fn run(
            mut network_rb: RingBuf<&mut aya::maps::MapData>,
            mut file_rb: RingBuf<&mut aya::maps::MapData>,
            network_tx: mpsc::Sender<NetworkEvent>,
            file_tx: mpsc::Sender<FileEvent>,
            stop: Arc<std::sync::atomic::AtomicBool>,
            stats: Arc<LiveStats>,
        ) -> Result<TraceStats> {
            debug!("Trace processor started");

            while !stop.load(Ordering::Relaxed) {
                // Poll network ring buffer
                while let Some(item) = network_rb.next() {
                    let data: &[u8] = item.as_ref();
                    if data.len() < std::mem::size_of::<NetworkEvent>() {
                        warn!(
                            len = data.len(),
                            expected = std::mem::size_of::<NetworkEvent>(),
                            "Short network event, dropping"
                        );
                        stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    // SAFETY: NetworkEvent is #[repr(C)] and we verified the
                    // length. The eBPF program writes this exact layout.
                    let event: NetworkEvent =
                        unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };

                    stats.network_events.fetch_add(1, Ordering::Relaxed);
                    trace!(
                        pid = event.pid,
                        event_type = event.event_type as u8,
                        "Network event"
                    );

                    if network_tx.try_send(event).is_err() {
                        stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // Poll file ring buffer
                while let Some(item) = file_rb.next() {
                    let data: &[u8] = item.as_ref();
                    if data.len() < std::mem::size_of::<FileEvent>() {
                        warn!(
                            len = data.len(),
                            expected = std::mem::size_of::<FileEvent>(),
                            "Short file event, dropping"
                        );
                        stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    let event: FileEvent =
                        unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };

                    stats.file_events.fetch_add(1, Ordering::Relaxed);
                    trace!(
                        pid = event.pid,
                        path = event.path_str(),
                        "File event"
                    );

                    if file_tx.try_send(event).is_err() {
                        stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // Yield to the runtime briefly to avoid busy-spinning.
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }

            let final_stats = stats.snapshot();
            debug!(
                network = final_stats.network_events,
                file = final_stats.file_events,
                dropped = final_stats.events_dropped,
                "Trace processor finished"
            );
            Ok(final_stats)
        }
    }
}

// ── Non-Linux stub ────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
mod inner {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use anyhow::{bail, Result};

    use super::{LiveStats, TraceStats};

    /// Stub trace processor for non-Linux platforms.
    pub struct TraceProcessor;

    impl TraceProcessor {
        /// Always returns an error on non-Linux platforms.
        pub async fn run_stub(
            _stop: Arc<AtomicBool>,
            _stats: Arc<LiveStats>,
        ) -> Result<TraceStats> {
            bail!("eBPF trace processing requires Linux — this platform is not supported")
        }
    }
}

