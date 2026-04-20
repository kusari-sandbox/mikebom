use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, BloomFilter, HashMap, PerCpuArray, RingBuf};

use mikebom_common::maps::{ConnInfo, SslBufferInfo, TraceConfig};

/// Ring buffer for network trace events (TLS plaintext captures).
/// 8 MB default — sized for high-throughput builds.
#[map]
pub static NETWORK_EVENTS: RingBuf = RingBuf::with_byte_size(8 * 1024 * 1024, 0);

/// Ring buffer for file access events (opens).
/// 128 MB — file events fire much more frequently than network events,
/// and every unrelated process on the host contributes to the stream
/// (do_filp_open is a system-wide kprobe). The userspace drain cadence
/// is 5 ms; if the buffer fills between drains we lose events. 128 MB
/// gives room for ~400k events (~280 B each), comfortably above what a
/// busy container produces during a single HTTPS download.
#[map]
pub static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(128 * 1024 * 1024, 0);

/// Per-thread SSL buffer info stored between uprobe entry and return.
/// Key: thread ID (u64), Value: SslBufferInfo
#[map]
pub static SSL_BUFFERS: HashMap<u64, SslBufferInfo> = HashMap::with_max_entries(1024, 0);

/// Per-socket connection metadata.
/// Key: socket cookie (u64), Value: ConnInfo
#[map]
pub static CONN_INFO: HashMap<u64, ConnInfo> = HashMap::with_max_entries(4096, 0);

/// Bloom filter for in-kernel deduplication of content hashes.
/// Drops duplicate network/file events to reduce ring buffer pressure.
/// NOTE: BloomFilter::contains/insert require &mut self; callers must use
/// get_ptr_mut or similar patterns to obtain mutable access from a static.
#[map]
pub static SEEN_HASHES: BloomFilter<[u8; 32]> = BloomFilter::with_max_entries(65536, 0);

/// Per-CPU scratch buffer for reading TLS plaintext without exceeding
/// the 512-byte BPF stack limit.
#[map]
pub static SCRATCH_BUF: PerCpuArray<[u8; 512]> = PerCpuArray::with_max_entries(1, 0);

/// PIDs to trace. Set by userspace for cgroup-isolated build processes.
/// Key: PID (u32), Value: 1 (present = trace this PID)
#[map]
pub static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

/// Runtime configuration passed from userspace.
/// Index 0 holds the TraceConfig struct.
#[map]
pub static CONFIG: Array<TraceConfig> = Array::with_max_entries(1, 0);
