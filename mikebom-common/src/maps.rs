use crate::ip::IpAddr;

/// Per-thread SSL buffer info stored between uprobe entry and return.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SslBufferInfo {
    /// Pointer to the buffer passed to SSL_read/SSL_write
    pub buf_ptr: u64,
    /// Length of the buffer
    pub buf_len: u32,
    pub _padding: u32,
    /// Pointer to the SSL context (for SNI extraction)
    pub ssl_ptr: u64,
}

/// Per-socket connection metadata.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ConnInfo {
    pub pid: u32,
    pub tid: u32,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub _padding: [u8; 6],
    pub established_ns: u64,
}

/// Runtime configuration passed from userspace to eBPF programs.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TraceConfig {
    /// Maximum bytes of payload to capture in the fragment (default 512)
    pub max_payload_capture: u32,
    /// PID of the tracer itself — events from this PID are always dropped
    /// in-kernel to prevent a feedback loop between probe emission and
    /// userspace ring buffer draining.
    pub tracer_pid: u32,
    /// Whether to compute content hashes in-kernel (0=no, 1=yes)
    pub capture_file_content_hash: u8,
    /// Whether to trace child processes (0=no, 1=yes)
    pub trace_children: u8,
    pub _padding: [u8; 2],
}

// Safety: these types are #[repr(C)], Copy, with explicit padding fields.
// The aya crate requires Pod for types used in eBPF maps.
#[cfg(all(feature = "aya-user", target_os = "linux"))]
unsafe impl aya::Pod for TraceConfig {}
#[cfg(all(feature = "aya-user", target_os = "linux"))]
unsafe impl aya::Pod for ConnInfo {}
#[cfg(all(feature = "aya-user", target_os = "linux"))]
unsafe impl aya::Pod for SslBufferInfo {}
