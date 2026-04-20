use crate::ip::IpAddr;

/// Type of network event observed by eBPF probes.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum NetworkEventType {
    ConnEstablished = 0,
    TlsRead = 1,
    TlsWrite = 2,
    ConnClosed = 3,
}

/// A network event emitted from eBPF ring buffer.
///
/// This struct is `#[repr(C)]` for shared use between kernel-space
/// eBPF programs and userspace. All fields are fixed-size.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct NetworkEvent {
    pub event_type: NetworkEventType,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub comm: [u8; 16],
    pub conn_id: u64,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub payload_size: u32,
    /// SHA-256 of the payload, computed in-kernel when feasible.
    pub payload_hash: [u8; 32],
    /// First 512 bytes of payload for HTTP header parsing.
    pub payload_fragment: [u8; 512],
    pub payload_truncated: u8,
    pub _padding: [u8; 3],
}

/// Type of file operation observed by eBPF probes.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum FileEventType {
    Open = 0,
    Read = 1,
    Write = 2,
    Close = 3,
}

/// A file access event emitted from eBPF ring buffer.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct FileEvent {
    pub event_type: FileEventType,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub comm: [u8; 16],
    pub path: [u8; 256],
    pub path_truncated: u8,
    pub _path_padding: [u8; 3],
    pub flags: u32,
    pub bytes_transferred: u64,
    /// SHA-256 of content when available.
    pub content_hash: [u8; 32],
    pub inode: u64,
}

#[cfg(feature = "std")]
impl NetworkEvent {
    /// Extract the process command name as a string.
    pub fn comm_str(&self) -> &str {
        let len = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        core::str::from_utf8(&self.comm[..len]).unwrap_or("<invalid>")
    }

    /// Extract the payload fragment as bytes (up to payload_size or 512).
    pub fn payload_bytes(&self) -> &[u8] {
        let len = core::cmp::min(self.payload_size as usize, 512);
        &self.payload_fragment[..len]
    }
}

#[cfg(feature = "std")]
impl FileEvent {
    /// Extract the file path as a string.
    pub fn path_str(&self) -> &str {
        let len = self.path.iter().position(|&b| b == 0).unwrap_or(256);
        core::str::from_utf8(&self.path[..len]).unwrap_or("<invalid>")
    }

    /// Extract the process command name as a string.
    pub fn comm_str(&self) -> &str {
        let len = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        core::str::from_utf8(&self.comm[..len]).unwrap_or("<invalid>")
    }
}
