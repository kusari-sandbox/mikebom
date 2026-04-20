use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_probe_read_user_buf},
    macros::{uprobe, uretprobe},
    programs::{ProbeContext, RetProbeContext},
};

use mikebom_common::events::{NetworkEvent, NetworkEventType};
use mikebom_common::ip::IpAddr;
use mikebom_common::maps::SslBufferInfo;

use crate::helpers::{current_comm, current_pid, current_tid, should_trace};
use crate::maps::{NETWORK_EVENTS, SCRATCH_BUF, SSL_BUFFERS};

/// uprobe on SSL_read entry — captures the buffer pointer and SSL context.
#[uprobe]
pub fn ssl_read_entry(ctx: ProbeContext) -> u32 {
    match try_ssl_read_entry(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_ssl_read_entry(ctx: &ProbeContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    let ssl_ptr: u64 = ctx.arg(0).ok_or(1i64)?;
    let buf_ptr: u64 = ctx.arg(1).ok_or(1i64)?;
    let buf_len: u32 = ctx.arg::<u32>(2).ok_or(1i64)?;

    let tid = current_tid() as u64;
    let info = SslBufferInfo {
        buf_ptr,
        buf_len,
        _padding: 0,
        ssl_ptr,
    };

    SSL_BUFFERS.insert(&tid, &info, 0).map_err(|e| e as i64)?;
    Ok(0)
}

/// uretprobe on SSL_read — reads plaintext via per-CPU scratch buffer
/// to avoid exceeding the 512-byte BPF stack limit.
#[uretprobe]
pub fn ssl_read_return(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_return(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_ssl_read_return(ctx: &RetProbeContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    let bytes_read: i32 = ctx.ret().ok_or(1i64)?;
    if bytes_read <= 0 {
        return Ok(0);
    }

    let tid = current_tid() as u64;
    let info = unsafe { SSL_BUFFERS.get(&tid).ok_or(1i64)? };

    let pid = current_pid();
    let comm = current_comm();
    let timestamp = unsafe { bpf_ktime_get_ns() };
    let ssl_ptr = info.ssl_ptr;
    let buf_ptr = info.buf_ptr;
    let payload_size = bytes_read as u32;

    // Use per-CPU scratch buffer to read userspace data
    // This avoids putting 512 bytes on the BPF stack
    let scratch = unsafe {
        let idx: u32 = 0;
        SCRATCH_BUF.get_ptr_mut(idx).ok_or(1i64)?
    };

    let capture_len = if payload_size < 512 {
        payload_size as usize
    } else {
        512usize
    };

    unsafe {
        // Zero the scratch buffer first
        let scratch_slice = core::slice::from_raw_parts_mut(
            scratch as *mut u8,
            512,
        );
        for b in scratch_slice.iter_mut() {
            *b = 0;
        }
        let _ = bpf_probe_read_user_buf(
            buf_ptr as *const u8,
            &mut scratch_slice[..capture_len],
        );
    }

    // Write directly into ring buffer entry
    if let Some(mut entry) = NETWORK_EVENTS.reserve::<NetworkEvent>(0) {
        let event = entry.as_mut_ptr();
        unsafe {
            (*event).event_type = NetworkEventType::TlsRead;
            (*event).timestamp_ns = timestamp;
            (*event).pid = pid;
            (*event).tid = current_tid();
            (*event).comm = comm;
            (*event).conn_id = ssl_ptr;
            (*event).dst_addr = IpAddr::new_v4(0, 0, 0, 0);
            (*event).dst_port = 0;
            (*event).src_addr = IpAddr::new_v4(0, 0, 0, 0);
            (*event).src_port = 0;
            (*event).payload_size = payload_size;
            (*event).payload_hash = [0; 32];
            // Copy from scratch buffer into ring buffer entry
            let src = core::slice::from_raw_parts(scratch as *const u8, 512);
            (*event).payload_fragment.copy_from_slice(src);
            (*event).payload_truncated = if payload_size > 512 { 1 } else { 0 };
            (*event)._padding = [0; 3];
        }
        entry.submit(0);
    }

    SSL_BUFFERS.remove(&tid).map_err(|e| e as i64)?;
    Ok(0)
}

/// uprobe on SSL_write entry — captures outgoing plaintext before encryption.
/// Uses per-CPU scratch buffer for the same stack-size reason.
#[uprobe]
pub fn ssl_write_entry(ctx: ProbeContext) -> u32 {
    match try_ssl_write_entry(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_ssl_write_entry(ctx: &ProbeContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    let ssl_ptr: u64 = ctx.arg(0).ok_or(1i64)?;
    let buf_ptr: u64 = ctx.arg(1).ok_or(1i64)?;
    let buf_len: u32 = ctx.arg::<u32>(2).ok_or(1i64)?;

    let pid = current_pid();
    let tid = current_tid();
    let comm = current_comm();
    let timestamp = unsafe { bpf_ktime_get_ns() };

    let capture_len = if buf_len < 512 {
        buf_len as usize
    } else {
        512usize
    };

    // Use per-CPU scratch buffer
    let scratch = unsafe {
        let idx: u32 = 0;
        SCRATCH_BUF.get_ptr_mut(idx).ok_or(1i64)?
    };

    unsafe {
        let scratch_slice = core::slice::from_raw_parts_mut(
            scratch as *mut u8,
            512,
        );
        for b in scratch_slice.iter_mut() {
            *b = 0;
        }
        let _ = bpf_probe_read_user_buf(
            buf_ptr as *const u8,
            &mut scratch_slice[..capture_len],
        );
    }

    if let Some(mut entry) = NETWORK_EVENTS.reserve::<NetworkEvent>(0) {
        let event = entry.as_mut_ptr();
        unsafe {
            (*event).event_type = NetworkEventType::TlsWrite;
            (*event).timestamp_ns = timestamp;
            (*event).pid = pid;
            (*event).tid = tid;
            (*event).comm = comm;
            (*event).conn_id = ssl_ptr;
            (*event).dst_addr = IpAddr::new_v4(0, 0, 0, 0);
            (*event).dst_port = 0;
            (*event).src_addr = IpAddr::new_v4(0, 0, 0, 0);
            (*event).src_port = 0;
            (*event).payload_size = buf_len;
            (*event).payload_hash = [0; 32];
            let src = core::slice::from_raw_parts(scratch as *const u8, 512);
            (*event).payload_fragment.copy_from_slice(src);
            (*event).payload_truncated = if buf_len > 512 { 1 } else { 0 };
            (*event)._padding = [0; 3];
        }
        entry.submit(0);
    }

    Ok(0)
}
