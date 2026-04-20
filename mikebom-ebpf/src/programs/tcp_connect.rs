use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{kprobe, kretprobe},
    programs::{ProbeContext, RetProbeContext},
};

use mikebom_common::events::{NetworkEvent, NetworkEventType};
use mikebom_common::ip::IpAddr;

use crate::helpers::{current_comm, current_pid, current_tid, should_trace};
use crate::maps::{CONN_INFO, NETWORK_EVENTS};

/// kprobe on tcp_v4_connect — captures destination address and port
/// before the connection is established.
#[kprobe]
pub fn tcp_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_connect(&ctx) {
        Ok(0) => 0,
        _ => 0, // swallow errors in eBPF — can't propagate
    }
}

fn try_tcp_connect(ctx: &ProbeContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    // arg0: struct sock *sk
    // We read the destination address from sk->__sk_common.skc_daddr
    // and port from sk->__sk_common.skc_dport
    let sk: *const u8 = ctx.arg(0).ok_or(1i64)?;

    // Read destination IPv4 address (offset varies by kernel version)
    // These offsets are for common kernel layouts; may need BTF for portability
    // skc_daddr is at offset 4 in struct sock_common, skc_dport at offset 12
    let daddr_ptr = unsafe { sk.add(4) } as *const u32;
    let daddr: u32 = unsafe { bpf_probe_read_kernel(daddr_ptr).map_err(|e| e as i64)? };
    let dport_ptr = unsafe { sk.add(12) } as *const u16;
    let dport: u16 = unsafe { bpf_probe_read_kernel(dport_ptr).map_err(|e| e as i64)? };
    let dport = u16::from_be(dport);

    let pid = current_pid();
    let tid = current_tid();
    let comm = current_comm();
    let timestamp = unsafe { bpf_ktime_get_ns() };

    // Store connection info for correlation with TLS events
    let conn_id = timestamp; // Use timestamp as connection ID for now
    let conn_info = mikebom_common::maps::ConnInfo {
        pid,
        tid,
        dst_addr: IpAddr::new_v4(
            (daddr & 0xFF) as u8,
            ((daddr >> 8) & 0xFF) as u8,
            ((daddr >> 16) & 0xFF) as u8,
            ((daddr >> 24) & 0xFF) as u8,
        ),
        dst_port: dport,
        _padding: [0; 6],
        established_ns: timestamp,
    };

    CONN_INFO.insert(&conn_id, &conn_info, 0).map_err(|e| e as i64)?;

    // Emit a connection established event
    if let Some(mut buf) = NETWORK_EVENTS.reserve::<NetworkEvent>(0) {
        let event = buf.as_mut_ptr();
        unsafe {
            (*event).event_type = NetworkEventType::ConnEstablished;
            (*event).timestamp_ns = timestamp;
            (*event).pid = pid;
            (*event).tid = tid;
            (*event).comm = comm;
            (*event).conn_id = conn_id;
            (*event).dst_addr = conn_info.dst_addr;
            (*event).dst_port = dport;
            (*event).src_addr = IpAddr::new_v4(0, 0, 0, 0);
            (*event).src_port = 0;
            (*event).payload_size = 0;
            (*event).payload_hash = [0; 32];
            (*event).payload_fragment = [0; 512];
            (*event).payload_truncated = 0;
            (*event)._padding = [0; 3];
        }
        buf.submit(0);
    }

    Ok(0)
}

/// kretprobe on tcp_v4_connect — confirms connection success.
#[kretprobe]
pub fn tcp_connect_ret(ctx: RetProbeContext) -> u32 {
    // Return value 0 = success, negative = error
    // We could filter out failed connections here if needed
    let _ret: i32 = ctx.ret().unwrap_or(-1);
    0
}
