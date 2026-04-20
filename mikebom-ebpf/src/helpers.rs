use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid};

use crate::maps::CONFIG;

/// Check if the current process should be traced.
///
/// Drops events originating from the tracer itself (mikebom userspace) to
/// prevent a feedback loop where ring buffer draining generates new events.
/// Broader PID filtering (e.g. limiting to a specific build command) is
/// applied in userspace against the aggregated stream.
#[inline(always)]
pub fn should_trace() -> bool {
    let pid = current_pid();
    if let Some(cfg) = CONFIG.get(0) {
        if cfg.tracer_pid != 0 && cfg.tracer_pid == pid {
            return false;
        }
    }
    true
}

/// Get the current PID (thread group ID).
#[inline(always)]
pub fn current_pid() -> u32 {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    (pid_tgid >> 32) as u32
}

/// Get the current TID (thread ID).
#[inline(always)]
pub fn current_tid() -> u32 {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    (pid_tgid & 0xFFFFFFFF) as u32
}

/// Get the current process command name.
#[inline(always)]
pub fn current_comm() -> [u8; 16] {
    bpf_get_current_comm().unwrap_or([0u8; 16])
}
