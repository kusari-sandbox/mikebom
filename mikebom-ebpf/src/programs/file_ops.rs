use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes},
    macros::kprobe,
    programs::ProbeContext,
};
use aya_ebpf::helpers::gen::bpf_d_path;

use mikebom_common::events::{FileEvent, FileEventType};

use crate::helpers::{current_comm, current_pid, current_tid, should_trace};
use crate::maps::FILE_EVENTS;

/// kprobe on vfs_write — captures file write operations.
///
/// ssize_t vfs_write(struct file *file, const char __user *buf,
///                   size_t count, loff_t *pos)
#[kprobe]
pub fn vfs_write_entry(ctx: ProbeContext) -> u32 {
    match try_vfs_write(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_vfs_write(ctx: &ProbeContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    let file_ptr: u64 = ctx.arg(0).ok_or(1i64)?;
    let count: u64 = ctx.arg(2).ok_or(1i64)?;

    let pid = current_pid();
    let tid = current_tid();
    let comm = current_comm();
    let timestamp = unsafe { bpf_ktime_get_ns() };

    // Read file path from struct file -> f_path -> dentry -> d_name
    // This is kernel-version dependent; using simplified approach
    let path = [0u8; 256];
    // In a real implementation, we'd use bpf_d_path or walk the dentry
    // For now, mark as needing userspace path resolution from fd
    let _ = file_ptr; // suppress unused warning

    if let Some(mut buf) = FILE_EVENTS.reserve::<FileEvent>(0) {
        let event = buf.as_mut_ptr();
        unsafe {
            (*event).event_type = FileEventType::Write;
            (*event).timestamp_ns = timestamp;
            (*event).pid = pid;
            (*event).tid = tid;
            (*event).comm = comm;
            (*event).path = path;
            (*event).path_truncated = 0;
            (*event)._path_padding = [0; 3];
            (*event).flags = 0;
            (*event).bytes_transferred = count;
            (*event).content_hash = [0; 32]; // computed in userspace
            (*event).inode = 0; // populated from file struct
        }
        buf.submit(0);
    }

    Ok(0)
}

/// kprobe on vfs_read — captures file read operations.
#[kprobe]
pub fn vfs_read_entry(ctx: ProbeContext) -> u32 {
    match try_vfs_read(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_vfs_read(ctx: &ProbeContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    let file_ptr: u64 = ctx.arg(0).ok_or(1i64)?;
    let count: u64 = ctx.arg(2).ok_or(1i64)?;

    let pid = current_pid();
    let tid = current_tid();
    let comm = current_comm();
    let timestamp = unsafe { bpf_ktime_get_ns() };

    let path = [0u8; 256];
    let _ = file_ptr;

    if let Some(mut buf) = FILE_EVENTS.reserve::<FileEvent>(0) {
        let event = buf.as_mut_ptr();
        unsafe {
            (*event).event_type = FileEventType::Read;
            (*event).timestamp_ns = timestamp;
            (*event).pid = pid;
            (*event).tid = tid;
            (*event).comm = comm;
            (*event).path = path;
            (*event).path_truncated = 0;
            (*event)._path_padding = [0; 3];
            (*event).flags = 0;
            (*event).bytes_transferred = count;
            (*event).content_hash = [0; 32];
            (*event).inode = 0;
        }
        buf.submit(0);
    }

    Ok(0)
}

/// kprobe on do_sys_openat2 — captures file open events with flags.
///
/// long do_sys_openat2(int dfd, const char __user *filename,
///                     struct open_how *how)
#[kprobe]
pub fn openat2_entry(ctx: ProbeContext) -> u32 {
    match try_openat2(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_openat2(ctx: &ProbeContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    let filename_ptr: u64 = ctx.arg(1).ok_or(1i64)?;

    let pid = current_pid();
    let tid = current_tid();
    let comm = current_comm();
    let timestamp = unsafe { bpf_ktime_get_ns() };

    // Read the filename from userspace
    let mut path = [0u8; 256];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(
            filename_ptr as *const u8,
            &mut path,
        );
    }

    if let Some(mut buf) = FILE_EVENTS.reserve::<FileEvent>(0) {
        let event = buf.as_mut_ptr();
        unsafe {
            (*event).event_type = FileEventType::Open;
            (*event).timestamp_ns = timestamp;
            (*event).pid = pid;
            (*event).tid = tid;
            (*event).comm = comm;
            (*event).path = path;
            (*event).path_truncated = 0;
            (*event)._path_padding = [0; 3];
            (*event).flags = 0;
            (*event).bytes_transferred = 0;
            (*event).content_hash = [0; 32];
            (*event).inode = 0;
        }
        buf.submit(0);
    }

    Ok(0)
}

/// kprobe on do_filp_open — the common entry point for every open-family
/// syscall (open, openat, openat2, creat). Hooking here catches file opens
/// that the glibc `openat` wrapper takes, which on modern kernels bypass
/// `do_sys_openat2` and would otherwise be invisible to us.
///
/// struct file *do_filp_open(int dfd, struct filename *pathname,
///                           const struct open_flags *op)
///
/// `struct filename` layout (stable across recent Linux versions):
///   const char *name;          // offset 0 — kernel-space pathname
///   const char __user *uptr;   // offset 8 — userspace pointer (may be NULL)
///
/// We read the 8-byte `name` pointer then dereference it as a kernel string.
#[kprobe]
pub fn do_filp_open_entry(ctx: ProbeContext) -> u32 {
    match try_do_filp_open(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

/// kprobe on vfs_open — the canonical place to observe every successful
/// file open, after the kernel has resolved the final path. `vfs_open`'s
/// first argument is `const struct path *`, which is exactly what
/// `bpf_d_path` takes to produce a full canonical pathname regardless of
/// the syscall wrapper the userspace program used (open, openat, openat2,
/// creat, io_uring open, …). This is the authoritative fallback for paths
/// that `do_filp_open_entry`'s struct-filename read misses — notably
/// curl's `-O` output file and cargo's `.crate` writes.
///
/// int vfs_open(const struct path *path, struct file *file)
#[kprobe]
pub fn vfs_open_entry(ctx: ProbeContext) -> u32 {
    match try_vfs_open(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_vfs_open(ctx: &ProbeContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    let path_ptr: u64 = ctx.arg(0).ok_or(1i64)?;
    if path_ptr == 0 {
        return Ok(0);
    }

    let pid = current_pid();
    let tid = current_tid();
    let comm = current_comm();
    let timestamp = unsafe { bpf_ktime_get_ns() };

    if let Some(mut buf) = FILE_EVENTS.reserve::<FileEvent>(0) {
        let event = buf.as_mut_ptr();
        unsafe {
            (*event).event_type = FileEventType::Open;
            (*event).timestamp_ns = timestamp;
            (*event).pid = pid;
            (*event).tid = tid;
            (*event).comm = comm;
            (*event).path = [0u8; 256];
            (*event).path_truncated = 0;
            (*event)._path_padding = [0; 3];
            (*event).flags = 0;
            (*event).bytes_transferred = 0;
            (*event).content_hash = [0; 32];
            (*event).inode = 0;

            // bpf_d_path writes the canonical pathname (with embedded NUL)
            // into the path buffer. Returns the byte count written or a
            // negative errno. We simply skip submission if the helper
            // fails — it is allow-listed by the kernel for a short set of
            // function hooks and may refuse on others.
            let n = bpf_d_path(
                path_ptr as *mut _,
                (*event).path.as_mut_ptr() as *mut _,
                256,
            );
            if n <= 0 {
                // Not an error; just nothing useful to record.
                return Ok(0);
            }
        }
        buf.submit(0);
    }

    Ok(0)
}

fn try_do_filp_open(ctx: &ProbeContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    let filename_struct: *const u8 = ctx.arg(1).ok_or(1i64)?;
    if filename_struct.is_null() {
        return Ok(0);
    }

    // Read the `name` pointer (first field of struct filename, offset 0).
    let name_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(filename_struct as *const *const u8)
            .map_err(|e| e as i64)?
    };
    if name_ptr.is_null() {
        return Ok(0);
    }

    let pid = current_pid();
    let tid = current_tid();
    let comm = current_comm();
    let timestamp = unsafe { bpf_ktime_get_ns() };

    let mut path = [0u8; 256];
    unsafe {
        let _ = bpf_probe_read_kernel_str_bytes(name_ptr, &mut path);
    }

    if let Some(mut buf) = FILE_EVENTS.reserve::<FileEvent>(0) {
        let event = buf.as_mut_ptr();
        unsafe {
            (*event).event_type = FileEventType::Open;
            (*event).timestamp_ns = timestamp;
            (*event).pid = pid;
            (*event).tid = tid;
            (*event).comm = comm;
            (*event).path = path;
            (*event).path_truncated = 0;
            (*event)._path_padding = [0; 3];
            (*event).flags = 0;
            (*event).bytes_transferred = 0;
            (*event).content_hash = [0; 32];
            (*event).inode = 0;
        }
        buf.submit(0);
    }

    Ok(0)
}
