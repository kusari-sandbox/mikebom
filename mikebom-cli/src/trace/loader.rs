use std::path::PathBuf;

pub struct LoaderConfig {
    pub target_pid: u32,
    pub libssl_path: Option<PathBuf>,
    pub ring_buffer_size: u32,
    pub trace_children: bool,
    pub ebpf_object: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
mod inner {
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result};
    use aya::programs::{KProbe, UProbe};
    use aya::Ebpf;
    use tracing::{debug, info, warn};

    use mikebom_common::maps::TraceConfig;

    use super::LoaderConfig;

    pub struct EbpfHandle {
        pub bpf: Ebpf,
    }

    pub fn load_and_attach(config: &LoaderConfig) -> Result<EbpfHandle> {
        info!(target_pid = config.target_pid, "Loading eBPF program");

        let obj_path = config
            .ebpf_object
            .clone()
            .unwrap_or_else(default_ebpf_path);

        let data = std::fs::read(&obj_path).with_context(|| {
            format!(
                "failed to read eBPF object at {}. Run `cargo xtask ebpf` first.",
                obj_path.display()
            )
        })?;

        let mut bpf = Ebpf::load(&data).context("failed to load eBPF bytecode")?;

        // Populate PID filter (even though kernel-side is disabled,
        // keep the map populated for future use)
        {
            let mut pid_filter: aya::maps::HashMap<_, u32, u8> =
                aya::maps::HashMap::try_from(
                    bpf.map_mut("PID_FILTER").context("PID_FILTER map not found")?,
                )?;
            pid_filter.insert(config.target_pid, 1, 0).ok();
        }

        // Set runtime configuration
        {
            let mut cfg_map: aya::maps::Array<_, TraceConfig> =
                aya::maps::Array::try_from(
                    bpf.map_mut("CONFIG").context("CONFIG map not found")?,
                )?;
            cfg_map
                .set(
                    0,
                    TraceConfig {
                        max_payload_capture: 512,
                        tracer_pid: std::process::id(),
                        capture_file_content_hash: 1,
                        trace_children: if config.trace_children { 1 } else { 0 },
                        _padding: [0; 2],
                    },
                    0,
                )
                .ok();
        }

        // Attach uprobes to OpenSSL
        let libssl = config
            .libssl_path
            .clone()
            .or_else(find_libssl)
            .context("could not find libssl.so — pass --libssl-path")?;

        info!(path = %libssl.display(), "Attaching uprobes to libssl");
        attach_uprobe(&mut bpf, "ssl_read_entry", &libssl, "SSL_read")?;
        attach_uprobe(&mut bpf, "ssl_read_return", &libssl, "SSL_read")?;
        attach_uprobe(&mut bpf, "ssl_write_entry", &libssl, "SSL_write")?;

        // Attach kprobes
        attach_kprobe(&mut bpf, "tcp_connect", "tcp_v4_connect")?;
        attach_kprobe(&mut bpf, "tcp_connect_ret", "tcp_v4_connect")?;
        // vfs_read/vfs_write are intentionally NOT attached. They fire on
        // every read/write syscall system-wide but the current probe emits
        // empty-path events (kernel path resolution for vfs_* is non-trivial).
        // Every such event consumes ring-buffer space for no aggregator
        // benefit — enough of them to push out the late opens (like curl's
        // -o output file). File opens already carry the path via
        // do_filp_open + openat2, so we rely on those alone.
        if let Err(e) = attach_kprobe(&mut bpf, "openat2_entry", "do_sys_openat2") {
            warn!("could not attach openat2 kprobe: {e}");
        }
        // do_filp_open catches every open-family syscall (open, openat,
        // openat2, creat) and is the fallback for paths openat2 misses,
        // e.g. glibc's default `open()` wrapper.
        if let Err(e) = attach_kprobe(&mut bpf, "do_filp_open_entry", "do_filp_open") {
            warn!("could not attach do_filp_open kprobe: {e}");
        }
        // vfs_open fires after successful open with the fully-resolved
        // `struct path *`. Hooking here and calling `bpf_d_path` yields a
        // canonical pathname even for opens that the other two probes
        // miss (observed with curl's -O output file and cargo's .crate
        // writes — root cause of the "Rust SBOM has zero components" bug).
        if let Err(e) = attach_kprobe(&mut bpf, "vfs_open_entry", "vfs_open") {
            warn!("could not attach vfs_open kprobe: {e}");
        }

        info!("All probes attached");
        Ok(EbpfHandle { bpf })
    }

    fn attach_uprobe(bpf: &mut Ebpf, prog: &str, lib: &Path, fn_name: &str) -> Result<()> {
        let p: &mut UProbe = bpf
            .program_mut(prog)
            .and_then(|p| p.try_into().ok())
            .with_context(|| format!("program '{prog}' not found"))?;
        p.load()?;
        p.attach(Some(fn_name), 0, lib, None)?;
        debug!(prog, fn_name, "uprobe attached");
        Ok(())
    }

    fn attach_kprobe(bpf: &mut Ebpf, prog: &str, fn_name: &str) -> Result<()> {
        let p: &mut KProbe = bpf
            .program_mut(prog)
            .and_then(|p| p.try_into().ok())
            .with_context(|| format!("program '{prog}' not found"))?;
        p.load()?;
        p.attach(fn_name, 0)?;
        debug!(prog, fn_name, "kprobe attached");
        Ok(())
    }

    fn default_ebpf_path() -> PathBuf {
        let p = PathBuf::from("mikebom-ebpf/target/bpfel-unknown-none/release/mikebom-ebpf");
        if p.exists() { return p; }
        PathBuf::from("target/bpfel-unknown-none/release/mikebom-ebpf")
    }

    fn find_libssl() -> Option<PathBuf> {
        for p in &[
            "/usr/lib/x86_64-linux-gnu/libssl.so",
            "/usr/lib/aarch64-linux-gnu/libssl.so",
            "/usr/lib/libssl.so",
            "/usr/lib64/libssl.so",
        ] {
            let path = PathBuf::from(p);
            if path.exists() { return Some(path); }
        }
        None
    }
}

#[cfg(target_os = "linux")]
pub use inner::{load_and_attach, EbpfHandle};

#[cfg(not(target_os = "linux"))]
pub struct EbpfHandle;

#[cfg(not(target_os = "linux"))]
pub fn load_and_attach(_: &LoaderConfig) -> anyhow::Result<EbpfHandle> {
    anyhow::bail!("eBPF tracing requires Linux.")
}
