use std::path::PathBuf;

use clap::Args;

#[derive(Args)]
pub struct ScanArgs {
    #[arg(long)]
    pub target_pid: Option<u32>,
    #[arg(long, default_value = "mikebom.attestation.json")]
    pub output: PathBuf,
    #[arg(long)]
    pub trace_children: bool,
    #[arg(long)]
    pub libssl_path: Option<PathBuf>,
    #[arg(long)]
    pub go_binary: Option<PathBuf>,
    #[arg(long, default_value = "8388608")]
    pub ring_buffer_size: u32,
    #[arg(long, default_value = "0")]
    pub timeout: u64,
    #[arg(long)]
    pub json: bool,
    /// Directories to scan for freshly-landed artifact files after the
    /// traced command exits. Any recognised package file (`.deb`,
    /// `.crate`, `.whl`, `.tar.gz`, …) whose mtime is newer than the
    /// trace start is hashed and added to the file-access record, so
    /// the resulting SBOM carries real content hashes even when the
    /// kernel-side kprobe misses the output-file open (observed with
    /// curl's -O and cargo's .crate writes — see EVALUATION.md).
    /// Accepts the flag multiple times or comma-separated.
    #[arg(long, value_delimiter = ',')]
    pub artifact_dir: Vec<PathBuf>,
    /// Auto-detect artifact directories from the traced command. Matches
    /// `argv[0]` against a table of known build tools (cargo, pip, npm,
    /// go, apt-get, …) and merges the canonical cache paths with any
    /// explicit `--artifact-dir` values. Skipped for shell-wrapped
    /// commands (`bash -c "…"`) — those are too dynamic to introspect.
    #[arg(long)]
    pub auto_dirs: bool,

    // ─────────────────────────────────────────────────────────────
    // Feature 006 — DSSE signing flags. See specs/006-sbomit-suite/
    // contracts/cli.md for the full contract.
    // ─────────────────────────────────────────────────────────────
    /// Path to a PEM-encoded private key for local-key DSSE signing.
    /// Mutually exclusive with `--keyless`.
    #[arg(long, conflicts_with = "keyless")]
    pub signing_key: Option<PathBuf>,

    /// Name of the env var holding the passphrase for an encrypted
    /// `--signing-key`. No effect on unencrypted keys. No interactive
    /// prompt — CI-friendly by design.
    #[arg(long, value_name = "NAME")]
    pub signing_key_passphrase_env: Option<String>,

    /// Use keyless signing via OIDC → Fulcio → Rekor. Mutually
    /// exclusive with `--signing-key`.
    #[arg(long)]
    pub keyless: bool,

    /// Override the Fulcio certificate-issuance URL.
    #[arg(long, default_value = "https://fulcio.sigstore.dev")]
    pub fulcio_url: String,

    /// Override the Rekor transparency-log URL.
    #[arg(long, default_value = "https://rekor.sigstore.dev")]
    pub rekor_url: String,

    /// Skip Rekor upload + inclusion-proof embedding. Keyless mode
    /// only; with this flag the envelope carries the Fulcio cert alone.
    #[arg(long)]
    pub no_transparency_log: bool,

    /// Fail the command if no signing identity was configured. Flips
    /// the default "emit unsigned + warn" behavior to a hard error.
    #[arg(long)]
    pub require_signing: bool,

    #[arg(last = true)]
    pub command: Vec<String>,
}

impl ScanArgs {
    /// Build a [`SigningIdentity`] from the current flag combination.
    /// Returns an error when `--require-signing` is set but no identity
    /// was configured.
    pub fn build_signing_identity(
        &self,
    ) -> anyhow::Result<crate::attestation::signer::SigningIdentity> {
        use crate::attestation::signer::{OidcProvider, SigningIdentity};
        match (self.signing_key.as_ref(), self.keyless) {
            (Some(path), false) => Ok(SigningIdentity::LocalKey {
                path: path.clone(),
                passphrase_env: self.signing_key_passphrase_env.clone(),
            }),
            (None, true) => Ok(SigningIdentity::Keyless {
                fulcio_url: self.fulcio_url.clone(),
                rekor_url: self.rekor_url.clone(),
                oidc_provider: OidcProvider::detect(),
                transparency_log: !self.no_transparency_log,
            }),
            (None, false) => {
                if self.require_signing {
                    anyhow::bail!(
                        "--require-signing set but no signing identity configured; \
                        pass --signing-key <PATH> or --keyless"
                    );
                }
                Ok(SigningIdentity::None)
            }
            (Some(_), true) => {
                // `conflicts_with` on clap prevents this path, but keep
                // the defensive check in case the struct is built by hand.
                anyhow::bail!("--signing-key and --keyless are mutually exclusive")
            }
        }
    }
}

pub async fn execute(args: ScanArgs) -> anyhow::Result<()> {
    if args.target_pid.is_none() && args.command.is_empty() {
        anyhow::bail!("either --target-pid or a command (after --) is required");
    }
    if args.target_pid.is_some() && !args.command.is_empty() {
        anyhow::bail!("--target-pid and command are mutually exclusive");
    }
    execute_scan(args).await
}

#[cfg(target_os = "linux")]
async fn execute_scan(args: ScanArgs) -> anyhow::Result<()> {
    use std::time::{Duration, Instant};

    use aya::maps::RingBuf;

    use crate::attestation::builder::{self, AttestationConfig};
    use crate::attestation::serializer;
    use crate::error::MikebomError;
    use crate::trace::aggregator::EventAggregator;
    use crate::trace::loader::{self, LoaderConfig};
    use crate::trace::processor::TraceStats;
    use mikebom_common::events::{FileEvent, NetworkEvent};
    use mikebom_common::types::timestamp::Timestamp;

    let trace_start = Timestamp::now();
    // Wall-clock at trace start, used below to filter artifact directories
    // for files that appeared during this trace (mtime ≥ trace_start_wall).
    // Subtract 1 s to tolerate filesystem timestamp granularity — the worst
    // case is that we hash one file that pre-existed, which is harmless.
    let trace_start_wall = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(1))
        .unwrap_or_else(std::time::SystemTime::now);
    tracing::info!("Starting eBPF trace");

    // Sample CLOCK_BOOTTIME vs CLOCK_REALTIME up front. bpf_ktime_get_ns
    // returns CLOCK_BOOTTIME; adding this offset converts it to wall clock.
    let boot_offset_ns = compute_boot_offset_ns();
    tracing::debug!(boot_offset_ns, "computed boot→wall offset");

    // Load eBPF FIRST so probes are active before child spawns
    let target_pid = args.target_pid.unwrap_or(std::process::id());
    let mut handle = loader::load_and_attach(&LoaderConfig {
        target_pid,
        libssl_path: args.libssl_path.clone(),
        ring_buffer_size: args.ring_buffer_size,
        ebpf_object: None,
        trace_children: args.trace_children,
    })?;
    tracing::info!("eBPF probes attached");

    // THEN spawn child
    let mut child = if args.target_pid.is_none() {
        let cmd = &args.command;
        tracing::info!(command = %cmd.join(" "), "Spawning traced command");
        let c = std::process::Command::new(&cmd[0])
            .args(&cmd[1..])
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn: {e}"))?;
        tracing::info!(pid = c.id(), "Child started");
        Some(c)
    } else {
        None
    };

    let child_pid = child.as_ref().map(|c| c.id()).unwrap_or(target_pid);

    // Poll ring buffers while child runs
    let mut agg = EventAggregator::with_boot_offset(boot_offset_ns);
    let mut net_count: u64 = 0;
    let mut file_count: u64 = 0;
    let start = Instant::now();
    let timeout = if args.timeout > 0 {
        Some(Duration::from_secs(args.timeout))
    } else {
        None
    };

    // Per-iteration drain is capped so a high event rate cannot starve the
    // child-exit check. The post-exit drain uses the same cap with a short
    // settling loop so events queued before the probes see the exit still
    // land in the aggregator.
    const MAX_PER_ITER: usize = 4096;

    // Userspace PID filter. Semantics:
    //   --trace-children  → no userspace filter (kernel still drops the
    //                       tracer's own events via should_trace). Build
    //                       processes frequently fork short-lived helpers
    //                       (apt-get's http method, cargo's rustc workers)
    //                       that exit before a /proc scan catches them, so
    //                       following the subtree conservatively drops
    //                       legitimate events. Pick up system noise over
    //                       missing the build's real activity.
    //   default           → restrict to the direct child PID. Good when the
    //                       traced command does all its own I/O (curl,
    //                       wget, a single binary that links libssl).
    let mut target_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();
    target_pids.insert(child_pid);
    let filter_by_pid = !args.trace_children;

    fn drain_network(
        bpf: &mut aya::Ebpf,
        agg: &mut EventAggregator,
        count: &mut u64,
        max: usize,
        target_pids: &std::collections::HashSet<u32>,
    ) -> usize {
        let map = bpf
            .map_mut("NETWORK_EVENTS")
            .expect("NETWORK_EVENTS ring buffer is statically declared in the eBPF object");
        let mut rb = RingBuf::try_from(map)
            .expect("NETWORK_EVENTS map shape is BPF_MAP_TYPE_RINGBUF by construction");
        let mut n = 0;
        while n < max {
            match rb.next() {
                Some(item) => {
                    let data: &[u8] = item.as_ref();
                    if data.len() >= core::mem::size_of::<NetworkEvent>() {
                        let ev = unsafe {
                            core::ptr::read_unaligned(data.as_ptr() as *const NetworkEvent)
                        };
                        if target_pids.is_empty() || target_pids.contains(&ev.pid) {
                            agg.handle_network_event(&ev);
                            *count += 1;
                        }
                        n += 1;
                    }
                }
                None => break,
            }
        }
        n
    }

    fn drain_file(
        bpf: &mut aya::Ebpf,
        agg: &mut EventAggregator,
        count: &mut u64,
        max: usize,
        target_pids: &std::collections::HashSet<u32>,
    ) -> usize {
        let map = bpf
            .map_mut("FILE_EVENTS")
            .expect("FILE_EVENTS ring buffer is statically declared in the eBPF object");
        let mut rb = RingBuf::try_from(map)
            .expect("FILE_EVENTS map shape is BPF_MAP_TYPE_RINGBUF by construction");
        let mut n = 0;
        while n < max {
            match rb.next() {
                Some(item) => {
                    let data: &[u8] = item.as_ref();
                    if data.len() >= core::mem::size_of::<FileEvent>() {
                        let ev = unsafe {
                            core::ptr::read_unaligned(data.as_ptr() as *const FileEvent)
                        };
                        if target_pids.is_empty() || target_pids.contains(&ev.pid) {
                            agg.handle_file_event(&ev);
                            *count += 1;
                        }
                        n += 1;
                    }
                }
                None => break,
            }
        }
        n
    }

    loop {
        let done = if let Some(ref mut c) = child {
            c.try_wait().ok().flatten().is_some()
        } else {
            !std::path::Path::new(&format!("/proc/{target_pid}")).exists()
        };

        // If filter_by_pid is off, pass an empty set so the drain functions
        // admit every event. Building the empty set once per iteration is
        // cheap and keeps the drain signature uniform.
        let empty: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let active_filter = if filter_by_pid { &target_pids } else { &empty };

        drain_network(&mut handle.bpf, &mut agg, &mut net_count, MAX_PER_ITER, active_filter);
        drain_file(&mut handle.bpf, &mut agg, &mut file_count, MAX_PER_ITER, active_filter);

        if done {
            // Settling drain: pull remaining events with a hard deadline so
            // we never loop forever if probes keep firing from unrelated PIDs.
            let deadline = Instant::now() + Duration::from_millis(250);
            while Instant::now() < deadline {
                let n = drain_network(&mut handle.bpf, &mut agg, &mut net_count, MAX_PER_ITER, active_filter)
                    + drain_file(&mut handle.bpf, &mut agg, &mut file_count, MAX_PER_ITER, active_filter);
                if n == 0 {
                    break;
                }
            }
            break;
        }

        if timeout.is_some_and(|t| start.elapsed() > t) {
            tracing::warn!("Trace timeout");
            break;
        }

        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    if let Some(mut c) = child {
        let st = c.wait()?;
        tracing::info!(?st, "Child exited");
    }

    let trace_end = Timestamp::now();
    tracing::info!(net = net_count, file = file_count, "Collection done");

    // Post-trace artifact-dir scan: walk user-supplied directories for
    // files that appeared during this trace (mtime ≥ trace_start_wall).
    // Each hit becomes a synthetic FileOperation (with real SHA-256)
    // whether or not the kernel-side kprobe captured it. This closes
    // the coverage gap observed with curl's -O and cargo's .crate writes.
    //
    // With --auto-dirs, the command argv is also inspected for known
    // build tools and their canonical cache paths are merged in. Explicit
    // --artifact-dir values always win (they come first) and duplicates
    // are dropped while preserving order.
    let merged_dirs: Vec<PathBuf> = {
        let mut v = args.artifact_dir.clone();
        if args.auto_dirs {
            for d in crate::cli::auto_dirs::detect(&args.command) {
                if !v.contains(&d) {
                    v.push(d);
                }
            }
        }
        v
    };
    if !merged_dirs.is_empty() {
        let added = scan_artifact_dirs(&merged_dirs, trace_start_wall, &mut agg);
        if added > 0 {
            tracing::info!(added, "post-trace artifact scan");
        }
    }

    // Post-trace hash pass: the SSL uprobes only ever see ~512 B of each
    // TLS record, so the "response hash" computed from what we observed
    // would not match the bytes actually on disk. Instead, stream-hash the
    // real files now that the traced command has finished writing them.
    // This also covers probe-captured paths (if any) for which the
    // artifact-dir scan wasn't configured.
    let file_hashes = hash_captured_artifacts(&agg);
    if !file_hashes.is_empty() {
        tracing::info!(count = file_hashes.len(), "hashed captured artifacts");
        agg.apply_file_hashes(&file_hashes);
    }

    let trace = agg.finalize(&TraceStats {
        network_events: net_count,
        file_events: file_count,
        ring_buffer_overflows: 0,
        events_dropped: 0,
    });

    if trace.network_trace.connections.is_empty()
        && trace.file_access.operations.is_empty()
    {
        tracing::error!(net = net_count, file = file_count, "Zero aggregated");
        return Err(MikebomError::NoDependencyActivity.into());
    }

    let cmd_str = if args.command.is_empty() {
        format!("pid:{target_pid}")
    } else {
        args.command.join(" ")
    };

    let stmt = builder::build_attestation(
        trace,
        &AttestationConfig {
            target_pid: child_pid,
            target_command: cmd_str,
            cgroup_id: 0,
            subject_name: "build-output".to_string(),
            subject_digest: None,
        },
        trace_start,
        trace_end,
    )?;

    // Feature 006 — write signed DSSE envelope when a signing identity
    // is configured; fall through to legacy raw shape otherwise.
    let identity = args.build_signing_identity()?;
    serializer::write_attestation_signed(&stmt, &args.output, &identity)?;

    let nc = stmt.predicate.network_trace.summary.total_connections;
    let fo = stmt.predicate.file_access.summary.total_operations;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "attestation_file": args.output.to_string_lossy(),
            "raw_net": net_count, "raw_file": file_count,
            "connections": nc, "file_operations": fo,
        }))?);
    }

    tracing::info!(output = %args.output.display(), connections = nc, file_ops = fo, "Done");
    Ok(())
}

/// Walk each `artifact_dir` recursively, find files whose mtime is at or
/// after `since`, stream-hash each one, and push a synthetic
/// `FileOperation` into the aggregator. Returns the count added.
///
/// The underlying directory walk + hash logic lives in
/// [`crate::scan_fs::walker::walk_and_hash`] and is shared with the
/// standalone `sbom scan` subcommand.
#[cfg(target_os = "linux")]
fn scan_artifact_dirs(
    dirs: &[PathBuf],
    since: std::time::SystemTime,
    agg: &mut crate::trace::aggregator::EventAggregator,
) -> usize {
    use crate::scan_fs::walker::{walk_and_hash, DEFAULT_SIZE_CAP_BYTES};

    let mut added = 0;
    for dir in dirs {
        if !dir.is_dir() {
            tracing::warn!(dir = %dir.display(), "--artifact-dir is not a directory, skipping");
            continue;
        }
        let artifacts = walk_and_hash(dir, Some(since), DEFAULT_SIZE_CAP_BYTES);
        for a in artifacts {
            let ts = chrono::DateTime::<chrono::Utc>::from(a.mtime);
            agg.record_synthetic_file_op(
                a.path.to_string_lossy().into_owned(),
                a.size,
                Some(a.hash),
                ts,
            );
            added += 1;
        }
    }
    added
}

/// Stream-hash every captured path that (a) ends in a package-artifact
/// suffix, (b) still exists on disk, and (c) is under the size cap. Each
/// hash is keyed by the exact path string the aggregator saw so
/// `apply_file_hashes` can match it back.
#[cfg(target_os = "linux")]
fn hash_captured_artifacts(
    agg: &crate::trace::aggregator::EventAggregator,
) -> std::collections::HashMap<String, mikebom_common::types::hash::ContentHash> {
    use crate::scan_fs::walker::{ARTIFACT_SUFFIXES, DEFAULT_SIZE_CAP_BYTES};
    use crate::trace::hasher::sha256_file_hex;
    use mikebom_common::types::hash::ContentHash;

    let mut out = std::collections::HashMap::new();
    for path in agg.captured_paths() {
        let lc = path.to_ascii_lowercase();
        if !ARTIFACT_SUFFIXES.iter().any(|s| lc.ends_with(s)) {
            continue;
        }
        let p = std::path::Path::new(path);
        if !p.is_file() {
            continue;
        }
        match sha256_file_hex(p, DEFAULT_SIZE_CAP_BYTES) {
            Ok(hex) => match ContentHash::sha256(&hex) {
                Ok(h) => {
                    out.insert(path.to_string(), h);
                }
                Err(e) => tracing::warn!(path, error = %e, "invalid sha256 hex"),
            },
            Err(e) => tracing::debug!(path, error = %e, "could not hash artifact"),
        }
    }
    out
}

/// Compute the offset (in nanoseconds) that converts a CLOCK_BOOTTIME
/// nanosecond timestamp (what `bpf_ktime_get_ns` returns) into a
/// CLOCK_REALTIME Unix-epoch nanosecond timestamp. Returns 0 on error so
/// callers still get a best-effort wall-clock rather than panicking.
#[cfg(target_os = "linux")]
fn compute_boot_offset_ns() -> u64 {
    fn sample(clock: libc::clockid_t) -> Option<u64> {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: clock_gettime is a syscall wrapper; `ts` is a writable,
        // properly-aligned timespec on the stack.
        let rc = unsafe { libc::clock_gettime(clock, &mut ts) };
        if rc != 0 {
            return None;
        }
        Some((ts.tv_sec as u64).saturating_mul(1_000_000_000)
            + ts.tv_nsec as u64)
    }

    match (sample(libc::CLOCK_REALTIME), sample(libc::CLOCK_BOOTTIME)) {
        (Some(real), Some(boot)) => real.saturating_sub(boot),
        _ => 0,
    }
}

#[cfg(not(target_os = "linux"))]
async fn execute_scan(_args: ScanArgs) -> anyhow::Result<()> {
    anyhow::bail!(
        "eBPF tracing requires Linux. Use a Lima VM for tracing.\n\
         Non-tracing commands (generate, enrich, validate) work on any platform."
    )
}
