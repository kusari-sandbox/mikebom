//! Child PID tracker for process tree isolation.
//!
//! When `--trace-children` is enabled, mikebom needs to discover all
//! child processes spawned by the target build command so their eBPF
//! events are also captured. On Linux, this reads the process tree from
//! `/proc/<pid>/task/<tid>/children`. On non-Linux, a stub is provided.

// Tracker is only constructed inside the Linux-only
// `cli/scan.rs::execute_scan` flow; on macOS the file compiles but is
// unreachable.
#![allow(dead_code)]

use std::collections::HashSet;

/// Tracks the set of PIDs in the target process tree.
#[derive(Clone, Debug)]
pub struct PidTracker {
    /// Root PID of the build process.
    root_pid: u32,
    /// Whether child process tracking is enabled.
    trace_children: bool,
    /// All PIDs currently being tracked (includes root).
    tracked_pids: HashSet<u32>,
}

impl PidTracker {
    /// Create a new PID tracker for the given root process.
    ///
    /// If `trace_children` is false, only the root PID is tracked.
    pub fn new(root_pid: u32, trace_children: bool) -> Self {
        let mut tracked_pids = HashSet::new();
        tracked_pids.insert(root_pid);
        Self {
            root_pid,
            trace_children,
            tracked_pids,
        }
    }

    /// The root PID of the traced build process.
    pub fn root_pid(&self) -> u32 {
        self.root_pid
    }

    /// Whether child process tracking is enabled.
    pub fn traces_children(&self) -> bool {
        self.trace_children
    }

    /// The current set of tracked PIDs.
    pub fn tracked_pids(&self) -> &HashSet<u32> {
        &self.tracked_pids
    }

    /// Re-scan the process tree and discover any new child PIDs.
    ///
    /// On Linux, reads `/proc/<pid>/task/<tid>/children` for every
    /// tracked PID. On other platforms, returns an error.
    pub fn refresh(&mut self) -> anyhow::Result<()> {
        if !self.trace_children {
            return Ok(());
        }

        self.refresh_platform()
    }

    /// Add a PID to the tracked set manually (e.g., from a fork event).
    pub fn add_pid(&mut self, pid: u32) {
        if self.trace_children {
            self.tracked_pids.insert(pid);
            tracing::debug!(pid, "Added PID to tracker");
        }
    }

    /// Remove a PID from the tracked set (e.g., on process exit).
    pub fn remove_pid(&mut self, pid: u32) {
        // Never remove the root PID.
        if pid != self.root_pid {
            self.tracked_pids.remove(&pid);
            tracing::debug!(pid, "Removed PID from tracker");
        }
    }

    /// Check whether a given PID is currently tracked.
    pub fn is_tracked(&self, pid: u32) -> bool {
        self.tracked_pids.contains(&pid)
    }
}

// ── Linux implementation ──────────────────────────────────────────────

#[cfg(all(target_os = "linux", feature = "ebpf-tracing"))]
impl PidTracker {
    fn refresh_platform(&mut self) -> anyhow::Result<()> {
        let mut new_pids = HashSet::new();

        // BFS through tracked PIDs to find all descendants.
        let mut queue: Vec<u32> = self.tracked_pids.iter().copied().collect();
        let mut visited = HashSet::new();

        while let Some(pid) = queue.pop() {
            if !visited.insert(pid) {
                continue;
            }
            new_pids.insert(pid);

            // Read children from /proc/<pid>/task/<tid>/children
            let task_dir = format!("/proc/{pid}/task");
            let task_entries = match std::fs::read_dir(&task_dir) {
                Ok(entries) => entries,
                Err(e) => {
                    // Process may have exited — not an error.
                    tracing::debug!(pid, error = %e, "Cannot read task dir, process may have exited");
                    continue;
                }
            };

            for entry in task_entries.flatten() {
                let tid_path = entry.path();
                let children_path = tid_path.join("children");

                let children_content = match std::fs::read_to_string(&children_path) {
                    Ok(content) => content,
                    Err(_) => continue,
                };

                for child_str in children_content.split_whitespace() {
                    if let Ok(child_pid) = child_str.parse::<u32>() {
                        if !visited.contains(&child_pid) {
                            queue.push(child_pid);
                            tracing::debug!(
                                parent_pid = pid,
                                child_pid,
                                "Discovered child process"
                            );
                        }
                    }
                }
            }
        }

        let added = new_pids.difference(&self.tracked_pids).count();
        let removed = self.tracked_pids.difference(&new_pids).count();

        if added > 0 || removed > 0 {
            tracing::debug!(
                added,
                removed,
                total = new_pids.len(),
                "PID tracker refreshed"
            );
        }

        self.tracked_pids = new_pids;
        Ok(())
    }
}

// ── Non-Linux stub ────────────────────────────────────────────────────

#[cfg(not(all(target_os = "linux", feature = "ebpf-tracing")))]
impl PidTracker {
    fn refresh_platform(&mut self) -> anyhow::Result<()> {
        anyhow::bail!(
            "Child PID tracking via /proc is only available on Linux — \
             only the root PID will be tracked on this platform"
        )
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn new_tracker_contains_root() {
        let tracker = PidTracker::new(1234, true);
        assert!(tracker.is_tracked(1234));
        assert_eq!(tracker.root_pid(), 1234);
        assert!(tracker.traces_children());
    }

    #[test]
    fn no_children_mode() {
        let tracker = PidTracker::new(5678, false);
        assert!(tracker.is_tracked(5678));
        assert!(!tracker.traces_children());
        assert_eq!(tracker.tracked_pids().len(), 1);
    }

    #[test]
    fn add_and_remove_pid() {
        let mut tracker = PidTracker::new(100, true);
        tracker.add_pid(101);
        tracker.add_pid(102);
        assert!(tracker.is_tracked(101));
        assert!(tracker.is_tracked(102));
        assert_eq!(tracker.tracked_pids().len(), 3);

        tracker.remove_pid(101);
        assert!(!tracker.is_tracked(101));
        assert_eq!(tracker.tracked_pids().len(), 2);
    }

    #[test]
    fn cannot_remove_root() {
        let mut tracker = PidTracker::new(100, true);
        tracker.remove_pid(100);
        assert!(tracker.is_tracked(100), "root PID should not be removable");
    }

    #[test]
    fn add_pid_noop_when_children_disabled() {
        let mut tracker = PidTracker::new(100, false);
        tracker.add_pid(101);
        assert!(!tracker.is_tracked(101));
        assert_eq!(tracker.tracked_pids().len(), 1);
    }

    #[test]
    fn refresh_noop_when_children_disabled() {
        let mut tracker = PidTracker::new(100, false);
        // Should succeed immediately without doing anything.
        tracker.refresh().expect("refresh should succeed when children disabled");
        assert_eq!(tracker.tracked_pids().len(), 1);
    }
}
