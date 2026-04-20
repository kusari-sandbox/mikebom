//! Legacy Berkeley-DB rpmdb reader (pre-RHEL-8 / CentOS-7 / Amazon
//! Linux 2). Milestone 004 US4 — gated behind the
//! `--include-legacy-rpmdb` CLI flag (also via `MIKEBOM_INCLUDE_LEGACY_RPMDB=1`).
//! Concrete parsing lands in tasks T061–T065.
//!
//! When the flag is UNSET, this reader is a no-op; milestone-003
//! behaviour is preserved (a WARN is logged from `rpm.rs` when a BDB
//! `Packages` file is observed without a sibling `rpmdb.sqlite`). When
//! the flag is SET and the rootfs contains `/var/lib/rpm/Packages` but
//! NOT `rpmdb.sqlite`, the reader parses Hash/BTree-page records and
//! emits `PackageDbEntry` rows identical in shape to the sqlite path
//! except for `evidence_kind = Some("rpmdb-bdb")`.
//!
//! The conflict rule (FR-019c): when both rpmdb.sqlite AND Packages
//! exist on the same rootfs, sqlite wins and this reader is skipped
//! regardless of the flag — prevents double-counting during filesystem
//! transitions.

use std::path::Path;

use super::PackageDbEntry;

/// Opt-in BDB rpmdb reader. Stub until T061–T065 land — returns empty
/// regardless of flag state so the dispatcher compiles and scan output
/// is unchanged from milestone 003.
pub fn read(_rootfs: &Path, _include_legacy_rpmdb: bool) -> Vec<PackageDbEntry> {
    Vec::new()
}
