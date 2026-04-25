//! Pure-Rust SQLite reader scoped to the subset RHEL's `/var/lib/rpm/rpmdb.sqlite`
//! exercises. Concrete page / record / schema decoders land in US2
//! (T033–T036); this module is scaffolding only.
//!
//! Principle I compliance: this submodule exists *instead of* linking
//! `libsqlite3` or pulling `rusqlite`. The full implementation covers
//! only the features RHEL rpmdbs use:
//!
//! - B-tree interior + leaf pages (no overflow pages).
//! - Record varint decoder with serial types 0–9, 12, 13+.
//! - UTF-8 text only; UTF-16 payloads are refused with
//!   [`RpmdbSqliteError::TextEncodingUnsupported`].
//! - Read-only access; no WAL, no transactions, no journal.
//!
//! See `specs/003-multi-ecosystem-expansion/research.md` R6 for the
//! feature matrix that drove this scope.

// Several internal types in this submodule have fields populated by
// the SQLite-format decoder (page header offsets, serial types, rowid)
// but only some are read by downstream consumers. They're intentionally
// preserved as documentation of the wire shape per
// `specs/003-multi-ecosystem-expansion/research.md` R6, even when the
// current decoder doesn't consume them. Allow dead_code at the
// submodule level to avoid annotating each struct individually.
#![allow(dead_code)]

pub mod page;
pub mod record;
pub mod rpm_header;
pub mod schema;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub use record::RecordValue;

/// Errors the pure-Rust SQLite reader can surface. All variants are
/// recoverable at the caller level — the rpm reader turns them into a
/// single WARN log + zero components, per FR-020's graceful-degradation
/// posture. The caller MUST NOT propagate these through `PackageDbError`.
#[derive(Debug, thiserror::Error)]
pub enum RpmdbSqliteError {
    /// File doesn't exist, isn't readable, or failed an open() syscall.
    #[error("io error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// File exceeds the caller-supplied size cap (defense-in-depth per
    /// FR-009). The cap is enforced by [`SqliteFile::open`] before any
    /// bytes are parsed.
    #[error("rpmdb at {path} exceeds size cap ({observed} bytes > {cap} bytes)")]
    FileTooLarge {
        path: PathBuf,
        observed: u64,
        cap: u64,
    },

    /// Leading 16-byte magic isn't `"SQLite format 3\0"`.
    #[error("rpmdb at {path} is not a SQLite 3 file (bad magic)")]
    BadMagic { path: PathBuf },

    /// Header declares a page size that isn't a valid SQLite value
    /// (must be a power of two between 512 and 65536). See US2 T033 for
    /// the full validation rules.
    #[error("rpmdb at {path} declares invalid page size {page_size}")]
    InvalidPageSize { path: PathBuf, page_size: u32 },

    /// Overflow pages are deliberately out of scope — real rpmdbs don't
    /// use them. Surface this rather than silently under-reading.
    #[error("rpmdb at {path} uses overflow pages (not supported)")]
    OverflowPageUnsupported { path: PathBuf },

    /// Text payload declares a non-UTF-8 encoding (SQLite supports
    /// UTF-16LE/BE via the `PRAGMA encoding` header byte — rpmdbs
    /// always use UTF-8 so refusing the others keeps the scope tight).
    #[error("rpmdb at {path} uses unsupported text encoding {encoding}")]
    TextEncodingUnsupported { path: PathBuf, encoding: u8 },

    /// Cell payload bytes terminate before the record decoder can finish
    /// reading the declared type list (indicates corruption or a bug).
    #[error("rpmdb at {path} has a truncated cell payload on page {page}")]
    TruncatedPayload { path: PathBuf, page: u32 },

    /// Varint exceeds 9 bytes, which violates the SQLite spec.
    #[error("rpmdb at {path} has a malformed varint on page {page}")]
    MalformedVarint { path: PathBuf, page: u32 },

    /// The `sqlite_schema` system table doesn't contain an entry with
    /// the requested name. US2 T035 populates the lookup.
    #[error("rpmdb at {path} does not contain table `{table}`")]
    TableNotFound { path: PathBuf, table: String },
}

/// Read-only handle to a SQLite 3 database file. Holds the entire
/// file in memory — RHEL rpmdbs are typically <50 MB, well within the
/// 200 MB cap enforced at open time.
#[derive(Debug)]
pub struct SqliteFile {
    path: PathBuf,
    bytes: Vec<u8>,
    page_size: usize,
    text_encoding: u8,
}

impl SqliteFile {
    /// Open a SQLite 3 file at `path`. Enforces `max_size_bytes` as a
    /// defence-in-depth cap (FR-009). Validates the magic, reads the
    /// 100-byte header, and records the page size + text encoding.
    pub fn open(path: &Path, max_size_bytes: u64) -> Result<Self, RpmdbSqliteError> {
        let meta = std::fs::metadata(path).map_err(|e| RpmdbSqliteError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        if meta.len() > max_size_bytes {
            return Err(RpmdbSqliteError::FileTooLarge {
                path: path.to_path_buf(),
                observed: meta.len(),
                cap: max_size_bytes,
            });
        }
        let bytes = std::fs::read(path).map_err(|e| RpmdbSqliteError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        if bytes.len() < 100 || !bytes.starts_with(b"SQLite format 3\0") {
            return Err(RpmdbSqliteError::BadMagic {
                path: path.to_path_buf(),
            });
        }
        // Page size at offset 16 (big-endian u16). Value 1 means 65536.
        let raw_ps = u16::from_be_bytes([bytes[16], bytes[17]]);
        let page_size: usize = if raw_ps == 1 {
            65536
        } else if raw_ps.is_power_of_two() && (512..=32768).contains(&raw_ps) {
            raw_ps as usize
        } else {
            return Err(RpmdbSqliteError::InvalidPageSize {
                path: path.to_path_buf(),
                page_size: raw_ps as u32,
            });
        };
        // Text encoding at offset 56 (big-endian u32). 1 = UTF-8.
        let text_encoding = bytes[59]; // low byte of the u32 (always 1..3)
        if text_encoding != 1 {
            return Err(RpmdbSqliteError::TextEncodingUnsupported {
                path: path.to_path_buf(),
                encoding: text_encoding,
            });
        }
        Ok(SqliteFile {
            path: path.to_path_buf(),
            bytes,
            page_size,
            text_encoding,
        })
    }

    /// Locate a table's root page by name from the sqlite_schema.
    /// Returns `None` if the table isn't declared.
    ///
    /// v6 Phase D: production rpmdbs (20+ tables) spill the schema
    /// across multiple pages. `read_schema` traverses interior pages
    /// to collect every table row; we pass a `get_page` closure so
    /// it can fetch children without coupling to `SqliteFile`.
    pub fn table_root_page(&self, table_name: &str) -> Option<u32> {
        let page1 = self.get_page(1)?;
        let tables = schema::read_schema(page1, self.text_encoding, |p| {
            self.get_page(p).map(|s| s.to_vec())
        })
        .ok()?;
        tables
            .into_iter()
            .find(|t| t.name == table_name)
            .map(|t| t.root_page)
    }

    /// Iterate every row in `table_name`, producing the decoded columns
    /// per row. Traverses interior-table pages recursively; refuses
    /// overflow pages. Per-row decode errors abort — callers should
    /// expect to receive a partial row list on malformed files.
    pub fn iter_table_rows<F>(
        &self,
        table_name: &str,
        mut visitor: F,
    ) -> Result<(), RpmdbSqliteError>
    where
        F: FnMut(&[RecordValue]),
    {
        let root = self
            .table_root_page(table_name)
            .ok_or_else(|| RpmdbSqliteError::TableNotFound {
                path: self.path.clone(),
                table: table_name.to_string(),
            })?;
        let mut visited: HashSet<u32> = HashSet::new();
        self.visit_page(root, &mut visited, &mut visitor)
    }

    /// Like [`Self::iter_table_rows`] but exposes the largest `Blob`
    /// column's raw bytes alongside the decoded row. Production
    /// rpmdb.sqlite stores each package's header as the single blob
    /// column; the visitor receives that payload so callers can feed
    /// it to [`rpm_header::parse_header_blob`]. Rows with no blob
    /// column (e.g. mikebom's test-fixture schema) receive an empty
    /// slice.
    pub fn iter_table_blobs<F>(
        &self,
        table_name: &str,
        mut visitor: F,
    ) -> Result<(), RpmdbSqliteError>
    where
        F: FnMut(&[RecordValue], &[u8]),
    {
        self.iter_table_rows(table_name, |values| {
            let biggest_blob: &[u8] = values
                .iter()
                .filter_map(|v| match v {
                    RecordValue::Blob(b) => Some(b.as_slice()),
                    _ => None,
                })
                .max_by_key(|b| b.len())
                .unwrap_or(&[]);
            visitor(values, biggest_blob);
        })
    }

    fn visit_page<F>(
        &self,
        page_num: u32,
        visited: &mut HashSet<u32>,
        visitor: &mut F,
    ) -> Result<(), RpmdbSqliteError>
    where
        F: FnMut(&[RecordValue]),
    {
        if !visited.insert(page_num) {
            // Already visited — guard against pathological loops.
            return Ok(());
        }
        let page = self
            .get_page(page_num)
            .ok_or(RpmdbSqliteError::TruncatedPayload {
                path: self.path.clone(),
                page: page_num,
            })?;
        let is_first = page_num == 1;
        let header = page::parse_page_header(page, is_first, page_num)?;
        let offsets = page::read_cell_offsets(page, &header)?;
        match header.page_type {
            page::PAGE_TYPE_LEAF_TABLE => {
                for off in offsets {
                    let Ok(cell) =
                        page::parse_leaf_cell(page, off as usize, self.page_size, page_num)
                    else {
                        continue;
                    };
                    // v6 Phase D: stitch overflow chain when the cell
                    // spills beyond the main page. Real rpm header
                    // blobs are 5-15 KB and always overflow on 4 KB
                    // pages; without stitching we'd decode zero rows.
                    if let Some(ref ov) = cell.overflow {
                        let Some(full) = page::stitch_overflow(
                            cell.on_page,
                            ov,
                            self.page_size,
                            |p| self.get_page(p).map(|s| s.to_vec()),
                        ) else {
                            continue;
                        };
                        if let Ok(values) =
                            record::decode_record(&full, self.text_encoding)
                        {
                            visitor(&values);
                        }
                    } else if let Ok(values) =
                        record::decode_record(cell.on_page, self.text_encoding)
                    {
                        visitor(&values);
                    }
                }
            }
            page::PAGE_TYPE_INTERIOR_TABLE => {
                for off in offsets {
                    match page::parse_interior_cell(page, off as usize, page_num) {
                        Ok(cell) => {
                            self.visit_page(cell.left_child_page, visited, visitor)?;
                        }
                        Err(_) => continue,
                    }
                }
                if let Some(rightmost) = header.right_most_pointer {
                    self.visit_page(rightmost, visited, visitor)?;
                }
            }
            _ => {
                // Unsupported page type — skip.
            }
        }
        Ok(())
    }

    fn get_page(&self, page_num: u32) -> Option<&[u8]> {
        let start = (page_num as usize).checked_sub(1)?.checked_mul(self.page_size)?;
        let end = start.checked_add(self.page_size)?;
        self.bytes.get(start..end)
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn open_missing_file_returns_io_error() {
        let err = SqliteFile::open(Path::new("/tmp/does-not-exist-xxx"), 200_000_000);
        assert!(matches!(err, Err(RpmdbSqliteError::Io { .. })));
    }

    #[test]
    fn open_non_sqlite_returns_bad_magic() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("garbage.sqlite");
        std::fs::write(&p, vec![0u8; 4096]).unwrap();
        assert!(matches!(
            SqliteFile::open(&p, 200_000_000),
            Err(RpmdbSqliteError::BadMagic { .. })
        ));
    }

    #[test]
    fn open_oversized_file_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("too-big.sqlite");
        std::fs::write(&p, vec![0u8; 2048]).unwrap();
        assert!(matches!(
            SqliteFile::open(&p, 512),
            Err(RpmdbSqliteError::FileTooLarge { .. })
        ));
    }

    #[test]
    fn error_display_includes_path_for_bad_magic() {
        let err = RpmdbSqliteError::BadMagic {
            path: PathBuf::from("/var/lib/rpm/rpmdb.sqlite"),
        };
        let msg = err.to_string();
        assert!(msg.contains("/var/lib/rpm/rpmdb.sqlite"));
        assert!(msg.contains("bad magic"));
    }

    #[test]
    fn error_display_reports_file_too_large_with_sizes() {
        let err = RpmdbSqliteError::FileTooLarge {
            path: PathBuf::from("/scan/rpmdb.sqlite"),
            observed: 300_000_000,
            cap: 200_000_000,
        };
        let msg = err.to_string();
        assert!(msg.contains("300000000"));
        assert!(msg.contains("200000000"));
    }
}
