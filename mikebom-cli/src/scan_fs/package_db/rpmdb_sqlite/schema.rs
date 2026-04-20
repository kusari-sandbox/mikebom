//! SQLite `sqlite_schema` table walker.
//!
//! The schema lives rooted at page 1 with rows of a 5-column table
//! B-tree: `(type TEXT, name TEXT, tbl_name TEXT, rootpage INTEGER,
//! sql TEXT)`. Small databases fit the schema in one leaf page (page 1
//! itself is a leaf); larger databases promote page 1 to an interior
//! table page whose children hold the actual leaf rows.
//!
//! v6 Phase D: production rpmdbs ship ~21 tables (Basenames, Dirnames,
//! Name, Packages, Obsoletename, Providename, …) and always trigger
//! the interior-page case. The previous implementation rejected page 1
//! when it wasn't a leaf, producing a misleading "table not found" at
//! the caller. This version traverses interior pages to collect every
//! schema row, mirroring the pattern in `SqliteFile::visit_page`.

use std::collections::HashSet;

use super::page::{
    parse_interior_cell, parse_leaf_cell, parse_page_header, read_cell_offsets,
    PAGE_TYPE_INTERIOR_TABLE, PAGE_TYPE_LEAF_TABLE,
};
use super::record::decode_record;
use super::RpmdbSqliteError;

/// A single schema row: table name + root page + declared SQL.
#[derive(Clone, Debug)]
pub(crate) struct TableInfo {
    pub name: String,
    pub root_page: u32,
}

/// Walk the sqlite_schema B-tree rooted at page 1 and collect every
/// `type = 'table'` row.
///
/// `get_page` maps a 1-based page number to the raw page bytes
/// (typically a closure wrapping `SqliteFile::get_page`). Used to
/// traverse interior pages without coupling `schema.rs` to
/// `SqliteFile`.
pub(crate) fn read_schema<F>(
    page1: &[u8],
    text_encoding: u8,
    get_page: F,
) -> Result<Vec<TableInfo>, RpmdbSqliteError>
where
    F: Fn(u32) -> Option<Vec<u8>>,
{
    let mut out = Vec::new();
    let mut visited: HashSet<u32> = HashSet::new();
    walk_schema_page(page1, true, 1, text_encoding, &get_page, &mut visited, &mut out)?;
    Ok(out)
}

fn walk_schema_page<F>(
    page_bytes: &[u8],
    is_first_page: bool,
    page_num: u32,
    text_encoding: u8,
    get_page: &F,
    visited: &mut HashSet<u32>,
    out: &mut Vec<TableInfo>,
) -> Result<(), RpmdbSqliteError>
where
    F: Fn(u32) -> Option<Vec<u8>>,
{
    if !visited.insert(page_num) {
        // Cycle guard. Sqlite isn't supposed to have cycles; if we see
        // one, it's corruption or a bug — stop the descent.
        return Ok(());
    }
    let header = parse_page_header(page_bytes, is_first_page, page_num)?;
    let offsets = read_cell_offsets(page_bytes, &header)?;
    match header.page_type {
        PAGE_TYPE_LEAF_TABLE => {
            for off in offsets {
                let cell = parse_leaf_cell(page_bytes, off as usize, page_bytes.len(), page_num)?;
                // Schema rows are small (<500 bytes — just table name +
                // SQL) and never overflow in practice. Skip any row
                // that claims overflow; losing it is better than a
                // half-decoded record.
                if cell.overflow.is_some() {
                    continue;
                }
                let values = decode_record(cell.on_page, text_encoding)?;
                if values.len() < 4 {
                    continue;
                }
                let ty = values[0].as_text().unwrap_or("");
                if ty != "table" {
                    continue;
                }
                let name = values[1].as_text().unwrap_or("").to_string();
                let root = values[3].as_integer().unwrap_or(0) as u32;
                if !name.is_empty() && root > 0 {
                    out.push(TableInfo {
                        name,
                        root_page: root,
                    });
                }
            }
        }
        PAGE_TYPE_INTERIOR_TABLE => {
            for off in offsets {
                let cell = parse_interior_cell(page_bytes, off as usize, page_num)?;
                let Some(child_bytes) = get_page(cell.left_child_page) else {
                    // Child page out of range — skip this branch, keep
                    // collecting from siblings. Mirrors the partial-result
                    // posture of the caller.
                    continue;
                };
                walk_schema_page(
                    &child_bytes,
                    false,
                    cell.left_child_page,
                    text_encoding,
                    get_page,
                    visited,
                    out,
                )?;
            }
            if let Some(rightmost) = header.right_most_pointer {
                if let Some(child_bytes) = get_page(rightmost) {
                    walk_schema_page(
                        &child_bytes,
                        false,
                        rightmost,
                        text_encoding,
                        get_page,
                        visited,
                        out,
                    )?;
                }
            }
        }
        _ => {
            return Err(RpmdbSqliteError::TruncatedPayload {
                path: Default::default(),
                page: page_num,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::super::SqliteFile;

    /// Regression guard — the synthetic fixture with a single leaf
    /// schema page must still be parsable. If this breaks the
    /// existing rpmdb fixture test does too, but this pins the
    /// schema layer in isolation.
    #[test]
    fn reads_single_leaf_schema_from_fixture() {
        let fixture = std::path::Path::new("/tmp/rpmdb-fixture/rpmdb.sqlite");
        if !fixture.is_file() {
            eprintln!("skipping: fixture {} not found", fixture.display());
            return;
        }
        let db = SqliteFile::open(fixture, 200_000_000).unwrap();
        assert!(
            db.table_root_page("Packages").is_some(),
            "fixture should expose a Packages table"
        );
    }

    /// Acceptance — real Rocky-9 rpmdb (production format, interior
    /// sqlite_schema root). Gated on the conformance fixture; skip
    /// gracefully if absent.
    #[test]
    fn reads_multi_page_schema_from_rocky_rpmdb() {
        let fixture = std::path::Path::new(
            "/Users/mlieberman/Projects/sbom-conformance/fixtures/rocky-9-minimal/project/var/lib/rpm/rpmdb.sqlite",
        );
        if !fixture.is_file() {
            eprintln!("skipping: production fixture {} not found", fixture.display());
            return;
        }
        let db = SqliteFile::open(fixture, 200_000_000).unwrap();
        let root = db
            .table_root_page("Packages")
            .expect("Packages table must be discoverable via interior-page traversal");
        assert!(root > 0, "root page must be non-zero");
    }
}
