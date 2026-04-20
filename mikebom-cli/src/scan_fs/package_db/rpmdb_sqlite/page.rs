//! SQLite B-tree page decoder — leaf-table + interior-table pages.
//!
//! Pages are either interior (0x02 index / 0x05 table) or leaf (0x0a
//! index / 0x0d table). RHEL rpmdbs in practice use 0x05 interior table
//! + 0x0d leaf table pages for the `Packages` table. Index pages live
//! in a separate B-tree rooted elsewhere in sqlite_schema.
//!
//! This decoder supports only the subset mikebom needs:
//! - Leaf-table (0x0d): cell = [payload_len varint, rowid varint, payload bytes].
//! - Interior-table (0x05): cell = [left_child u32, rowid varint] + right-most pointer.
//!
//! Overflow pages are NOT supported. If a cell declares a payload longer
//! than fits in the page, we surface an error.

use super::RpmdbSqliteError;

/// Tag byte at offset 0 of every B-tree page body.
pub(crate) const PAGE_TYPE_INTERIOR_TABLE: u8 = 0x05;
pub(crate) const PAGE_TYPE_LEAF_TABLE: u8 = 0x0d;

/// Parsed header of a B-tree page.
#[derive(Clone, Debug)]
pub(crate) struct PageHeader {
    pub page_type: u8,
    pub num_cells: u16,
    pub cell_content_start: u16,
    pub right_most_pointer: Option<u32>,
    /// Byte offset of the cell pointer array relative to the start of
    /// the page bytes. On page 1 this is shifted by 100 to skip the
    /// file header.
    pub cell_pointer_offset: usize,
}

/// Decode a page header. `page_bytes` is the raw page slice (page_size
/// bytes). `is_first_page` shifts the header parse to skip the initial
/// 100-byte file header.
pub(crate) fn parse_page_header(
    page_bytes: &[u8],
    is_first_page: bool,
    page_num: u32,
) -> Result<PageHeader, RpmdbSqliteError> {
    let hdr_start = if is_first_page { 100 } else { 0 };
    if page_bytes.len() < hdr_start + 12 {
        return Err(RpmdbSqliteError::TruncatedPayload {
            path: Default::default(),
            page: page_num,
        });
    }
    let page_type = page_bytes[hdr_start];
    let num_cells = u16::from_be_bytes([page_bytes[hdr_start + 3], page_bytes[hdr_start + 4]]);
    let cell_content_start =
        u16::from_be_bytes([page_bytes[hdr_start + 5], page_bytes[hdr_start + 6]]);
    let (right_most_pointer, header_size) = match page_type {
        PAGE_TYPE_INTERIOR_TABLE => {
            if page_bytes.len() < hdr_start + 12 {
                return Err(RpmdbSqliteError::TruncatedPayload {
                    path: Default::default(),
                    page: page_num,
                });
            }
            (
                Some(u32::from_be_bytes([
                    page_bytes[hdr_start + 8],
                    page_bytes[hdr_start + 9],
                    page_bytes[hdr_start + 10],
                    page_bytes[hdr_start + 11],
                ])),
                12,
            )
        }
        PAGE_TYPE_LEAF_TABLE => (None, 8),
        _ => {
            // Unsupported page type (index B-tree). Return TruncatedPayload
            // as a generic "can't process" signal.
            return Err(RpmdbSqliteError::TruncatedPayload {
                path: Default::default(),
                page: page_num,
            });
        }
    };
    Ok(PageHeader {
        page_type,
        num_cells,
        cell_content_start,
        right_most_pointer,
        cell_pointer_offset: hdr_start + header_size,
    })
}

/// Read cell offsets from the cell-pointer array. Each cell offset is a
/// 2-byte big-endian value relative to page start.
pub(crate) fn read_cell_offsets(
    page_bytes: &[u8],
    header: &PageHeader,
) -> Result<Vec<u16>, RpmdbSqliteError> {
    let num = header.num_cells as usize;
    let start = header.cell_pointer_offset;
    let end = start + num * 2;
    if page_bytes.len() < end {
        return Err(RpmdbSqliteError::TruncatedPayload {
            path: Default::default(),
            page: 0,
        });
    }
    let mut offsets = Vec::with_capacity(num);
    for i in 0..num {
        let o = u16::from_be_bytes([page_bytes[start + i * 2], page_bytes[start + i * 2 + 1]]);
        offsets.push(o);
    }
    Ok(offsets)
}

/// Decode a uvarint in SQLite's big-endian 9-byte variant (identical
/// bit layout to the standard uvarint except the 9th byte contributes
/// all 8 bits instead of 7).
pub(crate) fn read_sqlite_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for i in 0..9 {
        if i >= bytes.len() {
            return None;
        }
        let b = bytes[i];
        if i == 8 {
            value = (value << 8) | b as u64;
            return Some((value, 9));
        }
        value = (value << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// Overflow descriptor for a leaf-table cell whose payload doesn't
/// fit on the main page. The first `on_page` bytes (see `LeafCell`)
/// are followed by a 4-byte pointer to `first_overflow_page`; the
/// total payload size is `total_len`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OverflowRef {
    pub first_overflow_page: u32,
    pub total_len: usize,
}

/// Parsed leaf-table cell: rowid + on-page payload slice + optional
/// overflow continuation. v6 Phase D: overflow is no longer refused —
/// callers stitch the full payload via [`stitch_overflow`].
#[derive(Clone, Debug)]
pub(crate) struct LeafCell<'a> {
    pub rowid: u64,
    /// The on-page portion of the payload. When `overflow` is `None`
    /// this IS the complete payload. When `overflow` is `Some`, these
    /// bytes are the first N bytes and the remaining `total_len - N`
    /// bytes live on the overflow chain.
    pub on_page: &'a [u8],
    pub overflow: Option<OverflowRef>,
}

/// Decode a single leaf-table cell at `cell_offset` within `page_bytes`.
/// `usable_size` is the page size minus the reserved bytes (always the
/// full page size when reserved == 0, which is true for all RHEL rpmdbs).
///
/// Per the SQLite file-format spec (section 1.5, Payload Calculation):
///
/// - `X = usable_size − 35` — max in-page payload size for leaf table cells
/// - `M = ((usable_size − 12) × 32 / 255) − 23` — min embedded payload when overflow fires
/// - If `payload_len ≤ X`: entire payload on page, no overflow
/// - Else `K = M + (payload_len − M) mod (usable_size − 4)`; if `K ≤ X`
///   the on-page size is `K`, otherwise `M`. The 4 bytes after the
///   on-page region hold the first overflow page number.
pub(crate) fn parse_leaf_cell<'a>(
    page_bytes: &'a [u8],
    cell_offset: usize,
    usable_size: usize,
    page_num: u32,
) -> Result<LeafCell<'a>, RpmdbSqliteError> {
    let slice = &page_bytes[cell_offset..];
    let (payload_len, a) = read_sqlite_varint(slice).ok_or(RpmdbSqliteError::MalformedVarint {
        path: Default::default(),
        page: page_num,
    })?;
    let (rowid, b) =
        read_sqlite_varint(&slice[a..]).ok_or(RpmdbSqliteError::MalformedVarint {
            path: Default::default(),
            page: page_num,
        })?;
    let header_len = a + b;
    let payload_len = payload_len as usize;
    let x = usable_size.saturating_sub(35);

    if payload_len <= x {
        // Inline payload, no overflow.
        let start = cell_offset + header_len;
        let end = start + payload_len;
        if end > page_bytes.len() {
            return Err(RpmdbSqliteError::TruncatedPayload {
                path: Default::default(),
                page: page_num,
            });
        }
        return Ok(LeafCell {
            rowid,
            on_page: &page_bytes[start..end],
            overflow: None,
        });
    }

    // Overflow case — compute the on-page size K.
    let m = ((usable_size as i64 - 12) * 32 / 255 - 23).max(0) as usize;
    let u_minus_4 = usable_size.saturating_sub(4).max(1);
    let k_candidate = m + (payload_len - m) % u_minus_4;
    let on_page_len = if k_candidate <= x { k_candidate } else { m };
    let start = cell_offset + header_len;
    let on_page_end = start + on_page_len;
    let overflow_ptr_end = on_page_end + 4;
    if overflow_ptr_end > page_bytes.len() {
        return Err(RpmdbSqliteError::TruncatedPayload {
            path: Default::default(),
            page: page_num,
        });
    }
    let first_overflow_page = u32::from_be_bytes([
        page_bytes[on_page_end],
        page_bytes[on_page_end + 1],
        page_bytes[on_page_end + 2],
        page_bytes[on_page_end + 3],
    ]);
    Ok(LeafCell {
        rowid,
        on_page: &page_bytes[start..on_page_end],
        overflow: Some(OverflowRef {
            first_overflow_page,
            total_len: payload_len,
        }),
    })
}

/// Stitch an overflow-spilling cell's full payload by reading the
/// chained overflow pages pointed to by `overflow.first_overflow_page`.
/// Each overflow page is a raw `(u32 next_pointer, payload_chunk)`
/// structure using `usable_size − 4` bytes for the chunk.
///
/// Returns `None` on chain corruption (cycle, premature zero, missing
/// page) — the caller drops the row and moves on. Matches the
/// partial-result posture of the rest of the reader.
pub(crate) fn stitch_overflow(
    on_page: &[u8],
    overflow: &OverflowRef,
    usable_size: usize,
    mut get_page: impl FnMut(u32) -> Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    if on_page.len() >= overflow.total_len {
        // Pathological but defensive — on-page already has everything.
        return Some(on_page[..overflow.total_len].to_vec());
    }
    let mut out = Vec::with_capacity(overflow.total_len);
    out.extend_from_slice(on_page);
    let chunk_size = usable_size.saturating_sub(4);
    if chunk_size == 0 {
        return None;
    }
    let mut next = overflow.first_overflow_page;
    let mut visited = std::collections::HashSet::new();
    while next != 0 {
        if !visited.insert(next) {
            // Cycle — refuse.
            return None;
        }
        let page = get_page(next)?;
        if page.len() < 4 + chunk_size {
            return None;
        }
        let next_ptr =
            u32::from_be_bytes([page[0], page[1], page[2], page[3]]);
        let remaining = overflow.total_len.checked_sub(out.len())?;
        let take = remaining.min(chunk_size);
        out.extend_from_slice(&page[4..4 + take]);
        next = next_ptr;
        if out.len() >= overflow.total_len {
            break;
        }
    }
    if out.len() == overflow.total_len {
        Some(out)
    } else {
        None
    }
}

/// Parsed interior-table cell: left child page + rowid. Interior-table
/// cells are 4-byte child ptr + varint rowid.
#[derive(Clone, Debug)]
pub(crate) struct InteriorCell {
    pub left_child_page: u32,
    pub rowid: u64,
}

pub(crate) fn parse_interior_cell(
    page_bytes: &[u8],
    cell_offset: usize,
    page_num: u32,
) -> Result<InteriorCell, RpmdbSqliteError> {
    if cell_offset + 4 > page_bytes.len() {
        return Err(RpmdbSqliteError::TruncatedPayload {
            path: Default::default(),
            page: page_num,
        });
    }
    let left_child_page = u32::from_be_bytes([
        page_bytes[cell_offset],
        page_bytes[cell_offset + 1],
        page_bytes[cell_offset + 2],
        page_bytes[cell_offset + 3],
    ]);
    let (rowid, _) =
        read_sqlite_varint(&page_bytes[cell_offset + 4..]).ok_or(RpmdbSqliteError::MalformedVarint {
            path: Default::default(),
            page: page_num,
        })?;
    Ok(InteriorCell {
        left_child_page,
        rowid,
    })
}
