//! SQLite record-format decoder — serial types 0..13+ (UTF-8 only).
#![allow(dead_code)] // wire-shape fields populated by the binary decoder.
//!
//! Record layout:
//!
//! ```text
//! [header_size varint] [type1 varint] [type2 varint] ... [body1] [body2] ...
//! ```
//!
//! Serial types:
//! - 0: null
//! - 1..6: big-endian integers of width 1, 2, 3, 4, 6, 8 bytes
//! - 7: IEEE 754 float (8 bytes)
//! - 8: integer 0 (no body bytes)
//! - 9: integer 1 (no body bytes)
//! - 10, 11: reserved (unused)
//! - 12+ (even): blob, length (type - 12) / 2
//! - 13+ (odd): text, length (type - 13) / 2, encoding driven by file header

use super::page::read_sqlite_varint;
use super::RpmdbSqliteError;

/// A decoded column value.
#[derive(Clone, Debug)]
pub enum RecordValue {
    Null,
    Integer(i64),
    Float(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl RecordValue {
    pub fn as_text(&self) -> Option<&str> {
        if let RecordValue::Text(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn as_integer(&self) -> Option<i64> {
        if let RecordValue::Integer(i) = self {
            Some(*i)
        } else {
            None
        }
    }
}

/// Decode a record payload (the bytes of one leaf-cell's payload) into
/// a vector of `RecordValue`s. `text_encoding` is the file-header-level
/// encoding byte (1 = UTF-8, 2 = UTF-16LE, 3 = UTF-16BE). We refuse
/// anything but UTF-8.
pub(crate) fn decode_record(
    payload: &[u8],
    text_encoding: u8,
) -> Result<Vec<RecordValue>, RpmdbSqliteError> {
    let (header_size, h1) =
        read_sqlite_varint(payload).ok_or(RpmdbSqliteError::MalformedVarint {
            path: Default::default(),
            page: 0,
        })?;
    let header_size = header_size as usize;
    if header_size > payload.len() {
        return Err(RpmdbSqliteError::TruncatedPayload {
            path: Default::default(),
            page: 0,
        });
    }
    let mut types: Vec<u64> = Vec::new();
    let mut cursor = h1;
    while cursor < header_size {
        let (t, n) = read_sqlite_varint(&payload[cursor..]).ok_or(
            RpmdbSqliteError::MalformedVarint {
                path: Default::default(),
                page: 0,
            },
        )?;
        types.push(t);
        cursor += n;
    }
    let mut body_cursor = header_size;
    let mut values = Vec::with_capacity(types.len());
    for t in types {
        let (value, consumed) = decode_serial(t, &payload[body_cursor..], text_encoding)?;
        body_cursor += consumed;
        values.push(value);
    }
    Ok(values)
}

fn decode_serial(
    t: u64,
    bytes: &[u8],
    text_encoding: u8,
) -> Result<(RecordValue, usize), RpmdbSqliteError> {
    match t {
        0 => Ok((RecordValue::Null, 0)),
        1 => {
            if bytes.is_empty() {
                return Err(trunc());
            }
            Ok((RecordValue::Integer(i8::from_be_bytes([bytes[0]]) as i64), 1))
        }
        2 => take_int(bytes, 2),
        3 => take_int(bytes, 3),
        4 => take_int(bytes, 4),
        5 => take_int(bytes, 6),
        6 => take_int(bytes, 8),
        7 => {
            if bytes.len() < 8 {
                return Err(trunc());
            }
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes[..8]);
            Ok((RecordValue::Float(f64::from_be_bytes(arr)), 8))
        }
        8 => Ok((RecordValue::Integer(0), 0)),
        9 => Ok((RecordValue::Integer(1), 0)),
        10 | 11 => Err(RpmdbSqliteError::TextEncodingUnsupported {
            path: Default::default(),
            encoding: text_encoding,
        }),
        t if t >= 12 && t % 2 == 0 => {
            let len = ((t - 12) / 2) as usize;
            if bytes.len() < len {
                return Err(trunc());
            }
            Ok((RecordValue::Blob(bytes[..len].to_vec()), len))
        }
        t if t >= 13 && t % 2 == 1 => {
            let len = ((t - 13) / 2) as usize;
            if bytes.len() < len {
                return Err(trunc());
            }
            // Only UTF-8 supported (text_encoding == 1). Other encodings
            // are refused with a contract error.
            if text_encoding != 1 {
                return Err(RpmdbSqliteError::TextEncodingUnsupported {
                    path: Default::default(),
                    encoding: text_encoding,
                });
            }
            let s = std::str::from_utf8(&bytes[..len])
                .map_err(|_| RpmdbSqliteError::TextEncodingUnsupported {
                    path: Default::default(),
                    encoding: text_encoding,
                })?
                .to_string();
            Ok((RecordValue::Text(s), len))
        }
        _ => Err(trunc()),
    }
}

fn take_int(bytes: &[u8], n: usize) -> Result<(RecordValue, usize), RpmdbSqliteError> {
    if bytes.len() < n {
        return Err(trunc());
    }
    // Sign-extend the big-endian N-byte integer to i64.
    let mut value: i64 = 0;
    if bytes[0] & 0x80 != 0 {
        value = -1;
    }
    for &b in &bytes[..n] {
        value = (value << 8) | b as i64;
    }
    // Mask only to the bits we actually consumed to avoid high-bit
    // pollution from the initial -1 if the first byte was positive.
    if bytes[0] & 0x80 == 0 {
        let mut v: u64 = 0;
        for &b in &bytes[..n] {
            v = (v << 8) | b as u64;
        }
        value = v as i64;
    }
    Ok((RecordValue::Integer(value), n))
}

fn trunc() -> RpmdbSqliteError {
    RpmdbSqliteError::TruncatedPayload {
        path: Default::default(),
        page: 0,
    }
}
