//! Curated embedded-version-string scanner. Per research R6 / FR-025.
//! Seven patterns for well-known self-identifying libraries:
//!
//! | Library   | Signature                                                    |
//! |-----------|--------------------------------------------------------------|
//! | OpenSSL   | `OpenSSL X.Y.Z[letter] [DD MMM YYYY]`                        |
//! | BoringSSL | `BoringSSL <40-char-sha>`                                    |
//! | zlib      | `deflate X.Y.Z[letter] Copyright ...`                        |
//! | SQLite    | `SQLite version X.Y.Z[.W]`                                   |
//! | curl      | `libcurl/X.Y.Z`                                              |
//! | PCRE      | `PCRE X.Y YYYY-MM-DD`                                        |
//! | PCRE2     | `PCRE2 X.Y YYYY-MM-DD`                                       |
//!
//! Scanning runs ONLY against format-appropriate read-only string
//! sections (ELF `.rodata` + `.data.rel.ro`, Mach-O `__TEXT,__cstring`
//! + `__TEXT,__const`, PE `.rdata`) — never against the full binary
//! image (Q4 resolution / FR-025). This bounds the false-positive
//! surface. Control-set validation per SC-005.

/// One match from the curated scanner. Converted to a
/// `PackageDbEntry` with `pkg:generic/<library>@<version>` and
/// `mikebom:evidence-kind = "embedded-version-string"` +
/// `mikebom:confidence = "heuristic"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddedVersionMatch {
    pub library: CuratedLibrary,
    pub version: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CuratedLibrary {
    OpenSsl,
    BoringSsl,
    Zlib,
    Sqlite,
    Curl,
    Pcre,
    Pcre2,
}

impl CuratedLibrary {
    pub fn slug(self) -> &'static str {
        match self {
            CuratedLibrary::OpenSsl => "openssl",
            CuratedLibrary::BoringSsl => "boringssl",
            CuratedLibrary::Zlib => "zlib",
            CuratedLibrary::Sqlite => "sqlite",
            CuratedLibrary::Curl => "curl",
            CuratedLibrary::Pcre => "pcre",
            CuratedLibrary::Pcre2 => "pcre2",
        }
    }
}

/// Scan a read-only string region for curated version signatures.
/// Dedupes matches by (library, version) within a single binary.
pub fn scan(region: &[u8]) -> Vec<EmbeddedVersionMatch> {
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<(CuratedLibrary, String)> =
        std::collections::HashSet::new();

    // Iterate every position; the per-prefix check handles its own
    // length requirements. Using `windows` would drop positions near
    // the end of the region where fewer than 16 bytes remain.
    for i in 0..region.len() {
        if let Some(m) = match_prefix(region, i, &region[i..]) {
            if seen.insert((m.library, m.version.clone())) {
                out.push(m);
            }
        }
    }
    out
}

fn match_prefix(
    region: &[u8],
    pos: usize,
    window: &[u8],
) -> Option<EmbeddedVersionMatch> {
    // Only accept matches starting at a string boundary: the byte
    // before `pos` must be NUL (C-string terminator) or pos==0. This
    // prevents mid-string false positives that happen to contain a
    // library name substring.
    let at_boundary = pos == 0 || region[pos - 1] == 0;
    if !at_boundary {
        return None;
    }

    // OpenSSL — "OpenSSL "
    if window.starts_with(b"OpenSSL ") {
        let tail = &region[pos + 8..];
        if let Some(v) = parse_openssl_version(tail) {
            return Some(EmbeddedVersionMatch {
                library: CuratedLibrary::OpenSsl,
                version: v,
            });
        }
    }
    // BoringSSL — "BoringSSL "
    if window.starts_with(b"BoringSSL ") {
        let tail = &region[pos + 10..];
        if let Some(sha) = parse_git_sha(tail) {
            return Some(EmbeddedVersionMatch {
                library: CuratedLibrary::BoringSsl,
                version: sha,
            });
        }
    }
    // zlib — "deflate "
    if window.starts_with(b"deflate ") {
        let tail = &region[pos + 8..];
        if let Some(v) = parse_zlib_version(tail) {
            return Some(EmbeddedVersionMatch {
                library: CuratedLibrary::Zlib,
                version: v,
            });
        }
    }
    // SQLite — "SQLite version "
    if region.len() >= pos + 15 && &region[pos..pos + 15] == b"SQLite version " {
        let tail = &region[pos + 15..];
        if let Some(v) = parse_sqlite_version(tail) {
            return Some(EmbeddedVersionMatch {
                library: CuratedLibrary::Sqlite,
                version: v,
            });
        }
    }
    // curl — "libcurl/"
    if window.starts_with(b"libcurl/") {
        let tail = &region[pos + 8..];
        if let Some(v) = parse_semver_triple(tail) {
            return Some(EmbeddedVersionMatch {
                library: CuratedLibrary::Curl,
                version: v,
            });
        }
    }
    // PCRE2 (check first — PCRE prefix is a subset)
    if window.starts_with(b"PCRE2 ") {
        let tail = &region[pos + 6..];
        if let Some(v) = parse_pcre_version(tail) {
            return Some(EmbeddedVersionMatch {
                library: CuratedLibrary::Pcre2,
                version: v,
            });
        }
    }
    // PCRE
    if window.starts_with(b"PCRE ") {
        let tail = &region[pos + 5..];
        if let Some(v) = parse_pcre_version(tail) {
            return Some(EmbeddedVersionMatch {
                library: CuratedLibrary::Pcre,
                version: v,
            });
        }
    }

    None
}

/// OpenSSL version: N.N.N with optional lowercase letter suffix
/// (e.g. `3.0.11`, `1.1.1w`). Must be followed by space or NUL.
fn parse_openssl_version(tail: &[u8]) -> Option<String> {
    let mut end = 0;
    let mut dots = 0;
    while end < tail.len() {
        let b = tail[end];
        if b.is_ascii_digit() {
            end += 1;
        } else if b == b'.' {
            dots += 1;
            if dots > 2 {
                break;
            }
            end += 1;
        } else {
            break;
        }
    }
    // Optional single lowercase letter suffix.
    if end < tail.len() && tail[end].is_ascii_lowercase() && tail[end] != b'r' {
        // Avoid matching `OpenSSL r` from strings like "OpenSSL reasons"
        end += 1;
    }
    if dots != 2 || end == 0 {
        return None;
    }
    // Require a non-version-char immediately after (space, NUL, or similar).
    let terminator_ok = match tail.get(end) {
        Some(&c) => !c.is_ascii_alphanumeric() && c != b'.',
        None => true,
    };
    if !terminator_ok {
        return None;
    }
    std::str::from_utf8(&tail[..end]).ok().map(str::to_string)
}

/// zlib signature: `deflate X.Y.Z[letter] Copyright`. Must be
/// followed by ` Copyright` to qualify — avoids matching `deflate
/// X.Y.Z` that appears in a panic-message help string.
fn parse_zlib_version(tail: &[u8]) -> Option<String> {
    let v = parse_openssl_version(tail)?; // same shape
    // Confirm " Copyright" follows.
    let after = &tail[v.len()..];
    if after.starts_with(b" Copyright") {
        Some(v)
    } else {
        None
    }
}

/// SQLite version: `X.Y.Z` with optional `.W` fourth component.
fn parse_sqlite_version(tail: &[u8]) -> Option<String> {
    let mut end = 0;
    let mut dots = 0;
    while end < tail.len() {
        let b = tail[end];
        if b.is_ascii_digit() {
            end += 1;
        } else if b == b'.' {
            dots += 1;
            if dots > 3 {
                break;
            }
            end += 1;
        } else {
            break;
        }
    }
    if dots < 2 || end == 0 {
        return None;
    }
    let terminator_ok = matches!(tail.get(end), None | Some(&0) | Some(&b' '));
    if !terminator_ok {
        return None;
    }
    std::str::from_utf8(&tail[..end]).ok().map(str::to_string)
}

/// Semver triple `X.Y.Z` with no letter suffix.
fn parse_semver_triple(tail: &[u8]) -> Option<String> {
    let mut end = 0;
    let mut dots = 0;
    while end < tail.len() {
        let b = tail[end];
        if b.is_ascii_digit() {
            end += 1;
        } else if b == b'.' {
            dots += 1;
            if dots > 2 {
                break;
            }
            end += 1;
        } else {
            break;
        }
    }
    if dots != 2 || end == 0 {
        return None;
    }
    std::str::from_utf8(&tail[..end]).ok().map(str::to_string)
}

/// PCRE version: `X.Y YYYY-MM-DD`.
fn parse_pcre_version(tail: &[u8]) -> Option<String> {
    let mut end = 0;
    let mut seen_dot = false;
    while end < tail.len() {
        let b = tail[end];
        if b.is_ascii_digit() {
            end += 1;
        } else if b == b'.' && !seen_dot {
            seen_dot = true;
            end += 1;
        } else {
            break;
        }
    }
    if !seen_dot || end == 0 {
        return None;
    }
    // Confirm ` YYYY-MM-DD` follows.
    let after = &tail[end..];
    if after.len() < 11 || after[0] != b' ' {
        return None;
    }
    let date = &after[1..11];
    let looks_like_date = date[0..4].iter().all(|b| b.is_ascii_digit())
        && date[4] == b'-'
        && date[5..7].iter().all(|b| b.is_ascii_digit())
        && date[7] == b'-'
        && date[8..10].iter().all(|b| b.is_ascii_digit());
    if !looks_like_date {
        return None;
    }
    std::str::from_utf8(&tail[..end]).ok().map(str::to_string)
}

/// 40-char lowercase hex git SHA.
fn parse_git_sha(tail: &[u8]) -> Option<String> {
    if tail.len() < 40 {
        return None;
    }
    let sha = &tail[..40];
    if sha
        .iter()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        std::str::from_utf8(sha).ok().map(str::to_string)
    } else {
        None
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    fn region(inner: &[u8]) -> Vec<u8> {
        // Pad with a leading NUL so the first embed starts at a
        // C-string boundary.
        let mut v = vec![0u8];
        v.extend_from_slice(inner);
        v.push(0);
        v
    }

    #[test]
    fn openssl_positive() {
        let r = region(b"OpenSSL 3.0.11 19 Sep 2023");
        let hits = scan(&r);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].library, CuratedLibrary::OpenSsl);
        assert_eq!(hits[0].version, "3.0.11");
    }

    #[test]
    fn openssl_letter_suffix() {
        let r = region(b"OpenSSL 1.1.1w 11 Sep 2023");
        let hits = scan(&r);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].version, "1.1.1w");
    }

    #[test]
    fn openssl_no_false_positive_on_library_name_alone() {
        // `OpenSSL` followed by a word, not a version.
        let r = region(b"error building with OpenSSL enabled, need to install");
        let hits = scan(&r);
        assert!(hits.is_empty(), "no version → no hit; got {hits:?}");
    }

    #[test]
    fn zlib_requires_copyright_context() {
        let with_copyright = region(b"deflate 1.2.13 Copyright 1995-2022");
        let without = region(b"deflate 1.2.13 status unavailable");
        assert_eq!(scan(&with_copyright).len(), 1);
        assert_eq!(scan(&with_copyright)[0].library, CuratedLibrary::Zlib);
        assert_eq!(scan(&with_copyright)[0].version, "1.2.13");
        assert!(scan(&without).is_empty());
    }

    #[test]
    fn sqlite_positive() {
        let r = region(b"SQLite version 3.44.2");
        let hits = scan(&r);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].library, CuratedLibrary::Sqlite);
        assert_eq!(hits[0].version, "3.44.2");
    }

    #[test]
    fn sqlite_four_segment_version() {
        let r = region(b"SQLite version 3.44.2.1");
        let hits = scan(&r);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].version, "3.44.2.1");
    }

    #[test]
    fn curl_positive() {
        let r = region(b"libcurl/8.4.0");
        let hits = scan(&r);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].library, CuratedLibrary::Curl);
        assert_eq!(hits[0].version, "8.4.0");
    }

    #[test]
    fn pcre_vs_pcre2_disambiguation() {
        let r1 = region(b"PCRE 8.45 2021-06-15");
        let r2 = region(b"PCRE2 10.42 2022-12-11");
        assert_eq!(scan(&r1)[0].library, CuratedLibrary::Pcre);
        assert_eq!(scan(&r1)[0].version, "8.45");
        assert_eq!(scan(&r2)[0].library, CuratedLibrary::Pcre2);
        assert_eq!(scan(&r2)[0].version, "10.42");
    }

    #[test]
    fn boringssl_git_sha() {
        // 40-char lowercase hex git SHA (not 44).
        let r = region(b"BoringSSL aaaabbbbccccddddeeeeffff0000111122223333");
        let hits = scan(&r);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].library, CuratedLibrary::BoringSsl);
        assert_eq!(hits[0].version, "aaaabbbbccccddddeeeeffff0000111122223333");
    }

    #[test]
    fn bare_version_without_prefix_doesnt_match() {
        // SC-005 control: a number that looks like a version but has
        // no library-name prefix must NOT match.
        let r = region(b"3.0.11 is the magic number");
        assert!(scan(&r).is_empty());
    }

    #[test]
    fn mid_string_openssl_not_matched() {
        // Library name appears mid-string, not at a C-string boundary.
        let r = region(b"Using OpenSSL 3.0.11 for crypto");
        // Even though the name+version appears correctly, our boundary
        // rule (NUL-prefix) rejects the match because `OpenSSL` is
        // preceded by `Using `. This tightens the false-positive
        // surface. Users who want the match can store OpenSSL's ID
        // string at a string boundary (which real libraries do).
        let hits = scan(&r);
        assert!(hits.is_empty(), "mid-string match must be rejected; got {hits:?}");
    }

    #[test]
    fn dedup_within_single_scan() {
        // Two copies of the same embed → one match.
        let mut v = vec![0u8];
        v.extend_from_slice(b"OpenSSL 3.0.11 19 Sep 2023");
        v.push(0);
        v.extend_from_slice(b"OpenSSL 3.0.11 19 Sep 2023");
        v.push(0);
        let hits = scan(&v);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn two_different_libraries_both_match() {
        let mut v = vec![0u8];
        v.extend_from_slice(b"OpenSSL 3.0.11 foo");
        v.push(0);
        v.extend_from_slice(b"libcurl/8.4.0");
        v.push(0);
        let hits = scan(&v);
        assert_eq!(hits.len(), 2);
    }
}
