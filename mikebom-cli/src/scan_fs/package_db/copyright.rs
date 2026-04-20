//! Extract license expressions from `/usr/share/doc/<pkg>/copyright`.
//!
//! Two-tier strategy. Files in the **DEP-5 machine-readable format** are
//! parsed structurally — each `Files:` stanza has a `License:` key, we
//! collect all unique values. Files that aren't DEP-5 (the majority of
//! older packages, anything maintained by upstream) are scanned with a
//! small set of free-form heuristics.
//!
//! Each candidate string is normalised through a Debian-shorthand →
//! SPDX lookup table (`GPL-2+` → `GPL-2.0-or-later`) and then validated
//! against the real SPDX expression grammar via
//! [`SpdxExpression::try_canonical`]. Strings that fail validation fall
//! back to the permissive [`SpdxExpression::new`] so we still surface
//! the raw text to downstream consumers — it's better than silently
//! dropping the license claim.
//!
//! References:
//! - <https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/>
//! - <https://spdx.org/licenses/> (canonical identifier list)

use std::collections::BTreeSet;
use std::path::Path;

use mikebom_common::types::license::SpdxExpression;

/// Header that identifies a DEP-5 copyright file. Tolerant of trailing
/// whitespace and the (incorrectly common) http:// variant.
const DEP5_HEADER_NEEDLES: &[&str] = &[
    "https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/",
    "http://www.debian.org/doc/packaging-manuals/copyright-format/1.0/",
];

/// Maximum bytes to read from a copyright file. Some copyright files
/// embed the full GPL text (~35 KB) — we only need the header, the
/// `Files:` stanzas, and the first few lines for the heuristic. 128 KB
/// is a generous cap.
const MAX_COPYRIGHT_BYTES: usize = 128 * 1024;

/// Lines to consider for the free-form heuristic. Older copyright
/// files (GCC, glibc, libtool-style) bury the license declaration
/// behind a prose preamble of ~100 lines; 256 covers them without
/// ballooning parse time (the file is memory-resident already).
const HEURISTIC_LINE_BUDGET: usize = 256;

/// Read and parse `<rootfs>/usr/share/doc/<pkg_name>/copyright`. Returns
/// the unique set of [`SpdxExpression`]s the file mentions, normalised
/// to canonical SPDX form where possible. Empty vector when the file is
/// absent or contains no recognisable license claim.
pub fn read_copyright(rootfs: &Path, pkg_name: &str) -> Vec<SpdxExpression> {
    // dpkg multi-arch packages sometimes ship docs under a bare name
    // (`/usr/share/doc/libc6/copyright`) and sometimes under the
    // arch-suffixed form (`/usr/share/doc/libc6-amd64/...`). Try the
    // plain path first, then common arch-suffix fallbacks. `is_file()`
    // follows symlinks by default, so symlinked copyright files
    // (common: `/usr/share/doc/<lib>/copyright` → a sibling package)
    // resolve without extra work.
    let doc_root = rootfs.join("usr/share/doc");
    let candidates = [
        doc_root.join(pkg_name).join("copyright"),
        doc_root.join(format!("{pkg_name}-amd64")).join("copyright"),
        doc_root.join(format!("{pkg_name}-arm64")).join("copyright"),
        doc_root.join(format!("{pkg_name}-x86_64")).join("copyright"),
        doc_root.join(format!("{pkg_name}-aarch64")).join("copyright"),
    ];

    let mut path_opt = None;
    for p in &candidates {
        if p.is_file() {
            path_opt = Some(p.clone());
            break;
        }
    }
    let Some(path) = path_opt else {
        tracing::debug!(
            pkg = %pkg_name,
            rootfs = %rootfs.display(),
            "no copyright file found for package (tried plain + arch-suffixed paths)"
        );
        return Vec::new();
    };

    let raw = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::debug!(path = %path.display(), error = %e, "could not read copyright");
            return Vec::new();
        }
    };
    let truncated = if raw.len() > MAX_COPYRIGHT_BYTES {
        &raw[..MAX_COPYRIGHT_BYTES]
    } else {
        &raw[..]
    };
    let text = match std::str::from_utf8(truncated) {
        Ok(s) => s,
        Err(_) => {
            // Some copyright files have non-UTF-8 author names. Lossy
            // decoding lets us still pull the License: lines out.
            &String::from_utf8_lossy(truncated).into_owned().leak()[..]
        }
    };

    let extracted = extract_licenses(text);
    if extracted.is_empty() {
        tracing::debug!(
            pkg = %pkg_name,
            path = %path.display(),
            "license extraction returned empty — copyright file found but unparseable"
        );
    }
    extracted
}

/// Pure-text wrapper that splits the strategy on DEP-5 detection.
///
/// Run both passes for a DEP-5 file when the structured pass comes up
/// empty. Some packages declare "Format: ...copyright-format/1.0/" at
/// the top but then fall back to free-form prose or `SPDX-License-Identifier:`
/// tags; we want to catch those too.
fn extract_licenses(text: &str) -> Vec<SpdxExpression> {
    let is_structured = is_dep5(text);
    let mut candidates: Vec<String> = if is_structured {
        extract_dep5(text)
    } else {
        Vec::new()
    };

    if candidates.is_empty() {
        candidates = extract_freeform(text);
    }

    // Each candidate gets normalised + validated independently. Use a
    // BTreeSet keyed by the canonical string so duplicates collapse.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<SpdxExpression> = Vec::new();
    for raw in candidates {
        let normalised = normalise_debian_shorthand(&raw);
        let expr = SpdxExpression::try_canonical(&normalised)
            .or_else(|_| SpdxExpression::new(&normalised))
            .ok();
        if let Some(e) = expr {
            if seen.insert(e.as_str().to_string()) {
                out.push(e);
            }
        }
    }
    out
}

/// Probe the first ~10 lines for the DEP-5 format URI. Tolerant of
/// `Format:` keys that span continuations and of either http/https.
fn is_dep5(text: &str) -> bool {
    let head: String = text.lines().take(10).collect::<Vec<_>>().join("\n");
    DEP5_HEADER_NEEDLES.iter().any(|needle| head.contains(needle))
}

/// Tier 1 — DEP-5 stanza walker. Pulls every license claim we can find.
///
/// DEP-5 permits three shapes:
/// 1. `Files:` + `License:` — the typical per-file-group declaration.
/// 2. Stand-alone `License:` stanzas that declare a named license used
///    elsewhere via short-name reference (common for `License: GPL-2`
///    where the body is a `/usr/share/common-licenses/GPL-2` reference).
/// 3. `SPDX-License-Identifier:` tags — increasingly common in modern
///    packaging; unambiguous because they carry canonical SPDX IDs.
///
/// We accept all three. Shape 2 is the usual culprit for the
/// "license file exists but we emit nothing" class of miss: the
/// standalone stanza's `License:` short-name is the real license claim.
fn extract_dep5(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for stanza in text.split("\n\n") {
        let mut has_files = false;
        let mut license_value: Option<String> = None;
        let mut spdx_tag: Option<String> = None;

        for line in stanza.lines() {
            let trimmed = line.trim_start();
            if line.starts_with("Files:") {
                has_files = true;
            }
            if let Some(rest) = line.strip_prefix("License:") {
                let v = rest.trim();
                if !v.is_empty() {
                    license_value = Some(v.to_string());
                }
            }
            // Match `SPDX-License-Identifier:` anywhere in the stanza,
            // even indented inside a continuation block.
            if let Some(rest) = trimmed.strip_prefix("SPDX-License-Identifier:") {
                let v = rest.trim();
                if !v.is_empty() {
                    spdx_tag = Some(v.to_string());
                }
            }
        }

        // SPDX tags win when present — canonical by construction.
        if let Some(v) = spdx_tag {
            out.push(v);
            continue;
        }

        // Emit the `License:` short-name for BOTH `Files:`-keyed stanzas
        // AND standalone license-reference stanzas. Previously we only
        // accepted the former, which dropped legitimate declarations
        // that put the summary at the top of the file.
        if let Some(v) = license_value {
            if has_files || is_probably_standalone_license_stanza(stanza) {
                out.push(v);
            }
        }
    }
    out
}

/// Heuristic: a stanza with a `License:` key but no `Files:` / `Upstream-*` /
/// `Copyright:` keys is probably a standalone license-reference block.
/// Avoids false positives from e.g. a `Upstream-Contact: ...` header
/// that happens to contain a `License:` substring (doesn't start a line
/// anyway, but belt-and-suspenders).
fn is_probably_standalone_license_stanza(stanza: &str) -> bool {
    let mut has_license_key = false;
    let mut has_other_structural_key = false;
    for line in stanza.lines() {
        if line.starts_with("License:") {
            has_license_key = true;
        } else if line.starts_with("Files:")
            || line.starts_with("Format:")
            || line.starts_with("Upstream-Name:")
            || line.starts_with("Upstream-Contact:")
            || line.starts_with("Source:")
        {
            has_other_structural_key = true;
        }
    }
    has_license_key && !has_other_structural_key
}

/// Map a `/usr/share/common-licenses/<NAME>` basename to its SPDX id.
///
/// Covers the canonical set of files Debian's `base-files` ships. A
/// copyright file that only says "see /usr/share/common-licenses/GPL-3"
/// tells us the exact license even if no structural `License:` key is
/// present.
fn common_licenses_to_spdx(name: &str) -> Option<&'static str> {
    match name {
        "GPL-1" => Some("GPL-1.0-only"),
        "GPL-2" => Some("GPL-2.0-only"),
        "GPL-3" => Some("GPL-3.0-only"),
        "LGPL-2" => Some("LGPL-2.0-only"),
        "LGPL-2.1" => Some("LGPL-2.1-only"),
        "LGPL-3" => Some("LGPL-3.0-only"),
        "Apache-2.0" => Some("Apache-2.0"),
        "Artistic" => Some("Artistic-1.0-Perl"),
        "BSD" => Some("BSD-3-Clause"),
        "GFDL-1.2" => Some("GFDL-1.2-only"),
        "GFDL-1.3" => Some("GFDL-1.3-only"),
        "MPL-1.1" => Some("MPL-1.1"),
        "MPL-2.0" => Some("MPL-2.0"),
        _ => None,
    }
}

/// Extract license(s) implied by `/usr/share/common-licenses/<NAME>`
/// references in prose. GCC, glibc, and other GNU-style copyright files
/// commonly name the license only via this file-path reference.
fn extract_common_licenses_refs(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    const NEEDLE: &str = "/usr/share/common-licenses/";
    for line in text.lines().take(HEURISTIC_LINE_BUDGET) {
        let mut rest = line;
        while let Some(idx) = rest.find(NEEDLE) {
            let after = &rest[idx + NEEDLE.len()..];
            // License name runs until the first char that isn't valid
            // in a filename: quote, space, comma, paren, dot-then-space,
            // or end of line.
            let end = after
                .find(|c: char| {
                    c.is_whitespace()
                        || c == '\''
                        || c == '"'
                        || c == ','
                        || c == ')'
                        || c == ']'
                })
                .unwrap_or(after.len());
            let name = after[..end].trim_end_matches(&['.', '`', '\''][..]);
            if let Some(spdx) = common_licenses_to_spdx(name) {
                out.push(spdx.to_string());
            }
            rest = &after[end..];
        }
    }
    out
}

/// Detect the classic FSF licence-grant prose that debianized packages
/// commonly copy verbatim, e.g.
///
/// > "This library is free software; you can redistribute it and/or modify
/// >  it under the terms of the GNU Lesser General Public License as
/// >  published by the Free Software Foundation; either version 2.1 of
/// >  the License, or (at your option) any later version."
///
/// Returns the SPDX canonical form (e.g. `LGPL-2.1-or-later`). This is
/// multi-line by necessity — the license name and the version are
/// almost always split across a line break in the prose.
fn extract_fsf_prose(text: &str) -> Vec<String> {
    // Collapse whitespace so patterns don't care about newlines.
    let collapsed: String = text
        .chars()
        .take(HEURISTIC_LINE_BUDGET * 120) // ~120 chars/line cap
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    let mut out = Vec::new();

    // Table of (needle, later-suffix-required, spdx-only, spdx-or-later).
    // The "later-suffix-required" toggle reflects whether we need to see
    // "any later version" to pick the `-or-later` form — when missing we
    // emit the `-only` form.
    const PATTERNS: &[(&str, &str, &str)] = &[
        // LGPL
        ("GNU Lesser General Public License as published by the Free Software Foundation; either version 2.1", "LGPL-2.1-only", "LGPL-2.1-or-later"),
        ("GNU Lesser General Public License, version 2.1", "LGPL-2.1-only", "LGPL-2.1-or-later"),
        ("GNU Lesser General Public License as published by the Free Software Foundation; either version 2", "LGPL-2.0-only", "LGPL-2.0-or-later"),
        ("GNU Lesser General Public License as published by the Free Software Foundation; either version 3", "LGPL-3.0-only", "LGPL-3.0-or-later"),
        ("GNU Library General Public License as published by the Free Software Foundation; either version 2", "LGPL-2.0-only", "LGPL-2.0-or-later"),
        // GPL
        ("GNU General Public License as published by the Free Software Foundation; either version 2", "GPL-2.0-only", "GPL-2.0-or-later"),
        ("GNU General Public License as published by the Free Software Foundation; either version 3", "GPL-3.0-only", "GPL-3.0-or-later"),
        ("GNU General Public License as published by the Free Software Foundation, version 2", "GPL-2.0-only", "GPL-2.0-or-later"),
        ("GNU General Public License as published by the Free Software Foundation, version 3", "GPL-3.0-only", "GPL-3.0-or-later"),
        // AGPL
        ("GNU Affero General Public License as published by the Free Software Foundation; either version 3", "AGPL-3.0-only", "AGPL-3.0-or-later"),
    ];

    for (needle, only_id, or_later_id) in PATTERNS {
        if let Some(hit) = collapsed.find(needle) {
            // Look at a window after the match for "later version" markers.
            let tail = &collapsed[hit + needle.len()..];
            let lookahead = &tail[..tail.len().min(160)];
            let has_later = lookahead.contains("later version")
                || lookahead.contains("any later");
            out.push(
                if has_later { (*or_later_id).to_string() } else { (*only_id).to_string() },
            );
        }
    }

    out
}

/// Tier 2 — free-form heuristic. Patterns ordered by specificity.
fn extract_freeform(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    // High-precision pass: `/usr/share/common-licenses/<NAME>` mentions.
    // Runs across the full budget so we don't miss files that bury the
    // reference past the preamble (gcc-12-base puts it at line 97).
    out.extend(extract_common_licenses_refs(text));
    // Multi-line FSF prose recogniser — catches the boilerplate that
    // ships in most Debian-packaged GNU libraries (libsemanage,
    // debian-archive-keyring, libcrypt1, etc.).
    out.extend(extract_fsf_prose(text));

    for line in text.lines().take(HEURISTIC_LINE_BUDGET) {
        let trimmed = line.trim_start();
        // Pattern 0: `SPDX-License-Identifier:` tag (most specific;
        // canonical SPDX by construction).
        if let Some(rest) = trimmed.strip_prefix("SPDX-License-Identifier:") {
            let v = rest.trim();
            if !v.is_empty() {
                out.push(v.to_string());
                continue;
            }
        }
        // Pattern A: "License: <value>" outside any DEP-5 stanza.
        if let Some(rest) = line.strip_prefix("License:") {
            let v = rest.trim();
            if !v.is_empty() {
                out.push(v.to_string());
                continue;
            }
        }
        // Pattern B: "...licensed under the <X> license"
        if let Some(extracted) = extract_after("licensed under the ", line, " license") {
            out.push(extracted);
            continue;
        }
        if let Some(extracted) = extract_after("Licensed under the ", line, " license") {
            out.push(extracted);
            continue;
        }
        // Pattern C: "Released under <X>"
        if let Some(extracted) = extract_after("Released under ", line, "") {
            out.push(extracted.trim_end_matches('.').to_string());
            continue;
        }
        // Pattern D: "under the terms of the <X> (License|as published)"
        // Catches "under the terms of the GNU General Public License as
        // published" — very common in copyright headers.
        if let Some(extracted) =
            extract_after("under the terms of the ", line, " license")
        {
            out.push(extracted);
            continue;
        }
        if let Some(extracted) =
            extract_after("under the terms of the ", line, " as published")
        {
            out.push(extracted);
            continue;
        }
    }
    out
}

/// Find `between(prefix, suffix)` inside `line`. When `suffix` is empty,
/// returns the substring from after `prefix` to end-of-line (trimmed).
fn extract_after(prefix: &str, line: &str, suffix: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let prefix_lower = prefix.to_ascii_lowercase();
    let start = lower.find(&prefix_lower)? + prefix.len();
    let tail = &line[start..];
    if suffix.is_empty() {
        let v = tail.trim();
        if v.is_empty() { None } else { Some(v.to_string()) }
    } else {
        let suffix_lower = suffix.to_ascii_lowercase();
        let suffix_at = tail.to_ascii_lowercase().find(&suffix_lower)?;
        let v = tail[..suffix_at].trim();
        if v.is_empty() { None } else { Some(v.to_string()) }
    }
}

/// Map the small set of Debian-shorthand license names to canonical
/// SPDX 2.x identifiers. Anything not in the table passes through
/// unchanged for the SPDX parser to validate (or reject).
fn normalise_debian_shorthand(raw: &str) -> String {
    let trimmed = raw.trim();
    // Apply the lookup token-by-token so composite expressions like
    // "GPL-2+ and LGPL-2.1+" still get normalised on each side. We
    // also turn the Debian "and"/"or" into SPDX uppercase operators.
    let mut out = String::with_capacity(trimmed.len() + 8);
    for token in trimmed.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(map_shorthand_token(token));
    }
    out
}

/// Per-token mapping from Debian shorthand → canonical SPDX ID.
///
/// Matching is case-sensitive on the well-known mixed-case SPDX forms
/// (`GPL-2+`, `BSD-3-clause`) plus their common lowercase variants that
/// older Debian packaging and some upstream copyright headers ship.
/// Anything not in the table passes through unchanged so the SPDX
/// parser can reject it downstream.
fn map_shorthand_token(token: &str) -> &str {
    match token {
        // Boolean operators — SPDX requires uppercase
        "and" | "And" => "AND",
        "or" | "Or" => "OR",
        "with" | "With" => "WITH",
        // GPL family — both dash-form (`GPL-2`) and v-form (`GPLv2`,
        // seen in upstream-written copyright headers).
        "GPL-1" | "GPL-1.0" | "gpl-1" | "GPLv1" => "GPL-1.0-only",
        "GPL-1+" | "GPL-1.0+" | "gpl-1+" | "GPLv1+" => "GPL-1.0-or-later",
        "GPL-2" | "GPL-2.0" | "gpl-2" | "GPLv2" => "GPL-2.0-only",
        "GPL-2+" | "GPL-2.0+" | "gpl-2+" | "GPLv2+" => "GPL-2.0-or-later",
        "GPL-3" | "GPL-3.0" | "gpl-3" | "GPLv3" => "GPL-3.0-only",
        "GPL-3+" | "GPL-3.0+" | "gpl-3+" | "GPLv3+" => "GPL-3.0-or-later",
        // LGPL family
        "LGPL-2" | "LGPL-2.0" | "lgpl-2" | "LGPLv2" => "LGPL-2.0-only",
        "LGPL-2+" | "LGPL-2.0+" | "lgpl-2+" | "LGPLv2+" => "LGPL-2.0-or-later",
        "LGPL-2.1" | "lgpl-2.1" | "LGPLv2.1" => "LGPL-2.1-only",
        "LGPL-2.1+" | "lgpl-2.1+" | "LGPLv2.1+" => "LGPL-2.1-or-later",
        "LGPL-3" | "LGPL-3.0" | "lgpl-3" | "LGPLv3" => "LGPL-3.0-only",
        "LGPL-3+" | "LGPL-3.0+" | "lgpl-3+" | "LGPLv3+" => "LGPL-3.0-or-later",
        // AGPL family
        "AGPL-3" | "AGPL-3.0" | "agpl-3" | "AGPLv3" => "AGPL-3.0-only",
        "AGPL-3+" | "AGPL-3.0+" | "agpl-3+" | "AGPLv3+" => "AGPL-3.0-or-later",
        // BSD family — Debian uses lowercase clause counts
        "BSD-2-clause" | "BSD-2-Clause" | "bsd-2-clause" => "BSD-2-Clause",
        "BSD-3-clause" | "BSD-3-Clause" | "bsd-3-clause" => "BSD-3-Clause",
        "BSD-4-clause" | "BSD-4-Clause" | "bsd-4-clause" => "BSD-4-Clause",
        // Permissive & Apache variants
        "Apache-2" | "Apache-2.0" | "apache-2" | "apache-2.0" => "Apache-2.0",
        "Apache-1.1" | "apache-1.1" => "Apache-1.1",
        "MIT" | "Expat" | "expat" | "mit" => "MIT", // Debian historical alias
        "MIT-0" | "mit-0" => "MIT-0",
        "ISC" | "isc" => "ISC",
        "Zlib" | "zlib" | "zlib/libpng" => "Zlib",
        // Mozilla
        "MPL-1.1" | "mpl-1.1" => "MPL-1.1",
        "MPL-2.0" | "MPL-2" | "mpl-2.0" | "mpl-2" => "MPL-2.0",
        // Perl / Artistic
        "Artistic-2.0" | "artistic-2.0" => "Artistic-2.0",
        // Other permissive classics that recur in Debian copyright files
        "HPND" | "hpnd" => "HPND",
        "Python-2.0" | "python-2.0" | "PSF-2.0" => "Python-2.0",
        "Unicode-DFS-2016" | "unicode-dfs-2016" => "Unicode-DFS-2016",
        "OFL-1.1" | "ofl-1.1" => "OFL-1.1",
        "WTFPL" | "wtfpl" => "WTFPL",
        "CC0-1.0" | "cc0-1.0" | "CC0" | "cc0" => "CC0-1.0",
        "CC-BY-4.0" | "cc-by-4.0" => "CC-BY-4.0",
        "CC-BY-SA-4.0" | "cc-by-sa-4.0" => "CC-BY-SA-4.0",
        // FSF's various permissive helper licenses
        "FSFAP" | "fsfap" => "FSFAP",
        "FSFUL" | "fsful" => "FSFUL",
        "FSFULLR" | "fsfullr" => "FSFULLR",
        "X11" | "x11" => "X11",
        // Public domain & no-license markers (intentionally NOT mapped —
        // SPDX has no identifier for "public domain"; we let the SPDX
        // parser reject these and the permissive constructor preserve
        // the raw text).
        other => other,
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use std::fs;

    fn make_rootfs_with_copyright(pkg: &str, content: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let cpath = dir.path().join("usr/share/doc").join(pkg).join("copyright");
        fs::create_dir_all(cpath.parent().unwrap()).unwrap();
        fs::write(&cpath, content).unwrap();
        dir
    }

    #[test]
    fn dep5_single_license_canonicalised_to_spdx() {
        let body = "\
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: jq

Files: *
Copyright: 2012-2024 Stephen Dolan
License: MIT
";
        let dir = make_rootfs_with_copyright("jq", body);
        let licenses = read_copyright(dir.path(), "jq");
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "MIT");
    }

    #[test]
    fn dep5_debian_shorthand_normalised() {
        let body = "\
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: 2010 The libfoo authors
License: GPL-2+
";
        let dir = make_rootfs_with_copyright("libfoo", body);
        let licenses = read_copyright(dir.path(), "libfoo");
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "GPL-2.0-or-later");
    }

    #[test]
    fn dep5_composite_and_clause() {
        let body = "\
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: 2010
License: GPL-2+ and LGPL-2.1+
";
        let dir = make_rootfs_with_copyright("libcombo", body);
        let licenses = read_copyright(dir.path(), "libcombo");
        assert_eq!(licenses.len(), 1);
        // Either valid SPDX with AND, or a stored raw string —
        // normalisation happens regardless.
        let s = licenses[0].as_str();
        assert!(s.contains("GPL-2.0-or-later"), "expected normalised GPL: {s}");
        assert!(s.contains("LGPL-2.1-or-later"), "expected normalised LGPL: {s}");
        assert!(s.contains("AND"), "expected operator AND: {s}");
    }

    #[test]
    fn dep5_dedupes_repeated_licenses() {
        let body = "\
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: foo
License: MIT

Files: src/contrib/*
Copyright: bar
License: MIT
";
        let dir = make_rootfs_with_copyright("dupe", body);
        let licenses = read_copyright(dir.path(), "dupe");
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "MIT");
    }

    #[test]
    fn freeform_heuristic_finds_licensed_under() {
        let body = "\
This is the jq command-line JSON processor.

jq is licensed under the MIT license.
See LICENSE.md for details.
";
        let dir = make_rootfs_with_copyright("jq-noformat", body);
        let licenses = read_copyright(dir.path(), "jq-noformat");
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "MIT");
    }

    #[test]
    fn freeform_heuristic_finds_bare_license_line() {
        let body = "\
Some prose at the top.

License: Apache-2.0

Lots of license text follows...
";
        let dir = make_rootfs_with_copyright("apache-pkg", body);
        let licenses = read_copyright(dir.path(), "apache-pkg");
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "Apache-2.0");
    }

    #[test]
    fn freeform_garbage_returns_empty() {
        let body = "\
This is just some prose with no license claim anywhere in it.
Nothing to see here.
";
        let dir = make_rootfs_with_copyright("noclaim", body);
        let licenses = read_copyright(dir.path(), "noclaim");
        assert!(licenses.is_empty());
    }

    #[test]
    fn missing_copyright_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let licenses = read_copyright(dir.path(), "doesntexist");
        assert!(licenses.is_empty());
    }

    #[test]
    fn dep5_detects_http_variant_of_format_uri() {
        let body = "\
Format: http://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
License: BSD-3-clause
";
        let dir = make_rootfs_with_copyright("oldformat", body);
        let licenses = read_copyright(dir.path(), "oldformat");
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "BSD-3-Clause");
    }

    #[test]
    fn debian_uses_expat_as_alias_for_mit() {
        // Some Debian packages ship MIT under the historical name "Expat".
        let body = "\
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
License: Expat
";
        let dir = make_rootfs_with_copyright("expat-as-mit", body);
        let licenses = read_copyright(dir.path(), "expat-as-mit");
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "MIT");
    }

    #[test]
    fn spdx_license_identifier_tag_in_dep5() {
        // Modern packaging increasingly uses SPDX-License-Identifier.
        // When present, it wins (canonical by construction).
        let body = "\
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: 2020 Someone
SPDX-License-Identifier: Apache-2.0 OR MIT
License: some-local-name
";
        let dir = make_rootfs_with_copyright("spdx-tagged", body);
        let licenses = read_copyright(dir.path(), "spdx-tagged");
        assert_eq!(licenses.len(), 1);
        // Canonical SPDX expression preserved.
        assert_eq!(licenses[0].as_str(), "Apache-2.0 OR MIT");
    }

    #[test]
    fn spdx_license_identifier_tag_in_freeform_prose() {
        let body = "\
This is jq.

SPDX-License-Identifier: MIT

Lots of copyright prose below...
";
        let dir = make_rootfs_with_copyright("spdx-freeform", body);
        let licenses = read_copyright(dir.path(), "spdx-freeform");
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "MIT");
    }

    #[test]
    fn standalone_license_stanza_without_files_key_is_accepted() {
        // Debian's common pattern: the first stanza after Format: is a
        // standalone License: declaration naming the common-licenses
        // file to consult. Previously we only collected License: values
        // from stanzas that also had `Files:`, so this whole class of
        // copyright file (especially `License: GPL-2` with the body
        // being a reference to /usr/share/common-licenses/GPL-2) was
        // lost.
        let body = "\
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: coreutils

License: GPL-3+
 On Debian systems, the full text of the GPL-3 can be found in
 /usr/share/common-licenses/GPL-3.
";
        let dir = make_rootfs_with_copyright("coreutils", body);
        let licenses = read_copyright(dir.path(), "coreutils");
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "GPL-3.0-or-later");
    }

    #[test]
    fn under_the_terms_of_the_x_license_pattern() {
        let body = "\
Copyright (C) 2010 Free Software Foundation, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
";
        let dir = make_rootfs_with_copyright("fsf-style", body);
        let licenses = read_copyright(dir.path(), "fsf-style");
        // This is one of the patterns that syft and trivy pick up via
        // their free-form heuristics. We at least extract the phrase.
        assert!(!licenses.is_empty(), "free-form FSF pattern should match");
    }

    #[test]
    fn lowercase_shorthand_normalised() {
        assert_eq!(normalise_debian_shorthand("gpl-2+"), "GPL-2.0-or-later");
        assert_eq!(normalise_debian_shorthand("lgpl-3"), "LGPL-3.0-only");
        assert_eq!(normalise_debian_shorthand("bsd-3-clause"), "BSD-3-Clause");
        assert_eq!(normalise_debian_shorthand("apache-2.0"), "Apache-2.0");
        assert_eq!(normalise_debian_shorthand("expat"), "MIT");
    }

    #[test]
    fn arch_suffixed_copyright_dir_fallback() {
        // Multi-arch packages sometimes put docs under `<pkg>-<arch>/`
        // instead of the plain name.
        let dir = tempfile::tempdir().unwrap();
        let cpath = dir.path().join("usr/share/doc/libc6-amd64/copyright");
        fs::create_dir_all(cpath.parent().unwrap()).unwrap();
        fs::write(
            &cpath,
            "\
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
License: LGPL-2.1+
",
        )
        .unwrap();
        let licenses = read_copyright(dir.path(), "libc6");
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "LGPL-2.1-or-later");
    }

    #[test]
    fn fsf_prose_lgpl_2_1_or_later_pattern_recognised() {
        // This is the boilerplate the Debian libsemanage packages ship.
        let body = "\
This is the Debian package for libsemanage.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.
";
        let dir = make_rootfs_with_copyright("libsemanage2", body);
        let licenses = read_copyright(dir.path(), "libsemanage2");
        assert!(
            licenses.iter().any(|l| l.as_str() == "LGPL-2.1-or-later"),
            "expected LGPL-2.1-or-later, got {licenses:?}"
        );
    }

    #[test]
    fn fsf_prose_gpl_2_or_later_pattern_recognised() {
        // debian-archive-keyring's license declaration shape.
        let body = "\
Debian support files are free software; you can redistribute them and/or
modify them under the terms of the GNU General Public License as published
by the Free Software Foundation; either version 2, or (at your option) any
later version.
";
        let dir = make_rootfs_with_copyright("deb-ark", body);
        let licenses = read_copyright(dir.path(), "deb-ark");
        assert!(
            licenses.iter().any(|l| l.as_str() == "GPL-2.0-or-later"),
            "expected GPL-2.0-or-later, got {licenses:?}"
        );
    }

    #[test]
    fn common_licenses_reference_pattern_recognised() {
        // gcc-12-base shape: prose says "the Public License is in
        // `/usr/share/common-licenses/GPL-3'". No `License:` key, no
        // DEP-5 header, just the file-path reference.
        let body = "\
GCC is Copyright (C) 1986, 2019 Free Software Foundation, Inc.

GCC is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License version 3. A copy of the
license is in `/usr/share/common-licenses/GPL-3'.
";
        let dir = make_rootfs_with_copyright("gcc-12-base", body);
        let licenses = read_copyright(dir.path(), "gcc-12-base");
        assert!(
            licenses.iter().any(|l| l.as_str() == "GPL-3.0-only"),
            "expected GPL-3.0-only from common-licenses ref, got {licenses:?}"
        );
    }

    #[test]
    fn lgplv_prefixed_shorthand_normalised() {
        // libgcrypt copyright says "License (library): LGPLv2.1+".
        assert_eq!(normalise_debian_shorthand("LGPLv2.1+"), "LGPL-2.1-or-later");
        assert_eq!(normalise_debian_shorthand("GPLv2+"), "GPL-2.0-or-later");
    }

    #[test]
    fn symlinked_copyright_resolves() {
        // One package's copyright symlinks to a neighbour's. is_file()
        // follows symlinks by default, so this already works — this
        // test nails it down against regressions.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("usr/share/doc/glibc/copyright");
        fs::create_dir_all(real.parent().unwrap()).unwrap();
        fs::write(
            &real,
            "\
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
License: LGPL-2.1+
",
        )
        .unwrap();
        // Symlink libc6/copyright → glibc/copyright
        let link_parent = dir.path().join("usr/share/doc/libc6");
        fs::create_dir_all(&link_parent).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, link_parent.join("copyright")).unwrap();

        #[cfg(unix)]
        {
            let licenses = read_copyright(dir.path(), "libc6");
            assert_eq!(licenses.len(), 1);
            assert_eq!(licenses[0].as_str(), "LGPL-2.1-or-later");
        }
    }
}
