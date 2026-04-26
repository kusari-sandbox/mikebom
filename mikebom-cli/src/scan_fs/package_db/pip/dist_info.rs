//! Tier 1: PEP 376 venv site-packages walker + METADATA parser.
//!
//! Authoritative source for what's actually installed on disk: each
//! `<name>-<version>.dist-info/METADATA` file is parsed into a
//! [`PipDistInfoEntry`], converted to [`PackageDbEntry`] at the
//! module boundary, and emitted by [`super::read`] before the
//! lockfile and requirements-file tiers run.
//!
//! Also exports [`collect_claimed_paths`], the post-pip-install
//! claim tracker that prevents binary-walker double-counting of
//! cpython extension files. Callers reach it via the re-export in
//! `pip/mod.rs`.

use std::path::{Path, PathBuf};

use mikebom_common::types::license::SpdxExpression;
use mikebom_common::types::purl::Purl;

use super::super::PackageDbEntry;
use super::{build_pypi_purl_str, tokenise_requires_dist_name};

// -----------------------------------------------------------------------
// Tier 1: venv dist-info walker
// -----------------------------------------------------------------------

/// Iterate every dist-info `RECORD` file under every candidate
/// site-packages directory and insert each listed file (rootfs-joined
/// absolute path) into `claimed`. Milestone 004 post-ship fix for the
/// binary-walker double-counting of pip-installed cpython extensions.
///
/// RECORD format (PEP 376 / PEP 627): CSV where column 0 is the file
/// path relative to site-packages (forward slashes). We ignore the
/// remaining columns (hash + size — not needed for claim tracking).
///
/// No-op when no site-packages exists. Malformed CSV lines are
/// tolerated (partial claims, not scan failure).
pub fn collect_claimed_paths(
    rootfs: &Path,
    claimed: &mut std::collections::HashSet<std::path::PathBuf>,
    #[cfg(unix)] claimed_inodes: &mut std::collections::HashSet<(u64, u64)>,
) {
    for site_packages in candidate_site_packages_roots(rootfs) {
        if !site_packages.is_dir() {
            continue;
        }
        let Ok(read_dir) = std::fs::read_dir(&site_packages) else {
            continue;
        };
        for entry in read_dir.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) != Some("dist-info") {
                continue;
            }
            let record = p.join("RECORD");
            let Ok(content) = std::fs::read_to_string(&record) else {
                continue;
            };
            for line in content.lines() {
                // First field = path relative to site-packages.
                let Some(rel) = line.split(',').next() else {
                    continue;
                };
                let rel = rel.trim();
                if rel.is_empty() {
                    continue;
                }
                // Resolve path: site-packages + rel. Some RECORD
                // entries use `../` to escape for shared data
                // (`../../../bin/jq` etc.) — preserve that form.
                let abs = site_packages.join(rel);
                super::super::insert_claim_with_canonical(
                    claimed,
                    #[cfg(unix)]
                    claimed_inodes,
                    abs,
                );
            }
        }
    }
}

/// Walk candidate `site-packages/` locations under `rootfs` and parse
/// every `<name>-<version>.dist-info/METADATA` we find.
pub(super) fn read_venv_dist_info(rootfs: &Path) -> Vec<PackageDbEntry> {
    let mut out = Vec::new();
    for root in candidate_site_packages_roots(rootfs) {
        if !root.is_dir() {
            continue;
        }
        let Ok(read_dir) = std::fs::read_dir(&root) else {
            continue;
        };
        let mut names: Vec<PathBuf> = read_dir
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|ext| ext == "dist-info")
            })
            .collect();
        names.sort(); // determinism
        for dist_info in names {
            if let Some(entry) = parse_dist_info_dir(&dist_info) {
                out.push(entry);
            }
        }
    }
    out
}

/// Enumerate likely `site-packages/` locations. Covers:
/// - `<root>/.venv/lib/python*/site-packages/`
/// - `<root>/venv/lib/python*/site-packages/`
/// - `<root>/usr/lib/python*/dist-packages/` (Debian system python)
/// - `<root>/usr/lib/python*/site-packages/`
/// - `<root>/usr/local/lib/python*/site-packages/`
/// - `<root>/opt/app/.venv/lib/python*/site-packages/`
fn candidate_site_packages_roots(rootfs: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for venv in [".venv", "venv"] {
        out.extend(find_site_packages_under(&rootfs.join(venv).join("lib")));
    }
    for sys in ["usr/lib", "usr/local/lib", "opt/app/.venv/lib"] {
        out.extend(find_site_packages_under(&rootfs.join(sys)));
    }
    out
}

/// `<base>/python3.X/site-packages/` OR `<base>/python3.X/dist-packages/`.
/// Glob-equivalent for `python*/site-packages/` and `python*/dist-packages/`.
fn find_site_packages_under(base: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !base.is_dir() {
        return out;
    }
    let Ok(read_dir) = std::fs::read_dir(base) else {
        return out;
    };
    for entry in read_dir.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.starts_with("python") {
            continue;
        }
        for leaf in ["site-packages", "dist-packages"] {
            let candidate = entry.path().join(leaf);
            if candidate.is_dir() {
                out.push(candidate);
            }
        }
    }
    out
}

/// Parse one `<name>-<version>.dist-info/` directory. Returns None if
/// the METADATA file is absent or unreadable.
fn parse_dist_info_dir(dist_info: &Path) -> Option<PackageDbEntry> {
    let metadata_path = dist_info.join("METADATA");
    let bytes = std::fs::read(&metadata_path).ok()?;
    let parsed = parse_metadata_bytes(&bytes);
    parsed.into_package_db_entry(metadata_path.to_string_lossy().into_owned())
}

// -----------------------------------------------------------------------
// Tier 1 support: PipDistInfoEntry + METADATA parser
// -----------------------------------------------------------------------

/// Parsed content of a single `dist-info/METADATA` file. Intermediate
/// representation; converted to [`PackageDbEntry`] at the module
/// boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PipDistInfoEntry {
    pub name: String,
    pub version: String,
    pub license_expression: Option<String>, // PEP 639 `License-Expression:`
    pub license_raw: Option<String>,        // legacy `License:`
    pub classifiers: Vec<String>,           // `Classifier: License :: ...`
    pub requires_dist: Vec<String>,         // raw PEP 508 strings
    pub author: Option<String>,
    pub author_email: Option<String>,
}

impl PipDistInfoEntry {
    /// Convert to the scan-pipeline's `PackageDbEntry` shape.
    fn into_package_db_entry(self, source_path: String) -> Option<PackageDbEntry> {
        if self.name.is_empty() || self.version.is_empty() {
            return None;
        }
        let purl_str = build_pypi_purl_str(&self.name, &self.version);
        let purl = Purl::new(&purl_str).ok()?;

        // Author / Author-email concatenated into supplier text.
        let supplier = match (&self.author, &self.author_email) {
            (Some(n), Some(e)) if !e.is_empty() => Some(format!("{n} <{e}>")),
            (Some(n), _) => Some(n.clone()),
            (None, Some(e)) if !e.is_empty() => Some(e.clone()),
            _ => None,
        };

        // Depends: bare names from Requires-Dist (PEP 508 tokenised).
        let depends = self
            .requires_dist
            .iter()
            .filter_map(|raw| tokenise_requires_dist_name(raw))
            .collect();

        let licenses = extract_license(&self);

        Some(PackageDbEntry {
            purl,
            name: self.name,
            version: self.version,
            arch: None,
            source_path,
            depends,
            maintainer: supplier,
            licenses,
            is_dev: None, // venv dist-info doesn't carry a dev/prod marker
            requirement_range: None,
            source_type: None,
            buildinfo_status: None,
            evidence_kind: None,
            binary_class: None,
            binary_stripped: None,
            linkage_kind: None,
            detected_go: None,
            confidence: None,
            binary_packed: None,
            raw_version: None,
            parent_purl: None,
            npm_role: None,
            co_owned_by: None,
            hashes: Vec::new(),
            sbom_tier: Some("deployed".to_string()),
            shade_relocation: None,
            extra_annotations: Default::default(),
        })
    }
}

// -----------------------------------------------------------------------
// Tier 1 support: license precedence ladder (PEP 639 → legacy → classifier)
// -----------------------------------------------------------------------

/// Resolve license(s) from a `PipDistInfoEntry` per research.md R2.
/// Precedence: `License-Expression:` (PEP 639) → `License:` (legacy
/// free-form, passed through the copyright-shorthand normaliser) →
/// `Classifier: License ::` trove list. Returns at most one SPDX
/// expression from the first tier that produces a canonicalisable
/// value; empty Vec when nothing resolves.
pub(crate) fn extract_license(entry: &PipDistInfoEntry) -> Vec<SpdxExpression> {
    // Tier 1: PEP 639 — authoritative, SPDX by construction.
    if let Some(ref raw) = entry.license_expression {
        if let Ok(spdx) = SpdxExpression::try_canonical(raw.trim()) {
            return vec![spdx];
        }
    }
    // Tier 2: legacy `License:` free-form. Try canonical first.
    if let Some(ref raw) = entry.license_raw {
        let cleaned = raw.trim();
        if !cleaned.is_empty() {
            if let Ok(spdx) = SpdxExpression::try_canonical(cleaned) {
                return vec![spdx];
            }
        }
    }
    // Tier 3: classifier trove → SPDX lookup.
    for c in &entry.classifiers {
        if let Some(spdx) = classifier_to_spdx(c) {
            if let Ok(expr) = SpdxExpression::try_canonical(spdx) {
                return vec![expr];
            }
        }
    }
    Vec::new()
}

/// Map a `Classifier: License :: ...` trove string to the closest
/// canonical SPDX identifier. Table covers >95% of real-world PyPI
/// packages per research R2. Unknown classifiers return None.
pub(crate) fn classifier_to_spdx(classifier: &str) -> Option<&'static str> {
    // Classifiers look like "License :: OSI Approved :: MIT License".
    // Care about the last segment only.
    let last = classifier.rsplit("::").next()?.trim();
    Some(match last {
        "MIT License" => "MIT",
        "Apache Software License" => "Apache-2.0",
        "BSD License" => "BSD-3-Clause",
        "BSD 3-Clause" | "BSD 3-Clause License" => "BSD-3-Clause",
        "BSD 2-Clause" | "BSD 2-Clause License" => "BSD-2-Clause",
        "Mozilla Public License 2.0 (MPL 2.0)" => "MPL-2.0",
        "ISC License (ISCL)" => "ISC",
        "zlib/libpng License" => "Zlib",
        "Python Software Foundation License" => "Python-2.0",
        "GNU General Public License v2 (GPLv2)" => "GPL-2.0-only",
        "GNU General Public License v2 or later (GPLv2+)" => "GPL-2.0-or-later",
        "GNU General Public License v3 (GPLv3)" => "GPL-3.0-only",
        "GNU General Public License v3 or later (GPLv3+)" => "GPL-3.0-or-later",
        "GNU Lesser General Public License v2 (LGPLv2)" => "LGPL-2.0-only",
        "GNU Lesser General Public License v2 or later (LGPLv2+)" => "LGPL-2.0-or-later",
        "GNU Lesser General Public License v3 (LGPLv3)" => "LGPL-3.0-only",
        "GNU Lesser General Public License v3 or later (LGPLv3+)" => "LGPL-3.0-or-later",
        "GNU Affero General Public License v3" => "AGPL-3.0-only",
        "GNU Affero General Public License v3 or later (AGPLv3+)" => "AGPL-3.0-or-later",
        "Artistic License" => "Artistic-2.0",
        "The Unlicense (Unlicense)" => "Unlicense",
        _ => return None,
    })
}

/// Parse a METADATA file body. Tolerates non-UTF-8 by falling back to
/// lossy decoding (consistent with `copyright.rs` convention).
pub(crate) fn parse_metadata_bytes(bytes: &[u8]) -> PipDistInfoEntry {
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(bytes).into_owned(),
    };
    parse_metadata_text(&text)
}

/// Parse METADATA as RFC-822-style stanzas with continuation-line
/// support: a line starting with a space/tab continues the previous
/// key's value. Multiple occurrences of the same key collect into a
/// list (e.g. `Classifier:` appears many times).
pub(crate) fn parse_metadata_text(text: &str) -> PipDistInfoEntry {
    let mut out = PipDistInfoEntry::default();

    // Only the header block matters; stop at the first blank line
    // which separates headers from the payload (description / README).
    let mut current_key: Option<String> = None;
    let mut current_value = String::new();

    let flush = |key_opt: &mut Option<String>, value: &mut String, out: &mut PipDistInfoEntry| {
        if let Some(key) = key_opt.take() {
            let v = std::mem::take(value).trim().to_string();
            match key.as_str() {
                "Name" => out.name = v,
                "Version" => out.version = v,
                "License" if !v.is_empty() => out.license_raw = Some(v),
                "License-Expression" if !v.is_empty() => out.license_expression = Some(v),
                "Classifier" if !v.is_empty() => out.classifiers.push(v),
                "Requires-Dist" if !v.is_empty() => out.requires_dist.push(v),
                "Author" if !v.is_empty() => out.author = Some(v),
                "Author-email" if !v.is_empty() => out.author_email = Some(v),
                _ => {}
            }
        }
    };

    for line in text.lines() {
        if line.is_empty() {
            // End of headers; stop parsing.
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line — append to current value with a space.
            if current_key.is_some() {
                if !current_value.is_empty() {
                    current_value.push(' ');
                }
                current_value.push_str(line.trim());
            }
            continue;
        }
        // Fresh header.
        flush(&mut current_key, &mut current_value, &mut out);
        if let Some(idx) = line.find(':') {
            let (key, rest) = line.split_at(idx);
            current_key = Some(key.to_string());
            current_value = rest[1..].trim().to_string();
        }
    }
    flush(&mut current_key, &mut current_value, &mut out);
    out
}


#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
#[cfg_attr(test, allow(clippy::field_reassign_with_default))]
mod tests {
    use std::fs;

    use super::super::read;
    use super::*;
    fn make_venv_rootfs(
        packages: &[(&str, &str, &str)],
    ) -> tempfile::TempDir {
        // packages: [(name, version, metadata_body)]
        let dir = tempfile::tempdir().expect("tempdir");
        let sp = dir.path().join(".venv/lib/python3.12/site-packages");
        fs::create_dir_all(&sp).unwrap();
        for (name, version, body) in packages {
            let subdir = sp.join(format!("{name}-{version}.dist-info"));
            fs::create_dir_all(&subdir).unwrap();
            fs::write(subdir.join("METADATA"), body).unwrap();
        }
        dir
    }

    #[test]
    fn parse_metadata_single_package_basics() {
        let body = "\
Metadata-Version: 2.1
Name: requests
Version: 2.31.0
Summary: Python HTTP for Humans.
Home-page: https://requests.readthedocs.io
Author: Kenneth Reitz
Author-email: me@kennethreitz.org
License: Apache 2.0
Requires-Dist: charset-normalizer<4,>=2
Requires-Dist: idna<4,>=2.5
Requires-Dist: urllib3<3,>=1.21.1
Requires-Dist: certifi>=2017.4.17
Classifier: License :: OSI Approved :: Apache Software License
Classifier: Programming Language :: Python :: 3
";
        let e = parse_metadata_text(body);
        assert_eq!(e.name, "requests");
        assert_eq!(e.version, "2.31.0");
        assert_eq!(e.author.as_deref(), Some("Kenneth Reitz"));
        assert_eq!(e.author_email.as_deref(), Some("me@kennethreitz.org"));
        assert_eq!(e.license_raw.as_deref(), Some("Apache 2.0"));
        assert_eq!(e.requires_dist.len(), 4);
        assert_eq!(e.classifiers.len(), 2);
    }

    #[test]
    fn parse_metadata_with_continuation_lines() {
        let body = "\
Name: multiline-pkg
Version: 0.1.0
License: Some custom license
 that spans multiple lines
 with indentation.
";
        let e = parse_metadata_text(body);
        assert_eq!(e.name, "multiline-pkg");
        let raw = e.license_raw.expect("license present");
        assert!(raw.contains("Some custom license"));
        assert!(raw.contains("multiple lines"));
    }

    #[test]
    fn parse_metadata_pep_639_license_expression_wins() {
        let body = "\
Name: modern-pkg
Version: 2.0.0
License-Expression: Apache-2.0 OR MIT
License: legacy-free-form
";
        let e = parse_metadata_text(body);
        assert_eq!(e.license_expression.as_deref(), Some("Apache-2.0 OR MIT"));
        assert_eq!(e.license_raw.as_deref(), Some("legacy-free-form"));
    }

    #[test]
    fn parse_metadata_stops_at_first_blank_line() {
        let body = "\
Name: pkg
Version: 1.0

This is the description; it should NOT be parsed as a header.
License: Ignored
";
        let e = parse_metadata_text(body);
        assert_eq!(e.name, "pkg");
        assert!(e.license_raw.is_none());
    }

    #[test]
    fn parse_metadata_non_utf8_author_falls_back_losslessly() {
        // Mixed UTF-8 + an invalid byte in the author field.
        let mut body = b"Name: q\nVersion: 1.0\nAuthor: Jose \xE9 Surname\nLicense: MIT\n".to_vec();
        let _ = &mut body; // keep mutable reference simple
        let e = parse_metadata_bytes(&body);
        assert_eq!(e.name, "q");
        assert_eq!(e.license_raw.as_deref(), Some("MIT"));
        // Author present (lossy-decoded); we don't care about the exact bytes.
        assert!(e.author.is_some());
    }

    #[test]
    fn venv_walk_finds_packages_in_standard_location() {
        let dir = make_venv_rootfs(&[
            ("requests", "2.31.0", "Name: requests\nVersion: 2.31.0\nLicense: Apache 2.0\n"),
            ("urllib3", "2.0.7", "Name: urllib3\nVersion: 2.0.7\nLicense: MIT\n"),
        ]);
        let out = read(dir.path(), false);
        assert_eq!(out.len(), 2);
        // Deterministic alphabetical order by dist-info dir name.
        assert_eq!(out[0].name, "requests");
        assert_eq!(out[1].name, "urllib3");
        assert!(out
            .iter()
            .all(|e| e.sbom_tier.as_deref() == Some("deployed")));
    }

    #[test]
    fn pyproject_only_project_skips_with_log() {
        // Bare pyproject.toml; no venv, no lockfile, no requirements.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"myapp\"\nversion = \"0.1.0\"\ndependencies = [\"requests\"]\n",
        )
        .unwrap();
        let out = read(dir.path(), false);
        assert!(out.is_empty(), "pyproject-only project emits zero components");
    }

    #[test]
    fn dist_info_with_mixed_case_name_emits_lowercase_purl() {
        // Real-world dist-info carries the declared name (may be mixed
        // case). The PURL must canonicalise but `component.name` (via
        // the entry's `name` field) preserves the declared form.
        let dir = make_venv_rootfs(&[(
            "Flask",
            "3.0.0",
            "Name: Flask\nVersion: 3.0.0\nLicense: BSD-3-Clause\n",
        )]);
        let out = read(dir.path(), false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "Flask", "component.name keeps declared form");
        assert_eq!(
            out[0].purl.as_str(),
            "pkg:pypi/flask@3.0.0",
            "PURL must be lowercase per packageurl-python reference impl"
        );
    }

    #[test]
    fn license_pep_639_expression_wins() {
        let mut e = PipDistInfoEntry::default();
        e.license_expression = Some("Apache-2.0 OR MIT".into());
        e.license_raw = Some("Apache 2.0".into());
        e.classifiers.push("License :: OSI Approved :: MIT License".into());
        let out = extract_license(&e);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].as_str(), "Apache-2.0 OR MIT");
    }

    #[test]
    fn license_legacy_raw_tried_when_pep_639_absent() {
        let mut e = PipDistInfoEntry::default();
        e.license_raw = Some("MIT".into());
        let out = extract_license(&e);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].as_str(), "MIT");
    }

    #[test]
    fn license_classifier_fallback_maps_to_spdx() {
        let mut e = PipDistInfoEntry::default();
        e.classifiers.push("License :: OSI Approved :: Apache Software License".into());
        let out = extract_license(&e);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].as_str(), "Apache-2.0");
    }

    #[test]
    fn license_all_tiers_empty_returns_empty() {
        let e = PipDistInfoEntry::default();
        assert!(extract_license(&e).is_empty());
    }

    #[test]
    fn classifier_lookup_covers_common_licenses() {
        assert_eq!(
            classifier_to_spdx("License :: OSI Approved :: MIT License"),
            Some("MIT")
        );
        assert_eq!(
            classifier_to_spdx("License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)"),
            Some("GPL-3.0-or-later")
        );
        assert_eq!(
            classifier_to_spdx("License :: OSI Approved :: BSD License"),
            Some("BSD-3-Clause")
        );
    }

    #[test]
    fn classifier_lookup_returns_none_for_unknown() {
        assert_eq!(classifier_to_spdx("License :: Other/Proprietary License"), None);
        assert_eq!(classifier_to_spdx("Topic :: Software Development"), None);
    }

    #[test]
    fn requires_dist_tokenisation_drives_depends() {
        let body = "\
Name: requests
Version: 2.31.0
Requires-Dist: urllib3 < 3, >= 1.21.1
Requires-Dist: certifi >= 2017.4.17
Requires-Dist: charset-normalizer < 4, >= 2
Requires-Dist: pytest ; extra == 'dev'
";
        let dir = make_venv_rootfs(&[("requests", "2.31.0", body)]);
        let out = read(dir.path(), false);
        assert_eq!(out.len(), 1);
        let e = &out[0];
        // extra-marker dep dropped, rest emitted.
        assert!(e.depends.contains(&"urllib3".to_string()));
        assert!(e.depends.contains(&"certifi".to_string()));
        assert!(e.depends.contains(&"charset-normalizer".to_string()));
        assert!(!e.depends.contains(&"pytest".to_string()));
    }
}
