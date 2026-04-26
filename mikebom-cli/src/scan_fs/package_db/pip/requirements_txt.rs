//! Tier 4: requirements*.txt parser (legacy / heterogeneous).
//!
//! Reads any `requirements*.txt` at the project root. Lower-tier source
//! than venv / lockfile because range specs may resolve to different
//! versions at install time; entries get `sbom_tier = "design"` when
//! the version is unpinned.

use std::path::{Path, PathBuf};
use mikebom_common::types::purl::Purl;

use mikebom_common::types::hash::{ContentHash, HashAlgorithm};

use super::super::PackageDbEntry;
use super::{build_pypi_purl_str, tokenise_requires_dist_name};

pub(super) fn read_requirements_files(rootfs: &Path) -> Option<Vec<PackageDbEntry>> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(rootfs) else {
        return None;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|n| n.starts_with("requirements") && n.ends_with(".txt"))
        })
        .collect();
    paths.sort();
    for path in paths {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let source_path = path.to_string_lossy().into_owned();
        let parsed = parse_requirements_file_text(&text);
        for entry in parsed {
            if let Some(pdb) = entry.into_package_db_entry(&source_path) {
                out.push(pdb);
            }
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// One line from a `requirements.txt`-style file, normalised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequirementsTxtEntry {
    pub name: String,
    /// Only populated for exactly-pinned (`==`) requirements. For
    /// ranges / unpinned / URL refs, left empty.
    pub version: String,
    /// Original raw line (including operators, extras, hash flags).
    /// Emitted as `mikebom:requirement-range` on the component.
    pub range_spec: String,
    /// Non-registry source kind: `"url"` for `https://...`, `"local"`
    /// for `file:...`, `"git"` for `git+...`. None for registry-named
    /// requirements.
    pub source_type: Option<String>,
    /// Per-component content hashes from `--hash=alg:hex` flags. pip
    /// allows multiple `--hash=` flags per requirement (one per
    /// distribution file — sdist + per-platform wheels) and CDX
    /// `components[].hashes[]` is array-shaped, so all are emitted.
    pub hashes: Vec<ContentHash>,
}

impl RequirementsTxtEntry {
    fn into_package_db_entry(self, source_path: &str) -> Option<PackageDbEntry> {
        if self.name.is_empty() {
            return None;
        }
        // PURL for empty version: `pkg:pypi/<name>` (no @). packageurl
        // crate accepts this.
        let purl_str = build_pypi_purl_str(&self.name, &self.version);
        let purl = Purl::new(&purl_str).ok()?;
        // Tier: `source` when the requirement is exactly pinned
        // (`==` gives us a concrete version); `design` for ranges /
        // unpinned / URL refs where we kept the raw range string
        // but have no resolved version. A project that exclusively
        // pins its deps is authoritative for the pypi ecosystem —
        // `complete_ecosystems` keys off this.
        let tier = if self.version.is_empty() {
            "design"
        } else {
            "source"
        };
        Some(PackageDbEntry {
            purl,
            name: self.name,
            version: self.version,
            arch: None,
            source_path: source_path.to_string(),
            depends: Vec::new(),
            maintainer: None,
            licenses: Vec::new(),
            is_dev: None,
            requirement_range: Some(self.range_spec),
            source_type: self.source_type,
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
            hashes: self.hashes,
            sbom_tier: Some(tier.to_string()),
            shade_relocation: None,
            extra_annotations: Default::default(),
        })
    }
}

/// Parse raw `requirements.txt` text. Tolerates:
/// - `# comments` (full-line or trailing).
/// - Blank lines.
/// - `-r <other.txt>` includes (ignored this milestone; follow-up to recurse).
/// - `--hash=sha256:...` flags on their own line or trailing.
/// - URL refs (`https://...`, `git+...`, `file:...`).
/// - Pinned (`==`) and ranged (`>=`, `<`, `~=`, `!=`) requirements.
pub(crate) fn parse_requirements_file_text(text: &str) -> Vec<RequirementsTxtEntry> {
    let mut out = Vec::new();
    // Deal with line continuations: a trailing backslash joins to the
    // next line. Common in pinned-with-hash blocks.
    let joined = text.replace("\\\n", " ");
    for raw in joined.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        // Strip full-line comments.
        if line.starts_with('#') {
            continue;
        }
        // Strip trailing comments (but only when clearly after a space).
        let line = match line.split_once(" #") {
            Some((before, _)) => before.trim(),
            None => line,
        };
        // Skip `-r`, `-c`, `--index-url`, etc. lines — meta-commands.
        if line.starts_with('-') {
            continue;
        }

        if let Some(entry) = parse_requirements_line(line) {
            out.push(entry);
        }
    }
    out
}

/// Parse a single non-blank, non-comment, non-meta requirements line.
fn parse_requirements_line(line: &str) -> Option<RequirementsTxtEntry> {
    // Split off `--hash=alg:hex` flags. pip allows MULTIPLE per
    // requirement (one for sdist + one per platform wheel) so collect
    // all of them. Each flag has form `--hash=<alg>:<hex>`.
    let body = line.split("--hash").next().unwrap_or(line).trim();
    let hashes = parse_hash_flags(line);

    // URL-style sources.
    if body.starts_with("git+") {
        // e.g. `git+https://github.com/foo/bar.git@rev#egg=bar`
        let name = egg_fragment(body).unwrap_or_else(|| "unknown".to_string());
        return Some(RequirementsTxtEntry {
            name,
            version: String::new(),
            range_spec: body.to_string(),
            source_type: Some("git".to_string()),
            hashes,
        });
    }
    if body.starts_with("http://") || body.starts_with("https://") {
        let name = egg_fragment(body).unwrap_or_else(|| "unknown".to_string());
        return Some(RequirementsTxtEntry {
            name,
            version: String::new(),
            range_spec: body.to_string(),
            source_type: Some("url".to_string()),
            hashes,
        });
    }
    if body.starts_with("file:") || body.starts_with('.') || body.starts_with('/') {
        let name = egg_fragment(body).unwrap_or_else(|| "unknown".to_string());
        return Some(RequirementsTxtEntry {
            name,
            version: String::new(),
            range_spec: body.to_string(),
            source_type: Some("local".to_string()),
            hashes,
        });
    }

    // Registry-style: `name[extras] OP version, OP version; marker`.
    // Reuse the PEP 508 tokeniser for the name; detect `==` for pinning.
    let name = tokenise_requires_dist_name(body)?;

    // Look for a single `==` pin to populate `version`.
    let version = pinned_version_from(body).unwrap_or_default();

    Some(RequirementsTxtEntry {
        name,
        version,
        range_spec: body.to_string(),
        source_type: None,
        hashes,
    })
}

/// Extract every `--hash=<alg>:<hex>` flag from a requirements line.
/// Tolerates both `--hash=sha256:abc` and `--hash sha256:abc` shapes
/// (pip accepts the latter via getopt-style spacing). Unknown
/// algorithms are silently dropped (not just sha256/512/1 — md5
/// also gets through ContentHash::with_algorithm but pip docs only
/// list sha256/384/512).
fn parse_hash_flags(line: &str) -> Vec<ContentHash> {
    let mut out = Vec::new();
    // Iterate on `--hash` substring; each occurrence is followed by
    // either `=` or ` ` then `<alg>:<hex>`.
    let mut rest = line;
    while let Some(idx) = rest.find("--hash") {
        let after = &rest[idx + "--hash".len()..];
        // Skip the separator (`=` or whitespace).
        let after = after.trim_start_matches(|c: char| c == '=' || c.is_whitespace());
        // Take up to the next whitespace or end.
        let token_end = after
            .find(|c: char| c.is_whitespace())
            .unwrap_or(after.len());
        let token = &after[..token_end];
        if let Some((alg_str, hex)) = token.split_once(':') {
            if let Some(alg) = parse_hash_alg(alg_str) {
                if let Ok(hash) = ContentHash::with_algorithm(alg, hex) {
                    if !out.contains(&hash) {
                        out.push(hash);
                    }
                }
            }
        }
        rest = &after[token_end..];
    }
    out
}

fn parse_hash_alg(s: &str) -> Option<HashAlgorithm> {
    match s.to_ascii_lowercase().as_str() {
        "sha256" => Some(HashAlgorithm::Sha256),
        "sha512" => Some(HashAlgorithm::Sha512),
        "sha1" => Some(HashAlgorithm::Sha1),
        // sha384 not in HashAlgorithm yet; pip uses sha256/384/512.
        // md5 is supported by ContentHash but pip rejects md5 hashes.
        _ => None,
    }
}

/// Extract `egg=<name>` from a URL-style requirement, if present.
fn egg_fragment(url: &str) -> Option<String> {
    let frag = url.split_once('#')?.1;
    for part in frag.split('&') {
        if let Some(value) = part.strip_prefix("egg=") {
            let clean = value.split('[').next().unwrap_or(value);
            if !clean.is_empty() {
                return Some(clean.to_string());
            }
        }
    }
    None
}

/// If the requirement has a single `==` pin (and no disjunction like
/// `==1.0 || ==2.0`, which pip doesn't support anyway), return that
/// version string. Returns None for ranges.
fn pinned_version_from(body: &str) -> Option<String> {
    // Drop any env marker first.
    let head = body.split_once(';').map(|x| x.0).unwrap_or(body);
    // Look for `==` as an exact operator. Ignore `!=` and `~=`.
    for part in head.split(',') {
        let p = part.trim();
        if let Some(rest) = p.strip_prefix("==") {
            return Some(rest.trim().to_string());
        }
        // `name == 1.0` form: find `==` after some whitespace.
        if let Some(idx) = p.find("==") {
            // Ensure it's an `==` operator, not a substring of `===` etc.
            let before = &p[..idx];
            let after = &p[idx + 2..];
            if !before.ends_with('=') && !after.starts_with('=') {
                return Some(after.trim().trim_start_matches(' ').to_string());
            }
        }
    }
    None
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    #[test]
    fn requirements_txt_pinned_populates_version_and_range() {
        let entries = parse_requirements_file_text("requests==2.31.0\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "requests");
        assert_eq!(entries[0].version, "2.31.0");
        assert_eq!(entries[0].range_spec, "requests==2.31.0");
        assert!(entries[0].source_type.is_none());
    }

    #[test]
    fn requirements_txt_ranged_leaves_version_empty() {
        let entries = parse_requirements_file_text("requests>=2,<3\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "requests");
        assert!(entries[0].version.is_empty());
        assert_eq!(entries[0].range_spec, "requests>=2,<3");
    }

    #[test]
    fn requirements_txt_bare_name_empty_version() {
        let entries = parse_requirements_file_text("requests\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "requests");
        assert!(entries[0].version.is_empty());
    }

    #[test]
    fn requirements_txt_strips_comments_and_blank_lines() {
        let text = "\
# top comment
requests==2.31.0  # trailing comment
# another

urllib3>=2  # with space before hash
";
        let entries = parse_requirements_file_text(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "requests");
        assert_eq!(entries[1].name, "urllib3");
    }

    #[test]
    fn requirements_txt_skips_meta_commands() {
        let text = "\
-r other.txt
--index-url https://pypi.org/simple/
requests==2.31.0
";
        let entries = parse_requirements_file_text(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "requests");
    }

    #[test]
    fn requirements_txt_strips_hash_flags() {
        let text = "\
requests==2.31.0 --hash=sha256:abc123 --hash=sha256:def456
urllib3>=2 \\
    --hash=sha256:zzz
";
        let entries = parse_requirements_file_text(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "requests");
        assert_eq!(entries[1].name, "urllib3");
    }

    #[test]
    fn parse_hash_flags_captures_single_sha256() {
        let line = "requests==2.31.0 --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f";
        let hashes = parse_hash_flags(line);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].algorithm, HashAlgorithm::Sha256);
        assert_eq!(
            hashes[0].value.as_str(),
            "58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f"
        );
    }

    #[test]
    fn parse_hash_flags_captures_multiple() {
        // pip allows multiple --hash= flags (sdist + per-platform wheel).
        let sha256 = "a".repeat(64);
        let sha512 = "b".repeat(128);
        let line = format!(
            "requests==2.31.0 --hash=sha256:{sha256} --hash=sha512:{sha512}"
        );
        let hashes = parse_hash_flags(&line);
        assert_eq!(hashes.len(), 2);
        // Order preserved (first --hash flag → first slot).
        assert_eq!(hashes[0].algorithm, HashAlgorithm::Sha256);
        assert_eq!(hashes[1].algorithm, HashAlgorithm::Sha512);
    }

    #[test]
    fn parse_hash_flags_dedups_identical_entries() {
        // Pathological: same hash specified twice. Only emit once.
        let line = "x==1 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let hashes = parse_hash_flags(line);
        assert_eq!(hashes.len(), 1);
    }

    #[test]
    fn parse_hash_flags_drops_unknown_algorithm() {
        let line = "x==1 --hash=md4:dead --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let hashes = parse_hash_flags(line);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn parse_hash_flags_returns_empty_when_absent() {
        let line = "requests==2.31.0";
        assert!(parse_hash_flags(line).is_empty());
    }

    #[test]
    fn parse_hash_flags_handles_space_separator() {
        // pip also accepts `--hash sha256:abc` (getopt-style).
        let line = "x==1 --hash sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let hashes = parse_hash_flags(line);
        assert_eq!(hashes.len(), 1);
    }

    #[test]
    fn requirements_txt_threads_hashes_through_to_entry() {
        let text = "requests==2.31.0 --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f\n";
        let entries = parse_requirements_file_text(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hashes.len(), 1);
        let pdb = entries[0]
            .clone()
            .into_package_db_entry("/req.txt")
            .expect("converts");
        assert_eq!(pdb.hashes.len(), 1);
        assert_eq!(pdb.hashes[0].algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn requirements_txt_git_url_source_type() {
        let text = "git+https://github.com/psf/requests.git@main#egg=requests\n";
        let entries = parse_requirements_file_text(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "requests");
        assert_eq!(entries[0].source_type.as_deref(), Some("git"));
        assert!(entries[0].version.is_empty());
    }

    #[test]
    fn requirements_txt_https_url_source_type() {
        let text = "https://example.com/pkg/foo-1.0.tar.gz#egg=foo\n";
        let entries = parse_requirements_file_text(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "foo");
        assert_eq!(entries[0].source_type.as_deref(), Some("url"));
    }

    #[test]
    fn requirements_txt_file_ref_source_type() {
        let text = "file:./local/pkg#egg=local-pkg\n";
        let entries = parse_requirements_file_text(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "local-pkg");
        assert_eq!(entries[0].source_type.as_deref(), Some("local"));
    }

    #[test]
    fn requirements_txt_pinned_produces_source_tier() {
        // Exact pin (`==`) means the requirement IS authoritative for
        // the version — same semantics as a cargo.lock line.
        // `complete_ecosystems` keys off source/deployed tier, so
        // pinned requirements.txt entries mark the pypi ecosystem
        // complete and drive sbomqs `sbom_completeness_declared`.
        let entry = RequirementsTxtEntry {
            name: "requests".into(),
            version: "2.31.0".into(),
            range_spec: "requests==2.31.0".into(),
            source_type: None,
            hashes: Vec::new(),
        };
        let pdb = entry.into_package_db_entry("/req.txt").expect("converts");
        assert_eq!(pdb.sbom_tier.as_deref(), Some("source"));
        assert_eq!(pdb.requirement_range.as_deref(), Some("requests==2.31.0"));
    }

    #[test]
    fn requirements_txt_unpinned_stays_design_tier() {
        // Range / unpinned requirements have no resolved version —
        // tier stays `design`, same as a package.json dependency
        // block without a lockfile.
        let entry = RequirementsTxtEntry {
            name: "requests".into(),
            version: "".into(),
            range_spec: "requests>=2.0".into(),
            source_type: None,
            hashes: Vec::new(),
        };
        let pdb = entry.into_package_db_entry("/req.txt").expect("converts");
        assert_eq!(pdb.sbom_tier.as_deref(), Some("design"));
    }

    #[test]
    fn requirements_txt_empty_version_purl_well_formed() {
        let entry = RequirementsTxtEntry {
            name: "requests".into(),
            version: String::new(),
            range_spec: "requests>=2".into(),
            source_type: None,
            hashes: Vec::new(),
        };
        let pdb = entry.into_package_db_entry("/req.txt").expect("converts");
        // packageurl-rs accepts `pkg:pypi/<name>` without @version.
        assert!(pdb.purl.as_str().starts_with("pkg:pypi/requests"));
    }
}
