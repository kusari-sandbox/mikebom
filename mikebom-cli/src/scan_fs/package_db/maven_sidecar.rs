//! Fedora/RHEL sidecar POM reader.
//!
//! Fedora's `javapackages-tools` / `xmvn` RPM-build pipeline strips
//! `META-INF/maven/` from JARs and writes the effective POM to
//! `/usr/share/maven-poms/`. This module lets the Maven reader recover
//! the Maven coordinates for those JARs by consulting the sidecar POM
//! directory when the in-JAR metadata is absent.
//!
//! Scope (per feature 007 spec, clarification 1): Fedora/RHEL layout
//! only. Debian's `/usr/share/maven-repo/` GAV layout and Alpine
//! equivalents are deferred to a follow-up feature.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::maven::parse_pom_xml;

/// Per-scan in-memory index of a rootfs's `/usr/share/maven-poms/`
/// directory. Keyed by the canonical basename (JPP- prefix stripped,
/// `.pom` suffix stripped, ASCII-lowercased).
#[derive(Debug, Default)]
pub(crate) struct FedoraSidecarIndex {
    by_basename: HashMap<String, PathBuf>,
}

impl FedoraSidecarIndex {
    /// Walk `<rootfs>/usr/share/maven-poms/` once and build the
    /// basename → absolute-path index. When a basename is available
    /// under both `JPP-<name>.pom` and plain `<name>.pom`, the
    /// non-prefixed form wins (newer Fedora convention).
    pub(crate) fn build(rootfs: &Path) -> Self {
        let dir = rootfs.join("usr/share/maven-poms");
        let mut by_basename: HashMap<String, PathBuf> = HashMap::new();
        // Two-pass walk: first record `JPP-*.pom`, then let plain
        // `<name>.pom` overwrite on basename collision.
        let read = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => return Self { by_basename },
        };
        let mut plain: Vec<PathBuf> = Vec::new();
        for entry in read.flatten() {
            let path = entry.path();
            let Some(fname) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if !fname.ends_with(".pom") {
                continue;
            }
            let stem = &fname[..fname.len() - 4];
            if let Some(rest) = stem.strip_prefix("JPP-") {
                by_basename.insert(rest.to_ascii_lowercase(), path);
            } else {
                plain.push(path);
            }
        }
        for path in plain {
            let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let stem = &fname[..fname.len().saturating_sub(4)];
            by_basename.insert(stem.to_ascii_lowercase(), path);
        }
        Self { by_basename }
    }

    /// Look up a JAR by filename basename. Strips any trailing
    /// `-<version>` segment from the JAR filename before matching —
    /// Fedora sidecar POMs are version-agnostic because each RPM
    /// installs exactly one version. `guice-5.1.0.jar` → key `"guice"`.
    pub(crate) fn lookup_for_jar(&self, jar_path: &Path) -> Option<&Path> {
        let fname = jar_path.file_name().and_then(|s| s.to_str())?;
        if !fname.ends_with(".jar") {
            return None;
        }
        let stem = &fname[..fname.len() - 4];
        let basename = strip_trailing_version(stem).to_ascii_lowercase();
        self.by_basename.get(basename.as_str()).map(|p| p.as_path())
    }

    /// `true` when the index contains zero entries — used by callers
    /// to skip sidecar resolution entirely when the rootfs isn't
    /// Fedora-shaped.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.by_basename.is_empty()
    }

    /// Number of indexed sidecar POMs. Used for scan-summary logging.
    pub(crate) fn len(&self) -> usize {
        self.by_basename.len()
    }

    /// Look up a parent POM by its artifactId only — Fedora's flat
    /// layout keys sidecars by artifact, not by full GAV. Called
    /// during one-level parent inheritance resolution.
    pub(crate) fn lookup_by_artifact_id(&self, artifact_id: &str) -> Option<&Path> {
        self.by_basename
            .get(artifact_id.to_ascii_lowercase().as_str())
            .map(|p| p.as_path())
    }
}

/// Strip a trailing `-<digits-and-dots-and-letters>` version component
/// from a JAR basename. The split point is the last `-` followed by a
/// digit. Non-versioned names (e.g. `aopalliance` with no trailing
/// version) fall through unchanged.
fn strip_trailing_version(stem: &str) -> &str {
    let bytes = stem.as_bytes();
    for i in (0..bytes.len()).rev() {
        if bytes[i] == b'-' {
            if let Some(next) = bytes.get(i + 1) {
                if next.is_ascii_digit() {
                    return &stem[..i];
                }
            }
        }
    }
    stem
}

/// Resolved coordinates from a sidecar POM, with one-level parent
/// inheritance applied when the parent POM is present in the same
/// index. Returns `None` when a complete `(groupId, artifactId,
/// version)` triple cannot be assembled.
pub(crate) fn resolve_coords(
    sidecar_path: &Path,
    index: &FedoraSidecarIndex,
) -> Option<(String, String, String)> {
    let bytes = std::fs::read(sidecar_path).ok()?;
    let doc = parse_pom_xml(&bytes);
    // Seed from self_coord when fully present, otherwise split into
    // separate channels (self_artifact_id is always set when an
    // <artifactId> appears on the project element, even if groupId /
    // version are absent and inherited from <parent>).
    let (mut g, a, mut v): (Option<String>, Option<String>, Option<String>) =
        match doc.self_coord.clone() {
            Some((g, a, v)) => (Some(g), Some(a), Some(v)),
            None => (None, doc.self_artifact_id.clone(), None),
        };
    // Fedora child POMs typically omit `<groupId>` and `<version>`,
    // inheriting both from `<parent>`. Apply one level of inheritance.
    if let Some((pg, _pa, pv)) = &doc.parent_coord {
        if g.as_deref().unwrap_or("").is_empty() {
            g = Some(pg.clone());
        }
        if v.as_deref().unwrap_or("").is_empty() {
            v = Some(pv.clone());
        }
    }
    // When we still don't have groupId or version and the parent POM
    // is on disk in the same index, consult it for its own self-coord
    // as a secondary inheritance source.
    if g.as_deref().unwrap_or("").is_empty() || v.as_deref().unwrap_or("").is_empty() {
        if let Some((_pg, pa, _pv)) = &doc.parent_coord {
            if let Some(parent_path) = index.lookup_by_artifact_id(pa) {
                if let Ok(parent_bytes) = std::fs::read(parent_path) {
                    let parent_doc = parse_pom_xml(&parent_bytes);
                    if let Some((pg2, _pa2, pv2)) = &parent_doc.self_coord {
                        if g.as_deref().unwrap_or("").is_empty() {
                            g = Some(pg2.clone());
                        }
                        if v.as_deref().unwrap_or("").is_empty() {
                            v = Some(pv2.clone());
                        }
                    }
                }
            }
        }
    }
    match (g, a, v) {
        (Some(g), Some(a), Some(v))
            if !g.is_empty() && !a.is_empty() && !v.is_empty() =>
        {
            Some((g, a, v))
        }
        _ => None,
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn pom_text(group: &str, artifact: &str, version: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
               <modelVersion>4.0.0</modelVersion>\n\
               <groupId>{group}</groupId>\n\
               <artifactId>{artifact}</artifactId>\n\
               <version>{version}</version>\n\
             </project>\n"
        )
    }

    #[test]
    fn strips_trailing_version_basic() {
        assert_eq!(strip_trailing_version("guice-5.1.0"), "guice");
        assert_eq!(strip_trailing_version("aopalliance-1.0"), "aopalliance");
        assert_eq!(
            strip_trailing_version("commons-compress-1.21"),
            "commons-compress"
        );
    }

    #[test]
    fn strips_trailing_version_leaves_non_versioned_alone() {
        assert_eq!(strip_trailing_version("aopalliance"), "aopalliance");
        assert_eq!(strip_trailing_version("foo-bar"), "foo-bar");
    }

    #[test]
    fn index_empty_when_dir_missing() {
        let tmp = tempdir().unwrap();
        let idx = FedoraSidecarIndex::build(tmp.path());
        assert!(idx.is_empty());
    }

    #[test]
    fn index_picks_up_jpp_prefixed_and_plain() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("usr/share/maven-poms");
        write(&dir.join("JPP-guice.pom"), &pom_text("g", "guice", "1"));
        write(&dir.join("aopalliance.pom"), &pom_text("g", "a", "1"));
        let idx = FedoraSidecarIndex::build(tmp.path());
        assert!(idx.lookup_by_artifact_id("guice").is_some());
        assert!(idx.lookup_by_artifact_id("aopalliance").is_some());
    }

    #[test]
    fn plain_name_wins_on_basename_collision() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("usr/share/maven-poms");
        write(&dir.join("JPP-dup.pom"), &pom_text("g1", "dup", "1"));
        write(&dir.join("dup.pom"), &pom_text("g2", "dup", "2"));
        let idx = FedoraSidecarIndex::build(tmp.path());
        let hit = idx.lookup_by_artifact_id("dup").unwrap();
        // The non-JPP file wins — confirm by filename.
        assert_eq!(
            hit.file_name().and_then(|s| s.to_str()).unwrap(),
            "dup.pom"
        );
    }

    #[test]
    fn lookup_for_jar_strips_version_suffix() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("usr/share/maven-poms");
        write(&dir.join("JPP-guice.pom"), &pom_text("com.google.inject", "guice", "5.1.0"));
        let idx = FedoraSidecarIndex::build(tmp.path());
        let jar = tmp
            .path()
            .join("usr/share/maven/lib/guice-5.1.0.jar");
        assert!(idx.lookup_for_jar(&jar).is_some());
    }

    #[test]
    fn lookup_for_jar_miss_returns_none() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("usr/share/maven-poms");
        write(&dir.join("JPP-guice.pom"), &pom_text("g", "guice", "5.1.0"));
        let idx = FedoraSidecarIndex::build(tmp.path());
        let jar = tmp
            .path()
            .join("usr/share/maven/lib/logback-1.2.jar");
        assert!(idx.lookup_for_jar(&jar).is_none());
    }

    #[test]
    fn resolve_coords_direct_self_coord() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("usr/share/maven-poms");
        let pom_path = dir.join("JPP-guice.pom");
        write(
            &pom_path,
            &pom_text("com.google.inject", "guice", "5.1.0"),
        );
        let idx = FedoraSidecarIndex::build(tmp.path());
        let coords = resolve_coords(&pom_path, &idx).unwrap();
        assert_eq!(
            coords,
            (
                "com.google.inject".to_string(),
                "guice".to_string(),
                "5.1.0".to_string()
            )
        );
    }

    #[test]
    fn resolve_coords_inherits_groupid_from_parent() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("usr/share/maven-poms");
        let parent_path = dir.join("guice-parent.pom");
        let child_path = dir.join("guice-child.pom");
        write(
            &parent_path,
            &pom_text("com.google.inject", "guice-parent", "5.1.0"),
        );
        write(
            &child_path,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
               <modelVersion>4.0.0</modelVersion>\n\
               <parent>\n\
                 <groupId>com.google.inject</groupId>\n\
                 <artifactId>guice-parent</artifactId>\n\
                 <version>5.1.0</version>\n\
               </parent>\n\
               <artifactId>guice-child</artifactId>\n\
             </project>\n",
        );
        let idx = FedoraSidecarIndex::build(tmp.path());
        let coords = resolve_coords(&child_path, &idx).unwrap();
        assert_eq!(
            coords,
            (
                "com.google.inject".to_string(),
                "guice-child".to_string(),
                "5.1.0".to_string()
            )
        );
    }

    #[test]
    fn resolve_coords_returns_none_on_incomplete_child_without_parent() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("usr/share/maven-poms");
        let child_path = dir.join("orphan.pom");
        write(
            &child_path,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
               <modelVersion>4.0.0</modelVersion>\n\
               <artifactId>orphan</artifactId>\n\
             </project>\n",
        );
        let idx = FedoraSidecarIndex::build(tmp.path());
        assert!(resolve_coords(&child_path, &idx).is_none());
    }
}
