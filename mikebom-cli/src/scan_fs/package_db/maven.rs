//! Read Maven/Java package metadata from `pom.xml` files and JAR archives.
//!
//! Two source kinds (R4):
//!
//! - **pom.xml** → `sbom_tier = "source"`. Build-authoritative: these
//!   are the coordinates the build WILL resolve when Maven runs.
//!   `<dependencies>` edges feed the relationship graph. Unresolved
//!   `${property}` placeholders demote the entry to `sbom_tier =
//!   "design"` and populate `requirement_range`.
//! - **JAR/WAR/EAR archives** → `sbom_tier = "analyzed"`. We crack the
//!   archive open, read every `META-INF/maven/<group>/<artifact>/pom.properties`
//!   entry (shaded / fat-jar vendored coordinates), and emit one
//!   component per entry. `MANIFEST.MF` fills in the main artifact
//!   when pom.properties is absent.
//!
//! Transitive dep-graph enrichment: Maven's local repo at
//! `~/.m2/repository/<group-as-path>/<artifact>/<version>/<artifact>-<version>.pom`
//! has each transitive dep's own pom.xml. When the repo is present,
//! the reader fetches each dep's upstream pom and extracts its
//! `<dependencies>` block to populate outbound edges — same shape as
//! the Go module-cache walker. Cache-absent scans still emit the
//! root → direct-dep edges; transitive nodes stay flat.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use mikebom_common::types::purl::{encode_purl_segment, Purl};

use super::PackageDbEntry;

const MAX_PROJECT_ROOT_DEPTH: usize = 6;
/// Per-entry size cap inside JARs; 64 MB is well beyond real pom.properties.
const MAX_JAR_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Maven repo cache lookup — for transitive dep-graph reconstruction
// ---------------------------------------------------------------------------

/// Candidate local-repo roots for a given scan. Populated once per
/// scan. Layout: `<root>/<group-as-path>/<artifact>/<version>/<artifact>-<version>.pom`.
///
/// Roots are split by scope: `rootfs_roots` sit under the scanned
/// rootfs and are safe to walk unconditionally (they belong to the
/// scan target); `host_roots` come from the invoker's environment
/// (`$HOME`, `$M2_REPO`, `$MAVEN_HOME`) and are used for per-coord
/// BFS lookups but never enumerated wholesale — otherwise a developer
/// running mikebom against a project fixture would drag every cached
/// artifact on their laptop into the SBOM.
/// Maven coord identified as the scan subject — either by
/// artifactId match against `target_name` (Fix B) or by the fat-jar
/// heuristic (M3). Surfaced through the Maven reader's return value
/// up to `scan_cmd::execute`, where it overrides the generic
/// `pkg:generic/<target_name>@0.0.0` `metadata.component` with the
/// real Maven coord.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanTargetCoord {
    pub group: String,
    pub artifact: String,
    pub version: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MavenRepoCache {
    rootfs_roots: Vec<PathBuf>,
    host_roots: Vec<PathBuf>,
}

/// Provenance of fetched POM bytes.
///
/// `Rootfs` — the `.pom` came from the scanned rootfs's
/// `.m2/repository/` (or was embedded in a scanned JAR via
/// `PomStore`). Represents actual bytes present on the scanned
/// filesystem — in scope under the artifact-SBOM principle.
///
/// `Host` — the `.pom` was satisfied from the operator's host
/// caches (`$HOME/.m2`, `$M2_REPO`, `$MAVEN_HOME`). Used for
/// parent-chain and BOM-import resolution so property interpolation
/// and inherited `<dependencyManagement>` stay correct, but does
/// NOT represent an artifact in the scanned image. Emission sites
/// gate on `Rootfs` to avoid leaking host cache contents into the
/// scanned-image SBOM.
///
/// See docs/design-notes.md "Scope: artifact vs manifest SBOM" for
/// the broader on-disk-vs-declared framing this supports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PomSource {
    Rootfs,
    Host,
}

impl MavenRepoCache {
    /// Discover candidate `~/.m2/repository` style directories.
    /// Priority order (earlier entries win when multiple roots carry
    /// the same pom):
    /// 1. `$M2_REPO` / `$MAVEN_HOME/repository` when set.  *(host)*
    /// 2. `$HOME/.m2/repository` (most dev machines).        *(host)*
    /// 3. `<rootfs>/root/.m2/repository` (conventional container
    ///    images that pre-populate the cache as root).      *(rootfs)*
    /// 4. `<rootfs>/home/*/.m2/repository`.                 *(rootfs)*
    /// 5. `<rootfs>/usr/share/maven-repo` (Debian's system-Maven
    ///    repo).                                             *(rootfs)*
    ///
    /// Only rootfs-scoped roots are visited by
    /// [`walk_rootfs_poms`](Self::walk_rootfs_poms). Host roots are
    /// still consulted by [`read_pom`](Self::read_pom) and
    /// [`read_artifact_hash`](Self::read_artifact_hash) — the BFS
    /// benefits from them when resolving transitive deps.
    pub(crate) fn discover(rootfs: &Path) -> Self {
        let mut rootfs_roots: Vec<PathBuf> = Vec::new();
        let mut host_roots: Vec<PathBuf> = Vec::new();
        let mut seen: HashSet<PathBuf> = HashSet::new();

        let try_add = |candidate: PathBuf,
                       bucket: &mut Vec<PathBuf>,
                       seen: &mut HashSet<PathBuf>| {
            let canonical = std::fs::canonicalize(&candidate).unwrap_or(candidate.clone());
            if !seen.insert(canonical) {
                return;
            }
            if candidate.is_dir() {
                bucket.push(candidate);
            }
        };

        if let Ok(env) = std::env::var("M2_REPO") {
            if !env.is_empty() {
                try_add(PathBuf::from(&env), &mut host_roots, &mut seen);
            }
        }
        if let Ok(env) = std::env::var("MAVEN_HOME") {
            if !env.is_empty() {
                try_add(
                    PathBuf::from(&env).join("repository"),
                    &mut host_roots,
                    &mut seen,
                );
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                try_add(
                    PathBuf::from(&home).join(".m2/repository"),
                    &mut host_roots,
                    &mut seen,
                );
            }
        }
        try_add(
            rootfs.join("root/.m2/repository"),
            &mut rootfs_roots,
            &mut seen,
        );
        if let Ok(home_dir) = std::fs::read_dir(rootfs.join("home")) {
            for entry in home_dir.flatten() {
                let candidate = entry.path().join(".m2/repository");
                try_add(candidate, &mut rootfs_roots, &mut seen);
            }
        }
        try_add(
            rootfs.join("usr/share/maven-repo"),
            &mut rootfs_roots,
            &mut seen,
        );

        MavenRepoCache {
            rootfs_roots,
            host_roots,
        }
    }

    /// Test-only helper: build a cache whose roots are treated as
    /// rootfs-scoped. Lets existing unit tests (written before the
    /// rootfs/host split) construct a cache without reaching into
    /// private fields.
    #[cfg(test)]
    pub(crate) fn for_tests(rootfs_roots: Vec<PathBuf>) -> Self {
        Self {
            rootfs_roots,
            host_roots: Vec::new(),
        }
    }

    /// Test-only helper: build a cache with explicit rootfs + host
    /// root lists. Used by tests that exercise the host-vs-rootfs
    /// provenance distinction ([`PomSource`]).
    #[cfg(test)]
    pub(crate) fn for_tests_with_host(
        rootfs_roots: Vec<PathBuf>,
        host_roots: Vec<PathBuf>,
    ) -> Self {
        Self {
            rootfs_roots,
            host_roots,
        }
    }

    /// Total number of discovered roots (rootfs + host). Useful for
    /// log messages.
    pub(crate) fn total_roots(&self) -> usize {
        self.rootfs_roots.len() + self.host_roots.len()
    }

    /// Iterate every discovered root in priority order: host roots
    /// first (they win pom/hash lookups per the discover ordering),
    /// then rootfs roots. Used by [`read_artifact_hash`]. POM reads
    /// use [`read_pom`] directly so they can track provenance via
    /// [`PomSource`].
    fn all_roots(&self) -> impl Iterator<Item = &Path> {
        self.host_roots
            .iter()
            .chain(self.rootfs_roots.iter())
            .map(|p| p.as_path())
    }

    /// Read `<root>/<group-as-path>/<artifact>/<version>/<artifact>-<version>.pom`
    /// from the first cache root that has it. Walks `rootfs_roots`
    /// first so scanned-image bytes win when the same coord is
    /// cached in both places; falls back to `host_roots` for
    /// parent-chain / BOM resolution.
    ///
    /// Returns `None` when no cache has the artefact or IO fails,
    /// otherwise `Some((bytes, source))` where `source` identifies
    /// whether the bytes came from the scanned rootfs or the
    /// operator's host cache. Callers that only consume bytes for
    /// resolution (parent-POM merging, `${...}` interpolation) can
    /// ignore `source`; callers that EMIT components on the fetched
    /// coord MUST gate emission on `source == PomSource::Rootfs` so
    /// host-cache contents don't leak into the scanned-image SBOM.
    pub(crate) fn read_pom(
        &self,
        group: &str,
        artifact: &str,
        version: &str,
    ) -> Option<(Vec<u8>, PomSource)> {
        if self.total_roots() == 0 {
            return None;
        }
        let group_path = group.replace('.', "/");
        let relative =
            format!("{group_path}/{artifact}/{version}/{artifact}-{version}.pom");
        for root in &self.rootfs_roots {
            let path = root.join(&relative);
            if let Ok(bytes) = std::fs::read(&path) {
                return Some((bytes, PomSource::Rootfs));
            }
        }
        for root in &self.host_roots {
            let path = root.join(&relative);
            if let Ok(bytes) = std::fs::read(&path) {
                return Some((bytes, PomSource::Host));
            }
        }
        None
    }

    /// Read the strongest available SHA sidecar for a given Maven
    /// artifact from the M2 cache. Maven Central publishes
    /// `<artifact>-<version>.jar.sha1` for every artifact, plus
    /// optional `.sha256` and `.sha512` for newer releases. Each
    /// sidecar holds a single line of lowercase hex, optionally
    /// followed by whitespace and the original filename — we strip
    /// the filename and keep only the hex token.
    ///
    /// Probes algorithms in strongest-first order
    /// (sha512 → sha256 → sha1) and returns the FIRST hit. Returns
    /// an empty Vec when no sidecar exists for any algorithm.
    pub(crate) fn read_artifact_hash(
        &self,
        group: &str,
        artifact: &str,
        version: &str,
    ) -> Vec<mikebom_common::types::hash::ContentHash> {
        if self.total_roots() == 0 {
            return Vec::new();
        }
        let group_path = group.replace('.', "/");
        let base = format!("{group_path}/{artifact}/{version}/{artifact}-{version}.jar");
        let mut out: Vec<mikebom_common::types::hash::ContentHash> = Vec::new();
        for root in self.all_roots() {
            let jar_path = root.join(&base);
            if let Some(hash) = read_sidecar(&jar_path) {
                out.push(hash);
            }
            // Always compute a SHA-256 of the JAR itself when it
            // exists in this cache root. Maven Central sidecars are
            // usually SHA-1 only; the computed digest is what lifts
            // sbomqs `comp_with_strong_checksums` out of 0/10.
            if jar_path.is_file() {
                if let Some(hash) = compute_archive_sha256(&jar_path) {
                    out.push(hash);
                }
                break;
            }
        }
        out
    }

    /// Walk every `.pom` file under the rootfs-scoped cache roots and
    /// extract `(group, artifact, version)` from the path structure:
    ///   `<root>/<group-as-path>/<artifact>/<version>/<artifact>-<version>.pom`
    ///
    /// This is the "unconditional cache walk" that closes the gap where
    /// a scan finds no scanned `pom.xml` and no packed-JAR `META-INF/maven/`
    /// metadata — trivy walks the whole `.m2/repository/` tree for
    /// exactly this case. The returned coords are deduplicated and
    /// ordered as discovered.
    ///
    /// Host-scoped roots (`$HOME/.m2`, `$M2_REPO`, `$MAVEN_HOME`) are
    /// intentionally skipped: they belong to the invoker, not the scan
    /// target. Walking them would leak the dev's unrelated cache
    /// contents into every scan.
    ///
    /// Stops emitting new coords once `cap` distinct `.pom` files have
    /// been visited across all rootfs roots; a `warn` log fires when
    /// truncation happens so users know the output is bounded.
    /// I/O errors on individual directory entries are silently skipped
    /// so a single unreadable subtree doesn't abort the whole walk.
    pub(crate) fn walk_rootfs_poms(
        &self,
        cap: usize,
    ) -> Vec<(String, String, String)> {
        if self.rootfs_roots.is_empty() || cap == 0 {
            return Vec::new();
        }
        let mut seen: HashSet<(String, String, String)> = HashSet::new();
        let mut out: Vec<(String, String, String)> = Vec::new();
        let mut files_visited: usize = 0;
        let mut truncated = false;

        'roots: for root in &self.rootfs_roots {
            // Manual stack-based walker mirroring `scan_fs/walker.rs`.
            // Using `walkdir` would pull a new transitive dep; the
            // std-library form is short enough to inline.
            let mut stack: Vec<PathBuf> = vec![root.clone()];
            while let Some(dir) = stack.pop() {
                let entries = match std::fs::read_dir(&dir) {
                    Ok(it) => it,
                    Err(_) => continue,
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    let ft = match entry.file_type() {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    if ft.is_dir() {
                        stack.push(path);
                        continue;
                    }
                    if !ft.is_file() {
                        continue;
                    }
                    // Cheap extension check before we do the path
                    // arithmetic: skip non-.pom files immediately.
                    let is_pom = path
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.eq_ignore_ascii_case("pom"))
                        .unwrap_or(false);
                    if !is_pom {
                        continue;
                    }
                    files_visited += 1;
                    if files_visited > cap {
                        truncated = true;
                        break 'roots;
                    }
                    if let Some(coord) = coord_from_m2_path(root, &path) {
                        if seen.insert(coord.clone()) {
                            tracing::debug!(
                                group = %coord.0,
                                artifact = %coord.1,
                                version = %coord.2,
                                "maven cache walk seed",
                            );
                            out.push(coord);
                        }
                    }
                }
            }
        }

        if truncated {
            tracing::warn!(
                cap,
                visited = files_visited,
                seeds = out.len(),
                "maven cache walk truncated — .m2 cache has more .pom files than the safety cap; some coords will not be emitted",
            );
        }
        out
    }

    /// Check whether the rootfs `.m2/repository/` cache has a JAR
    /// artifact for `(group, artifact, version)` — `<artifact>-<version>.jar`
    /// sitting in the same directory as the coord's `.pom`.
    ///
    /// Used by the M1 artifact-presence gate for the common case
    /// where a real Maven cache ships POM + JAR side by side: the
    /// `find_maven_artifacts` walker skips hidden directories like
    /// `.m2/` so those JARs aren't in the `jar_meta`-backed coord
    /// index, but they ARE distributable artifacts on the scanned
    /// filesystem. Only rootfs roots are consulted — host caches
    /// stay excluded per the dual-SBOM principle.
    pub(crate) fn has_rootfs_jar(&self, group: &str, artifact: &str, version: &str) -> bool {
        if self.rootfs_roots.is_empty() {
            return false;
        }
        let group_path = group.replace('.', "/");
        let relative = format!("{group_path}/{artifact}/{version}/{artifact}-{version}.jar");
        for root in &self.rootfs_roots {
            if root.join(&relative).is_file() {
                return true;
            }
        }
        false
    }
}

/// Parse `(group, artifact, version)` from a Maven repo path of the
/// shape `<root>/<g1>/<g2>/.../<artifact>/<version>/<artifact>-<version>.pom`.
///
/// The group is the path segments between `root` and `<artifact>`,
/// joined with `.`. The filename must be `<artifact>-<version>.pom`
/// (sanity-checks group/artifact/version consistency between path and
/// filename — a sibling `<artifact>-<version>-sources.pom` or
/// `maven-metadata.xml` would fail this check and be silently
/// skipped).
///
/// Returns `None` for any path that doesn't fit the Maven layout.
fn coord_from_m2_path(root: &Path, pom_path: &Path) -> Option<(String, String, String)> {
    let rel = pom_path.strip_prefix(root).ok()?;
    let segments: Vec<&str> = rel
        .iter()
        .filter_map(|s| s.to_str())
        .collect();
    // Need at least group/<artifact>/<version>/<file>, and the group
    // must carry at least one segment (no artifact at the repo root).
    if segments.len() < 4 {
        return None;
    }
    let file_name = segments.last()?;
    let version = segments[segments.len() - 2];
    let artifact = segments[segments.len() - 3];
    let group_parts = &segments[..segments.len() - 3];
    if group_parts.is_empty() || artifact.is_empty() || version.is_empty() {
        return None;
    }
    let expected_file = format!("{artifact}-{version}.pom");
    if *file_name != expected_file.as_str() {
        return None;
    }
    let group = group_parts.join(".");
    if group.is_empty() {
        return None;
    }
    Some((group, artifact.to_string(), version.to_string()))
}

/// Probe the three sidecar extensions in strongest-first order at
/// `<jar_base_path>.{sha512,sha256,sha1}`. Returns the first parsed
/// `ContentHash`. `jar_base_path` is the JAR's full path (NOT the
/// JAR contents) — sidecars live alongside it.
pub(crate) fn read_sidecar(
    jar_base_path: &Path,
) -> Option<mikebom_common::types::hash::ContentHash> {
    use mikebom_common::types::hash::{ContentHash, HashAlgorithm};
    let candidates = [
        ("sha512", HashAlgorithm::Sha512),
        ("sha256", HashAlgorithm::Sha256),
        ("sha1", HashAlgorithm::Sha1),
    ];
    for (ext, alg) in candidates {
        let sidecar_path = jar_base_path.with_extension(format!(
            "{}.{ext}",
            jar_base_path.extension().and_then(|s| s.to_str()).unwrap_or("jar")
        ));
        if let Ok(text) = std::fs::read_to_string(&sidecar_path) {
            // Maven sidecar format: hex digest, optionally followed by
            // whitespace + filename ("abc123  myartifact.jar").
            let token = text.split_whitespace().next().unwrap_or("");
            if token.is_empty() {
                continue;
            }
            if let Ok(hash) = ContentHash::with_algorithm(alg, token) {
                return Some(hash);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// pom.xml parser
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub(crate) struct PomXmlDocument {
    pub self_coord: Option<(String, String, String)>, // (groupId, artifactId, version)
    pub parent_coord: Option<(String, String, String)>,
    pub properties: HashMap<String, String>,
    pub dependencies: Vec<PomDependency>,
    /// `<dependencyManagement>/<dependencies>/<dependency>` entries.
    /// Maven uses these to declare versions for deps that child
    /// POMs reference without an inline `<version>`. BOM imports
    /// (`<type>pom</type><scope>import</scope>`) also live here.
    pub dependency_management: Vec<PomDependency>,
}

#[derive(Clone, Debug)]
pub(crate) struct PomDependency {
    pub group_id: String,
    pub artifact_id: String,
    pub version: Option<String>,
    pub scope: Option<String>,
    /// `<type>` element on the dep. Used to distinguish BOM imports
    /// (`<type>pom</type><scope>import</scope>`) from regular deps.
    /// `None` means the element was absent (Maven default is `jar`).
    pub dep_type: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MavenVersion {
    Resolved(String),
    Placeholder(String), // raw `${...}` text
}

/// Parse `pom.xml` bytes with quick-xml. Event-driven traversal — we
/// keep a stack of element names and collect textual content inside
/// the ones we care about.
pub(crate) fn parse_pom_xml(bytes: &[u8]) -> PomXmlDocument {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_reader(bytes);
    reader.trim_text(true);

    let mut doc = PomXmlDocument::default();
    let mut stack: Vec<String> = Vec::new();
    let mut current_text = String::new();
    // Current in-progress data during traversal.
    let mut self_g: Option<String> = None;
    let mut self_a: Option<String> = None;
    let mut self_v: Option<String> = None;
    let mut parent_g: Option<String> = None;
    let mut parent_a: Option<String> = None;
    let mut parent_v: Option<String> = None;
    let mut dep_g: Option<String> = None;
    let mut dep_a: Option<String> = None;
    let mut dep_v: Option<String> = None;
    let mut dep_scope: Option<String> = None;
    let mut dep_type: Option<String> = None;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                stack.push(name);
                current_text.clear();
            }
            Ok(Event::End(_)) => {
                let popped = stack.pop().unwrap_or_default();
                let parent = stack.last().cloned().unwrap_or_default();
                let grand = stack.iter().rev().nth(1).cloned().unwrap_or_default();
                // project/{groupId,artifactId,version}
                if parent == "project" {
                    match popped.as_str() {
                        "groupId" => self_g = Some(current_text.clone()),
                        "artifactId" => self_a = Some(current_text.clone()),
                        "version" => self_v = Some(current_text.clone()),
                        _ => {}
                    }
                }
                // project/parent/{groupId,artifactId,version}
                if parent == "parent" && grand == "project" {
                    match popped.as_str() {
                        "groupId" => parent_g = Some(current_text.clone()),
                        "artifactId" => parent_a = Some(current_text.clone()),
                        "version" => parent_v = Some(current_text.clone()),
                        _ => {}
                    }
                }
                // project/properties/<key>  — content is the value.
                if parent == "properties" && grand == "project" {
                    doc.properties
                        .insert(popped.clone(), current_text.clone());
                }
                // project/dependencies/dependency/{groupId,artifactId,version,scope,type}
                // ALSO fires for project/dependencyManagement/dependencies/dependency/...
                // — same structure inside the <dependency> element in both cases.
                if parent == "dependency" {
                    match popped.as_str() {
                        "groupId" => dep_g = Some(current_text.clone()),
                        "artifactId" => dep_a = Some(current_text.clone()),
                        "version" => dep_v = Some(current_text.clone()),
                        "scope" => dep_scope = Some(current_text.clone()),
                        "type" => dep_type = Some(current_text.clone()),
                        _ => {}
                    }
                }
                if popped == "dependency" {
                    // At this point `stack` is one of:
                    //   [..., project, dependencies]                      → regular dep
                    //   [..., project, dependencyManagement, dependencies]→ managed dep
                    // We route to the right list based on `stack[-2]`.
                    let inside_dep_mgmt = stack
                        .iter()
                        .rev()
                        .nth(1)
                        .map(|s| s == "dependencyManagement")
                        .unwrap_or(false);
                    if let (Some(g), Some(a)) = (dep_g.take(), dep_a.take()) {
                        let entry = PomDependency {
                            group_id: g,
                            artifact_id: a,
                            version: dep_v.take(),
                            scope: dep_scope.take(),
                            dep_type: dep_type.take(),
                        };
                        if inside_dep_mgmt {
                            doc.dependency_management.push(entry);
                        } else {
                            doc.dependencies.push(entry);
                        }
                    } else {
                        dep_v = None;
                        dep_scope = None;
                        dep_type = None;
                    }
                }
                current_text.clear();
            }
            Ok(Event::Text(t)) => {
                if let Ok(s) = t.unescape() {
                    current_text.push_str(&s);
                }
            }
            Ok(Event::CData(t)) => {
                current_text.push_str(&String::from_utf8_lossy(&t));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        buf.clear();
    }

    if let (Some(g), Some(a)) = (self_g.clone(), self_a.clone()) {
        // version may be inherited from parent when omitted on project
        let v = self_v.clone().or_else(|| parent_v.clone()).unwrap_or_default();
        doc.self_coord = Some((g, a, v));
    }
    if let (Some(g), Some(a), Some(v)) = (parent_g, parent_a, parent_v) {
        doc.parent_coord = Some((g, a, v));
    }
    doc
}

/// Resolve `${name}`-style property references in a Maven value. Handles
/// two common cases: `${project.version}` (use the POM's self version)
/// and `${user.property}` (look up in the POM's `<properties>` block).
/// Returns `Resolved(...)` when the placeholder is replaced successfully,
/// `Placeholder(...)` otherwise.
pub(crate) fn resolve_maven_property(
    raw: &str,
    doc: &PomXmlDocument,
) -> MavenVersion {
    if !raw.contains("${") {
        return MavenVersion::Resolved(raw.to_string());
    }
    let mut result = raw.to_string();
    loop {
        let Some(open) = result.find("${") else {
            break;
        };
        let Some(close) = result[open..].find('}') else {
            break;
        };
        let close_abs = open + close;
        let key = &result[open + 2..close_abs];
        let replacement = match key {
            "project.version" => doc.self_coord.as_ref().map(|(_, _, v)| v.clone()),
            "project.groupId" => doc.self_coord.as_ref().map(|(g, _, _)| g.clone()),
            "project.artifactId" => doc.self_coord.as_ref().map(|(_, a, _)| a.clone()),
            other => doc.properties.get(other).cloned(),
        };
        let Some(value) = replacement else {
            // Can't resolve this placeholder — leave raw text for
            // caller to treat as `Placeholder`.
            return MavenVersion::Placeholder(raw.to_string());
        };
        result.replace_range(open..=close_abs, &value);
    }
    MavenVersion::Resolved(result)
}

// ---------------------------------------------------------------------------
// Effective-POM computation (parent-chain walker)
// ---------------------------------------------------------------------------

/// A POM merged with everything inherited from its `<parent>` chain:
/// every `<properties>` entry (child wins) and every
/// `<dependencyManagement>` version (child wins, BOM imports
/// flattened). Callers resolve dep versions through this rather than
/// the raw `PomXmlDocument` so POMs like guava's or jackson-databind's
/// — which declare deps with no inline version or with a `${...}`
/// placeholder defined upstream — produce the right edges.
#[derive(Clone, Debug)]
pub(crate) struct EffectivePom {
    pub doc: PomXmlDocument,
    /// Merged properties. Includes `${project.*}` + any values
    /// contributed by the parent chain.
    pub properties: HashMap<String, String>,
    /// `(group, artifact) → version` from every `<dependencyManagement>`
    /// entry reachable through the parent chain (including BOM
    /// imports). Pre-substituted: values that referenced properties
    /// in their original POMs already had those properties resolved
    /// before insertion here.
    pub dependency_management: HashMap<(String, String), String>,
}

/// In-memory store of raw POM bytes keyed by `"group:artifact:version"`.
/// Used so `build_effective_pom` can look up parents without
/// re-reading them from disk. The outer `read()` builds it once per
/// scan from (a) JAR-embedded pom.xml files and (b) on-demand
/// lookups from the M2 cache.
pub(crate) type PomStore = HashMap<String, Vec<u8>>;

/// Memoization cache for `build_effective_pom` results, keyed on the
/// POM's self coord `"group:artifact:version"`. A parent referenced
/// by dozens of siblings is parsed + merged once.
pub(crate) type EffectivePomMemo = HashMap<String, EffectivePom>;

fn coord_key(g: &str, a: &str, v: &str) -> String {
    format!("{g}:{a}:{v}")
}

/// Fetch POM bytes: prefer the in-memory store (JAR-embedded /
/// previously-read), fall back to the on-disk M2 cache.
/// Fetch POM bytes for `(g, a, v)` from the in-memory
/// JAR-embedded-pom store, falling back to on-disk `.m2/repository/`
/// caches. Returns `(bytes, source)` so emission sites can gate on
/// [`PomSource::Rootfs`]; resolution-only callers ignore `source`.
///
/// `PomStore` hits are always `Rootfs` — the store is populated
/// exclusively from JAR files discovered in the scanned rootfs
/// (see `walk_jar_maven_meta` + the `jar_meta.pom_xml_bytes`
/// population loop in `read_with_claims`).
fn fetch_pom_bytes(
    store: &PomStore,
    cache: &MavenRepoCache,
    g: &str,
    a: &str,
    v: &str,
) -> Option<(Vec<u8>, PomSource)> {
    if let Some(bytes) = store.get(&coord_key(g, a, v)) {
        return Some((bytes.clone(), PomSource::Rootfs));
    }
    cache.read_pom(g, a, v)
}

/// Resolve a raw value against an explicit properties map + optional
/// self-coord (for `${project.*}`). Unlike [`resolve_maven_property`]
/// this doesn't take the whole `PomXmlDocument` — effective-pom
/// callers have pre-merged properties to substitute against.
fn resolve_with_properties(
    raw: &str,
    properties: &HashMap<String, String>,
    self_coord: Option<&(String, String, String)>,
) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    if !raw.contains("${") {
        return Some(raw.to_string());
    }
    let mut result = raw.to_string();
    // Cap iterations to catch pathological `${foo}`-expands-to-`${foo}`
    // loops; real POMs don't nest more than a handful of levels deep.
    for _ in 0..16 {
        let Some(open) = result.find("${") else {
            break;
        };
        let Some(close) = result[open..].find('}') else {
            break;
        };
        let close_abs = open + close;
        let key = &result[open + 2..close_abs];
        let replacement = match key {
            "project.version" => self_coord.map(|(_, _, v)| v.clone()),
            "project.groupId" => self_coord.map(|(g, _, _)| g.clone()),
            "project.artifactId" => self_coord.map(|(_, a, _)| a.clone()),
            other => properties.get(other).cloned(),
        };
        let value = replacement?;
        result.replace_range(open..=close_abs, &value);
    }
    if result.contains("${") {
        return None;
    }
    Some(result)
}

/// Build the effective POM for `doc` by walking its `<parent>` chain,
/// merging every ancestor's `<properties>` and `<dependencyManagement>`
/// (child wins). BOM imports in `<dependencyManagement>` are flattened:
/// when an entry has `<type>pom</type><scope>import</scope>`, fetch
/// that BOM's effective POM and merge ITS `dependency_management`
/// into ours.
///
/// `seen` guards against pathological parent cycles. `memo` short-
/// circuits revisits of the same coord (parent POMs are typically
/// referenced by many siblings).
pub(crate) fn build_effective_pom(
    doc: PomXmlDocument,
    cache: &MavenRepoCache,
    store: &PomStore,
    seen: &mut HashSet<String>,
    memo: &mut EffectivePomMemo,
) -> EffectivePom {
    if let Some(ref coord) = doc.self_coord {
        let key = coord_key(&coord.0, &coord.1, &coord.2);
        if let Some(cached) = memo.get(&key) {
            return cached.clone();
        }
    }

    // Seed with the POM's own contributions.
    let mut properties = doc.properties.clone();
    let mut dependency_management: HashMap<(String, String), String> = HashMap::new();
    for entry in &doc.dependency_management {
        // Skip BOM-import entries at this pass — they're handled in
        // a dedicated pass below after property substitution.
        if is_bom_import(entry) {
            continue;
        }
        if let Some(ref v) = entry.version {
            dependency_management.insert(
                (entry.group_id.clone(), entry.artifact_id.clone()),
                v.clone(),
            );
        }
    }

    // Merge the parent chain (child wins on collision).
    if let Some((pg, pa, pv)) = doc.parent_coord.clone() {
        let parent_key = coord_key(&pg, &pa, &pv);
        if seen.insert(parent_key.clone()) {
            // Parent-POM fetch is resolution-only (used to inherit
            // `<properties>` and `<dependencyManagement>` for
            // `${project.version}`-style interpolation); the parent
            // coord itself is not emitted as a component from here,
            // so we can consume parent bytes from either rootfs or
            // host without violating the artifact-SBOM principle.
            if let Some((bytes, _source)) = fetch_pom_bytes(store, cache, &pg, &pa, &pv) {
                let parent_doc = parse_pom_xml(&bytes);
                let parent_eff = build_effective_pom(parent_doc, cache, store, seen, memo);
                for (k, v) in parent_eff.properties {
                    properties.entry(k).or_insert(v);
                }
                for (k, v) in parent_eff.dependency_management {
                    dependency_management.entry(k).or_insert(v);
                }
            } else {
                tracing::debug!(
                    group = %pg,
                    artifact = %pa,
                    version = %pv,
                    "parent POM not in cache — effective POM will lack inherited properties",
                );
            }
            seen.remove(&parent_key);
        }
    }

    // BOM imports: each `<dependencyManagement>` entry with
    // <type>pom</type><scope>import</scope> contributes the imported
    // POM's entire <dependencyManagement> to ours. Property-substitute
    // the BOM coord first (its version is often a `${...}` placeholder).
    for entry in &doc.dependency_management {
        if !is_bom_import(entry) {
            continue;
        }
        let Some(ref raw_v) = entry.version else {
            continue;
        };
        let Some(bom_g) = resolve_with_properties(
            &entry.group_id,
            &properties,
            doc.self_coord.as_ref(),
        ) else {
            continue;
        };
        let Some(bom_v) = resolve_with_properties(
            raw_v,
            &properties,
            doc.self_coord.as_ref(),
        ) else {
            continue;
        };
        let bom_key = coord_key(&bom_g, &entry.artifact_id, &bom_v);
        if !seen.insert(bom_key.clone()) {
            continue;
        }
        // BOM-import fetch is resolution-only (imported POMs
        // contribute `<dependencyManagement>` entries used to pin
        // transitive versions); the imported coord is not emitted
        // as a component from here, so host-sourced bytes are fine.
        if let Some((bytes, _source)) =
            fetch_pom_bytes(store, cache, &bom_g, &entry.artifact_id, &bom_v)
        {
            let bom_doc = parse_pom_xml(&bytes);
            let bom_eff = build_effective_pom(bom_doc, cache, store, seen, memo);
            for (k, v) in bom_eff.dependency_management {
                // Child (current POM) wins over BOM imports — BOM
                // entries only fill gaps, matching Maven's rule that
                // declared <dependencyManagement> beats imported.
                dependency_management.entry(k).or_insert(v);
            }
        } else {
            tracing::debug!(
                group = %bom_g,
                artifact = %entry.artifact_id,
                version = %bom_v,
                "BOM import POM not in cache",
            );
        }
        seen.remove(&bom_key);
    }

    // Post-resolve the dependencyManagement versions against the
    // merged properties — many managed versions reference `${foo}`
    // defined in the parent chain.
    let mut resolved_dep_mgmt: HashMap<(String, String), String> = HashMap::new();
    for (key, raw_v) in dependency_management {
        match resolve_with_properties(&raw_v, &properties, doc.self_coord.as_ref()) {
            Some(v) => {
                resolved_dep_mgmt.insert(key, v);
            }
            None => {
                // Leave unresolvable entries out — callers will fall
                // through to None and drop the edge silently.
            }
        }
    }

    let result = EffectivePom {
        doc,
        properties,
        dependency_management: resolved_dep_mgmt,
    };
    if let Some(ref coord) = result.doc.self_coord {
        let key = coord_key(&coord.0, &coord.1, &coord.2);
        memo.insert(key, result.clone());
    }
    result
}

/// A `<dependency>` entry is a BOM import when it has
/// `<type>pom</type><scope>import</scope>`. Matches the Maven spec.
fn is_bom_import(dep: &PomDependency) -> bool {
    matches!(dep.dep_type.as_deref(), Some("pom"))
        && matches!(dep.scope.as_deref(), Some("import"))
}

/// Resolve a dep's concrete group using the effective POM's merged
/// properties. Returns `None` when the groupId contains an unresolvable
/// placeholder.
pub(crate) fn resolve_dep_group(dep: &PomDependency, eff: &EffectivePom) -> Option<String> {
    resolve_with_properties(
        &dep.group_id,
        &eff.properties,
        eff.doc.self_coord.as_ref(),
    )
    .filter(|s| !s.is_empty())
}

/// Resolve a dep's concrete version by:
///   1. Substituting properties into the inline `<version>` (if any),
///   2. Falling back to the effective `<dependencyManagement>` entry
///      for `(group, artifact)`.
/// Returns `None` when both paths fail — caller drops the edge.
pub(crate) fn resolve_dep_version(dep: &PomDependency, eff: &EffectivePom) -> Option<String> {
    if let Some(ref raw) = dep.version {
        if let Some(v) = resolve_with_properties(raw, &eff.properties, eff.doc.self_coord.as_ref())
        {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    // Need the resolved group to key into dep_management.
    let group = resolve_dep_group(dep, eff)?;
    eff.dependency_management
        .get(&(group, dep.artifact_id.clone()))
        .cloned()
}

// ---------------------------------------------------------------------------
// JAR archive walker
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub(crate) struct PomProperties {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
}

/// Parse a `pom.properties` file body. Format: Java properties file
/// with `key=value` lines, UTF-8.
///
/// Returns `None` when `version` is empty or still contains an
/// unresolved `${...}` placeholder — some RPM-packaged Maven JARs ship
/// with the build-time property substitution never applied, which would
/// otherwise yield garbage PURLs like `pkg:maven/g/a@` or
/// `pkg:maven/g/a@${project.version}`. The pom.xml path already guards
/// placeholders via `resolve_maven_property` (see `pom_dep_to_entry`);
/// this mirrors that behavior for the pom.properties path.
pub(crate) fn parse_pom_properties(text: &str) -> Option<PomProperties> {
    let mut g = None;
    let mut a = None;
    let mut v = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, val)) = line.split_once('=') {
            match k.trim() {
                "groupId" => g = Some(val.trim().to_string()),
                "artifactId" => a = Some(val.trim().to_string()),
                "version" => v = Some(val.trim().to_string()),
                _ => {}
            }
        }
    }
    let version = v?;
    if version.is_empty() || version.contains("${") {
        tracing::debug!(
            version = %version,
            "pom.properties has empty or unresolved placeholder version, skipping"
        );
        return None;
    }
    Some(PomProperties {
        group_id: g?,
        artifact_id: a?,
        version,
    })
}

/// Every Maven-metadata artefact mikebom can extract from one entry
/// inside a JAR: the identity (`pom.properties`) and, when present, the
/// full pom.xml declaring that artefact's own `<dependencies>`. Fat /
/// shaded JARs yield one of these per vendored artefact.
#[derive(Clone, Debug)]
pub(crate) struct EmbeddedMavenMeta {
    pub coord: PomProperties,
    /// Deps declared in the embedded `META-INF/maven/<g>/<a>/pom.xml`
    /// when present, else empty. Provides the edge topology for the
    /// tree-walker; actual edge targets are resolved against the
    /// disk-observed coord index (same JAR scan) so versions always
    /// reflect what's on disk.
    pub declared_deps: Vec<PomDependency>,
    /// Raw bytes of the embedded pom.xml. `None` when only
    /// pom.properties was present. Feeds the unified POM store so
    /// parent-chain walks can resolve through JAR-shipped parents
    /// even when they aren't in the M2 cache.
    pub pom_xml_bytes: Option<Vec<u8>>,
    /// SHA-512/256/1 sidecar hash for this JAR, when present
    /// alongside the JAR on disk. `None` for fat JAR vendored
    /// artefacts (which don't have their own sidecar). Sidecar
    /// reads happen in [`walk_jar_maven_meta`] using
    /// [`read_sidecar`]. Plumbed onto `entry.hashes` via
    /// [`jar_pom_to_entry`].
    pub sidecar_hash: Option<mikebom_common::types::hash::ContentHash>,
    /// SHA-256 of the JAR archive itself, computed by streaming the
    /// file during the walk. Present on the primary coord of any
    /// readable JAR; `None` for vendored fat-JAR sub-coords and
    /// unreadable files. Coexists with `sidecar_hash` so consumers
    /// can pick the strongest algorithm (sbomqs grades SHA-256+ as
    /// strong, SHA-1 as weak — Maven Central sidecars are usually
    /// SHA-1 only, so this is the primary source of strong hashes
    /// for Maven components).
    pub archive_sha256: Option<mikebom_common::types::hash::ContentHash>,
    /// `true` when this coord is the JAR's own identity
    /// (`<artifactId>-<version>.jar` matches the archive stem). In a
    /// shade-plugin fat-jar, exactly one coord is primary (the project
    /// itself) and the rest are vendored children. Drives CDX 1.6
    /// `component.components[]` nesting at emission time: primary ==
    /// parent, non-primary == children with `parent_purl` set.
    pub is_primary: bool,
}

/// Crack open `archive_path` and return every `META-INF/maven/<g>/<a>/`
/// metadata block we can parse. The block is represented by
/// [`EmbeddedMavenMeta`]: at minimum the `pom.properties` coord, plus
/// the embedded `pom.xml`'s `<dependencies>` list when that file is
/// present alongside. Refuses zip-slip attempts by rejecting any
/// entry whose normalised path contains `..`.
pub(crate) fn walk_jar_maven_meta(archive_path: &Path) -> Vec<EmbeddedMavenMeta> {
    let Ok(file) = std::fs::File::open(archive_path) else {
        return Vec::new();
    };
    let Ok(mut zip) = zip::ZipArchive::new(file) else {
        return Vec::new();
    };
    // Collect pom.properties and pom.xml bodies keyed by their
    // containing directory (e.g. "META-INF/maven/com.google.guava/guava/"),
    // then pair them up at the end. A fat JAR has one directory per
    // vendored artefact.
    let mut properties_by_dir: HashMap<String, PomProperties> = HashMap::new();
    let mut pom_xml_by_dir: HashMap<String, Vec<u8>> = HashMap::new();

    for i in 0..zip.len() {
        let Ok(mut entry) = zip.by_index(i) else {
            continue;
        };
        if entry.size() > MAX_JAR_ENTRY_BYTES {
            continue;
        }
        let name = entry.name().to_string();
        // Zip-slip guard (FR-009): reject entries whose name has path
        // traversal components.
        if name.contains("..") {
            continue;
        }
        if !name.starts_with("META-INF/maven/") {
            continue;
        }
        use std::io::Read;
        if name.ends_with("/pom.properties") {
            let dir = name.trim_end_matches("pom.properties").to_string();
            let mut text = String::new();
            if entry.read_to_string(&mut text).is_err() {
                continue;
            }
            if let Some(props) = parse_pom_properties(&text) {
                properties_by_dir.insert(dir, props);
            }
        } else if name.ends_with("/pom.xml") {
            let dir = name.trim_end_matches("pom.xml").to_string();
            let mut bytes = Vec::new();
            if entry.read_to_end(&mut bytes).is_err() {
                continue;
            }
            pom_xml_by_dir.insert(dir, bytes);
        }
    }

    // The sidecar hash applies to the WHOLE jar archive, not the
    // individual vendored coords inside a fat JAR. Read it once from
    // the JAR's filesystem path and attach to whichever embedded coord
    // matches the JAR's primary coord (artifactId == jar filename
    // stem, naive but covers the common case). For fat / shaded JARs
    // with multiple vendored coords, only the primary coord gets the
    // hash — others are second-party artefacts whose hashes the
    // shader didn't record.
    let archive_sidecar = read_sidecar(archive_path);
    // Compute a SHA-256 over the JAR file itself as a strong-hash
    // complement to the sidecar. Maven Central's sidecar artefacts
    // are usually SHA-1 only; sbomqs grades SHA-1 as weak, so
    // without a computed SHA-256 every Maven component reads as
    // "no strong checksum" regardless of sidecar presence.
    let archive_sha256 = compute_archive_sha256(archive_path);
    let archive_stem = archive_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    let mut out = Vec::new();
    for (dir, coord) in properties_by_dir {
        let pom_xml_bytes = pom_xml_by_dir.get(&dir).cloned();
        let declared_deps = pom_xml_bytes
            .as_ref()
            .map(|bytes| parse_pom_xml(bytes).dependencies)
            .unwrap_or_default();
        // Match this coord to the JAR's filesystem name to decide
        // whether to attach the sidecar hash. Maven's standard naming
        // is `<artifactId>-<version>.jar`; if the stem starts with
        // the artifactId (or matches the artifactId+version), this
        // is the JAR's primary coord.
        let is_primary = archive_stem.starts_with(&coord.artifact_id)
            || archive_stem == format!("{}-{}", coord.artifact_id, coord.version);
        let (sidecar_hash, sha256_for_coord) = if is_primary {
            (archive_sidecar.clone(), archive_sha256.clone())
        } else {
            (None, None)
        };
        out.push(EmbeddedMavenMeta {
            coord,
            declared_deps,
            pom_xml_bytes,
            sidecar_hash,
            archive_sha256: sha256_for_coord,
            is_primary,
        });
    }
    out
}

/// Stream-hash a JAR file and return its SHA-256 wrapped as a
/// `ContentHash`. Returns `None` when the file is unreadable; the
/// walker already ignores unreadable entries upstream, but this
/// keeps the helper infallible at the call site.
fn compute_archive_sha256(
    path: &Path,
) -> Option<mikebom_common::types::hash::ContentHash> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    let digest = format!("{:x}", hasher.finalize());
    mikebom_common::types::hash::ContentHash::sha256(&digest).ok()
}


// ---------------------------------------------------------------------------
// Conversion to PackageDbEntry
// ---------------------------------------------------------------------------

fn build_maven_purl(group: &str, artifact: &str, version: &str) -> Option<Purl> {
    // purl-spec § Character encoding: all three segments are
    // percent-encoded strings. Debian-packaged Maven artifacts carry
    // versions like `1.0+dfsg` → `1.0%2Bdfsg`.
    Purl::new(&format!(
        "pkg:maven/{}/{}@{}",
        encode_purl_segment(group),
        encode_purl_segment(artifact),
        encode_purl_segment(version),
    ))
    .ok()
}

fn pom_dep_to_entry(
    dep: &PomDependency,
    doc: &PomXmlDocument,
    source_path: &str,
    include_dev: bool,
    cache: Option<&MavenRepoCache>,
) -> Option<PackageDbEntry> {
    // Filter out test-scope when include_dev is false.
    if !include_dev && matches!(dep.scope.as_deref(), Some("test")) {
        return None;
    }
    let raw_version = dep.version.clone().unwrap_or_default();
    let (resolved_version, tier, requirement_range) = match resolve_maven_property(&raw_version, doc) {
        MavenVersion::Resolved(v) if !v.is_empty() => (v, "source".to_string(), None),
        MavenVersion::Resolved(_) => {
            // Empty version — demote to design tier.
            (
                String::from("unknown"),
                "design".to_string(),
                Some(raw_version.clone()),
            )
        }
        MavenVersion::Placeholder(raw) => (
            String::from("unknown"),
            "design".to_string(),
            Some(raw),
        ),
    };
    let purl = build_maven_purl(&dep.group_id, &dep.artifact_id, &resolved_version)?;
    // Probe the M2 cache for a sidecar SHA hash for this coord. Empty
    // when no cache root has the artifact (common for design-tier
    // entries with placeholder versions).
    let hashes = cache
        .map(|c| c.read_artifact_hash(&dep.group_id, &dep.artifact_id, &resolved_version))
        .unwrap_or_default();
    Some(PackageDbEntry {
        purl,
        name: dep.artifact_id.clone(),
        version: resolved_version,
        arch: None,
        source_path: source_path.to_string(),
        depends: Vec::new(),
        maintainer: None,
        licenses: Vec::new(),
        is_dev: matches!(dep.scope.as_deref(), Some("test")).then_some(true),
        requirement_range,
        // Mark as workspace to distinguish from BFS-inferred transitive
        // coords (source_type = "transitive"). `app` (the scanned
        // project itself) also gets this tag.
        source_type: Some("workspace".to_string()),
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
        hashes,
        sbom_tier: Some(tier),
    })
}

/// BFS the M2 repo cache starting from `seeds` and emit one
/// `PackageDbEntry` per unique coord reached. Cycle-safe via a
/// `seen` set keyed on `"group:artifact:version"`; cache-miss
/// branches terminate with `depends: vec![]` and stop exploring.
///
/// The seeds are expected to be already-resolved concrete coords —
/// callers filter out deps with placeholder groups / versions before
/// handing them to this function, because no cache lookup is
/// possible without a full `(group, artifact, version)` triple.
///
/// Returned entries carry `sbom_tier = "source"` and
/// `source_type = "transitive"` to distinguish them from the
/// project-declared direct deps (`source_type = "workspace"`).
/// Per-node property resolution uses the upstream pom's own
/// `<properties>` + `${project.*}` derived from the current coord —
/// NOT the scanned root's properties.
/// `on_disk_jar_coords`: artifact-presence gate (M1). When `Some`, a
/// BFS cache-hit emission fires only when the coord's
/// `(group, artifact)` appears in this set — i.e. the JAR walk
/// found a corresponding JAR in the scanned rootfs. When `None`,
/// the gate is off (backward-compat for unit tests that exercise
/// BFS behavior in isolation without a JAR-walk context). POMs
/// whose coords are in the rootfs `.m2` cache but have no JAR on
/// disk (parent POMs, BOM aggregators with `<packaging>pom</packaging>`)
/// still drive BFS traversal for resolution but don't surface as
/// components.
fn bfs_transitive_poms(
    cache: &MavenRepoCache,
    store: &PomStore,
    seeds: &[(String, String, String)],
    include_dev: bool,
    include_declared_deps: bool,
    source_path: &str,
    on_disk_jar_coords: Option<&HashSet<(String, String)>>,
) -> Vec<PackageDbEntry> {
    use std::collections::VecDeque;

    let mut out: Vec<PackageDbEntry> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, String, String)> = VecDeque::new();
    // Memoize effective-POM computation across the entire BFS so a
    // heavily-referenced parent POM (e.g. `org.sonatype.oss:oss-parent`)
    // is parsed + merged exactly once per scan.
    let mut memo: EffectivePomMemo = HashMap::new();
    for coord in seeds {
        queue.push_back(coord.clone());
    }

    while let Some((group, artifact, version)) = queue.pop_front() {
        let key = coord_key(&group, &artifact, &version);
        if !seen.insert(key) {
            continue;
        }

        let Some((bytes, source)) = fetch_pom_bytes(store, cache, &group, &artifact, &version)
        else {
            // Cache miss — no .pom and no .jar on disk for this coord,
            // either in the scanned rootfs or the host cache.
            // In artifact scope (default for image scans) this is a
            // declared-but-not-on-disk transitive and is dropped. In
            // manifest scope (path scans, or `--include-declared-deps`)
            // we still emit it with no outbound edges — matches the
            // pre-dual-SBOM behavior and gives source-tree users a
            // "what would be pulled in" view.
            //
            // See docs/design-notes.md, "Scope: artifact vs manifest
            // SBOM". TODO(sbom-kind): drive this from the kind flag.
            if include_declared_deps {
                if let Some(entry) = build_transitive_entry(
                    &group,
                    &artifact,
                    &version,
                    Vec::new(),
                    source_path,
                    Some(cache),
                ) {
                    out.push(entry);
                }
            }
            continue;
        };

        let upstream = parse_pom_xml(&bytes);
        // Build the effective POM: merges properties and
        // dependencyManagement up the full parent chain so deps
        // with no inline version or with `${...}` placeholders can
        // resolve through inherited declarations. Resolution
        // consumes parent/BOM bytes regardless of their source
        // (rootfs or host) — that fallback is required for
        // correctness when parent POMs aren't shipped in the image.
        let mut parent_seen: HashSet<String> = HashSet::new();
        let effective = build_effective_pom(upstream, cache, store, &mut parent_seen, &mut memo);

        // Collect this coord's declared outbound edges (artifactId
        // only, matching how the scan-wide resolver keys lookups).
        let edges: Vec<String> = effective
            .doc
            .dependencies
            .iter()
            .filter(|d| include_dev || !matches!(d.scope.as_deref(), Some("test")))
            // Only emit an edge when the dep's version can be resolved
            // (either inline, via properties, or via dep-management).
            // This matches Maven's behavior: an unresolvable version
            // would fail the build, so we don't fabricate the edge.
            .filter(|d| resolve_dep_version(d, &effective).is_some())
            .map(|d| d.artifact_id.clone())
            .collect();

        // Emit a component for this coord ONLY when the POM bytes
        // came from the scanned rootfs. Host-sourced POMs represent
        // the operator's laptop cache — their bytes aren't in the
        // scanned image, so the coord isn't an artifact in scope.
        // BFS continues regardless so transitive edges still resolve
        // through host-cached parent chains (correctness preserved).
        //
        // This is the decisive gate that stops host-cache coords
        // from leaking into scanned-image SBOMs (the 141 Maven FPs
        // on polyglot-builder-image were all host-resolved).
        // Artifact-presence gate (M1): even when the POM bytes are
        // from the rootfs, require a matching JAR on disk before
        // emitting. Rootfs `.m2/repository/` caches routinely
        // contain parent POMs and BOM aggregators
        // (`<packaging>pom</packaging>`) that have no distributable
        // JAR — those POMs legitimately drive resolution but
        // shouldn't surface as components.
        //
        // Two-source check:
        //   1. `on_disk_jar_coords` — JARs the scanner's
        //      `walk_jar_maven_meta` found outside `.m2/` (e.g.
        //      `/app/*.jar`, `/usr/share/java/*.jar`). Keyed on
        //      `(group, artifact)`, version-agnostic.
        //   2. `cache.has_rootfs_jar(g, a, v)` — JARs living INSIDE
        //      `.m2/repository/<path>/<artifact>-<version>.jar`.
        //      The artifact walker skips `.m2/` (hidden dir), so
        //      this filesystem check catches cache-resident JARs.
        //
        // When `on_disk_jar_coords` is `None` (tests that exercise
        // BFS in isolation without a JAR-walk context), gate is
        // off and Phase 1's `PomSource::Rootfs` check alone
        // decides emission.
        let jar_on_disk = match on_disk_jar_coords {
            Some(set) => {
                set.contains(&(group.clone(), artifact.clone()))
                    || cache.has_rootfs_jar(&group, &artifact, &version)
            }
            None => true,
        };
        if matches!(source, PomSource::Rootfs) && jar_on_disk {
            if let Some(entry) = build_transitive_entry(
                &group,
                &artifact,
                &version,
                edges,
                source_path,
                Some(cache),
            ) {
                out.push(entry);
            }
        } else {
            tracing::trace!(
                group = %group,
                artifact = %artifact,
                version = %version,
                "BFS resolved coord via host cache; consulted for resolution but not emitted",
            );
        }

        // Enqueue each resolvable upstream dep's concrete coord for
        // BFS continuation. Uses effective-POM resolution so
        // version-less deps (guava-parent's `<dependencyManagement>`
        // pattern) and `${...}` placeholders (jackson's
        // `${jackson.version.core}`) both resolve to concrete coords.
        for dep in &effective.doc.dependencies {
            if !include_dev && matches!(dep.scope.as_deref(), Some("test")) {
                continue;
            }
            let Some(g) = resolve_dep_group(dep, &effective) else {
                continue;
            };
            let Some(v) = resolve_dep_version(dep, &effective) else {
                continue;
            };
            if v.is_empty() {
                continue;
            }
            queue.push_back((g, dep.artifact_id.clone(), v));
        }
    }

    out
}

/// Build a `PackageDbEntry` for a BFS-discovered coord. `depends`
/// holds the outbound edges (artifactIds). `source_type = "transitive"`
/// marks this as cache-inferred rather than scanned-project-declared.
///
/// Probes the M2 cache for a sidecar SHA hash for this coord
/// (`<a>-<v>.jar.sha512` etc.) and attaches whichever is strongest.
/// `cache` may be `None` for synthetic / non-cache callers (tests).
fn build_transitive_entry(
    group: &str,
    artifact: &str,
    version: &str,
    depends: Vec<String>,
    source_path: &str,
    cache: Option<&MavenRepoCache>,
) -> Option<PackageDbEntry> {
    let purl = build_maven_purl(group, artifact, version)?;
    let hashes = cache
        .map(|c| c.read_artifact_hash(group, artifact, version))
        .unwrap_or_default();
    Some(PackageDbEntry {
        purl,
        name: artifact.to_string(),
        version: version.to_string(),
        arch: None,
        source_path: source_path.to_string(),
        depends,
        maintainer: None,
        licenses: Vec::new(),
        is_dev: None,
        requirement_range: None,
        source_type: Some("transitive".to_string()),
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
        hashes,
        sbom_tier: Some("source".to_string()),
    })
}

fn jar_pom_to_entry(
    p: &PomProperties,
    depends: Vec<String>,
    source_path: &str,
    sidecar_hash: Option<mikebom_common::types::hash::ContentHash>,
    archive_sha256: Option<mikebom_common::types::hash::ContentHash>,
    parent_purl: Option<String>,
    co_owned_by: Option<String>,
) -> Option<PackageDbEntry> {
    let purl = build_maven_purl(&p.group_id, &p.artifact_id, &p.version)?;
    let mut hashes: Vec<mikebom_common::types::hash::ContentHash> = Vec::new();
    hashes.extend(sidecar_hash);
    // `archive_sha256` is the SHA-256 of the JAR file on disk. When
    // the JAR is co-owned by an OS package-db reader (RPM/deb/apk),
    // the archive hash is more naturally attached to the OS
    // component (which "owns" the bytes); the Maven coord's identity
    // is the embedded pom.properties, not the archive. Dropping the
    // hash here keeps dedup cleaner — the OS reader's file-occurrence
    // hash remains authoritative.
    if co_owned_by.is_none() {
        hashes.extend(archive_sha256);
    }
    Some(PackageDbEntry {
        purl,
        name: p.artifact_id.clone(),
        version: p.version.clone(),
        arch: None,
        source_path: source_path.to_string(),
        depends,
        maintainer: None,
        licenses: Vec::new(),
        is_dev: None,
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
        parent_purl,
        npm_role: None,
        co_owned_by,
        hashes,
        sbom_tier: Some("analyzed".to_string()),
    })
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Backward-compat shim for tests. Delegates to [`read_with_claims`]
/// with empty claim sets. Production code goes through
/// `read_with_claims` directly via the package-db walker's claim set
/// so RPM-owned Maven JARs are skipped (conformance bug 2b).
#[cfg(test)]
pub fn read(rootfs: &Path, include_dev: bool) -> Vec<PackageDbEntry> {
    let claimed = std::collections::HashSet::new();
    #[cfg(unix)]
    let claimed_inodes = std::collections::HashSet::new();
    // Backward-compat shim. Defaults to include_declared_deps=true so
    // tests and other non-orchestrator callers get the pre-dual-SBOM
    // behavior (permissive — emit everything the POMs declare).
    // Production callers go through read_with_claims directly.
    // Discard the scan-target coord — backward-compat shim for
    // tests that only need the entries list.
    let (entries, _scan_target) = read_with_claims(
        rootfs,
        include_dev,
        true,
        &claimed,
        #[cfg(unix)]
        &claimed_inodes,
        None,
    );
    entries
}

/// Read Maven coords from the rootfs.
///
/// `include_declared_deps` gates emission of declared-but-not-on-disk
/// coords (see docs/design-notes.md, "Scope: artifact vs manifest
/// SBOM"). When **false** (strict artifact scope, default for image
/// scans): the pom.xml-declared direct-dep loop skips coords whose
/// JAR isn't in the JAR-walk coord_index AND whose .pom isn't in the
/// `.m2/repository/` cache; the BFS cache-miss branch in
/// `bfs_transitive_poms` also skips. When **true** (manifest scope,
/// default for path / source-tree scans): every declared coord is
/// emitted regardless of on-disk presence, matching the pre-flag
/// behavior — source-tree users get an SBOM of what WOULD be pulled
/// in on install/build.
///
/// TODO(sbom-kind): when `--sbom-kind {artifact, manifest}` lands as
/// a first-class CLI flag, this parameter becomes the kind selector
/// rather than a raw bool. Default auto-detection stays the same
/// (image → artifact, path → manifest).
pub fn read_with_claims(
    rootfs: &Path,
    include_dev: bool,
    include_declared_deps: bool,
    claimed: &std::collections::HashSet<std::path::PathBuf>,
    #[cfg(unix)] claimed_inodes: &std::collections::HashSet<(u64, u64)>,
    scan_target_name: Option<&str>,
) -> (Vec<PackageDbEntry>, Option<ScanTargetCoord>) {
    let mut out: Vec<PackageDbEntry> = Vec::new();
    let mut seen_purls: HashSet<String> = HashSet::new();
    // Populated when the JAR walker identifies a scan-subject
    // primary coord (target-name match or fat-jar heuristic). The
    // caller promotes this to `metadata.component` instead of the
    // generic placeholder.
    let mut scan_target_coord: Option<ScanTargetCoord> = None;
    let (pom_files, jar_files) = find_maven_artifacts(rootfs);
    // Discover M2 repo cache once per scan. Each dep's own pom.xml
    // sits at <repo>/<group-as-path>/<artifact>/<version>/<artifact>-<version>.pom;
    // fetching it gives us that dep's own <dependencies> block for
    // transitive edges.
    let repo_cache = MavenRepoCache::discover(rootfs);
    if repo_cache.total_roots() > 0 {
        tracing::debug!(
            rootfs = %rootfs.display(),
            repo_roots = repo_cache.total_roots(),
            "Maven repo cache discovered",
        );
    }
    // Unified POM bytestore: populated incrementally as we scan JARs
    // and fetch POMs. Parent-chain lookups check this first (covers
    // JAR-embedded parents) and fall back to the M2 cache on disk.
    let mut pom_store: PomStore = HashMap::new();

    // Walk JARs up front so their embedded pom.xml bytes land in
    // `pom_store` before BFS runs. This lets parent-chain resolution
    // find parents shipped in-JAR (e.g. uber-JARs that vendor their
    // full parent hierarchy).
    //
    // v7 (dual-identity): walk every JAR for embedded Maven meta,
    // including those whose on-disk path is already claimed by a
    // package-db reader (dpkg / apk / rpm). Fedora's `dnf install
    // maven` drops JARs at `/usr/share/java/*.jar` — the RPM owns
    // the bytes, but the JAR's `META-INF/maven/.../pom.properties`
    // carries a semantically distinct Maven identity
    // (ecosystem-independent GAV vs. distro-specific NEVRA) that
    // downstream tools legitimately need.
    //
    // Claimed JARs get a third field in `jar_meta`: the ecosystem
    // ("rpm" / "deb" / "apk") that co-owns the bytes. This
    // eventually flows into `PackageDbEntry.co_owned_by` so the CDX
    // emitter can tag the component with `mikebom:co-owned-by` for
    // provenance.
    //
    // The original conformance-bug-2b concern about empty versions
    // from unresolved `${project.version}` placeholders is already
    // handled upstream in `parse_pom_properties` — placeholder
    // versions return `None` and never surface as components.
    let mut jar_meta: Vec<(String, Vec<EmbeddedMavenMeta>, Option<String>)> = Vec::new();
    for jar_path in &jar_files {
        let co_owned_by = if crate::scan_fs::binary::is_path_claimed(
            jar_path,
            claimed,
            #[cfg(unix)]
            claimed_inodes,
        ) {
            // Which ecosystem claimed it? We don't currently surface
            // the owner identity from the claim set (it's a flat
            // `HashSet<PathBuf>`), so we pick a heuristic from the
            // on-disk path: paths under `/usr/share/java/` are
            // almost always RPM-owned on Fedora-family images;
            // anything else we tag generically. A future refinement
            // would wire owner identity through the claim machinery
            // (would need `HashMap<PathBuf, String>` from each
            // package-db reader).
            let path_str = jar_path.to_string_lossy();
            let ecosystem = if path_str.contains("/usr/share/java/")
                || path_str.contains("/usr/lib/java/")
            {
                "rpm"
            } else {
                "package-db"
            };
            tracing::debug!(
                path = %jar_path.display(),
                co_owned_by = ecosystem,
                "walking claimed JAR for embedded Maven meta (dual-identity)"
            );
            Some(ecosystem.to_string())
        } else {
            None
        };
        let meta = walk_jar_maven_meta(jar_path);
        if meta.is_empty() {
            continue;
        }
        for m in &meta {
            if let Some(ref bytes) = m.pom_xml_bytes {
                let key = coord_key(&m.coord.group_id, &m.coord.artifact_id, &m.coord.version);
                pom_store.entry(key).or_insert_with(|| bytes.clone());
            }
        }
        jar_meta.push((jar_path.to_string_lossy().into_owned(), meta, co_owned_by));
    }

    // On-disk coord index: `(group, artifact)` is "on disk" when either a
    // JAR with that coord was found or an `<artifact>-<version>.pom` sits
    // in the `.m2/repository/` cache. This index drives the
    // `include_declared_deps = false` gate below — a pom.xml-declared dep
    // is emitted only when its coord has actual bytes backing it.
    //
    // Cache-HIT .pom counts as "on disk" even without a .jar: the POM
    // itself is a real artifact and the dep's transitive edges can still
    // be resolved through it.
    //
    // See docs/design-notes.md, "Scope: artifact vs manifest SBOM" for
    // the principle; this is the enforcement point for Maven.
    let mut on_disk_coords: HashSet<(String, String)> = HashSet::new();
    for (_src, meta_list, _co_owned) in &jar_meta {
        for m in meta_list {
            on_disk_coords.insert((m.coord.group_id.clone(), m.coord.artifact_id.clone()));
        }
    }
    // Stricter JAR-only set (M1). Drives the BFS transitive-emission
    // gate: a coord only emits as `source_type="transitive"` when a
    // matching JAR was found in the scanned rootfs. POM-only coords
    // (parent POMs, BOM aggregators with `<packaging>pom</packaging>`)
    // legitimately drive BFS traversal for resolution but aren't
    // distributable artifacts — they shouldn't surface as components.
    // Built from `jar_meta` alone, before cached_pom_coords pulls in
    // POM-only entries.
    let on_disk_jar_coords: HashSet<(String, String)> = on_disk_coords.clone();
    // Same cap as the unconditional `.m2` walk below; populating the
    // coord set is cheap enough that we don't need a separate budget.
    const MAVEN_CACHE_POM_LIMIT: usize = 10_000;
    let cached_pom_coords = repo_cache.walk_rootfs_poms(MAVEN_CACHE_POM_LIMIT);
    for (group, artifact, _version) in &cached_pom_coords {
        on_disk_coords.insert((group.clone(), artifact.clone()));
    }

    for pom_path in pom_files {
        let Ok(bytes) = std::fs::read(&pom_path) else {
            continue;
        };
        let doc = parse_pom_xml(&bytes);
        let source_path = pom_path.to_string_lossy().into_owned();
        // Intentionally NOT emitting the project's own self_coord as a
        // component — it's the workspace root being scanned, not a
        // dependency consumed by it. This mirrors the cargo workspace
        // filter (`pkg.source.is_none()` skip at
        // `scan_fs/package_db/cargo.rs`) and the npm workspace-root
        // skip: only declared deps of the project surface as
        // components, never the project itself.
        //
        // Also note: the workspace-root coord is often unqualified
        // (e.g. `1.0-SNAPSHOT`), which conformance frameworks flag as
        // false-positive dependency claims — see bug report
        // `runs/mikebom-2026-04-21-comparison.md` §1 for the polyglot
        // fixture case.
        // Build the project's own effective POM so direct deps with
        // no inline version or `${foo}`-placeholder versions (both
        // common when the project inherits from a parent/BOM) can
        // resolve through the parent chain.
        let mut project_seen: HashSet<String> = HashSet::new();
        let mut project_memo: EffectivePomMemo = HashMap::new();
        let project_eff = build_effective_pom(
            doc.clone(),
            &repo_cache,
            &pom_store,
            &mut project_seen,
            &mut project_memo,
        );

        // Direct deps from the scanned project's pom.xml. Each becomes a
        // component with source_type = "workspace"; its outbound edges
        // are populated from the BFS below (which ALSO walks the direct
        // deps' coords, so direct and transitive nodes share a
        // consistent edge shape).
        let mut direct_entries: Vec<(PomDependency, PackageDbEntry)> = Vec::new();
        let mut bfs_seeds: Vec<(String, String, String)> = Vec::new();
        for dep in &doc.dependencies {
            let Some(entry) =
                pom_dep_to_entry(dep, &doc, &source_path, include_dev, Some(&repo_cache))
            else {
                continue;
            };
            // Resolve the dep's concrete (group, artifact, version)
            // through the effective POM. `group` drives both the BFS
            // seed and the on-disk gate below.
            let resolved_group = resolve_dep_group(dep, &project_eff);
            let resolved_version = resolve_dep_version(dep, &project_eff);

            // Dual-SBOM gate: in artifact scope (image scan, default),
            // skip pom.xml-declared deps whose coord has no bytes on
            // disk. Manifest scope (path scan, or `--include-declared-deps`)
            // emits everything. See docs/design-notes.md, "Scope:
            // artifact vs manifest SBOM".
            //
            // TODO(sbom-kind): when `--sbom-kind {artifact,manifest}`
            // lands, drive this gate from the kind rather than a raw
            // bool flag.
            let on_disk = resolved_group
                .as_ref()
                .map(|g| on_disk_coords.contains(&(g.clone(), dep.artifact_id.clone())))
                .unwrap_or(false);
            let emit = include_declared_deps || on_disk;

            // Seed BFS with the concrete (group, artifact, version) —
            // effective POM fills in values from parent depMgmt or
            // inherited properties. Drop the seed when either can't
            // be resolved (no concrete coord, no cache lookup possible).
            if let (Some(group), Some(version)) = (resolved_group, resolved_version) {
                if !version.is_empty() {
                    bfs_seeds.push((group, dep.artifact_id.clone(), version));
                }
            }
            if emit {
                direct_entries.push((dep.clone(), entry));
            }
        }

        // BFS the M2 cache from every direct-dep seed. Uses the unified
        // POM store for parent-chain lookups so BOM imports and
        // JAR-embedded parents resolve alongside on-disk cached poms.
        let bfs_entries = bfs_transitive_poms(
            &repo_cache,
            &pom_store,
            &bfs_seeds,
            include_dev,
            include_declared_deps,
            &source_path,
            Some(&on_disk_jar_coords),
        );

        // For each direct-dep entry, transplant the BFS's computed
        // `depends` onto it (the BFS walked this coord too) so direct
        // and transitive nodes share a consistent edge shape. Keep
        // the `source_type = "workspace"` marker.
        let bfs_index: HashMap<String, Vec<String>> = bfs_entries
            .iter()
            .map(|e| (e.purl.as_str().to_string(), e.depends.clone()))
            .collect();
        for (_dep, mut entry) in direct_entries {
            let key = entry.purl.as_str().to_string();
            if let Some(computed_deps) = bfs_index.get(&key) {
                entry.depends = computed_deps.clone();
            }
            if seen_purls.insert(key) {
                out.push(entry);
            }
        }
        // Append the transitive entries (deduped against direct coords
        // via PURL so we never emit the same coord twice).
        for entry in bfs_entries {
            let key = entry.purl.as_str().to_string();
            if seen_purls.insert(key) {
                out.push(entry);
            }
        }
    }

    // Unconditional `.m2` cache walk — closes the coverage gap where
    // the scan finds no project `pom.xml` and no packed-JAR metadata
    // (e.g. shaded uber-JARs that strip `META-INF/maven/`, or
    // container images pre-warmed with a `.m2/repository/` but no
    // sources). Each cached `<artifact>-<version>.pom` seeds the BFS;
    // it then fetches each coord's pom from the cache, parses its
    // declared deps, and extends the transitive closure across the
    // full cache.
    //
    // Ordering matters: runs AFTER the pom.xml loop so any direct-dep
    // coord emitted as `source_type="workspace"` wins over the
    // cache-walker's `"transitive"` tagging via the `seen_purls`
    // dedup. JAR-meta emission below also wins since it runs after.
    //
    // Only rootfs-scoped roots are walked. Host-scoped roots
    // (`$HOME/.m2`, `$M2_REPO`, `$MAVEN_HOME`) are still used by
    // `read_pom` for BFS lookups but never walked wholesale — a dev
    // running mikebom against a project fixture shouldn't drag every
    // artifact on their laptop into the output.
    // `cached_pom_coords` was populated earlier (before the pom.xml
    // loop) to build the on-disk coord index — reuse it as the BFS seed
    // list to avoid walking `.m2/repository/` twice per scan.
    let cache_seeds = cached_pom_coords;
    if !cache_seeds.is_empty() {
        tracing::info!(
            cache_seeds = cache_seeds.len(),
            "seeding Maven BFS from unconditional .m2 cache walk",
        );
        let cache_source_path = rootfs.to_string_lossy().into_owned();
        let cache_entries = bfs_transitive_poms(
            &repo_cache,
            &pom_store,
            &cache_seeds,
            include_dev,
            include_declared_deps,
            &cache_source_path,
            Some(&on_disk_jar_coords),
        );
        for entry in cache_entries {
            let key = entry.purl.as_str().to_string();
            if seen_purls.insert(key) {
                out.push(entry);
            }
        }
    }

    // Each JAR carries its own pom.properties (identity) and, when it's
    // non-shaded, its own pom.xml (declared deps). The coord index
    // `(group, artifact) -> version` tells us exactly which versions
    // are on disk, so a JAR's declared dep on `(g, a)` with no inline
    // version still resolves to a concrete edge target via whatever's
    // present locally. Deps with no matching JAR on disk are dropped
    // (honest: "this dep isn't here").
    //
    // `jar_meta` was populated earlier (before the project pom loop)
    // so its embedded pom.xml bytes already feed `pom_store`.
    let mut coord_index: HashMap<(String, String), String> = HashMap::new();
    for (_src, meta_list, _co_owned) in &jar_meta {
        for m in meta_list {
            coord_index
                .entry((m.coord.group_id.clone(), m.coord.artifact_id.clone()))
                .or_insert_with(|| m.coord.version.clone());
        }
    }
    for (source_path, meta_list, co_owned_by) in jar_meta {
        // First, find the primary coord's PURL (if any) so vendored
        // children in the same JAR can point their `parent_purl` at it.
        // A shade-plugin fat-jar has exactly one primary (is_primary ==
        // true, matched against the JAR filename's
        // `<artifactId>-<version>` stem in walk_jar_maven_meta) and N
        // vendored non-primary coords. A non-shaded simple JAR has a
        // single primary with no vendored children. A rare JAR with no
        // recognizable primary gets all coords emitted flat (no nesting
        // possible without a parent PURL to attach).
        let primary_purl: Option<String> = meta_list
            .iter()
            .find(|m| m.is_primary)
            .and_then(|m| {
                build_maven_purl(
                    &m.coord.group_id,
                    &m.coord.artifact_id,
                    &m.coord.version,
                )
            })
            .map(|p| p.as_str().to_string());

        for meta in &meta_list {
            // Resolve each declared dep against the disk-observed
            // coord index — use whatever version is actually here.
            // Drop test-scope unless include_dev; drop deps with no
            // matching JAR on disk (nothing to edge to).
            let depends: Vec<String> = meta
                .declared_deps
                .iter()
                .filter(|d| include_dev || !matches!(d.scope.as_deref(), Some("test")))
                .filter_map(|d| {
                    let key = (d.group_id.clone(), d.artifact_id.clone());
                    coord_index.get(&key).map(|_v| d.artifact_id.clone())
                })
                .collect();
            // Scan-target filter (Fix B + M3): the primary coord of
            // the artifact being scanned is the SBOM subject, not a
            // dependency. It belongs in CDX's `metadata.component`,
            // not `components[]`. Vendored children of the same JAR
            // stay emitted with their `parent_purl` pointing at the
            // (now-absent) primary; the CDX builder's orphan-
            // fallback path at `builder.rs:build_components` demotes
            // them to top-level.
            //
            // Two heuristics, either fires:
            //
            // 1. **target_name match (Fix B).** Case-insensitive
            //    exact equality between the primary coord's
            //    artifactId and the scan target name. Covers the
            //    common case where the built artifact's name
            //    matches the image tag.
            //
            // 2. **Unclaimed fat-jar heuristic (M3 + post-PR-#2
            //    refinement).** The JAR contains ≥2
            //    `META-INF/maven/<g>/<a>/pom.properties` entries —
            //    classic shade-plugin fat-jar signature with one
            //    primary + N vendored children. An *unclaimed*
            //    fat-jar on disk is almost certainly the build
            //    output, not a dependency. Post-PR-#2, the JAR
            //    walker no longer skips OS-claimed JARs (they emit
            //    with `co_owned_by = "rpm"/"deb"/"apk"` tags), so
            //    this heuristic gates on `co_owned_by.is_none()`:
            //    distro-shipped fat JARs like Fedora's
            //    `/usr/share/java/guava/guava.jar` must NOT be
            //    treated as the scan subject.
            //
            // Surfaces the suppressed coord through
            // `scan_target_coord` back to the caller for
            // `metadata.component` promotion.
            if meta.is_primary {
                let target_name_matches = scan_target_name
                    .map(|t| meta.coord.artifact_id.eq_ignore_ascii_case(t))
                    .unwrap_or(false);
                // Fat-jar heuristic (M3 + refinement): a JAR with ≥2
                // embedded META-INF/maven/ entries is almost always a
                // shade-plugin fat-jar, i.e. a build output that IS
                // the scan subject. BUT after the PR #2 claim-skip
                // lift, this loop now also runs on RPM/deb/apk-owned
                // JARs — distro-shipped fat JARs like Fedora's
                // `/usr/share/java/guava/guava.jar` (which bundles
                // `failureaccess` etc.). Those are dependencies of
                // the scan target, not the scan subject, so the
                // heuristic must NOT suppress their primary coord.
                //
                // Gate on `co_owned_by.is_none()`: only unclaimed
                // fat JARs are scan-subject candidates. Claimed fat
                // JARs emit their primary normally (carrying the
                // `mikebom:co-owned-by = rpm` tag PR #2 established).
                let is_unclaimed_fat_jar =
                    meta_list.len() >= 2 && co_owned_by.is_none();
                if target_name_matches || is_unclaimed_fat_jar {
                    tracing::debug!(
                        artifact_id = %meta.coord.artifact_id,
                        version = %meta.coord.version,
                        reason = if target_name_matches {
                            "target-name-match"
                        } else {
                            "unclaimed-fat-jar-heuristic"
                        },
                        "suppressing scan-target primary coord from components[]"
                    );
                    // Record the suppressed coord for metadata.component
                    // promotion. If multiple primaries fire the
                    // heuristic (rare: image contains several fat
                    // JARs), the first-seen wins; rest are still
                    // suppressed but logged.
                    if scan_target_coord.is_none() {
                        scan_target_coord = Some(ScanTargetCoord {
                            group: meta.coord.group_id.clone(),
                            artifact: meta.coord.artifact_id.clone(),
                            version: meta.coord.version.clone(),
                        });
                    } else {
                        tracing::warn!(
                            artifact_id = %meta.coord.artifact_id,
                            "multiple scan-target primary coords detected; keeping first-seen for metadata.component",
                        );
                    }
                    continue;
                }
            }
            // Primary coord stays top-level (parent_purl = None); every
            // other coord in the same JAR nests under the primary via
            // its parent_purl.
            let parent_purl = if meta.is_primary {
                None
            } else {
                primary_purl.clone()
            };
            let Some(entry) = jar_pom_to_entry(
                &meta.coord,
                depends,
                &source_path,
                meta.sidecar_hash.clone(),
                meta.archive_sha256.clone(),
                parent_purl,
                co_owned_by.clone(),
            ) else {
                continue;
            };
            // Dedup-key includes parent_purl so the same (name, version)
            // coord vendored in two different fat-jars surfaces twice
            // (once nested under each parent) rather than collapsing
            // to one. CDX nested-components model is the intent.
            let key = format!(
                "{}#{}",
                entry.purl.as_str(),
                entry.parent_purl.as_deref().unwrap_or(""),
            );
            if seen_purls.insert(key) {
                out.push(entry);
            }
        }
    }

    if !out.is_empty() {
        tracing::info!(
            rootfs = %rootfs.display(),
            entries = out.len(),
            "parsed Maven coordinates",
        );
    }
    (out, scan_target_coord)
}

fn find_maven_artifacts(rootfs: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut poms = Vec::new();
    let mut jars = Vec::new();
    walk_for_maven(rootfs, 0, &mut poms, &mut jars);
    (poms, jars)
}

fn walk_for_maven(dir: &Path, depth: usize, poms: &mut Vec<PathBuf>, jars: &mut Vec<PathBuf>) {
    if depth >= MAX_PROJECT_ROOT_DEPTH {
        // Even past the depth cap, still scan for archives in the
        // current dir — JARs can be anywhere.
    }
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if let Ok(meta) = entry.metadata() {
            if meta.is_file() {
                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    let name_lower = name.to_ascii_lowercase();
                    if name_lower == "pom.xml" {
                        poms.push(path.clone());
                    } else if name_lower.ends_with(".jar")
                        || name_lower.ends_with(".war")
                        || name_lower.ends_with(".ear")
                    {
                        jars.push(path.clone());
                    }
                }
                continue;
            }
            if meta.is_dir() {
                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    if should_skip_descent(name) {
                        continue;
                    }
                }
                if depth < MAX_PROJECT_ROOT_DEPTH {
                    walk_for_maven(&path, depth + 1, poms, jars);
                }
            }
        }
    }
}

fn should_skip_descent(name: &str) -> bool {
    if name.starts_with('.') {
        return true;
    }
    matches!(
        name,
        "node_modules" | "vendor" | "target/classes" | "dist" | "__pycache__"
    )
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_pom() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.2.3</version>
</project>"#;
        let doc = parse_pom_xml(pom.as_bytes());
        assert_eq!(
            doc.self_coord,
            Some((
                "com.example".to_string(),
                "app".to_string(),
                "1.2.3".to_string(),
            ))
        );
    }

    #[test]
    fn parses_dependencies_block() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <groupId>g</groupId>
  <artifactId>a</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.1.3-jre</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>"#;
        let doc = parse_pom_xml(pom.as_bytes());
        assert_eq!(doc.dependencies.len(), 2);
        let guava = doc
            .dependencies
            .iter()
            .find(|d| d.artifact_id == "guava")
            .unwrap();
        assert_eq!(guava.version.as_deref(), Some("32.1.3-jre"));
        let junit = doc
            .dependencies
            .iter()
            .find(|d| d.artifact_id == "junit")
            .unwrap();
        assert_eq!(junit.scope.as_deref(), Some("test"));
    }

    #[test]
    fn property_resolver_replaces_project_version() {
        let doc = PomXmlDocument {
            self_coord: Some(("g".into(), "a".into(), "1.2.3".into())),
            ..Default::default()
        };
        let v = resolve_maven_property("${project.version}", &doc);
        assert_eq!(v, MavenVersion::Resolved("1.2.3".to_string()));
    }

    #[test]
    fn property_resolver_replaces_user_property() {
        let mut doc = PomXmlDocument::default();
        doc.properties.insert("guava.version".into(), "32.1.3-jre".into());
        let v = resolve_maven_property("${guava.version}", &doc);
        assert_eq!(v, MavenVersion::Resolved("32.1.3-jre".to_string()));
    }

    #[test]
    fn property_resolver_returns_placeholder_when_unresolvable() {
        let doc = PomXmlDocument::default();
        let v = resolve_maven_property("${nobody.set.this}", &doc);
        assert_eq!(
            v,
            MavenVersion::Placeholder("${nobody.set.this}".to_string())
        );
    }

    #[test]
    fn parses_pom_properties_file() {
        let body = "#Generated by Maven\nversion=32.1.3\ngroupId=com.google.guava\nartifactId=guava\n";
        let p = parse_pom_properties(body).unwrap();
        assert_eq!(p.group_id, "com.google.guava");
        assert_eq!(p.artifact_id, "guava");
        assert_eq!(p.version, "32.1.3");
    }

    #[test]
    fn parse_pom_properties_rejects_unresolved_placeholder() {
        // Some RPM-packaged Maven JARs (Fedora's /usr/share/java/*.jar)
        // ship pom.properties with unresolved build-time placeholders.
        // Emitting these would yield `pkg:maven/g/a@${project.version}`
        // garbage PURLs.
        let body = "version=${project.version}\ngroupId=org.apache.commons\nartifactId=commons-io\n";
        assert!(parse_pom_properties(body).is_none());
    }

    #[test]
    fn parse_pom_properties_rejects_empty_version() {
        let body = "version=\ngroupId=org.apache.commons\nartifactId=commons-io\n";
        assert!(parse_pom_properties(body).is_none());
    }

    #[test]
    fn parse_pom_properties_rejects_nested_placeholder() {
        // Nested or compound placeholders like `${foo}-SNAPSHOT` are
        // still unresolved — guard matches the `${` substring anywhere
        // in the version.
        let body = "version=${foo}-SNAPSHOT\ngroupId=g\nartifactId=a\n";
        assert!(parse_pom_properties(body).is_none());
    }

    // --- JAR-embedded pom.xml walker -----------------------------------

    fn write_jar(
        path: &Path,
        entries: &[(&str, &[u8])],
    ) {
        use std::io::Write;
        let file = std::fs::File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, body) in entries {
            zip.start_file(*name, opts).unwrap();
            zip.write_all(body).unwrap();
        }
        zip.finish().unwrap();
    }

    fn pom_properties(g: &str, a: &str, v: &str) -> Vec<u8> {
        format!("#Generated by Maven\ngroupId={g}\nartifactId={a}\nversion={v}\n").into_bytes()
    }

    fn pom_xml_with_deps(g: &str, a: &str, v: &str, deps: &[(&str, &str, &str)]) -> Vec<u8> {
        let mut xml = format!(
            "<?xml version=\"1.0\"?><project><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version>"
        );
        if !deps.is_empty() {
            xml.push_str("<dependencies>");
            for (dg, da, dv) in deps {
                xml.push_str(&format!(
                    "<dependency><groupId>{dg}</groupId><artifactId>{da}</artifactId><version>{dv}</version></dependency>"
                ));
            }
            xml.push_str("</dependencies>");
        }
        xml.push_str("</project>");
        xml.into_bytes()
    }

    #[test]
    fn walk_jar_collects_coord_and_embedded_deps() {
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("guava.jar");
        write_jar(
            &jar,
            &[
                (
                    "META-INF/maven/com.google.guava/guava/pom.properties",
                    &pom_properties("com.google.guava", "guava", "32.1.3-jre"),
                ),
                (
                    "META-INF/maven/com.google.guava/guava/pom.xml",
                    &pom_xml_with_deps(
                        "com.google.guava",
                        "guava",
                        "32.1.3-jre",
                        &[("com.google.guava", "failureaccess", "1.0.1")],
                    ),
                ),
            ],
        );
        let meta = walk_jar_maven_meta(&jar);
        assert_eq!(meta.len(), 1);
        assert_eq!(meta[0].coord.artifact_id, "guava");
        assert_eq!(meta[0].declared_deps.len(), 1);
        assert_eq!(meta[0].declared_deps[0].artifact_id, "failureaccess");
    }

    #[test]
    fn walk_jar_attaches_sidecar_hash_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("guava.jar");
        write_jar(
            &jar,
            &[(
                "META-INF/maven/com.google.guava/guava/pom.properties",
                &pom_properties("com.google.guava", "guava", "32.1.3-jre"),
            )],
        );
        let hex = "b".repeat(64);
        std::fs::write(dir.path().join("guava.jar.sha256"), &hex).unwrap();

        let meta = walk_jar_maven_meta(&jar);
        assert_eq!(meta.len(), 1);
        let sidecar = meta[0]
            .sidecar_hash
            .as_ref()
            .expect("sidecar hash must be attached");
        assert_eq!(sidecar.algorithm, HashAlgorithm::Sha256);
        assert_eq!(sidecar.value.as_str(), &hex);
    }

    #[test]
    fn walk_jar_no_sidecar_still_computes_archive_sha256() {
        // Even when no `.sha256`/`.sha512`/`.sha1` sidecar exists
        // alongside the JAR (the common container-image case where
        // ~/.m2 isn't present), the walker stream-hashes the JAR
        // and attaches a SHA-256. Maven sidecars are usually SHA-1
        // only; the computed SHA-256 is what lifts sbomqs
        // `comp_with_strong_checksums` out of 0/10.
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("guava.jar");
        write_jar(
            &jar,
            &[(
                "META-INF/maven/com.google.guava/guava/pom.properties",
                &pom_properties("com.google.guava", "guava", "32.1.3-jre"),
            )],
        );
        let meta = walk_jar_maven_meta(&jar);
        assert_eq!(meta.len(), 1);
        assert!(meta[0].sidecar_hash.is_none());
        let sha256 = meta[0]
            .archive_sha256
            .as_ref()
            .expect("archive SHA-256 must be computed when no sidecar is present");
        assert_eq!(sha256.algorithm, HashAlgorithm::Sha256);
        assert_eq!(sha256.value.as_str().len(), 64);
    }

    #[test]
    fn walk_jar_with_sha1_sidecar_also_gets_sha256() {
        // When a SHA-1 sidecar (Maven Central default) exists, the
        // walker emits BOTH the sidecar hash AND a computed SHA-256,
        // so consumers can pick the strongest algorithm per
        // component. sbomqs grades SHA-256 as strong and SHA-1 as
        // weak; both land on `entry.hashes`.
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("guava.jar");
        write_jar(
            &jar,
            &[(
                "META-INF/maven/com.google.guava/guava/pom.properties",
                &pom_properties("com.google.guava", "guava", "32.1.3-jre"),
            )],
        );
        let sha1_hex = "a".repeat(40);
        std::fs::write(dir.path().join("guava.jar.sha1"), &sha1_hex).unwrap();
        let meta = walk_jar_maven_meta(&jar);
        assert_eq!(meta.len(), 1);
        let sidecar = meta[0].sidecar_hash.as_ref().expect("sha1 sidecar");
        assert_eq!(sidecar.algorithm, HashAlgorithm::Sha1);
        let sha256 = meta[0].archive_sha256.as_ref().expect("computed sha256");
        assert_eq!(sha256.algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn walk_fat_jar_only_primary_coord_gets_archive_sha256() {
        // Fat / shaded JARs ship META-INF/maven dirs for their
        // vendored dependencies. The archive SHA-256 describes the
        // outer JAR, not the vendored artifacts, so it attaches only
        // to the primary coord (matched by filename stem).
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("myapp-1.0.jar");
        write_jar(
            &jar,
            &[
                (
                    "META-INF/maven/com.example/myapp/pom.properties",
                    &pom_properties("com.example", "myapp", "1.0"),
                ),
                (
                    "META-INF/maven/com.google.guava/guava/pom.properties",
                    &pom_properties("com.google.guava", "guava", "32.1.3-jre"),
                ),
            ],
        );
        let meta = walk_jar_maven_meta(&jar);
        assert_eq!(meta.len(), 2);
        let primary = meta
            .iter()
            .find(|m| m.coord.artifact_id == "myapp")
            .expect("primary coord present");
        let vendored = meta
            .iter()
            .find(|m| m.coord.artifact_id == "guava")
            .expect("vendored coord present");
        assert!(primary.archive_sha256.is_some());
        assert!(vendored.archive_sha256.is_none());
    }

    #[test]
    fn walk_jar_without_pom_xml_returns_empty_deps() {
        // A JAR that ships pom.properties but no pom.xml — should still
        // emit a coord entry with empty declared_deps.
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("bare.jar");
        write_jar(
            &jar,
            &[(
                "META-INF/maven/com.example/bare/pom.properties",
                &pom_properties("com.example", "bare", "1.0"),
            )],
        );
        let meta = walk_jar_maven_meta(&jar);
        assert_eq!(meta.len(), 1);
        assert!(meta[0].declared_deps.is_empty());
    }

    #[test]
    fn walk_fat_jar_collects_one_meta_per_vendored_artifact() {
        // Shaded / uber JAR: multiple META-INF/maven/<g>/<a>/ directories,
        // each with its own pom.properties + pom.xml. Each yields a
        // separate EmbeddedMavenMeta.
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("uber.jar");
        write_jar(
            &jar,
            &[
                (
                    "META-INF/maven/com.example/foo/pom.properties",
                    &pom_properties("com.example", "foo", "1.0"),
                ),
                (
                    "META-INF/maven/com.example/foo/pom.xml",
                    &pom_xml_with_deps(
                        "com.example",
                        "foo",
                        "1.0",
                        &[("com.example", "bar", "2.0")],
                    ),
                ),
                (
                    "META-INF/maven/com.example/bar/pom.properties",
                    &pom_properties("com.example", "bar", "2.0"),
                ),
                (
                    "META-INF/maven/com.example/bar/pom.xml",
                    &pom_xml_with_deps("com.example", "bar", "2.0", &[]),
                ),
            ],
        );
        let meta = walk_jar_maven_meta(&jar);
        assert_eq!(meta.len(), 2);
        let foo = meta.iter().find(|m| m.coord.artifact_id == "foo").unwrap();
        let bar = meta.iter().find(|m| m.coord.artifact_id == "bar").unwrap();
        assert_eq!(foo.declared_deps.len(), 1);
        assert!(bar.declared_deps.is_empty());
    }

    #[test]
    fn jar_scan_builds_edges_from_disk_observed_coord_index() {
        // End-to-end via `read()`: three JARs on disk — foo (declares
        // bar), bar (declares baz), baz (leaf). The coord index built
        // from disk tells us which versions are actually here; the
        // emitted edges use those.
        let dir = tempfile::tempdir().unwrap();
        write_jar(
            &dir.path().join("foo-1.0.jar"),
            &[
                (
                    "META-INF/maven/ex/foo/pom.properties",
                    &pom_properties("ex", "foo", "1.0"),
                ),
                (
                    "META-INF/maven/ex/foo/pom.xml",
                    &pom_xml_with_deps("ex", "foo", "1.0", &[("ex", "bar", "2.0")]),
                ),
            ],
        );
        write_jar(
            &dir.path().join("bar-2.0.jar"),
            &[
                (
                    "META-INF/maven/ex/bar/pom.properties",
                    &pom_properties("ex", "bar", "2.0"),
                ),
                (
                    "META-INF/maven/ex/bar/pom.xml",
                    &pom_xml_with_deps("ex", "bar", "2.0", &[("ex", "baz", "3.0")]),
                ),
            ],
        );
        write_jar(
            &dir.path().join("baz-3.0.jar"),
            &[(
                "META-INF/maven/ex/baz/pom.properties",
                &pom_properties("ex", "baz", "3.0"),
            )],
        );
        let entries = read(dir.path(), false);
        let foo = entries.iter().find(|e| e.name == "foo").unwrap();
        assert_eq!(foo.depends, vec!["bar".to_string()]);
        let bar = entries.iter().find(|e| e.name == "bar").unwrap();
        assert_eq!(bar.depends, vec!["baz".to_string()]);
        let baz = entries.iter().find(|e| e.name == "baz").unwrap();
        assert!(baz.depends.is_empty());
        // JAR-sourced entries are analyzed-tier.
        for e in [foo, bar, baz] {
            assert_eq!(e.sbom_tier.as_deref(), Some("analyzed"));
        }
    }

    #[test]
    fn jar_scan_drops_edges_with_no_matching_jar_on_disk() {
        // foo declares a dep on `missing`, but no JAR for `missing`
        // exists on disk. The edge is dropped — honest about what
        // we actually have.
        let dir = tempfile::tempdir().unwrap();
        write_jar(
            &dir.path().join("foo-1.0.jar"),
            &[
                (
                    "META-INF/maven/ex/foo/pom.properties",
                    &pom_properties("ex", "foo", "1.0"),
                ),
                (
                    "META-INF/maven/ex/foo/pom.xml",
                    &pom_xml_with_deps("ex", "foo", "1.0", &[("ex", "missing", "2.0")]),
                ),
            ],
        );
        let entries = read(dir.path(), false);
        let foo = entries.iter().find(|e| e.name == "foo").unwrap();
        // missing wasn't observed on disk — edge dropped.
        assert!(foo.depends.is_empty());
        assert!(entries.iter().all(|e| e.name != "missing"));
    }

    #[test]
    fn jar_scan_uses_on_disk_version_even_when_pom_xml_declares_different() {
        // foo's pom.xml says "depends on bar@2.0", but the bar JAR
        // on disk is at 2.5. The edge target's identity is by
        // (group, artifact) — we resolve to whatever's actually on
        // disk, which is bar@2.5.
        let dir = tempfile::tempdir().unwrap();
        write_jar(
            &dir.path().join("foo-1.0.jar"),
            &[
                (
                    "META-INF/maven/ex/foo/pom.properties",
                    &pom_properties("ex", "foo", "1.0"),
                ),
                (
                    "META-INF/maven/ex/foo/pom.xml",
                    &pom_xml_with_deps("ex", "foo", "1.0", &[("ex", "bar", "2.0")]),
                ),
            ],
        );
        write_jar(
            &dir.path().join("bar-2.5.jar"),
            &[(
                "META-INF/maven/ex/bar/pom.properties",
                &pom_properties("ex", "bar", "2.5"),
            )],
        );
        let entries = read(dir.path(), false);
        let bar = entries.iter().find(|e| e.name == "bar").unwrap();
        // Version is the one on disk, not the one declared.
        assert_eq!(bar.version, "2.5");
        let foo = entries.iter().find(|e| e.name == "foo").unwrap();
        // Edge target is artifactId "bar"; the resolver in scan_fs
        // matches on ecosystem + name and finds bar@2.5.
        assert_eq!(foo.depends, vec!["bar".to_string()]);
    }

    #[test]
    fn read_pom_xml_emits_source_tier() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pom.xml"),
            r#"<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.1.3-jre</version>
    </dependency>
  </dependencies>
</project>"#,
        )
        .unwrap();
        let entries = read(dir.path(), false);
        // Workspace root ("app") must NOT surface — same semantics as
        // cargo + npm workspace roots. Only the declared dep ("guava")
        // is emitted. See bug fix in `read_with_claims`: the project's
        // own pom.xml coord is the scan target, not a dependency.
        assert!(!entries.iter().any(|e| e.name == "app"));
        assert!(entries.iter().any(|e| e.name == "guava"));
        for e in &entries {
            assert_eq!(e.sbom_tier.as_deref(), Some("source"));
        }
    }

    #[test]
    fn read_empty_rootfs_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(dir.path(), false).is_empty());
    }

    // --- M2 repo cache walker --------------------------------------------

    fn write_cached_pom(
        repo_root: &Path,
        group: &str,
        artifact: &str,
        version: &str,
        body: &str,
    ) {
        let group_path = group.replace('.', "/");
        let rel = format!("{group_path}/{artifact}/{version}/{artifact}-{version}.pom");
        let full = repo_root.join(&rel);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&full, body).unwrap();
    }

    #[test]
    fn cache_read_pom_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "com.google.guava",
            "guava",
            "32.1.3-jre",
            r#"<?xml version="1.0"?>
<project>
  <groupId>com.google.guava</groupId>
  <artifactId>guava</artifactId>
  <version>32.1.3-jre</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>failureaccess</artifactId>
      <version>1.0.1</version>
    </dependency>
  </dependencies>
</project>"#,
        );
        let cache = MavenRepoCache::for_tests(vec![repo_root.clone()]);
        let (bytes, source) = cache
            .read_pom("com.google.guava", "guava", "32.1.3-jre")
            .expect("cached pom readable");
        assert!(std::str::from_utf8(&bytes).unwrap().contains("failureaccess"));
        assert_eq!(source, PomSource::Rootfs);
    }

    #[test]
    fn bfs_walks_three_deep_chain() {
        // cache: A(1) → B(2) → C(3) → D(4), each cached.
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "ex",
            "a",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>a</artifactId><version>1</version>
<dependencies><dependency><groupId>ex</groupId><artifactId>b</artifactId><version>2</version></dependency></dependencies>
</project>"#,
        );
        write_cached_pom(
            &repo_root,
            "ex",
            "b",
            "2",
            r#"<project><groupId>ex</groupId><artifactId>b</artifactId><version>2</version>
<dependencies><dependency><groupId>ex</groupId><artifactId>c</artifactId><version>3</version></dependency></dependencies>
</project>"#,
        );
        write_cached_pom(
            &repo_root,
            "ex",
            "c",
            "3",
            r#"<project><groupId>ex</groupId><artifactId>c</artifactId><version>3</version>
<dependencies><dependency><groupId>ex</groupId><artifactId>d</artifactId><version>4</version></dependency></dependencies>
</project>"#,
        );
        write_cached_pom(
            &repo_root,
            "ex",
            "d",
            "4",
            r#"<project><groupId>ex</groupId><artifactId>d</artifactId><version>4</version></project>"#,
        );
        let cache = MavenRepoCache::for_tests(vec![repo_root.clone()]);
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex".into(), "a".into(), "1".into())],
            false,
            true,
            "/p/pom.xml",
            None,
        );
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
        assert!(names.contains(&"c"));
        assert!(names.contains(&"d"));
        let b = entries.iter().find(|e| e.name == "b").unwrap();
        assert_eq!(b.depends, vec!["c".to_string()]);
        // Leaf node — no outbound.
        let d = entries.iter().find(|e| e.name == "d").unwrap();
        assert!(d.depends.is_empty());
        // All transitive entries tagged source_type = "transitive".
        for e in &entries {
            assert_eq!(e.source_type.as_deref(), Some("transitive"));
            assert_eq!(e.sbom_tier.as_deref(), Some("source"));
        }
    }

    // --- PomSource emission gate (Phase 1) ------------------------------

    #[test]
    fn bfs_emits_only_rootfs_sourced_transitives() {
        // Rootfs has alpha's POM declaring a dep on beta.
        // Host has beta's POM (no deps).
        // Seed BFS from alpha.
        // Expected: alpha emits (rootfs-sourced), beta does NOT
        // emit (host-only sourced) — matches the artifact-SBOM
        // principle that only bytes present in the scanned rootfs
        // surface as components.
        let dir = tempfile::tempdir().unwrap();
        let rootfs_repo = dir.path().join("rootfs/.m2/repository");
        let host_repo = dir.path().join("host/.m2/repository");
        write_cached_pom(
            &rootfs_repo,
            "ex.a",
            "alpha",
            "1.0",
            r#"<project><groupId>ex.a</groupId><artifactId>alpha</artifactId><version>1.0</version>
<dependencies><dependency><groupId>ex.b</groupId><artifactId>beta</artifactId><version>1.0</version></dependency></dependencies>
</project>"#,
        );
        write_cached_pom(
            &host_repo,
            "ex.b",
            "beta",
            "1.0",
            r#"<project><groupId>ex.b</groupId><artifactId>beta</artifactId><version>1.0</version></project>"#,
        );

        let cache = MavenRepoCache::for_tests_with_host(vec![rootfs_repo], vec![host_repo]);
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex.a".into(), "alpha".into(), "1.0".into())],
            false,
            true,
            "/p/pom.xml",
            None,
        );
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"alpha"),
            "rootfs-sourced alpha must emit: {names:?}",
        );
        assert!(
            !names.contains(&"beta"),
            "host-only beta must NOT emit: {names:?}",
        );
    }

    #[test]
    fn bfs_resolution_uses_host_parent_pom_but_doesnt_emit_it() {
        // Rootfs has child's POM which inherits from a parent POM
        // that's only in the host cache. The parent POM carries a
        // property definition (`ext.version = 2.0`) that the child
        // uses to pin its own dep on `ex.external:ext:${ext.version}`.
        //
        // Without the host fallback for resolution, `ext.version`
        // would fail to resolve and the child's edge on `ext` would
        // drop. With the fallback (but gated emission), resolution
        // works AND the parent coord doesn't leak as a component.
        let dir = tempfile::tempdir().unwrap();
        let rootfs_repo = dir.path().join("rootfs/.m2/repository");
        let host_repo = dir.path().join("host/.m2/repository");
        write_cached_pom(
            &rootfs_repo,
            "ex.child",
            "foo",
            "1.0",
            r#"<project>
<parent><groupId>ex.parent</groupId><artifactId>parent</artifactId><version>1.0</version></parent>
<groupId>ex.child</groupId><artifactId>foo</artifactId><version>1.0</version>
<dependencies>
  <dependency><groupId>ex.external</groupId><artifactId>ext</artifactId><version>${ext.version}</version></dependency>
</dependencies>
</project>"#,
        );
        write_cached_pom(
            &host_repo,
            "ex.parent",
            "parent",
            "1.0",
            r#"<project><groupId>ex.parent</groupId><artifactId>parent</artifactId><version>1.0</version>
<properties><ext.version>2.0</ext.version></properties>
</project>"#,
        );

        let cache = MavenRepoCache::for_tests_with_host(vec![rootfs_repo], vec![host_repo]);
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex.child".into(), "foo".into(), "1.0".into())],
            false,
            true,
            "/p/pom.xml",
            None,
        );
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        // foo is rootfs-sourced → emits.
        assert!(names.contains(&"foo"), "rootfs foo must emit: {names:?}");
        // Parent coord must NOT leak as a component — resolution-only.
        assert!(
            !names.contains(&"parent"),
            "host parent must not emit: {names:?}",
        );
        // foo's declared edge on `ext` must resolve via host parent —
        // the `depends` list carries the edge as proof the host-
        // sourced parent POM was consulted for property resolution.
        let foo = entries.iter().find(|e| e.name == "foo").unwrap();
        assert!(
            foo.depends.iter().any(|d| d == "ext"),
            "ext edge must resolve via host parent: depends = {:?}",
            foo.depends,
        );
    }

    #[test]
    fn bfs_host_only_coords_dont_leak_when_seeded_from_host() {
        // Degenerate case: rootfs empty, host populated. Nothing
        // should emit — even if we seed BFS with a coord whose POM
        // sits in the host cache (this shouldn't happen in practice
        // because `walk_rootfs_poms` is rootfs-scoped, but the gate
        // must hold regardless).
        let dir = tempfile::tempdir().unwrap();
        let host_repo = dir.path().join("host/.m2/repository");
        write_cached_pom(
            &host_repo,
            "ex.only",
            "hosted",
            "1.0",
            r#"<project><groupId>ex.only</groupId><artifactId>hosted</artifactId><version>1.0</version></project>"#,
        );

        let cache = MavenRepoCache::for_tests_with_host(Vec::new(), vec![host_repo]);
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex.only".into(), "hosted".into(), "1.0".into())],
            false,
            true,
            "/p/pom.xml",
            None,
        );
        assert!(
            entries.is_empty(),
            "host-only coords must never emit even when BFS-seeded: {entries:?}",
        );
    }

    // --- On-disk JAR gate (M1) ------------------------------------------

    #[test]
    fn bfs_pom_only_coord_without_jar_does_not_emit() {
        // Rootfs has alpha's POM cached but no JAR. Under M1's
        // artifact-presence gate, alpha must NOT emit — the POM
        // alone isn't a distributable artifact (matches the
        // parent-POM / BOM-aggregator case: cached `.pom` but no
        // accompanying `.jar`).
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "ex.a",
            "alpha",
            "1.0",
            r#"<project><groupId>ex.a</groupId><artifactId>alpha</artifactId><version>1.0</version></project>"#,
        );

        let cache = MavenRepoCache::for_tests(vec![repo_root]);
        // Empty on_disk_jar_coords → alpha has no JAR on disk.
        let on_disk: HashSet<(String, String)> = HashSet::new();
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex.a".into(), "alpha".into(), "1.0".into())],
            false,
            true,
            "/p/pom.xml",
            Some(&on_disk),
        );
        assert!(
            entries.is_empty(),
            "POM-only coord without on-disk JAR must not emit: {entries:?}",
        );
    }

    #[test]
    fn bfs_pom_plus_jar_coord_emits_transitive() {
        // Rootfs has both alpha's POM AND a matching JAR (signaled
        // via `on_disk_jar_coords`). Transitive emission fires.
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "ex.a",
            "alpha",
            "1.0",
            r#"<project><groupId>ex.a</groupId><artifactId>alpha</artifactId><version>1.0</version></project>"#,
        );

        let cache = MavenRepoCache::for_tests(vec![repo_root]);
        let mut on_disk: HashSet<(String, String)> = HashSet::new();
        on_disk.insert(("ex.a".into(), "alpha".into()));
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex.a".into(), "alpha".into(), "1.0".into())],
            false,
            true,
            "/p/pom.xml",
            Some(&on_disk),
        );
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"alpha"), "POM+JAR coord must emit: {names:?}");
    }

    #[test]
    fn bfs_parent_pom_consulted_for_resolution_doesnt_emit_without_jar() {
        // Rootfs has child's POM + JAR (child emits). Parent POM is
        // ALSO in the cache (packaging=pom, no JAR) and is needed
        // for property resolution. Parent must NOT emit but its
        // properties must flow through to child's edges.
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "ex.child",
            "foo",
            "1.0",
            r#"<project>
<parent><groupId>ex.parent</groupId><artifactId>parent</artifactId><version>1.0</version></parent>
<groupId>ex.child</groupId><artifactId>foo</artifactId><version>1.0</version>
<dependencies>
  <dependency><groupId>ex.external</groupId><artifactId>ext</artifactId><version>${ext.version}</version></dependency>
</dependencies>
</project>"#,
        );
        write_cached_pom(
            &repo_root,
            "ex.parent",
            "parent",
            "1.0",
            r#"<project><groupId>ex.parent</groupId><artifactId>parent</artifactId><version>1.0</version>
<packaging>pom</packaging>
<properties><ext.version>2.0</ext.version></properties>
</project>"#,
        );

        let cache = MavenRepoCache::for_tests(vec![repo_root]);
        // Only foo has a JAR; parent does not (it's packaging=pom).
        let mut on_disk: HashSet<(String, String)> = HashSet::new();
        on_disk.insert(("ex.child".into(), "foo".into()));
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex.child".into(), "foo".into(), "1.0".into())],
            false,
            true,
            "/p/pom.xml",
            Some(&on_disk),
        );
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"foo"), "foo must emit (has JAR): {names:?}");
        assert!(
            !names.contains(&"parent"),
            "parent POM must not emit (no JAR): {names:?}",
        );
        // foo's declared edge on `ext` resolves via the (non-emitted)
        // parent POM's property — the `depends` list proves parent
        // was consulted for resolution.
        let foo = entries.iter().find(|e| e.name == "foo").unwrap();
        assert!(
            foo.depends.iter().any(|d| d == "ext"),
            "ext edge must resolve via parent POM property: depends = {:?}",
            foo.depends,
        );
    }

    #[test]
    fn bfs_cycle_a_to_b_to_a_terminates() {
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "ex",
            "a",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>a</artifactId><version>1</version>
<dependencies><dependency><groupId>ex</groupId><artifactId>b</artifactId><version>1</version></dependency></dependencies>
</project>"#,
        );
        write_cached_pom(
            &repo_root,
            "ex",
            "b",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>b</artifactId><version>1</version>
<dependencies><dependency><groupId>ex</groupId><artifactId>a</artifactId><version>1</version></dependency></dependencies>
</project>"#,
        );
        let cache = MavenRepoCache::for_tests(vec![repo_root.clone()]);
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex".into(), "a".into(), "1".into())],
            false,
            true,
            "/p/pom.xml",
            None,
        );
        // Each coord emitted exactly once — cycle short-circuited by
        // the seen-set on the second visit to "a".
        assert_eq!(entries.len(), 2);
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
    }

    #[test]
    fn bfs_cache_miss_stops_branch_gracefully() {
        // A cached (declares B). B not cached. Expect A with
        // depends=["B"], B with empty depends, no further entries.
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "ex",
            "a",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>a</artifactId><version>1</version>
<dependencies><dependency><groupId>ex</groupId><artifactId>b</artifactId><version>1</version></dependency></dependencies>
</project>"#,
        );
        let cache = MavenRepoCache::for_tests(vec![repo_root.clone()]);
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex".into(), "a".into(), "1".into())],
            false,
            true,
            "/p/pom.xml",
            None,
        );
        assert_eq!(entries.len(), 2);
        let a = entries.iter().find(|e| e.name == "a").unwrap();
        assert_eq!(a.depends, vec!["b".to_string()]);
        let b = entries.iter().find(|e| e.name == "b").unwrap();
        assert!(b.depends.is_empty());
    }

    #[test]
    fn bfs_test_scope_filter_prunes_transitive_tree() {
        // A → B(scope=test) → C. Without --include-dev: only A emitted.
        // With --include-dev: A, B, C all emitted.
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "ex",
            "a",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>a</artifactId><version>1</version>
<dependencies><dependency><groupId>ex</groupId><artifactId>b</artifactId><version>1</version><scope>test</scope></dependency></dependencies>
</project>"#,
        );
        write_cached_pom(
            &repo_root,
            "ex",
            "b",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>b</artifactId><version>1</version>
<dependencies><dependency><groupId>ex</groupId><artifactId>c</artifactId><version>1</version></dependency></dependencies>
</project>"#,
        );
        write_cached_pom(
            &repo_root,
            "ex",
            "c",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>c</artifactId><version>1</version></project>"#,
        );
        let cache = MavenRepoCache::for_tests(vec![repo_root.clone()]);
        // include_dev = false: test-scope B not followed, so BFS emits only A.
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex".into(), "a".into(), "1".into())],
            false,
            true,
            "/p/pom.xml",
            None,
        );
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a"]);
        let a = entries.iter().find(|e| e.name == "a").unwrap();
        assert!(
            a.depends.is_empty(),
            "A should drop test-scope B from edges without include_dev: {:?}",
            a.depends,
        );
        // include_dev = true: full tree.
        let entries_dev = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex".into(), "a".into(), "1".into())],
            true,
            true,
            "/p/pom.xml",
            None,
        );
        let names_dev: Vec<_> = entries_dev.iter().map(|e| e.name.as_str()).collect();
        assert!(names_dev.contains(&"a"));
        assert!(names_dev.contains(&"b"));
        assert!(names_dev.contains(&"c"));
    }

    #[test]
    fn bfs_handles_placeholder_groups_by_skipping() {
        // A's pom declares a dep with a groupId placeholder that can't
        // be resolved. A still emits (with the artifactId listed in
        // depends), but the unresolvable dep is not queued.
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "ex",
            "a",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>a</artifactId><version>1</version>
<dependencies><dependency><groupId>${unresolved}</groupId><artifactId>x</artifactId><version>1</version></dependency></dependencies>
</project>"#,
        );
        let cache = MavenRepoCache::for_tests(vec![repo_root.clone()]);
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex".into(), "a".into(), "1".into())],
            false,
            true,
            "/p/pom.xml",
            None,
        );
        assert_eq!(entries.len(), 1);
        let a = &entries[0];
        assert_eq!(a.name, "a");
        // Edge still appears in depends — scan-wide resolver will drop
        // it as dangling if no matching coord is observed.
        assert_eq!(a.depends, vec!["x".to_string()]);
    }

    #[test]
    fn bfs_empty_cache_returns_seed_only_with_empty_edges() {
        let cache = MavenRepoCache::default();
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex".into(), "a".into(), "1".into())],
            false,
            true,
            "/p/pom.xml",
            None,
        );
        // Cache miss on the seed — we still emit the coord with
        // empty depends so downstream consumers see the node.
        assert_eq!(entries.len(), 1);
        assert!(entries[0].depends.is_empty());
    }

    // --- effective-POM / parent-chain walker ---------------------------

    #[test]
    fn parse_pom_captures_dependency_management() {
        let body = r#"<?xml version="1.0"?>
<project>
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>ex</groupId><artifactId>bar</artifactId><version>2.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>ex</groupId><artifactId>bar</artifactId>
    </dependency>
  </dependencies>
</project>"#;
        let doc = parse_pom_xml(body.as_bytes());
        // The managed entry lives on dependency_management, NOT dependencies.
        assert_eq!(doc.dependency_management.len(), 1);
        assert_eq!(doc.dependency_management[0].artifact_id, "bar");
        assert_eq!(doc.dependency_management[0].version.as_deref(), Some("2.0"));
        // The <dependencies> entry has no inline version.
        assert_eq!(doc.dependencies.len(), 1);
        assert!(doc.dependencies[0].version.is_none());
    }

    #[test]
    fn effective_pom_merges_parent_properties() {
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "ex",
            "parent",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>parent</artifactId><version>1</version>
<properties><foo>parent</foo><bar>parent</bar></properties>
</project>"#,
        );
        let cache = MavenRepoCache::for_tests(vec![repo_root.clone()]);
        let child = parse_pom_xml(
            br#"<project>
<parent><groupId>ex</groupId><artifactId>parent</artifactId><version>1</version></parent>
<groupId>ex</groupId><artifactId>child</artifactId><version>1</version>
<properties><foo>child</foo></properties>
</project>"#,
        );
        let mut seen = HashSet::new();
        let mut memo = HashMap::new();
        let eff = build_effective_pom(child, &cache, &HashMap::new(), &mut seen, &mut memo);
        // Child wins on `foo`; `bar` inherits from parent.
        assert_eq!(eff.properties.get("foo").map(String::as_str), Some("child"));
        assert_eq!(eff.properties.get("bar").map(String::as_str), Some("parent"));
    }

    #[test]
    fn effective_pom_merges_parent_dependency_management() {
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "ex",
            "parent",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>parent</artifactId><version>1</version>
<dependencyManagement><dependencies>
  <dependency><groupId>ex</groupId><artifactId>bar</artifactId><version>2.0</version></dependency>
</dependencies></dependencyManagement>
</project>"#,
        );
        let cache = MavenRepoCache::for_tests(vec![repo_root.clone()]);
        let child = parse_pom_xml(
            br#"<project>
<parent><groupId>ex</groupId><artifactId>parent</artifactId><version>1</version></parent>
<groupId>ex</groupId><artifactId>child</artifactId><version>1</version>
</project>"#,
        );
        let mut seen = HashSet::new();
        let mut memo = HashMap::new();
        let eff = build_effective_pom(child, &cache, &HashMap::new(), &mut seen, &mut memo);
        assert_eq!(
            eff.dependency_management
                .get(&("ex".to_string(), "bar".to_string()))
                .map(String::as_str),
            Some("2.0"),
        );
    }

    #[test]
    fn grandparent_property_resolves_through_chain() {
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "ex",
            "grand",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>grand</artifactId><version>1</version>
<properties><foo>grand</foo></properties>
</project>"#,
        );
        write_cached_pom(
            &repo_root,
            "ex",
            "parent",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>parent</artifactId><version>1</version>
<parent><groupId>ex</groupId><artifactId>grand</artifactId><version>1</version></parent>
</project>"#,
        );
        let cache = MavenRepoCache::for_tests(vec![repo_root.clone()]);
        let child = parse_pom_xml(
            br#"<project>
<parent><groupId>ex</groupId><artifactId>parent</artifactId><version>1</version></parent>
<groupId>ex</groupId><artifactId>child</artifactId><version>1</version>
</project>"#,
        );
        let mut seen = HashSet::new();
        let mut memo = HashMap::new();
        let eff = build_effective_pom(child, &cache, &HashMap::new(), &mut seen, &mut memo);
        assert_eq!(eff.properties.get("foo").map(String::as_str), Some("grand"));
    }

    #[test]
    fn resolve_dep_version_uses_depmgmt_when_version_absent() {
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "ex",
            "parent",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>parent</artifactId><version>1</version>
<dependencyManagement><dependencies>
  <dependency><groupId>ex</groupId><artifactId>bar</artifactId><version>3.3</version></dependency>
</dependencies></dependencyManagement>
</project>"#,
        );
        let cache = MavenRepoCache::for_tests(vec![repo_root.clone()]);
        let child = parse_pom_xml(
            br#"<project>
<parent><groupId>ex</groupId><artifactId>parent</artifactId><version>1</version></parent>
<groupId>ex</groupId><artifactId>child</artifactId><version>1</version>
<dependencies>
  <dependency><groupId>ex</groupId><artifactId>bar</artifactId></dependency>
</dependencies>
</project>"#,
        );
        let mut seen = HashSet::new();
        let mut memo = HashMap::new();
        let eff = build_effective_pom(child, &cache, &HashMap::new(), &mut seen, &mut memo);
        let dep = &eff.doc.dependencies[0];
        assert_eq!(
            resolve_dep_version(dep, &eff),
            Some("3.3".to_string()),
            "version-less dep should resolve via parent's dependencyManagement",
        );
    }

    #[test]
    fn resolve_dep_version_applies_properties_to_managed_version() {
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        // Parent provides both the property and the dep-mgmt entry.
        write_cached_pom(
            &repo_root,
            "ex",
            "parent",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>parent</artifactId><version>1</version>
<properties><bar.version>4.2</bar.version></properties>
<dependencyManagement><dependencies>
  <dependency><groupId>ex</groupId><artifactId>bar</artifactId><version>${bar.version}</version></dependency>
</dependencies></dependencyManagement>
</project>"#,
        );
        let cache = MavenRepoCache::for_tests(vec![repo_root.clone()]);
        let child = parse_pom_xml(
            br#"<project>
<parent><groupId>ex</groupId><artifactId>parent</artifactId><version>1</version></parent>
<groupId>ex</groupId><artifactId>child</artifactId><version>1</version>
<dependencies>
  <dependency><groupId>ex</groupId><artifactId>bar</artifactId></dependency>
</dependencies>
</project>"#,
        );
        let mut seen = HashSet::new();
        let mut memo = HashMap::new();
        let eff = build_effective_pom(child, &cache, &HashMap::new(), &mut seen, &mut memo);
        let dep = &eff.doc.dependencies[0];
        assert_eq!(resolve_dep_version(dep, &eff), Some("4.2".to_string()));
    }

    #[test]
    fn parent_chain_cycle_guard_terminates() {
        // A's parent is B, B's parent is A. Pathological; should not
        // overflow the stack.
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "ex",
            "a",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>a</artifactId><version>1</version>
<parent><groupId>ex</groupId><artifactId>b</artifactId><version>1</version></parent>
</project>"#,
        );
        write_cached_pom(
            &repo_root,
            "ex",
            "b",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>b</artifactId><version>1</version>
<parent><groupId>ex</groupId><artifactId>a</artifactId><version>1</version></parent>
</project>"#,
        );
        let cache = MavenRepoCache::for_tests(vec![repo_root.clone()]);
        let doc = parse_pom_xml(
            br#"<project><groupId>ex</groupId><artifactId>a</artifactId><version>1</version>
<parent><groupId>ex</groupId><artifactId>b</artifactId><version>1</version></parent>
</project>"#,
        );
        let mut seen = HashSet::new();
        let mut memo = HashMap::new();
        // Should terminate, not panic/stack-overflow.
        let _eff = build_effective_pom(doc, &cache, &HashMap::new(), &mut seen, &mut memo);
    }

    #[test]
    fn parent_not_in_cache_does_not_crash() {
        let cache = MavenRepoCache::default();
        let doc = parse_pom_xml(
            br#"<project>
<parent><groupId>ex</groupId><artifactId>missing</artifactId><version>1</version></parent>
<groupId>ex</groupId><artifactId>child</artifactId><version>1</version>
<properties><foo>child</foo></properties>
</project>"#,
        );
        let mut seen = HashSet::new();
        let mut memo = HashMap::new();
        let eff = build_effective_pom(doc, &cache, &HashMap::new(), &mut seen, &mut memo);
        // Child's own properties still present; no panic from missing parent.
        assert_eq!(eff.properties.get("foo").map(String::as_str), Some("child"));
    }

    #[test]
    fn bom_import_flattens_into_dependency_management() {
        // BOM import: child's <dependencyManagement> has an entry with
        // <type>pom</type><scope>import</scope>; the imported BOM
        // contributes its own dep-mgmt entries to the effective POM.
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "ex",
            "bom",
            "1",
            r#"<project><groupId>ex</groupId><artifactId>bom</artifactId><version>1</version>
<dependencyManagement><dependencies>
  <dependency><groupId>ex</groupId><artifactId>jackson-core</artifactId><version>2.17.2</version></dependency>
</dependencies></dependencyManagement>
</project>"#,
        );
        let cache = MavenRepoCache::for_tests(vec![repo_root.clone()]);
        let child = parse_pom_xml(
            br#"<project>
<groupId>ex</groupId><artifactId>child</artifactId><version>1</version>
<dependencyManagement><dependencies>
  <dependency>
    <groupId>ex</groupId><artifactId>bom</artifactId><version>1</version>
    <type>pom</type><scope>import</scope>
  </dependency>
</dependencies></dependencyManagement>
</project>"#,
        );
        let mut seen = HashSet::new();
        let mut memo = HashMap::new();
        let eff = build_effective_pom(child, &cache, &HashMap::new(), &mut seen, &mut memo);
        assert_eq!(
            eff.dependency_management
                .get(&("ex".to_string(), "jackson-core".to_string()))
                .map(String::as_str),
            Some("2.17.2"),
        );
    }

    #[test]
    fn bfs_guava_like_scenario_resolves_all_deps_via_parent_chain() {
        // Simulate guava's layout: guava's pom references several deps
        // with no inline version; guava-parent's depMgmt carries those
        // versions. BFS from guava should emit every transitive coord.
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join(".m2/repository");
        write_cached_pom(
            &repo_root,
            "com.google.guava",
            "guava-parent",
            "32.1.3-jre",
            r#"<project><groupId>com.google.guava</groupId><artifactId>guava-parent</artifactId><version>32.1.3-jre</version>
<dependencyManagement><dependencies>
  <dependency><groupId>com.google.code.findbugs</groupId><artifactId>jsr305</artifactId><version>3.0.2</version></dependency>
  <dependency><groupId>org.checkerframework</groupId><artifactId>checker-qual</artifactId><version>3.37.0</version></dependency>
  <dependency><groupId>com.google.errorprone</groupId><artifactId>error_prone_annotations</artifactId><version>2.21.1</version></dependency>
  <dependency><groupId>com.google.j2objc</groupId><artifactId>j2objc-annotations</artifactId><version>2.8</version></dependency>
</dependencies></dependencyManagement>
</project>"#,
        );
        write_cached_pom(
            &repo_root,
            "com.google.guava",
            "guava",
            "32.1.3-jre",
            r#"<project>
<parent><groupId>com.google.guava</groupId><artifactId>guava-parent</artifactId><version>32.1.3-jre</version></parent>
<groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>32.1.3-jre</version>
<dependencies>
  <dependency><groupId>com.google.guava</groupId><artifactId>failureaccess</artifactId><version>1.0.1</version></dependency>
  <dependency><groupId>com.google.guava</groupId><artifactId>listenablefuture</artifactId><version>9999.0-empty-to-avoid-conflict-with-guava</version></dependency>
  <dependency><groupId>com.google.code.findbugs</groupId><artifactId>jsr305</artifactId></dependency>
  <dependency><groupId>org.checkerframework</groupId><artifactId>checker-qual</artifactId></dependency>
  <dependency><groupId>com.google.errorprone</groupId><artifactId>error_prone_annotations</artifactId></dependency>
  <dependency><groupId>com.google.j2objc</groupId><artifactId>j2objc-annotations</artifactId></dependency>
</dependencies>
</project>"#,
        );
        // Emit leaf poms for each transitive so BFS can emit them as
        // components (cache miss would work too, but hitting gives a
        // closer trivy parity).
        for (g, a, v) in [
            ("com.google.guava", "failureaccess", "1.0.1"),
            (
                "com.google.guava",
                "listenablefuture",
                "9999.0-empty-to-avoid-conflict-with-guava",
            ),
            ("com.google.code.findbugs", "jsr305", "3.0.2"),
            ("org.checkerframework", "checker-qual", "3.37.0"),
            ("com.google.errorprone", "error_prone_annotations", "2.21.1"),
            ("com.google.j2objc", "j2objc-annotations", "2.8"),
        ] {
            write_cached_pom(
                &repo_root,
                g,
                a,
                v,
                &format!("<project><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version></project>"),
            );
        }
        let cache = MavenRepoCache::for_tests(vec![repo_root.clone()]);
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("com.google.guava".into(), "guava".into(), "32.1.3-jre".into())],
            false,
            true,
            "/p/pom.xml",
            None,
        );
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        for expected in [
            "guava",
            "failureaccess",
            "listenablefuture",
            "jsr305",
            "checker-qual",
            "error_prone_annotations",
            "j2objc-annotations",
        ] {
            assert!(
                names.contains(&expected),
                "expected {expected} in BFS output, got {names:?}",
            );
        }
    }

    #[test]
    fn placeholder_dependency_version_becomes_design_tier() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pom.xml"),
            r#"<?xml version="1.0"?>
<project>
  <groupId>g</groupId>
  <artifactId>a</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>sibling</artifactId>
      <version>${unresolved.version}</version>
    </dependency>
  </dependencies>
</project>"#,
        )
        .unwrap();
        let entries = read(dir.path(), false);
        let sibling = entries.iter().find(|e| e.name == "sibling").unwrap();
        assert_eq!(sibling.sbom_tier.as_deref(), Some("design"));
        assert_eq!(
            sibling.requirement_range.as_deref(),
            Some("${unresolved.version}")
        );
    }

    #[test]
    fn read_with_claims_emits_claimed_jars_with_co_ownership_tag() {
        // Simulate Fedora's `dnf install maven` layout: a JAR in
        // /usr/share/java is owned by an RPM package, so its path is
        // in the claim set. The Maven JAR walker still extracts its
        // embedded pom.properties (dual-identity: the same bytes are
        // both `pkg:rpm/...` and `pkg:maven/...`), tagging the
        // emitted entry with `co_owned_by = Some("rpm")`.
        let dir = tempfile::tempdir().unwrap();
        let share_java = dir.path().join("usr/share/java");
        std::fs::create_dir_all(&share_java).unwrap();
        let jar_path = share_java.join("commons-io.jar");
        write_jar(
            &jar_path,
            &[(
                "META-INF/maven/commons-io/commons-io/pom.properties",
                b"groupId=commons-io\nartifactId=commons-io\nversion=2.12.0\n",
            )],
        );

        // Without the claim, the walker emits the JAR with no
        // co-ownership tag (standalone Maven artifact).
        let empty_claims: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        #[cfg(unix)]
        let empty_inodes: std::collections::HashSet<(u64, u64)> =
            std::collections::HashSet::new();
        let (no_claim, _) = read_with_claims(
            dir.path(),
            false,
            true,
            &empty_claims,
            #[cfg(unix)]
            &empty_inodes,
            None,
        );
        assert_eq!(no_claim.len(), 1, "baseline: expected 1 Maven entry");
        assert_eq!(no_claim[0].name, "commons-io");
        assert_eq!(
            no_claim[0].co_owned_by, None,
            "standalone JAR must not carry co-ownership tag",
        );

        // With the JAR path claimed, the walker still emits but tags
        // `co_owned_by = Some("rpm")` (derived from /usr/share/java/
        // path heuristic).
        let mut claimed: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        claimed.insert(jar_path.clone());
        #[cfg(unix)]
        let claimed_inodes: std::collections::HashSet<(u64, u64)> =
            std::collections::HashSet::new();
        let (with_claim, _) = read_with_claims(
            dir.path(),
            false,
            true,
            &claimed,
            #[cfg(unix)]
            &claimed_inodes,
            None,
        );
        assert_eq!(
            with_claim.len(),
            1,
            "claimed JAR must still emit (dual-identity); got {with_claim:?}",
        );
        assert_eq!(with_claim[0].name, "commons-io");
        assert_eq!(
            with_claim[0].co_owned_by.as_deref(),
            Some("rpm"),
            "claimed JAR under /usr/share/java must carry co_owned_by=rpm",
        );
        // archive_sha256 must be dropped on co-owned coords (the
        // RPM component owns the archive identity).
        let has_sha256 = with_claim[0].hashes.iter().any(|h| {
            matches!(
                h.algorithm,
                mikebom_common::types::hash::HashAlgorithm::Sha256
            )
        });
        assert!(
            !has_sha256,
            "co-owned coord must not carry archive_sha256; hashes = {:?}",
            with_claim[0].hashes,
        );
    }

    #[test]
    fn read_with_claims_placeholder_version_filtered_even_when_claimed() {
        // A JAR with two embedded pom.properties: one with a concrete
        // version (emits) and one with `${project.version}` (must be
        // filtered upstream in parse_pom_properties, regardless of
        // claim status). Even when the JAR path is claimed — i.e.
        // when the pre-fix claim-skip would have hidden everything —
        // placeholder entries stay hidden via the parse-level filter.
        let dir = tempfile::tempdir().unwrap();
        let share_java = dir.path().join("usr/share/java");
        std::fs::create_dir_all(&share_java).unwrap();
        let jar_path = share_java.join("multi.jar");
        write_jar(
            &jar_path,
            &[
                (
                    "META-INF/maven/com.google.guava/guava/pom.properties",
                    b"groupId=com.google.guava\nartifactId=guava\nversion=32.1.3-jre\n",
                ),
                (
                    "META-INF/maven/ex.placeholder/broken/pom.properties",
                    b"groupId=ex.placeholder\nartifactId=broken\nversion=${project.version}\n",
                ),
            ],
        );

        let mut claimed: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        claimed.insert(jar_path.clone());
        #[cfg(unix)]
        let claimed_inodes: std::collections::HashSet<(u64, u64)> =
            std::collections::HashSet::new();
        let (out, _scan_target) = read_with_claims(
            dir.path(),
            false,
            true,
            &claimed,
            #[cfg(unix)]
            &claimed_inodes,
            None,
        );
        let names: Vec<&str> = out.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"guava"),
            "concrete-version coord must emit: {names:?}",
        );
        assert!(
            !names.contains(&"broken"),
            "placeholder-version coord must be filtered: {names:?}",
        );
        // The emitted guava carries the co-ownership tag.
        let guava = out.iter().find(|e| e.name == "guava").unwrap();
        assert_eq!(guava.co_owned_by.as_deref(), Some("rpm"));
    }

    // --- Dual-SBOM gate (artifact vs manifest scope) --------------------

    fn write_project_pom(dir: &Path, body: &str) {
        std::fs::write(dir.join("pom.xml"), body).unwrap();
    }

    #[test]
    fn pom_xml_with_no_jars_drops_declared_deps_in_artifact_scope() {
        // Project pom.xml declaring two deps. No JARs on disk, no .m2
        // cache. Artifact scope (include_declared_deps=false) must emit
        // zero Maven components — these deps don't have bytes on disk.
        //
        // Synthetic group IDs (`ex.only`) so the host's real `.m2/`
        // can't accidentally satisfy the BFS lookup and leak coords.
        let dir = tempfile::tempdir().unwrap();
        write_project_pom(
            dir.path(),
            r#"<project>
              <groupId>ex.app</groupId><artifactId>app</artifactId><version>1.0.0</version>
              <dependencies>
                <dependency><groupId>ex.only</groupId><artifactId>alpha</artifactId><version>1.0</version></dependency>
                <dependency><groupId>ex.only</groupId><artifactId>beta</artifactId><version>2.0</version></dependency>
              </dependencies>
            </project>"#,
        );
        let claimed = std::collections::HashSet::new();
        #[cfg(unix)]
        let claimed_inodes = std::collections::HashSet::new();
        let (out, _) = read_with_claims(
            dir.path(),
            false,
            false,
            &claimed,
            #[cfg(unix)]
            &claimed_inodes,
            None,
        );
        assert_eq!(
            out.len(),
            0,
            "artifact scope with no JARs and no cache must drop all declared deps; got {out:?}",
        );
    }

    #[test]
    fn pom_xml_with_no_jars_emits_declared_deps_in_manifest_scope() {
        // Same fixture; manifest scope (include_declared_deps=true)
        // emits both declared deps. Matches the pre-dual-SBOM
        // behavior and source-tree expectations.
        let dir = tempfile::tempdir().unwrap();
        write_project_pom(
            dir.path(),
            r#"<project>
              <groupId>ex.app</groupId><artifactId>app</artifactId><version>1.0.0</version>
              <dependencies>
                <dependency><groupId>ex.only</groupId><artifactId>alpha</artifactId><version>1.0</version></dependency>
                <dependency><groupId>ex.only</groupId><artifactId>beta</artifactId><version>2.0</version></dependency>
              </dependencies>
            </project>"#,
        );
        let claimed = std::collections::HashSet::new();
        #[cfg(unix)]
        let claimed_inodes = std::collections::HashSet::new();
        let (out, _) = read_with_claims(
            dir.path(),
            false,
            true,
            &claimed,
            #[cfg(unix)]
            &claimed_inodes,
            None,
        );
        let names: Vec<&str> = out.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"alpha"), "alpha missing: {names:?}");
        assert!(names.contains(&"beta"), "beta missing: {names:?}");
    }

    #[test]
    fn pom_xml_with_one_cached_pom_emits_only_on_disk_coord_in_artifact_scope() {
        // Project pom.xml declaring two deps. Only alpha's .pom is
        // present in the in-rootfs .m2 cache. Artifact scope emits
        // only alpha (beta is declared-but-not-on-disk → gated out).
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        write_project_pom(
            &project,
            r#"<project>
              <groupId>ex.app</groupId><artifactId>app</artifactId><version>1.0.0</version>
              <dependencies>
                <dependency><groupId>ex.only</groupId><artifactId>alpha</artifactId><version>1.0</version></dependency>
                <dependency><groupId>ex.only</groupId><artifactId>beta</artifactId><version>2.0</version></dependency>
              </dependencies>
            </project>"#,
        );
        // Seed the in-rootfs .m2 cache with just alpha's POM.
        let repo_root = dir.path().join("root/.m2/repository");
        write_cached_pom(
            &repo_root,
            "ex.only",
            "alpha",
            "1.0",
            r#"<project><groupId>ex.only</groupId><artifactId>alpha</artifactId><version>1.0</version></project>"#,
        );
        let claimed = std::collections::HashSet::new();
        #[cfg(unix)]
        let claimed_inodes = std::collections::HashSet::new();
        let (out, _) = read_with_claims(
            dir.path(),
            false,
            false,
            &claimed,
            #[cfg(unix)]
            &claimed_inodes,
            None,
        );
        let names: Vec<&str> = out.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"alpha"),
            "cached alpha must emit in artifact scope: {names:?}",
        );
        assert!(
            !names.contains(&"beta"),
            "uncached beta must be dropped in artifact scope: {names:?}",
        );
    }

    // --- Scan-target filter (Fix B) -------------------------------------

    #[test]
    fn scan_target_primary_coord_skipped_when_artifactid_matches() {
        // A fat-jar named `myapp.jar` with primary coord
        // `com.example:myapp:1.0.0` plus two vendored non-primary
        // children. Pass `scan_target_name = Some("myapp")`. The
        // primary coord IS the SBOM subject — must be suppressed from
        // components[]. Vendored children still emit.
        let dir = tempfile::tempdir().unwrap();
        let jar_path = dir.path().join("myapp.jar");
        write_jar(
            &jar_path,
            &[
                (
                    "META-INF/maven/com.example/myapp/pom.properties",
                    b"groupId=com.example\nartifactId=myapp\nversion=1.0.0\n",
                ),
                (
                    "META-INF/maven/com.google.guava/guava/pom.properties",
                    b"groupId=com.google.guava\nartifactId=guava\nversion=32.1.3-jre\n",
                ),
                (
                    "META-INF/maven/org.slf4j/slf4j-api/pom.properties",
                    b"groupId=org.slf4j\nartifactId=slf4j-api\nversion=2.0.9\n",
                ),
            ],
        );

        let empty_claims: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        #[cfg(unix)]
        let empty_inodes: std::collections::HashSet<(u64, u64)> =
            std::collections::HashSet::new();
        let (out, _) = read_with_claims(
            dir.path(),
            false,
            true,
            &empty_claims,
            #[cfg(unix)]
            &empty_inodes,
            Some("myapp"),
        );
        let names: Vec<&str> = out.iter().map(|e| e.name.as_str()).collect();
        assert!(
            !names.contains(&"myapp"),
            "primary coord matching scan target must be suppressed: {names:?}",
        );
        assert!(
            names.contains(&"guava"),
            "vendored guava must still emit: {names:?}",
        );
        assert!(
            names.contains(&"slf4j-api"),
            "vendored slf4j-api must still emit: {names:?}",
        );
    }

    #[test]
    fn scan_target_primary_coord_emits_when_artifactid_differs() {
        // Standalone JAR (not a fat-jar — only ONE embedded
        // pom.properties), and scan target doesn't match the
        // primary coord's artifactId. The primary coord must emit
        // normally. This exercises Fix B's target-name gate in
        // isolation: without the fat-jar heuristic firing (M3),
        // suppression only happens when the artifactId matches.
        let dir = tempfile::tempdir().unwrap();
        let jar_path = dir.path().join("myapp.jar");
        write_jar(
            &jar_path,
            &[(
                "META-INF/maven/com.example/myapp/pom.properties",
                b"groupId=com.example\nartifactId=myapp\nversion=1.0.0\n",
            )],
        );

        let empty_claims: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        #[cfg(unix)]
        let empty_inodes: std::collections::HashSet<(u64, u64)> =
            std::collections::HashSet::new();
        let (out, _) = read_with_claims(
            dir.path(),
            false,
            true,
            &empty_claims,
            #[cfg(unix)]
            &empty_inodes,
            Some("other-service"),
        );
        let names: Vec<&str> = out.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"myapp"),
            "primary coord with non-matching target on standalone JAR must emit: {names:?}",
        );
    }

    #[test]
    fn scan_target_none_leaves_behavior_unchanged() {
        // scan_target_name=None, non-fat JAR. Primary coord emits
        // normally — neither heuristic fires.
        let dir = tempfile::tempdir().unwrap();
        let jar_path = dir.path().join("myapp.jar");
        write_jar(
            &jar_path,
            &[(
                "META-INF/maven/com.example/myapp/pom.properties",
                b"groupId=com.example\nartifactId=myapp\nversion=1.0.0\n",
            )],
        );

        let empty_claims: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        #[cfg(unix)]
        let empty_inodes: std::collections::HashSet<(u64, u64)> =
            std::collections::HashSet::new();
        let (out, _) = read_with_claims(
            dir.path(),
            false,
            true,
            &empty_claims,
            #[cfg(unix)]
            &empty_inodes,
            None,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "myapp");
    }

    // --- Fat-jar heuristic (M3) -----------------------------------------

    #[test]
    fn fat_jar_primary_suppressed_without_target_name() {
        // Fat JAR (≥2 embedded META-INF/maven entries) with
        // scan_target_name=None — M3's heuristic fires regardless of
        // target-name match. Primary suppressed; vendored children
        // still emit. Surfaced scan_target_coord carries the
        // suppressed identity.
        let dir = tempfile::tempdir().unwrap();
        let jar_path = dir.path().join("sbom-fixture.jar");
        write_jar(
            &jar_path,
            &[
                (
                    "META-INF/maven/com.example/sbom-fixture/pom.properties",
                    b"groupId=com.example\nartifactId=sbom-fixture\nversion=1.0.0\n",
                ),
                (
                    "META-INF/maven/com.google.guava/guava/pom.properties",
                    b"groupId=com.google.guava\nartifactId=guava\nversion=32.1.3-jre\n",
                ),
                (
                    "META-INF/maven/org.slf4j/slf4j-api/pom.properties",
                    b"groupId=org.slf4j\nartifactId=slf4j-api\nversion=2.0.9\n",
                ),
            ],
        );

        let empty_claims: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        #[cfg(unix)]
        let empty_inodes: std::collections::HashSet<(u64, u64)> =
            std::collections::HashSet::new();
        let (out, scan_target) = read_with_claims(
            dir.path(),
            false,
            true,
            &empty_claims,
            #[cfg(unix)]
            &empty_inodes,
            None,
        );
        let names: Vec<&str> = out.iter().map(|e| e.name.as_str()).collect();
        assert!(
            !names.contains(&"sbom-fixture"),
            "fat-jar primary must be suppressed: {names:?}",
        );
        assert!(names.contains(&"guava"));
        assert!(names.contains(&"slf4j-api"));
        let coord = scan_target.expect("scan_target_coord must be surfaced");
        assert_eq!(coord.artifact, "sbom-fixture");
        assert_eq!(coord.version, "1.0.0");
    }

    #[test]
    fn non_fat_jar_primary_still_emits() {
        // Single-entry JAR (not a fat-jar) with no target-name match.
        // Neither heuristic fires — primary emits, scan_target_coord
        // stays None.
        let dir = tempfile::tempdir().unwrap();
        let jar_path = dir.path().join("guava-32.1.3-jre.jar");
        write_jar(
            &jar_path,
            &[(
                "META-INF/maven/com.google.guava/guava/pom.properties",
                b"groupId=com.google.guava\nartifactId=guava\nversion=32.1.3-jre\n",
            )],
        );

        let empty_claims: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        #[cfg(unix)]
        let empty_inodes: std::collections::HashSet<(u64, u64)> =
            std::collections::HashSet::new();
        let (out, scan_target) = read_with_claims(
            dir.path(),
            false,
            true,
            &empty_claims,
            #[cfg(unix)]
            &empty_inodes,
            None,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "guava");
        assert!(
            scan_target.is_none(),
            "plain-JAR primary must not populate scan_target_coord: {scan_target:?}",
        );
    }

    #[test]
    fn fat_jar_primary_claimed_by_rpm_emits_normally() {
        // Post-PR-#2 regression guard (M3 refinement): a fat JAR
        // owned by an OS package-db reader must NOT trigger M3's
        // "this is the scan subject" heuristic. Fedora's
        // `/usr/share/java/guava/guava.jar` bundles `failureaccess`
        // etc. but is a dep of the scan target, not the target
        // itself. Its primary coord must emit with
        // `co_owned_by = Some("rpm")`, and `scan_target_coord`
        // must stay None.
        let dir = tempfile::tempdir().unwrap();
        let share_java = dir.path().join("usr/share/java");
        std::fs::create_dir_all(&share_java).unwrap();
        let jar_path = share_java.join("guava.jar");
        write_jar(
            &jar_path,
            &[
                (
                    "META-INF/maven/com.google.guava/guava/pom.properties",
                    b"groupId=com.google.guava\nartifactId=guava\nversion=32.1.3-jre\n",
                ),
                (
                    "META-INF/maven/com.google.guava/failureaccess/pom.properties",
                    b"groupId=com.google.guava\nartifactId=failureaccess\nversion=1.0.1\n",
                ),
            ],
        );

        let mut claimed: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        claimed.insert(jar_path.clone());
        #[cfg(unix)]
        let claimed_inodes: std::collections::HashSet<(u64, u64)> =
            std::collections::HashSet::new();
        let (out, scan_target) = read_with_claims(
            dir.path(),
            false,
            true,
            &claimed,
            #[cfg(unix)]
            &claimed_inodes,
            None,
        );
        let names: Vec<&str> = out.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"guava"),
            "claimed fat-jar primary must still emit: {names:?}",
        );
        assert!(
            names.contains(&"failureaccess"),
            "shaded child must still emit: {names:?}",
        );
        let guava = out.iter().find(|e| e.name == "guava").unwrap();
        assert_eq!(
            guava.co_owned_by.as_deref(),
            Some("rpm"),
            "primary coord must carry co_owned_by=rpm",
        );
        assert!(
            scan_target.is_none(),
            "claimed fat-jar must NOT promote to metadata.component: {scan_target:?}",
        );
    }

    // --- Sidecar hash helper (sbomqs Integrity lift, Maven) -------------

    use mikebom_common::types::hash::HashAlgorithm;

    fn write_sidecar(jar_path: &Path, ext: &str, contents: &str) {
        let sidecar = jar_path.with_extension(format!("jar.{ext}"));
        std::fs::write(sidecar, contents).unwrap();
    }

    #[test]
    fn read_sidecar_prefers_sha512_over_sha256_and_sha1() {
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("myartifact-1.0.jar");
        // Write all three. Each uses a digest of the right length.
        write_sidecar(&jar, "sha1", &"a".repeat(40));
        write_sidecar(&jar, "sha256", &"b".repeat(64));
        write_sidecar(&jar, "sha512", &"c".repeat(128));

        let hash = read_sidecar(&jar).expect("hash returned");
        assert_eq!(hash.algorithm, HashAlgorithm::Sha512);
        assert_eq!(hash.value.as_str(), &"c".repeat(128));
    }

    #[test]
    fn read_sidecar_falls_back_to_sha256_when_sha512_missing() {
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("myartifact-1.0.jar");
        write_sidecar(&jar, "sha1", &"a".repeat(40));
        write_sidecar(&jar, "sha256", &"b".repeat(64));

        let hash = read_sidecar(&jar).expect("hash returned");
        assert_eq!(hash.algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn read_sidecar_falls_back_to_sha1_when_others_missing() {
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("myartifact-1.0.jar");
        write_sidecar(&jar, "sha1", &"a".repeat(40));

        let hash = read_sidecar(&jar).expect("hash returned");
        assert_eq!(hash.algorithm, HashAlgorithm::Sha1);
    }

    #[test]
    fn read_sidecar_handles_filename_suffix_in_sidecar_content() {
        // Maven Central + many CI tools emit `<hex>  <filename>` pairs.
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("myartifact-1.0.jar");
        let hex = "b".repeat(64);
        write_sidecar(&jar, "sha256", &format!("{hex}  myartifact-1.0.jar\n"));
        let hash = read_sidecar(&jar).expect("hash returned");
        assert_eq!(hash.value.as_str(), &hex);
    }

    #[test]
    fn read_sidecar_returns_none_when_no_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("myartifact-1.0.jar");
        // No sidecar files at all.
        assert!(read_sidecar(&jar).is_none());
    }

    #[test]
    fn read_sidecar_skips_invalid_hex() {
        // A sidecar with garbage content should fall through to the
        // next algorithm rather than be silently accepted.
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("myartifact-1.0.jar");
        write_sidecar(&jar, "sha512", "not_hex_garbage_zzz");
        write_sidecar(&jar, "sha256", &"b".repeat(64));
        let hash = read_sidecar(&jar).expect("hash returned");
        assert_eq!(hash.algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn read_artifact_hash_resolves_through_cache_root() {
        let dir = tempfile::tempdir().unwrap();
        // Plant <root>/com/example/myapp/1.0.0/myapp-1.0.0.jar.sha256
        let artifact_dir = dir.path().join("com/example/myapp/1.0.0");
        std::fs::create_dir_all(&artifact_dir).unwrap();
        let jar = artifact_dir.join("myapp-1.0.0.jar");
        let hex = "f".repeat(64);
        write_sidecar(&jar, "sha256", &hex);

        let cache = MavenRepoCache::for_tests(vec![dir.path().to_path_buf()]);
        let hashes = cache.read_artifact_hash("com.example", "myapp", "1.0.0");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].value.as_str(), &hex);
    }

    #[test]
    fn read_artifact_hash_returns_empty_when_no_cache_roots() {
        let cache = MavenRepoCache::for_tests(vec![]);
        let hashes = cache.read_artifact_hash("com.example", "myapp", "1.0.0");
        assert!(hashes.is_empty());
    }

    // --- walk_rootfs_poms ----------------------------------------------
    // (reuses the existing `write_cached_pom` helper defined higher up
    // in this tests module)

    #[test]
    fn walk_rootfs_poms_finds_multiple_cached_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().to_path_buf();
        write_cached_pom(
            &repo_root,
            "com.example",
            "alpha",
            "1.0.0",
            r#"<project><groupId>com.example</groupId><artifactId>alpha</artifactId><version>1.0.0</version></project>"#,
        );
        write_cached_pom(
            &repo_root,
            "org.sample",
            "beta",
            "2.1.5",
            r#"<project><groupId>org.sample</groupId><artifactId>beta</artifactId><version>2.1.5</version></project>"#,
        );

        let cache = MavenRepoCache::for_tests(vec![repo_root]);
        let coords = cache.walk_rootfs_poms(1000);

        assert_eq!(coords.len(), 2, "expected both cached coords: {coords:?}");
        assert!(coords.contains(&(
            "com.example".to_string(),
            "alpha".to_string(),
            "1.0.0".to_string()
        )));
        assert!(coords.contains(&(
            "org.sample".to_string(),
            "beta".to_string(),
            "2.1.5".to_string()
        )));
    }

    #[test]
    fn walk_rootfs_poms_skips_host_scoped_roots() {
        // A cache whose only root is in `host_roots` should produce
        // zero seeds even if the directory contains cached .pom files.
        // This is the invariant that prevents `$HOME/.m2` from
        // leaking into the scan output.
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().to_path_buf();
        write_cached_pom(
            &repo_root,
            "com.example",
            "alpha",
            "1.0.0",
            r#"<project><groupId>com.example</groupId><artifactId>alpha</artifactId><version>1.0.0</version></project>"#,
        );
        let cache = MavenRepoCache {
            rootfs_roots: Vec::new(),
            host_roots: vec![repo_root.clone()],
        };
        let coords = cache.walk_rootfs_poms(1000);
        assert!(
            coords.is_empty(),
            "host-scoped root must not be walked unconditionally: {coords:?}"
        );
        // But read_pom still finds host-cached artifacts — the BFS
        // path consults host caches even when the walk ignores them.
        assert!(cache
            .read_pom("com.example", "alpine", "1.0.0")
            .is_none());
        assert!(cache.read_pom("com.example", "alpha", "1.0.0").is_some());
    }

    #[test]
    fn walk_rootfs_poms_ignores_sibling_non_pom_files() {
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().to_path_buf();
        write_cached_pom(
            &repo_root,
            "com.example",
            "alpha",
            "1.0.0",
            r#"<project><groupId>com.example</groupId><artifactId>alpha</artifactId><version>1.0.0</version></project>"#,
        );
        // Sibling files that live alongside a real .pom in .m2: a
        // sources-classifier pom variant, maven-metadata, sidecars.
        // None of these should produce coords.
        let dir_path = repo_root.join("com/example/alpha/1.0.0");
        std::fs::write(dir_path.join("alpha-1.0.0.jar"), b"").unwrap();
        std::fs::write(dir_path.join("alpha-1.0.0.jar.sha1"), b"deadbeef").unwrap();
        std::fs::write(dir_path.join("alpha-1.0.0-sources.pom"), b"").unwrap();
        std::fs::write(dir_path.join("maven-metadata.xml"), b"").unwrap();

        let cache = MavenRepoCache::for_tests(vec![repo_root]);
        let coords = cache.walk_rootfs_poms(1000);
        assert_eq!(coords, vec![(
            "com.example".to_string(),
            "alpha".to_string(),
            "1.0.0".to_string()
        )]);
    }

    #[test]
    fn walk_rootfs_poms_truncates_at_cap() {
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().to_path_buf();
        for i in 0..5 {
            write_cached_pom(
                &repo_root,
                "com.example",
                "alpha",
                &format!("{i}.0"),
                &format!(
                    "<project><groupId>com.example</groupId><artifactId>alpha</artifactId><version>{i}.0</version></project>",
                ),
            );
        }
        let cache = MavenRepoCache::for_tests(vec![repo_root]);
        let coords = cache.walk_rootfs_poms(3);
        assert_eq!(coords.len(), 3, "cap=3 must truncate 5 cached poms");
    }

    #[test]
    fn walk_rootfs_poms_handles_deep_group_paths() {
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().to_path_buf();
        write_cached_pom(
            &repo_root,
            "org.apache.commons.collections",
            "commons-collections4",
            "4.4",
            r#"<project><groupId>org.apache.commons.collections</groupId><artifactId>commons-collections4</artifactId><version>4.4</version></project>"#,
        );
        let cache = MavenRepoCache::for_tests(vec![repo_root]);
        let coords = cache.walk_rootfs_poms(1000);
        assert_eq!(coords, vec![(
            "org.apache.commons.collections".to_string(),
            "commons-collections4".to_string(),
            "4.4".to_string(),
        )]);
    }

    #[test]
    fn walk_rootfs_poms_empty_cache_returns_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cache = MavenRepoCache::for_tests(vec![dir.path().to_path_buf()]);
        assert!(cache.walk_rootfs_poms(1000).is_empty());
    }

    #[test]
    fn coord_from_m2_path_rejects_malformed_paths() {
        let root = Path::new("/fake/root");
        // Short path (missing group segment entirely)
        assert!(coord_from_m2_path(root, Path::new("/fake/root/a/1.0/a-1.0.pom")).is_none());
        // File name doesn't match artifact-version.pom
        assert!(coord_from_m2_path(
            root,
            Path::new("/fake/root/com/example/a/1.0/OTHER.pom")
        )
        .is_none());
        // Well-formed path — accepts.
        assert_eq!(
            coord_from_m2_path(
                root,
                Path::new("/fake/root/com/example/a/1.0/a-1.0.pom"),
            ),
            Some(("com.example".to_string(), "a".to_string(), "1.0".to_string()))
        );
    }
}