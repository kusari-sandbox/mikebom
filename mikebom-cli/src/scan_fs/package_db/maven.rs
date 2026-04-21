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

use mikebom_common::types::purl::Purl;

use super::PackageDbEntry;

const MAX_PROJECT_ROOT_DEPTH: usize = 6;
/// Per-entry size cap inside JARs; 64 MB is well beyond real pom.properties.
const MAX_JAR_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Maven repo cache lookup — for transitive dep-graph reconstruction
// ---------------------------------------------------------------------------

/// Candidate local-repo roots for a given scan. Populated once per
/// scan. Layout: `<root>/<group-as-path>/<artifact>/<version>/<artifact>-<version>.pom`.
#[derive(Clone, Debug, Default)]
pub(crate) struct MavenRepoCache {
    roots: Vec<PathBuf>,
}

impl MavenRepoCache {
    /// Discover candidate `~/.m2/repository` style directories.
    /// Priority order:
    /// 1. `$M2_REPO` / `$MAVEN_HOME/repository` when set.
    /// 2. `$HOME/.m2/repository` (most dev machines).
    /// 3. `<rootfs>/root/.m2/repository` (conventional container images
    ///    that pre-populate the cache as root).
    /// 4. `<rootfs>/home/*/.m2/repository`.
    /// 5. `<rootfs>/usr/share/maven-repo` (Debian's system-Maven repo).
    ///
    /// Each candidate is included only when the directory actually
    /// exists. Earlier entries win when the same pom is present in
    /// multiple caches.
    pub(crate) fn discover(rootfs: &Path) -> Self {
        let mut roots: Vec<PathBuf> = Vec::new();
        let mut seen: HashSet<PathBuf> = HashSet::new();

        let mut try_add = |candidate: PathBuf, roots: &mut Vec<PathBuf>| {
            let canonical = std::fs::canonicalize(&candidate).unwrap_or(candidate.clone());
            if !seen.insert(canonical) {
                return;
            }
            if candidate.is_dir() {
                roots.push(candidate);
            }
        };

        if let Ok(env) = std::env::var("M2_REPO") {
            if !env.is_empty() {
                try_add(PathBuf::from(&env), &mut roots);
            }
        }
        if let Ok(env) = std::env::var("MAVEN_HOME") {
            if !env.is_empty() {
                try_add(PathBuf::from(&env).join("repository"), &mut roots);
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                try_add(PathBuf::from(&home).join(".m2/repository"), &mut roots);
            }
        }
        try_add(rootfs.join("root/.m2/repository"), &mut roots);
        if let Ok(home_dir) = std::fs::read_dir(rootfs.join("home")) {
            for entry in home_dir.flatten() {
                let candidate = entry.path().join(".m2/repository");
                try_add(candidate, &mut roots);
            }
        }
        try_add(rootfs.join("usr/share/maven-repo"), &mut roots);

        MavenRepoCache { roots }
    }

    /// Read `<root>/<group-as-path>/<artifact>/<version>/<artifact>-<version>.pom`
    /// from the first cache root that has it. Returns `None` when no
    /// cache has the artefact or IO fails.
    pub(crate) fn read_pom(&self, group: &str, artifact: &str, version: &str) -> Option<Vec<u8>> {
        if self.roots.is_empty() {
            return None;
        }
        let group_path = group.replace('.', "/");
        let relative =
            format!("{group_path}/{artifact}/{version}/{artifact}-{version}.pom");
        for root in &self.roots {
            let path = root.join(&relative);
            if let Ok(bytes) = std::fs::read(&path) {
                return Some(bytes);
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
        if self.roots.is_empty() {
            return Vec::new();
        }
        let group_path = group.replace('.', "/");
        let base = format!("{group_path}/{artifact}/{version}/{artifact}-{version}.jar");
        let mut out: Vec<mikebom_common::types::hash::ContentHash> = Vec::new();
        for root in &self.roots {
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
fn fetch_pom_bytes(
    store: &PomStore,
    cache: &MavenRepoCache,
    g: &str,
    a: &str,
    v: &str,
) -> Option<Vec<u8>> {
    if let Some(bytes) = store.get(&coord_key(g, a, v)) {
        return Some(bytes.clone());
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
            if let Some(bytes) = fetch_pom_bytes(store, cache, &pg, &pa, &pv) {
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
        if let Some(bytes) = fetch_pom_bytes(store, cache, &bom_g, &entry.artifact_id, &bom_v) {
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
    Purl::new(&format!("pkg:maven/{group}/{artifact}@{version}")).ok()
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
        npm_role: None,
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
fn bfs_transitive_poms(
    cache: &MavenRepoCache,
    store: &PomStore,
    seeds: &[(String, String, String)],
    include_dev: bool,
    source_path: &str,
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

        let Some(bytes) = fetch_pom_bytes(store, cache, &group, &artifact, &version) else {
            // Cache miss — emit the component with no outbound edges
            // and don't enqueue further. This keeps partial-cache
            // scans as useful as possible without fabricating data.
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
            continue;
        };

        let upstream = parse_pom_xml(&bytes);
        // Build the effective POM: merges properties and
        // dependencyManagement up the full parent chain so deps
        // with no inline version or with `${...}` placeholders can
        // resolve through inherited declarations.
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
        npm_role: None,
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
) -> Option<PackageDbEntry> {
    let purl = build_maven_purl(&p.group_id, &p.artifact_id, &p.version)?;
    let mut hashes: Vec<mikebom_common::types::hash::ContentHash> = Vec::new();
    hashes.extend(sidecar_hash);
    hashes.extend(archive_sha256);
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
        npm_role: None,
        hashes,
        sbom_tier: Some("analyzed".to_string()),
    })
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Backward-compat shim for tests and callers that don't have a
/// populated claim set. Delegates to [`read_with_claims`] with empty
/// claim sets. Production code should go through `read_with_claims`
/// with the package-db walker's claim set so RPM-owned Maven JARs are
/// skipped (conformance bug 2b).
pub fn read(rootfs: &Path, include_dev: bool) -> Vec<PackageDbEntry> {
    let claimed = std::collections::HashSet::new();
    #[cfg(unix)]
    let claimed_inodes = std::collections::HashSet::new();
    read_with_claims(
        rootfs,
        include_dev,
        &claimed,
        #[cfg(unix)]
        &claimed_inodes,
    )
}

pub fn read_with_claims(
    rootfs: &Path,
    include_dev: bool,
    claimed: &std::collections::HashSet<std::path::PathBuf>,
    #[cfg(unix)] claimed_inodes: &std::collections::HashSet<(u64, u64)>,
) -> Vec<PackageDbEntry> {
    let mut out: Vec<PackageDbEntry> = Vec::new();
    let mut seen_purls: HashSet<String> = HashSet::new();
    let (pom_files, jar_files) = find_maven_artifacts(rootfs);
    // Discover M2 repo cache once per scan. Each dep's own pom.xml
    // sits at <repo>/<group-as-path>/<artifact>/<version>/<artifact>-<version>.pom;
    // fetching it gives us that dep's own <dependencies> block for
    // transitive edges.
    let repo_cache = MavenRepoCache::discover(rootfs);
    if !repo_cache.roots.is_empty() {
        tracing::debug!(
            rootfs = %rootfs.display(),
            repo_roots = repo_cache.roots.len(),
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
    // v6 fix (conformance bug 2b): skip JARs whose on-disk path is
    // claimed by a package-db reader (dpkg / apk / rpm). Fedora's
    // `dnf install maven` drops JARs at `/usr/share/java/*.jar` which
    // are owned by RPM packages; walking them as Maven artefacts
    // double-reports them as `pkg:maven/...` alongside `pkg:rpm/...`
    // AND frequently emits empty versions because the RPM-packaged
    // JARs ship `pom.properties` with unresolved `${project.version}`
    // placeholders.
    let mut jar_meta: Vec<(String, Vec<EmbeddedMavenMeta>)> = Vec::new();
    for jar_path in &jar_files {
        if crate::scan_fs::binary::is_path_claimed(
            jar_path,
            claimed,
            #[cfg(unix)]
            claimed_inodes,
        ) {
            tracing::debug!(
                path = %jar_path.display(),
                "skipping claimed JAR (already owned by a package-db reader)"
            );
            continue;
        }
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
        jar_meta.push((jar_path.to_string_lossy().into_owned(), meta));
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
            // Seed BFS with the concrete (group, artifact, version) —
            // effective POM fills in values from parent depMgmt or
            // inherited properties. Drop the seed when either can't
            // be resolved (no concrete coord, no cache lookup possible).
            let Some(group) = resolve_dep_group(dep, &project_eff) else {
                direct_entries.push((dep.clone(), entry));
                continue;
            };
            let Some(version) = resolve_dep_version(dep, &project_eff) else {
                direct_entries.push((dep.clone(), entry));
                continue;
            };
            if !version.is_empty() {
                bfs_seeds.push((group, dep.artifact_id.clone(), version));
            }
            direct_entries.push((dep.clone(), entry));
        }

        // BFS the M2 cache from every direct-dep seed. Uses the unified
        // POM store for parent-chain lookups so BOM imports and
        // JAR-embedded parents resolve alongside on-disk cached poms.
        let bfs_entries = bfs_transitive_poms(
            &repo_cache,
            &pom_store,
            &bfs_seeds,
            include_dev,
            &source_path,
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
    for (_src, meta_list) in &jar_meta {
        for m in meta_list {
            coord_index
                .entry((m.coord.group_id.clone(), m.coord.artifact_id.clone()))
                .or_insert_with(|| m.coord.version.clone());
        }
    }
    for (source_path, meta_list) in jar_meta {
        for meta in meta_list {
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
            let Some(entry) = jar_pom_to_entry(
                &meta.coord,
                depends,
                &source_path,
                meta.sidecar_hash.clone(),
                meta.archive_sha256.clone(),
            ) else {
                continue;
            };
            let key = entry.purl.as_str().to_string();
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
    out
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
        let cache = MavenRepoCache {
            roots: vec![repo_root.clone()],
        };
        let bytes = cache
            .read_pom("com.google.guava", "guava", "32.1.3-jre")
            .expect("cached pom readable");
        assert!(std::str::from_utf8(&bytes).unwrap().contains("failureaccess"));
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
        let cache = MavenRepoCache {
            roots: vec![repo_root.clone()],
        };
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex".into(), "a".into(), "1".into())],
            false,
            "/p/pom.xml",
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
        let cache = MavenRepoCache {
            roots: vec![repo_root.clone()],
        };
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex".into(), "a".into(), "1".into())],
            false,
            "/p/pom.xml",
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
        let cache = MavenRepoCache {
            roots: vec![repo_root.clone()],
        };
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex".into(), "a".into(), "1".into())],
            false,
            "/p/pom.xml",
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
        let cache = MavenRepoCache {
            roots: vec![repo_root.clone()],
        };
        // include_dev = false: test-scope B not followed, so BFS emits only A.
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex".into(), "a".into(), "1".into())],
            false,
            "/p/pom.xml",
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
            "/p/pom.xml",
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
        let cache = MavenRepoCache {
            roots: vec![repo_root.clone()],
        };
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("ex".into(), "a".into(), "1".into())],
            false,
            "/p/pom.xml",
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
            "/p/pom.xml",
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
        let cache = MavenRepoCache {
            roots: vec![repo_root.clone()],
        };
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
        let cache = MavenRepoCache {
            roots: vec![repo_root.clone()],
        };
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
        let cache = MavenRepoCache {
            roots: vec![repo_root.clone()],
        };
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
        let cache = MavenRepoCache {
            roots: vec![repo_root.clone()],
        };
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
        let cache = MavenRepoCache {
            roots: vec![repo_root.clone()],
        };
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
        let cache = MavenRepoCache {
            roots: vec![repo_root.clone()],
        };
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
        let cache = MavenRepoCache {
            roots: vec![repo_root.clone()],
        };
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
        let cache = MavenRepoCache {
            roots: vec![repo_root.clone()],
        };
        let entries = bfs_transitive_poms(
            &cache,
            &HashMap::new(),
            &[("com.google.guava".into(), "guava".into(), "32.1.3-jre".into())],
            false,
            "/p/pom.xml",
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
    fn read_with_claims_skips_jars_in_claim_set() {
        // Simulate Fedora's `dnf install maven` layout: a JAR in
        // /usr/share/java is already emitted by the rpm reader, so its
        // path is in the claim set. The Maven JAR walker must skip it.
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

        // Without the claim, the walker emits the JAR.
        let empty_claims: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        #[cfg(unix)]
        let empty_inodes: std::collections::HashSet<(u64, u64)> =
            std::collections::HashSet::new();
        let no_claim = read_with_claims(
            dir.path(),
            false,
            &empty_claims,
            #[cfg(unix)]
            &empty_inodes,
        );
        assert_eq!(no_claim.len(), 1, "baseline: expected 1 Maven entry");
        assert_eq!(no_claim[0].name, "commons-io");

        // With the JAR path claimed, the walker skips it.
        let mut claimed: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        claimed.insert(jar_path.clone());
        #[cfg(unix)]
        let claimed_inodes: std::collections::HashSet<(u64, u64)> =
            std::collections::HashSet::new();
        let with_claim = read_with_claims(
            dir.path(),
            false,
            &claimed,
            #[cfg(unix)]
            &claimed_inodes,
        );
        assert_eq!(
            with_claim.len(),
            0,
            "claimed JAR must be skipped; got {with_claim:?}"
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

        let cache = MavenRepoCache {
            roots: vec![dir.path().to_path_buf()],
        };
        let hashes = cache.read_artifact_hash("com.example", "myapp", "1.0.0");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].value.as_str(), &hex);
    }

    #[test]
    fn read_artifact_hash_returns_empty_when_no_cache_roots() {
        let cache = MavenRepoCache { roots: vec![] };
        let hashes = cache.read_artifact_hash("com.example", "myapp", "1.0.0");
        assert!(hashes.is_empty());
    }
}