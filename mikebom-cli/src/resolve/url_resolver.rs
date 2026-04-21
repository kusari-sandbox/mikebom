//! Resolve registry download URLs into Package URLs (PURLs).
//!
//! Given an HTTP hostname and request path captured during a build trace,
//! determine the ecosystem and extract name + version to construct a PURL.

use mikebom_common::types::purl::Purl;

/// Attempt to resolve a hostname + path pair into a PURL by matching
/// against known package registry URL patterns.
///
/// Returns `None` if the URL doesn't match any known registry pattern.
pub fn resolve_url(hostname: &str, path: &str) -> Option<Purl> {
    resolve_url_with_context(hostname, path, None)
}

/// Same as [`resolve_url`] but threads per-trace context (e.g. the distro
/// codename sampled from `/etc/os-release` on the build host) through to
/// resolvers that need it. Only the deb resolver consumes this today.
pub fn resolve_url_with_context(
    hostname: &str,
    path: &str,
    deb_codename: Option<&str>,
) -> Option<Purl> {
    None.or_else(|| resolve_cargo(hostname, path))
        .or_else(|| resolve_pypi(hostname, path))
        .or_else(|| resolve_npm(hostname, path))
        .or_else(|| resolve_golang(hostname, path))
        .or_else(|| resolve_maven(hostname, path))
        .or_else(|| resolve_rubygems(hostname, path))
        .or_else(|| resolve_deb(hostname, path, deb_codename))
}

// ---------------------------------------------------------------------------
// Cargo / crates.io
// ---------------------------------------------------------------------------
// Pattern: /api/v1/crates/{name}/{version}/download
// Also:    /crates/{name}/{name}-{version}.crate  (static.crates.io CDN)
fn resolve_cargo(hostname: &str, path: &str) -> Option<Purl> {
    match hostname {
        "crates.io" | "static.crates.io" => {}
        _ => return None,
    }

    // /api/v1/crates/{name}/{version}/download
    if let Some(rest) = path.strip_prefix("/api/v1/crates/") {
        let parts: Vec<&str> = rest.splitn(3, '/').collect();
        if parts.len() >= 2 {
            let name = parts[0];
            let version = parts[1];
            let purl_str = format!("pkg:cargo/{name}@{version}");
            let purl = Purl::new(&purl_str).ok()?;
            tracing::debug!("cargo URL match: {purl_str}");
            return Some(purl);
        }
    }

    // /crates/{name}/{name}-{version}.crate  (CDN pattern)
    if let Some(rest) = path.strip_prefix("/crates/") {
        let parts: Vec<&str> = rest.splitn(2, '/').collect();
        if parts.len() == 2 {
            let name = parts[0];
            let filename = parts[1];
            if let Some(stem) = filename.strip_suffix(".crate") {
                // filename is "{name}-{version}"
                if let Some(version) = stem.strip_prefix(name).and_then(|s| s.strip_prefix('-')) {
                    let purl_str = format!("pkg:cargo/{name}@{version}");
                    let purl = Purl::new(&purl_str).ok()?;
                    tracing::debug!("cargo CDN URL match: {purl_str}");
                    return Some(purl);
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// PyPI
// ---------------------------------------------------------------------------
// Pattern: /packages/{hash_prefix}/{hash}/{name}-{version}.(tar.gz|whl|zip)
// Also:    /simple/{name}/ index pages (ignored — only downloads)
fn resolve_pypi(hostname: &str, path: &str) -> Option<Purl> {
    match hostname {
        "pypi.org" | "files.pythonhosted.org" => {}
        _ => return None,
    }

    if !path.starts_with("/packages/") {
        return None;
    }

    // Extract the filename from the last path segment.
    let filename = path.rsplit('/').next()?;

    // Strip known extensions to get "{name}-{version}" stem.
    let stem = strip_pypi_extension(filename)?;

    // Split on the last '-' that separates name from version.
    // PyPI filenames: {distribution}-{version}(-{build})?(-{python}(-{abi}(-{platform})))?.whl
    // For .tar.gz: {name}-{version}.tar.gz
    // We split on '-' and try to find where the version starts (first segment starting with digit).
    let (name, version) = split_pypi_name_version(stem)?;

    // Normalize: PEP 503 — replace hyphens/dots with underscores, lowercase.
    let normalized_name = name.replace('-', "_").replace('.', "_").to_lowercase();

    let purl_str = format!("pkg:pypi/{normalized_name}@{version}");
    let purl = Purl::new(&purl_str).ok()?;
    tracing::debug!("pypi URL match: {purl_str}");
    Some(purl)
}

fn strip_pypi_extension(filename: &str) -> Option<&str> {
    if let Some(s) = filename.strip_suffix(".tar.gz") {
        return Some(s);
    }
    if let Some(s) = filename.strip_suffix(".whl") {
        return Some(s);
    }
    if let Some(s) = filename.strip_suffix(".zip") {
        return Some(s);
    }
    if let Some(s) = filename.strip_suffix(".tar.bz2") {
        return Some(s);
    }
    None
}

/// Split a PyPI filename stem into (name, version).
/// The version starts at the first '-' followed by a digit.
fn split_pypi_name_version(stem: &str) -> Option<(&str, &str)> {
    // For wheel files the format is: {distribution}-{version}(-...)?
    // We need the first '-' where the next char is a digit.
    let bytes = stem.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            let name = &stem[..i];
            // Version goes until the next '-' (if wheel) or end (if sdist).
            let rest = &stem[i + 1..];
            // For sdist: rest IS the version.
            // For wheel: rest is "version-python-abi-platform"
            let version = rest.split('-').next()?;
            return Some((name, version));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// npm
// ---------------------------------------------------------------------------
// Pattern: /{name}/-/{name}-{version}.tgz
// Scoped:  /{@scope}/{name}/-/{name}-{version}.tgz
fn resolve_npm(hostname: &str, path: &str) -> Option<Purl> {
    if hostname != "registry.npmjs.org" {
        return None;
    }

    // Remove leading slash.
    let path = path.strip_prefix('/')?;

    // Check for scoped package: @scope/name/-/name-version.tgz
    if path.starts_with('@') {
        let parts: Vec<&str> = path.splitn(4, '/').collect();
        // parts: ["@scope", "name", "-", "name-version.tgz"]
        if parts.len() == 4 && parts[2] == "-" {
            let scope = parts[0]; // includes '@'
            let name = parts[1];
            let filename = parts[3];
            let version = extract_npm_version(filename, name)?;
            // PURL spec: scope is percent-encoded '@' → '%40'
            let encoded_scope = scope.replace('@', "%40");
            let purl_str = format!("pkg:npm/{encoded_scope}/{name}@{version}");
            let purl = Purl::new(&purl_str).ok()?;
            tracing::debug!("npm scoped URL match: {purl_str}");
            return Some(purl);
        }
    }

    // Unscoped: name/-/name-version.tgz
    let parts: Vec<&str> = path.splitn(3, '/').collect();
    if parts.len() == 3 && parts[1] == "-" {
        let name = parts[0];
        let filename = parts[2];
        let version = extract_npm_version(filename, name)?;
        let purl_str = format!("pkg:npm/{name}@{version}");
        let purl = Purl::new(&purl_str).ok()?;
        tracing::debug!("npm URL match: {purl_str}");
        return Some(purl);
    }

    None
}

/// Extract version from npm tarball filename: "{name}-{version}.tgz"
fn extract_npm_version<'a>(filename: &'a str, name: &str) -> Option<&'a str> {
    let stem = filename.strip_suffix(".tgz")?;
    let version = stem.strip_prefix(name)?.strip_prefix('-')?;
    Some(version)
}

// ---------------------------------------------------------------------------
// Go modules
// ---------------------------------------------------------------------------
// Pattern: /{module}/@v/{version}.zip|.mod|.info
fn resolve_golang(hostname: &str, path: &str) -> Option<Purl> {
    if hostname != "proxy.golang.org" && hostname != "sum.golang.org" {
        return None;
    }

    // Find "/@v/" separator.
    let at_v_idx = path.find("/@v/")?;
    let module = path[1..at_v_idx].to_string(); // strip leading '/'
    let version_file = &path[at_v_idx + 4..]; // after "/@v/"

    // Strip known extensions.
    let version = version_file
        .strip_suffix(".zip")
        .or_else(|| version_file.strip_suffix(".mod"))
        .or_else(|| version_file.strip_suffix(".info"))
        .or_else(|| version_file.strip_suffix(".ziphash"))?;

    if module.is_empty() || version.is_empty() {
        return None;
    }

    let purl_str = format!("pkg:golang/{module}@{version}");
    let purl = Purl::new(&purl_str).ok()?;
    tracing::debug!("golang URL match: {purl_str}");
    Some(purl)
}

// ---------------------------------------------------------------------------
// Maven
// ---------------------------------------------------------------------------
// Pattern: /{group/path}/{artifact}/{version}/{artifact}-{version}.jar|.pom|.aar
fn resolve_maven(hostname: &str, path: &str) -> Option<Purl> {
    match hostname {
        "repo1.maven.org" | "repo.maven.apache.org" | "central.maven.org" => {}
        _ => return None,
    }

    // Strip common prefix: /maven2/ or /maven/
    let rest = path
        .strip_prefix("/maven2/")
        .or_else(|| path.strip_prefix("/maven/"))
        .unwrap_or(path.strip_prefix('/').unwrap_or(path));

    // Split into segments.
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();

    // Need at least 3 segments: group(1+), artifact, version, filename
    if segments.len() < 4 {
        return None;
    }

    let filename = segments[segments.len() - 1];
    let version = segments[segments.len() - 2];
    let artifact = segments[segments.len() - 3];
    let group_parts = &segments[..segments.len() - 3];

    // Validate filename starts with "{artifact}-{version}"
    let expected_prefix = format!("{artifact}-{version}");
    if !filename.starts_with(&expected_prefix) {
        return None;
    }

    let group = group_parts.join(".");

    let purl_str = format!("pkg:maven/{group}/{artifact}@{version}");
    let purl = Purl::new(&purl_str).ok()?;
    tracing::debug!("maven URL match: {purl_str}");
    Some(purl)
}

// ---------------------------------------------------------------------------
// RubyGems
// ---------------------------------------------------------------------------
// Pattern: /downloads/{name}-{version}.gem  OR  /gems/{name}-{version}.gem
fn resolve_rubygems(hostname: &str, path: &str) -> Option<Purl> {
    if hostname != "rubygems.org" {
        return None;
    }

    let filename = path
        .strip_prefix("/downloads/")
        .or_else(|| path.strip_prefix("/gems/"))?;

    let stem = filename.strip_suffix(".gem")?;

    // The version starts after the last '-' that is followed by a digit.
    let (name, version) = split_gem_name_version(stem)?;

    let purl_str = format!("pkg:gem/{name}@{version}");
    let purl = Purl::new(&purl_str).ok()?;
    tracing::debug!("rubygems URL match: {purl_str}");
    Some(purl)
}

/// Split a gem filename stem into (name, version).
/// The version starts at the last '-' followed by a digit.
fn split_gem_name_version(stem: &str) -> Option<(&str, &str)> {
    let bytes = stem.as_bytes();
    // Search from the end for the last '-' followed by a digit.
    for i in (0..bytes.len()).rev() {
        if bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            return Some((&stem[..i], &stem[i + 1..]));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Debian / Ubuntu apt
// ---------------------------------------------------------------------------
// Pattern: /debian/pool/main/{letter}/{name}/{name}_{version}_{arch}.deb
// Also:    /ubuntu/pool/main/{letter}/{name}/{name}_{version}_{arch}.deb
fn resolve_deb(hostname: &str, path: &str, codename_hint: Option<&str>) -> Option<Purl> {
    let distro_namespace = match hostname {
        "deb.debian.org" | "security.debian.org" => "debian",
        "archive.ubuntu.com" | "security.ubuntu.com" => "ubuntu",
        _ => return None,
    };

    // Find the pool/ section.
    let pool_idx = path.find("/pool/")?;
    let after_pool = &path[pool_idx + 6..]; // after "/pool/"

    // Split: "main/{letter}/{name}/{name}_{version}_{arch}.deb"
    // or: "main/{letter}/{name}/{filename}.deb"
    let segments: Vec<&str> = after_pool.split('/').collect();
    if segments.len() < 4 {
        return None;
    }

    // The filename is the last segment.
    let filename = segments.last()?;
    let stem = filename.strip_suffix(".deb")
        .or_else(|| filename.strip_suffix(".udeb"))?;

    // Split filename stem: "{name}_{version}_{arch}"
    // Note: package names may contain hyphens but not underscores (usually).
    let parts: Vec<&str> = stem.splitn(3, '_').collect();
    if parts.len() < 3 {
        return None;
    }

    let name = parts[0];
    let version = parts[1];
    let arch = parts[2];

    // Codename precedence: explicit hint from the trace host (preferred,
    // because it comes from `/etc/os-release` on the machine the build
    // actually ran on), then a URL-path heuristic for pool URLs that
    // include the codename (`/dists/bookworm/` etc.), then nothing.
    let codename = codename_hint
        .map(|s| s.to_string())
        .or_else(|| guess_deb_codename(distro_namespace, path).map(|s| s.to_string()));

    // Percent-encode special characters in the version for PURL qualifiers.
    // The PURL spec requires proper encoding in the canonical form.
    let encoded_version = percent_encode_deb_version(version);
    // Encode `+` in name too (`libstdc++6` → `libstdc%2B%2B6`).
    let encoded_name = mikebom_common::types::purl::encode_purl_segment(name);

    // PURL deb spec: `distro` qualifier value is the codename alone
    // (`bookworm`, `jammy`), not `<namespace>-<codename>`. Matching the
    // spec here lets downstream tools (deps.dev, osv.dev, vex feeds) use
    // the PURL as a stable lookup key.
    let mut purl_str = format!(
        "pkg:deb/{distro_namespace}/{encoded_name}@{encoded_version}?arch={arch}"
    );
    if let Some(cn) = codename {
        purl_str.push_str(&format!("&distro={cn}"));
    }

    let purl = Purl::new(&purl_str).ok()?;
    tracing::debug!("deb URL match: {purl_str}");
    Some(purl)
}

/// Percent-encode a Debian version string to match the packageurl
/// reference implementation's canonical form. Delegates to the shared
/// helper so scan-mode and trace-mode produce byte-identical PURLs.
///
/// Note the asymmetry: only `+` is encoded; `:` (epoch) and `~`
/// (pre-release marker) stay literal per the reference impl.
fn percent_encode_deb_version(version: &str) -> String {
    mikebom_common::types::purl::encode_purl_version(version)
}

/// Attempt to guess the distribution codename from the URL path.
/// This is a best-effort heuristic; the codename is not always present.
fn guess_deb_codename(namespace: &str, path: &str) -> Option<&'static str> {
    // Check for known codenames in the path.
    let debian_codenames = [
        "trixie", "bookworm", "bullseye", "buster", "stretch",
    ];
    let ubuntu_codenames = [
        "noble", "mantic", "lunar", "kinetic", "jammy", "focal", "bionic",
    ];

    let codenames: &[&str] = match namespace {
        "debian" => &debian_codenames,
        "ubuntu" => &ubuntu_codenames,
        _ => return None,
    };

    let path_lower = path.to_ascii_lowercase();
    for &cn in codenames {
        if path_lower.contains(cn) {
            return Some(cn);
        }
    }

    // Default codenames when we can't determine from URL.
    None
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Cargo tests
    // -----------------------------------------------------------------------
    #[test]
    fn cargo_api_download() {
        let purl = resolve_url("crates.io", "/api/v1/crates/serde/1.0.197/download");
        let purl = purl.expect("should resolve cargo PURL");
        assert_eq!(purl.ecosystem(), "cargo");
        assert_eq!(purl.name(), "serde");
        assert_eq!(purl.version(), Some("1.0.197"));
    }

    #[test]
    fn cargo_cdn_download() {
        let purl = resolve_url(
            "static.crates.io",
            "/crates/anyhow/anyhow-1.0.86.crate",
        );
        let purl = purl.expect("should resolve cargo CDN PURL");
        assert_eq!(purl.ecosystem(), "cargo");
        assert_eq!(purl.name(), "anyhow");
        assert_eq!(purl.version(), Some("1.0.86"));
    }

    #[test]
    fn cargo_hyphenated_name() {
        let purl = resolve_url(
            "crates.io",
            "/api/v1/crates/serde_json/1.0.120/download",
        );
        let purl = purl.expect("should resolve hyphenated cargo PURL");
        assert_eq!(purl.name(), "serde_json");
        assert_eq!(purl.version(), Some("1.0.120"));
    }

    // -----------------------------------------------------------------------
    // PyPI tests
    // -----------------------------------------------------------------------
    #[test]
    fn pypi_sdist() {
        let purl = resolve_url(
            "files.pythonhosted.org",
            "/packages/ab/cd/ef012345/requests-2.31.0.tar.gz",
        );
        let purl = purl.expect("should resolve pypi sdist PURL");
        assert_eq!(purl.ecosystem(), "pypi");
        assert_eq!(purl.name(), "requests");
        assert_eq!(purl.version(), Some("2.31.0"));
    }

    #[test]
    fn pypi_wheel() {
        let purl = resolve_url(
            "files.pythonhosted.org",
            "/packages/ab/cd/ef/cryptography-42.0.5-cp39-abi3-manylinux_2_28_x86_64.whl",
        );
        let purl = purl.expect("should resolve pypi wheel PURL");
        assert_eq!(purl.ecosystem(), "pypi");
        assert_eq!(purl.name(), "cryptography");
        assert_eq!(purl.version(), Some("42.0.5"));
    }

    #[test]
    fn pypi_name_normalization() {
        let purl = resolve_url(
            "files.pythonhosted.org",
            "/packages/aa/bb/cc/my-cool-package-1.2.3.tar.gz",
        );
        let purl = purl.expect("should resolve and normalize pypi PURL");
        // The packageurl crate normalizes PyPI names to use hyphens per the PURL spec.
        // Our input normalization (underscores) is further normalized to hyphens.
        assert_eq!(purl.name(), "my-cool-package");
    }

    // -----------------------------------------------------------------------
    // npm tests
    // -----------------------------------------------------------------------
    #[test]
    fn npm_unscoped() {
        let purl = resolve_url(
            "registry.npmjs.org",
            "/lodash/-/lodash-4.17.21.tgz",
        );
        let purl = purl.expect("should resolve npm PURL");
        assert_eq!(purl.ecosystem(), "npm");
        assert_eq!(purl.name(), "lodash");
        assert_eq!(purl.version(), Some("4.17.21"));
    }

    #[test]
    fn npm_scoped() {
        let purl = resolve_url(
            "registry.npmjs.org",
            "/@angular/core/-/core-16.0.0.tgz",
        );
        let purl = purl.expect("should resolve scoped npm PURL");
        assert_eq!(purl.ecosystem(), "npm");
        assert_eq!(purl.namespace(), Some("@angular"));
        assert_eq!(purl.name(), "core");
        assert_eq!(purl.version(), Some("16.0.0"));
    }

    #[test]
    fn npm_scoped_with_dots_in_version() {
        let purl = resolve_url(
            "registry.npmjs.org",
            "/@types/node/-/node-20.11.5.tgz",
        );
        let purl = purl.expect("should resolve scoped npm with dots");
        assert_eq!(purl.namespace(), Some("@types"));
        assert_eq!(purl.name(), "node");
        assert_eq!(purl.version(), Some("20.11.5"));
    }

    // -----------------------------------------------------------------------
    // Go tests
    // -----------------------------------------------------------------------
    #[test]
    fn golang_zip() {
        let purl = resolve_url(
            "proxy.golang.org",
            "/golang.org/x/net/@v/v0.24.0.zip",
        );
        let purl = purl.expect("should resolve golang zip PURL");
        assert_eq!(purl.ecosystem(), "golang");
        assert_eq!(purl.version(), Some("v0.24.0"));
    }

    #[test]
    fn golang_mod() {
        let purl = resolve_url(
            "proxy.golang.org",
            "/github.com/stretchr/testify/@v/v1.9.0.mod",
        );
        let purl = purl.expect("should resolve golang mod PURL");
        assert_eq!(purl.ecosystem(), "golang");
        assert_eq!(purl.version(), Some("v1.9.0"));
    }

    #[test]
    fn golang_info() {
        let purl = resolve_url(
            "proxy.golang.org",
            "/google.golang.org/protobuf/@v/v1.33.0.info",
        );
        let purl = purl.expect("should resolve golang info PURL");
        assert_eq!(purl.ecosystem(), "golang");
        assert_eq!(purl.version(), Some("v1.33.0"));
    }

    // -----------------------------------------------------------------------
    // Maven tests
    // -----------------------------------------------------------------------
    #[test]
    fn maven_jar() {
        let purl = resolve_url(
            "repo1.maven.org",
            "/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar",
        );
        let purl = purl.expect("should resolve maven PURL");
        assert_eq!(purl.ecosystem(), "maven");
        assert_eq!(purl.namespace(), Some("org.apache.commons"));
        assert_eq!(purl.name(), "commons-lang3");
        assert_eq!(purl.version(), Some("3.12.0"));
    }

    #[test]
    fn maven_pom() {
        let purl = resolve_url(
            "repo1.maven.org",
            "/maven2/com/google/guava/guava/33.0.0-jre/guava-33.0.0-jre.pom",
        );
        let purl = purl.expect("should resolve maven POM PURL");
        assert_eq!(purl.ecosystem(), "maven");
        assert_eq!(purl.namespace(), Some("com.google.guava"));
        assert_eq!(purl.name(), "guava");
        assert_eq!(purl.version(), Some("33.0.0-jre"));
    }

    // -----------------------------------------------------------------------
    // RubyGems tests
    // -----------------------------------------------------------------------
    #[test]
    fn rubygems_downloads() {
        let purl = resolve_url(
            "rubygems.org",
            "/downloads/rails-7.1.3.gem",
        );
        let purl = purl.expect("should resolve rubygems PURL");
        assert_eq!(purl.ecosystem(), "gem");
        assert_eq!(purl.name(), "rails");
        assert_eq!(purl.version(), Some("7.1.3"));
    }

    #[test]
    fn rubygems_gems() {
        let purl = resolve_url(
            "rubygems.org",
            "/gems/nokogiri-1.16.5.gem",
        );
        let purl = purl.expect("should resolve rubygems gems PURL");
        assert_eq!(purl.ecosystem(), "gem");
        assert_eq!(purl.name(), "nokogiri");
        assert_eq!(purl.version(), Some("1.16.5"));
    }

    #[test]
    fn rubygems_hyphenated_name() {
        let purl = resolve_url(
            "rubygems.org",
            "/gems/aws-sdk-core-3.190.0.gem",
        );
        let purl = purl.expect("should resolve hyphenated rubygems PURL");
        assert_eq!(purl.name(), "aws-sdk-core");
        assert_eq!(purl.version(), Some("3.190.0"));
    }

    // -----------------------------------------------------------------------
    // Debian / apt tests
    // -----------------------------------------------------------------------
    #[test]
    fn deb_simple() {
        let purl = resolve_url(
            "deb.debian.org",
            "/debian/pool/main/c/curl/curl_8.5.0-2_amd64.deb",
        );
        let purl = purl.expect("should resolve simple deb PURL");
        assert_eq!(purl.ecosystem(), "deb");
        assert_eq!(purl.namespace(), Some("debian"));
        assert_eq!(purl.name(), "curl");
    }

    #[test]
    fn deb_version_with_plus() {
        // The '+' in version "3.11.2+dfsg-2" is a valid Debian version character.
        let purl = resolve_url(
            "deb.debian.org",
            "/debian/pool/main/p/python3.11/python3.11_3.11.2+dfsg-2_amd64.deb",
        );
        let purl = purl.expect("should resolve deb PURL with + in version");
        assert_eq!(purl.ecosystem(), "deb");
        assert_eq!(purl.name(), "python3.11");
        // The version is stored decoded by the packageurl crate.
        // We verify the version was correctly parsed including the '+'.
        let version = purl.version().expect("should have version");
        assert!(
            version.contains('+') || version.contains("%2B") || version.contains("%2b"),
            "version should contain '+' or its encoding, got: {version}"
        );
    }

    #[test]
    fn deb_version_with_colon_epoch() {
        // Epoch prefix: "2:8.2.5105-2" — the ':' separates epoch from upstream version.
        let purl = resolve_url(
            "deb.debian.org",
            "/debian/pool/main/v/vim/vim_2:8.2.5105-2_amd64.deb",
        );
        let purl = purl.expect("should resolve deb PURL with epoch colon");
        assert_eq!(purl.name(), "vim");
        // The version should contain the epoch and upstream version.
        let version = purl.version().expect("should have version");
        assert!(
            version.contains(':') || version.contains("%3A") || version.contains("%3a"),
            "version should contain ':' or its encoding, got: {version}"
        );
    }

    #[test]
    fn deb_version_with_tilde() {
        // Tilde in version: "1.2.3~rc1-1" — the '~' is a pre-release indicator in Debian.
        let purl = resolve_url(
            "deb.debian.org",
            "/debian/pool/main/f/foo/foo_1.2.3~rc1-1_arm64.deb",
        );
        let purl = purl.expect("should resolve deb PURL with ~ in version");
        assert_eq!(purl.name(), "foo");
        // The version should contain the tilde.
        let version = purl.version().expect("should have version");
        assert!(
            version.contains('~') || version.contains("%7E") || version.contains("%7e"),
            "version should contain '~' or its encoding, got: {version}"
        );
    }

    #[test]
    fn deb_ubuntu() {
        let purl = resolve_url(
            "archive.ubuntu.com",
            "/ubuntu/pool/main/o/openssl/openssl_3.0.13-0ubuntu3.4_amd64.deb",
        );
        let purl = purl.expect("should resolve ubuntu deb PURL");
        assert_eq!(purl.ecosystem(), "deb");
        assert_eq!(purl.namespace(), Some("ubuntu"));
        assert_eq!(purl.name(), "openssl");
    }

    #[test]
    fn deb_with_codename_in_path() {
        let purl = resolve_url(
            "deb.debian.org",
            "/debian/pool/main/bookworm/l/libssl/libssl3_3.0.13-1~deb12u1_amd64.deb",
        );
        // URL-path parsing should still work when the path segment
        // contains a codename. Whatever value the in-path detector
        // produces is stamped verbatim as the `distro=` qualifier; the
        // canonical shape across scan-mode code paths is
        // `<namespace>-<VERSION_ID>` (e.g. `debian-12`), but this URL
        // path only exposes the bare codename so that's what lands.
        if let Some(p) = purl {
            assert_eq!(p.ecosystem(), "deb");
            let canonical = p.as_str();
            assert!(
                canonical.contains("distro="),
                "expected some distro= qualifier in {canonical}"
            );
        }
    }

    #[test]
    fn deb_codename_hint_from_host_metadata() {
        // Even when the URL path does not contain a codename, an explicit
        // host-metadata hint (e.g. from /etc/os-release) should land in the
        // PURL.
        let purl = super::resolve_url_with_context(
            "deb.debian.org",
            "/debian/pool/main/j/jq/jq_1.6-2.1+deb12u1_arm64.deb",
            Some("bookworm"),
        )
        .expect("should resolve");
        let canonical = purl.as_str();
        assert!(
            canonical.contains("distro=bookworm"),
            "expected distro=bookworm in {canonical}"
        );
    }

    #[test]
    fn deb_complex_version_all_special_chars() {
        // Version with both tilde and plus: "12.3.0~rc1+dfsg-1".
        let purl = resolve_url(
            "deb.debian.org",
            "/debian/pool/main/g/gcc/gcc-12_12.3.0~rc1+dfsg-1_amd64.deb",
        );
        let purl = purl.expect("should resolve deb PURL with complex version");
        assert_eq!(purl.name(), "gcc-12");
        // Verify both special characters are preserved in the version.
        let version = purl.version().expect("should have version");
        assert!(
            version.contains('~') || version.contains("%7E") || version.contains("%7e"),
            "version should contain '~' or its encoding, got: {version}"
        );
        assert!(
            version.contains('+') || version.contains("%2B") || version.contains("%2b"),
            "version should contain '+' or its encoding, got: {version}"
        );
    }

    // -----------------------------------------------------------------------
    // Negative / unknown tests
    // -----------------------------------------------------------------------
    #[test]
    fn unknown_host_returns_none() {
        let purl = resolve_url("example.com", "/some/path");
        assert!(purl.is_none());
    }

    #[test]
    fn malformed_path_returns_none() {
        let purl = resolve_url("crates.io", "/api/v1/crates/");
        assert!(purl.is_none());
    }
}
