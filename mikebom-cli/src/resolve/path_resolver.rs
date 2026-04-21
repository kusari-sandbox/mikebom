//! Resolve file paths to PURLs using SBOMit-style path pattern matching.
//!
//! When a build trace captures file write operations (e.g., downloading a
//! crate to ~/.cargo/registry/cache/), the file path itself often encodes
//! enough information to identify the package.

use mikebom_common::types::purl::Purl;

/// Attempt to resolve a file path into a PURL by matching against known
/// package manager cache/install directory patterns.
///
/// Returns `None` if the path doesn't match any known pattern.
pub fn resolve_path(path: &str) -> Option<Purl> {
    resolve_path_with_context(path, None)
}

/// Same as [`resolve_path`] but threads per-trace context (e.g. the distro
/// identifier from `/etc/os-release`) through to the deb resolver so the
/// produced PURL can carry a `distro=<value>` qualifier. The value is
/// stamped verbatim — callers decide the shape (scan-mode package-DB
/// readers use `<namespace>-<VERSION_ID>`, e.g. `debian-12`).
pub fn resolve_path_with_context(path: &str, deb_codename: Option<&str>) -> Option<Purl> {
    None.or_else(|| resolve_cargo_path(path))
        .or_else(|| resolve_pip_path(path))
        .or_else(|| resolve_npm_path(path))
        .or_else(|| resolve_go_path(path))
        .or_else(|| resolve_deb_path(path, deb_codename))
}

// ---------------------------------------------------------------------------
// Cargo: ~/.cargo/registry/cache/{index}/{name}-{version}.crate
// Also:  $CARGO_HOME/registry/cache/{index}/{name}-{version}.crate where
//        $CARGO_HOME is commonly `/usr/local/cargo` (rust Docker images),
//        `/opt/cargo`, etc. — any directory whose path contains
//        `cargo/registry/cache/<index>/`.
// ---------------------------------------------------------------------------
fn resolve_cargo_path(path: &str) -> Option<Purl> {
    // Prefer the dotfile form for back-compat, fall back to any
    // `cargo/registry/cache/` anchor so non-$HOME CARGO_HOMEs work too.
    let (cache_idx, marker_len) = if let Some(i) = path.find(".cargo/registry/cache/") {
        (i, ".cargo/registry/cache/".len())
    } else if let Some(i) = path.find("cargo/registry/cache/") {
        (i, "cargo/registry/cache/".len())
    } else {
        return None;
    };
    let after_cache = &path[cache_idx + marker_len..];

    // Skip the index hash directory (e.g., "crates.io-6f17d22bba15001f/"
    // or "index.crates.io-1949cf8c6b5b557f/" for the sparse protocol).
    let slash_idx = after_cache.find('/')?;
    let filename = &after_cache[slash_idx + 1..];

    // Strip .crate extension.
    let stem = filename.strip_suffix(".crate")?;

    // Split on the last '-' followed by a digit to get name and version.
    let (name, version) = split_name_version_last_dash(stem)?;

    let purl_str = format!("pkg:cargo/{name}@{version}");
    let purl = Purl::new(&purl_str).ok()?;
    tracing::debug!("cargo path match: {purl_str}");
    Some(purl)
}

// ---------------------------------------------------------------------------
// pip: site-packages/{name}-{version}.dist-info/
//      site-packages/{name}/  (harder — no version)
//      wheel cache: <anywhere>/{name}-{version}(-<build>)?-<py>-<abi>-<plat>.whl
// ---------------------------------------------------------------------------
fn resolve_pip_path(path: &str) -> Option<Purl> {
    // Wheel file: check extension first since it's the cheapest fail.
    if path.ends_with(".whl") {
        let filename = path.rsplit('/').next()?;
        let stem = filename.strip_suffix(".whl")?;
        // Wheel filenames are hyphen-separated with either 5 or 6
        // segments: {name}-{version}-{py}-{abi}-{plat} (5) or
        // {name}-{version}-{build}-{py}-{abi}-{plat} (6). We strip
        // the last 3 segments ({py}-{abi}-{plat}) and handle the
        // optional numeric build tag between version and tags.
        let parts: Vec<&str> = stem.split('-').collect();
        if parts.len() >= 5 {
            // Strip trailing 3 tag segments ({py}-{abi}-{plat}).
            let tail_start = parts.len() - 3;
            let leading = &parts[..tail_start];
            if leading.len() >= 2 {
                // Find the boundary between name and version: version
                // segments start with a digit (PEP 440); name segments
                // typically don't. Walk leading from right, stopping at
                // the last segment that does NOT start with a digit —
                // that's the last name segment. Everything after it is
                // version (and possibly a build tag).
                let name_end_idx = leading
                    .iter()
                    .enumerate()
                    .rev()
                    .find(|(_, s)| {
                        !s.chars().next().is_some_and(|c| c.is_ascii_digit())
                    })
                    .map(|(i, _)| i);
                let (name, version) = match name_end_idx {
                    Some(idx) if idx + 1 < leading.len() => {
                        let name = leading[..=idx].join("-");
                        // version_etc has 1 (version only) or 2 (version
                        // + build tag) segments. Either way, version is
                        // the first one.
                        let version = leading[idx + 1].to_string();
                        (name, version)
                    }
                    // No non-digit-starting segment found, or name
                    // consumed all leading: can't parse cleanly.
                    _ => (String::new(), String::new()),
                };
                if !name.is_empty() && !version.is_empty() {
                    // Wheel filenames substitute `_` for `-` in the
                    // name on disk. Flip back to the packageurl
                    // reference-impl canonical form (lowercase + `-`
                    // separator) for the PURL.
                    let normalised_name = name.replace('_', "-").to_lowercase();
                    let purl_str = format!(
                        "pkg:pypi/{}@{}",
                        mikebom_common::types::purl::encode_purl_segment(&normalised_name),
                        mikebom_common::types::purl::encode_purl_segment(&version),
                    );
                    if let Ok(purl) = Purl::new(&purl_str) {
                        tracing::debug!("pip wheel match: {purl_str}");
                        return Some(purl);
                    }
                }
            }
        }
        // Fall through: wheel with weird structure, skip.
    }

    let sp_idx = path.find("site-packages/")?;
    let after_sp = &path[sp_idx + "site-packages/".len()..];

    // Get the first path segment after site-packages/.
    let segment = after_sp.split('/').next()?;

    // Try .dist-info pattern: "{name}-{version}.dist-info"
    if let Some(stem) = segment.strip_suffix(".dist-info") {
        let (name, version) = split_pypi_dist_info(stem)?;
        // packageurl reference impl normalises pypi names: lowercase,
        // `_` → `-`. Dist-info dirs use the opposite convention on disk
        // (`_` in place of the declared `-`), so we flip here.
        let normalized = name.replace('_', "-").to_lowercase();
        let purl_str = format!("pkg:pypi/{normalized}@{version}");
        let purl = Purl::new(&purl_str).ok()?;
        tracing::debug!("pip dist-info path match: {purl_str}");
        return Some(purl);
    }

    // Try .egg-info pattern: "{name}-{version}.egg-info"
    if let Some(stem) = segment.strip_suffix(".egg-info") {
        let (name, version) = split_pypi_dist_info(stem)?;
        // packageurl reference impl normalises pypi names: lowercase,
        // `_` → `-`. Dist-info dirs use the opposite convention on disk
        // (`_` in place of the declared `-`), so we flip here.
        let normalized = name.replace('_', "-").to_lowercase();
        let purl_str = format!("pkg:pypi/{normalized}@{version}");
        let purl = Purl::new(&purl_str).ok()?;
        tracing::debug!("pip egg-info path match: {purl_str}");
        return Some(purl);
    }

    None
}

/// Split a dist-info directory name into (name, version).
/// Format: "{distribution}-{version}"
fn split_pypi_dist_info(stem: &str) -> Option<(&str, &str)> {
    // The first '-' followed by a digit starts the version.
    let bytes = stem.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            return Some((&stem[..i], &stem[i + 1..]));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// npm: node_modules/.pnpm/{name}@{version}/
//      node_modules/{name}/  (no version available)
// ---------------------------------------------------------------------------
fn resolve_npm_path(path: &str) -> Option<Purl> {
    // `*.tgz` cache blobs (npm pack output, `~/.npm/_cacache/`, and
    // registry download staging). Filename shape is
    // `<name>-<version>.tgz`. Scoped packages publish as
    // `<name>-<version>.tgz` too (scope stripped from the filename), so
    // this branch only recovers the bare name; image-mode will cross-
    // reference against `node_modules/` to recover scope. See FR-011 of
    // specs/002-python-npm-ecosystem/spec.md.
    if let Some(filename) = path.rsplit('/').next() {
        if let Some(stem) = filename.strip_suffix(".tgz") {
            // Rightmost `-` preceded by a digit-starting segment separates
            // name from version: `lodash-4.17.21` → `(lodash, 4.17.21)`.
            if let Some((name, version)) = split_name_version_last_dash(stem) {
                if !name.is_empty() && !version.is_empty() {
                    let purl_str = format!(
                        "pkg:npm/{}@{}",
                        mikebom_common::types::purl::encode_purl_segment(name),
                        mikebom_common::types::purl::encode_purl_segment(version),
                    );
                    if let Ok(purl) = Purl::new(&purl_str) {
                        tracing::debug!("npm tgz path match: {purl_str}");
                        return Some(purl);
                    }
                }
            }
        }
    }

    // Try .pnpm store pattern first: node_modules/.pnpm/{name}@{version}/
    if let Some(pnpm_idx) = path.find("node_modules/.pnpm/") {
        let after = &path[pnpm_idx + "node_modules/.pnpm/".len()..];
        let segment = after.split('/').next()?;

        // pnpm uses "+" instead of "/" for scoped packages:
        // @scope+name@version or name@version
        if let Some(at_idx) = segment.rfind('@') {
            if at_idx == 0 {
                // Scoped package: the entire segment is "@scope+name@version"
                // but rfind('@') would find the last one. Try again.
                return None;
            }
            let name_part = &segment[..at_idx];
            let version = &segment[at_idx + 1..];

            // Handle pnpm's "+" encoding of scoped package slashes.
            let name = name_part.replace('+', "/");

            if name.is_empty() || version.is_empty() {
                return None;
            }

            let purl_str = if name.starts_with('@') {
                let encoded = name.replace('@', "%40");
                format!("pkg:npm/{encoded}@{version}")
            } else {
                format!("pkg:npm/{name}@{version}")
            };

            let purl = Purl::new(&purl_str).ok()?;
            tracing::debug!("npm pnpm path match: {purl_str}");
            return Some(purl);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Go: $GOPATH/pkg/mod/{module}@{version}/
// ---------------------------------------------------------------------------
fn resolve_go_path(path: &str) -> Option<Purl> {
    let mod_idx = path.find("/pkg/mod/")?;
    let after = &path[mod_idx + "/pkg/mod/".len()..];

    // Reject $GOMODCACHE/cache/{download,lock,vcs}/... — these are
    // toolchain-internal cache files, not extracted modules. A path
    // resolver match here produces nonsense PURLs because the first
    // `@` in the path belongs to the `@v` version-index directory,
    // not a `module@version` separator.
    if after.starts_with("cache/") {
        return None;
    }

    // Find the '@' separator between module path and version.
    let at_idx = after.find('@')?;
    let module = &after[..at_idx];

    // Version goes until the next '/' or end of string.
    let rest = &after[at_idx + 1..];
    let version = rest.split('/').next()?;

    if module.is_empty() || version.is_empty() {
        return None;
    }

    let purl_str = format!("pkg:golang/{module}@{version}");
    let purl = Purl::new(&purl_str).ok()?;
    tracing::debug!("go module path match: {purl_str}");
    Some(purl)
}

// ---------------------------------------------------------------------------
// Debian: /var/cache/apt/archives/{name}_{version}_{arch}.deb
//         Also matches the apt partial directory and any tmp download dir
//         that keeps the canonical `_` separated filename.
// ---------------------------------------------------------------------------
fn resolve_deb_path(path: &str, codename_hint: Option<&str>) -> Option<Purl> {
    let filename = path.rsplit('/').next()?;
    let stem = filename.strip_suffix(".deb")?;

    let mut parts = stem.splitn(3, '_');
    let name = parts.next()?;
    let version = parts.next()?;
    let arch = parts.next()?;

    if name.is_empty() || version.is_empty() || arch.is_empty() {
        return None;
    }

    // apt URL-encodes both colons (epoch separator) and plus signs
    // (Debian revision marker, e.g. `+b1` for a binNMU rebuild) in
    // cache filenames. The reference implementation (packageurl-python)
    // canonicalises `:` as LITERAL but `+` as `%2B`, so decode the
    // colon and ensure `+` is encoded — `encode_purl_version` is
    // idempotent, so it handles both shapes the filename might arrive
    // in (literal or already-encoded).
    let version = version.replace("%3a", ":").replace("%3A", ":");
    let version = mikebom_common::types::purl::encode_purl_version(&version);

    // Names like `libstdc++6` need the same `+` → `%2B` encoding as
    // versions per the packageurl-python reference impl.
    let encoded_name = mikebom_common::types::purl::encode_purl_segment(name);

    // The `distro` qualifier is stamped verbatim from whatever the caller
    // passed — usually `<namespace>-<VERSION_ID>` (e.g. `debian-12`) to
    // match what the scan-mode package-DB readers emit. Omitted entirely
    // when no hint was supplied.
    let mut purl_str = format!("pkg:deb/debian/{encoded_name}@{version}?arch={arch}");
    if let Some(cn) = codename_hint {
        purl_str.push_str(&format!("&distro={cn}"));
    }

    let purl = Purl::new(&purl_str).ok()?;
    tracing::debug!("deb path match: {purl_str}");
    Some(purl)
}

/// Split on the last '-' that is followed by a digit to separate name from version.
fn split_name_version_last_dash(stem: &str) -> Option<(&str, &str)> {
    let bytes = stem.as_bytes();
    for i in (0..bytes.len()).rev() {
        if bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            return Some((&stem[..i], &stem[i + 1..]));
        }
    }
    None
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Cargo path tests
    // -----------------------------------------------------------------------
    #[test]
    fn cargo_registry_cache() {
        let purl = resolve_path(
            "/home/user/.cargo/registry/cache/crates.io-6f17d22bba15001f/serde-1.0.197.crate",
        );
        let purl = purl.expect("should resolve cargo cache path");
        assert_eq!(purl.ecosystem(), "cargo");
        assert_eq!(purl.name(), "serde");
        assert_eq!(purl.version(), Some("1.0.197"));
    }

    #[test]
    fn cargo_registry_cache_hyphenated_name() {
        let purl = resolve_path(
            "/home/user/.cargo/registry/cache/crates.io-6f17d22bba15001f/tokio-macros-2.2.0.crate",
        );
        let purl = purl.expect("should resolve hyphenated cargo path");
        assert_eq!(purl.name(), "tokio-macros");
        assert_eq!(purl.version(), Some("2.2.0"));
    }

    #[test]
    fn cargo_registry_cache_system_cargo_home() {
        // $CARGO_HOME=/usr/local/cargo (rust Docker images). No leading dot.
        let purl = resolve_path(
            "/usr/local/cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/serde-1.0.197.crate",
        );
        let purl = purl.expect("should resolve system-CARGO_HOME cargo path");
        assert_eq!(purl.ecosystem(), "cargo");
        assert_eq!(purl.name(), "serde");
        assert_eq!(purl.version(), Some("1.0.197"));
    }

    // -----------------------------------------------------------------------
    // pip path tests
    // -----------------------------------------------------------------------
    #[test]
    fn pip_dist_info() {
        let purl = resolve_path(
            "/usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA",
        );
        let purl = purl.expect("should resolve pip dist-info path");
        assert_eq!(purl.ecosystem(), "pypi");
        assert_eq!(purl.name(), "requests");
        assert_eq!(purl.version(), Some("2.31.0"));
    }

    #[test]
    fn pip_dist_info_with_normalization() {
        let purl = resolve_path(
            "/usr/lib/python3/site-packages/my-cool-package-1.2.3.dist-info/top_level.txt",
        );
        let purl = purl.expect("should resolve and normalize pip path");
        // The packageurl crate normalizes PyPI names to use hyphens per the PURL spec.
        assert_eq!(purl.name(), "my-cool-package");
        assert_eq!(purl.version(), Some("1.2.3"));
    }

    #[test]
    fn pip_egg_info() {
        let purl = resolve_path(
            "/usr/lib/python3.11/site-packages/setuptools-69.0.3.egg-info/PKG-INFO",
        );
        let purl = purl.expect("should resolve pip egg-info path");
        assert_eq!(purl.ecosystem(), "pypi");
        assert_eq!(purl.name(), "setuptools");
        assert_eq!(purl.version(), Some("69.0.3"));
    }

    #[test]
    fn pip_wheel_simple() {
        let purl = resolve_path("/tmp/wheels/requests-2.31.0-py3-none-any.whl")
            .expect("wheel resolves");
        assert_eq!(purl.ecosystem(), "pypi");
        assert_eq!(purl.name(), "requests");
        assert_eq!(purl.version(), Some("2.31.0"));
    }

    #[test]
    fn pip_wheel_name_with_hyphens() {
        let purl = resolve_path(
            "/home/user/.cache/pip/wheels/my-cool-pkg-1.2.3-py3-none-any.whl",
        )
        .expect("wheel with hyphens resolves");
        assert_eq!(purl.name(), "my-cool-pkg");
        assert_eq!(purl.version(), Some("1.2.3"));
    }

    #[test]
    fn pip_wheel_with_build_tag() {
        // PEP 491: build tag inserted between version and py tag.
        let purl = resolve_path("/tmp/pip/foo-1.0-1-py3-none-any.whl")
            .expect("wheel with build tag resolves");
        assert_eq!(purl.name(), "foo");
        assert_eq!(purl.version(), Some("1.0"));
    }

    #[test]
    fn pip_wheel_malformed_returns_none() {
        // Missing the triple tag suffix — not a valid wheel.
        assert!(resolve_path("/tmp/foo.whl").is_none());
        assert!(resolve_path("/tmp/foo-1.0.whl").is_none());
    }

    // -----------------------------------------------------------------------
    // npm path tests
    // -----------------------------------------------------------------------
    #[test]
    fn npm_pnpm_store() {
        let purl = resolve_path(
            "/home/user/project/node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/index.js",
        );
        let purl = purl.expect("should resolve npm pnpm path");
        assert_eq!(purl.ecosystem(), "npm");
        assert_eq!(purl.name(), "lodash");
        assert_eq!(purl.version(), Some("4.17.21"));
    }

    #[test]
    fn npm_pnpm_scoped() {
        let purl = resolve_path(
            "/project/node_modules/.pnpm/@types+node@20.11.5/node_modules/@types/node/index.d.ts",
        );
        let purl = purl.expect("should resolve scoped npm pnpm path");
        assert_eq!(purl.ecosystem(), "npm");
        assert_eq!(purl.namespace(), Some("@types"));
        assert_eq!(purl.name(), "node");
        assert_eq!(purl.version(), Some("20.11.5"));
    }

    #[test]
    fn npm_tgz_unscoped() {
        let purl = resolve_path("/home/user/.npm/_cacache/tmp/lodash-4.17.21.tgz")
            .expect("should resolve npm tgz");
        assert_eq!(purl.ecosystem(), "npm");
        assert_eq!(purl.name(), "lodash");
        assert_eq!(purl.version(), Some("4.17.21"));
    }

    #[test]
    fn npm_tgz_compound_name_and_prerelease_version() {
        // Pathological-but-real case: name itself has a dash, and the
        // version has a pre-release suffix. The `last-dash-followed-by-
        // digit` rule still wins.
        let purl = resolve_path("/tmp/react-dom-18.2.0-rc.1.tgz")
            .expect("should resolve compound-name tgz");
        assert_eq!(purl.ecosystem(), "npm");
        assert_eq!(purl.name(), "react-dom");
        assert_eq!(purl.version(), Some("18.2.0-rc.1"));
    }

    // -----------------------------------------------------------------------
    // Go path tests
    // -----------------------------------------------------------------------
    #[test]
    fn go_module_path() {
        let purl = resolve_path(
            "/home/user/go/pkg/mod/golang.org/x/net@v0.24.0/http2/h2_bundle.go",
        );
        let purl = purl.expect("should resolve go module path");
        assert_eq!(purl.ecosystem(), "golang");
        assert_eq!(purl.version(), Some("v0.24.0"));
    }

    #[test]
    fn go_module_github() {
        let purl = resolve_path(
            "/home/user/go/pkg/mod/github.com/stretchr/testify@v1.9.0/assert/assertions.go",
        );
        let purl = purl.expect("should resolve go github module path");
        assert_eq!(purl.ecosystem(), "golang");
        assert_eq!(purl.version(), Some("v1.9.0"));
    }

    #[test]
    fn go_cache_download_path_not_resolved() {
        // $GOMODCACHE/cache/download/<module>/@v/<version>.{mod,zip,info}
        // are toolchain-internal artefacts, not extracted modules. Their
        // first `@` belongs to the `/@v/` version-index directory, so a
        // naive resolver would emit e.g.
        // `pkg:golang/cache/download/github.com/davecgh/go-spew/@v` — nonsense.
        assert!(resolve_path(
            "/root/go/pkg/mod/cache/download/github.com/davecgh/go-spew/@v/v1.1.1.zip"
        )
        .is_none());
        assert!(resolve_path("/root/go/pkg/mod/cache/lock").is_none());
        assert!(resolve_path(
            "/home/user/go/pkg/mod/cache/download/sumdb/sum.golang.org/lookup/rsc.io/quote/@v/v1.5.2.ziphash"
        )
        .is_none());
    }

    // -----------------------------------------------------------------------
    // Debian path tests
    // -----------------------------------------------------------------------
    #[test]
    fn deb_apt_cache_arm64() {
        let purl = resolve_path(
            "/var/cache/apt/archives/jq_1.7.1-3build1_arm64.deb",
        );
        let purl = purl.expect("should resolve apt archive deb path");
        assert_eq!(purl.ecosystem(), "deb");
        assert_eq!(purl.namespace(), Some("debian"));
        assert_eq!(purl.name(), "jq");
        assert_eq!(purl.version(), Some("1.7.1-3build1"));
    }

    #[test]
    fn deb_partial_download() {
        let purl = resolve_path(
            "/var/cache/apt/archives/partial/libssl3_3.0.11-1~deb12u2_amd64.deb",
        );
        let purl = purl.expect("should resolve apt partial deb path");
        assert_eq!(purl.name(), "libssl3");
        assert_eq!(purl.version(), Some("3.0.11-1~deb12u2"));
    }

    #[test]
    fn deb_decodes_epoch_colon() {
        let purl = resolve_path(
            "/var/cache/apt/archives/vim_2%3a9.0.1378-2_amd64.deb",
        );
        let purl = purl.expect("should resolve deb with epoch");
        assert_eq!(purl.name(), "vim");
        assert_eq!(purl.version(), Some("2:9.0.1378-2"));
    }

    #[test]
    fn deb_canonicalises_plus_to_percent_2b() {
        // apt percent-encodes `+` (binNMU marker) as `%2B` in cache
        // filenames, and the packageurl-python reference impl keeps it
        // that way in the canonical PURL form. The typed `version()`
        // accessor decodes back to a literal `+` for human-facing
        // consumers (CycloneDX `component.version`, CPE, dedup key).
        let purl = resolve_path(
            "/var/cache/apt/archives/libjq1_1.6-2.1%2Bb1_arm64.deb",
        )
        .expect("should resolve deb with +b1 revision");
        assert_eq!(purl.name(), "libjq1");
        assert_eq!(
            purl.version(),
            Some("1.6-2.1+b1"),
            "typed accessor returns the human-readable literal form"
        );
        assert!(
            purl.as_str().contains("1.6-2.1%2Bb1"),
            "canonical form must carry %2B, not literal +: {}",
            purl.as_str()
        );
        assert!(
            !purl.as_str().contains("1.6-2.1+"),
            "canonical form must not leak literal +: {}",
            purl.as_str()
        );
    }

    #[test]
    fn deb_canonicalises_literal_plus_in_filename_too() {
        // Even when a filename arrives with a literal `+` (synthetic
        // test input, some pre-apt tooling), the encoder kicks in and
        // the canonical PURL is still `%2B`.
        let purl = resolve_path(
            "/var/cache/apt/archives/libjq1_1.6-2.1+b1_arm64.deb",
        )
        .expect("should resolve deb with literal +");
        assert_eq!(purl.version(), Some("1.6-2.1+b1"));
        assert!(
            purl.as_str().contains("1.6-2.1%2Bb1"),
            "canonical form normalises literal + to %2B: {}",
            purl.as_str()
        );
    }

    #[test]
    fn deb_name_with_plus_plus_encodes_to_percent_2b() {
        // libstdc++6 and similar C++-runtime packages carry `++` in
        // the PURL name segment. Per the packageurl-python reference
        // impl, both plus signs must be percent-encoded.
        let purl = resolve_path(
            "/var/cache/apt/archives/libstdc++6_12.2.0-14_arm64.deb",
        )
        .expect("should resolve libstdc++6");
        assert_eq!(purl.name(), "libstdc++6", "typed accessor keeps literal form");
        assert!(
            purl.as_str().contains("/libstdc%2B%2B6@"),
            "canonical form must encode ++ as %2B%2B: {}",
            purl.as_str()
        );
        assert!(
            !purl.as_str().contains("libstdc++6@"),
            "no literal ++ should leak into canonical form: {}",
            purl.as_str()
        );
    }

    #[test]
    fn deb_decodes_both_colon_and_plus_together() {
        // Real-world shape: epoch + binNMU. e.g. `1:2.3+b1`. Canonical:
        // `:` stays literal (reference impl leaves it alone), `+` gets
        // encoded to `%2B`.
        let purl = resolve_path(
            "/var/cache/apt/archives/foo_1%3a2.3%2bb1_amd64.deb",
        )
        .expect("should resolve deb with epoch and +bN");
        assert_eq!(purl.version(), Some("1:2.3+b1"));
        assert!(
            purl.as_str().contains("@1:2.3%2Bb1"),
            "canonical: colon literal, plus encoded: {}",
            purl.as_str()
        );
    }

    #[test]
    fn deb_path_stamps_distro_hint_verbatim() {
        // The resolver stamps whatever the caller passed. Scan-mode code
        // paths pass `<namespace>-<VERSION_ID>` (e.g. `debian-12`); legacy
        // trace-capture paths may still pass a bare codename. Either way,
        // the function stamps it verbatim.
        let purl = super::resolve_path_with_context(
            "/var/cache/apt/archives/jq_1.7.1-3build1_arm64.deb",
            Some("debian-12"),
        )
        .expect("should resolve");
        assert!(
            purl.as_str().contains("distro=debian-12"),
            "expected distro=debian-12 in {}",
            purl.as_str()
        );
    }

    #[test]
    fn deb_path_without_codename_omits_qualifier() {
        let purl = super::resolve_path_with_context(
            "/var/cache/apt/archives/jq_1.7.1-3build1_arm64.deb",
            None,
        )
        .expect("should resolve");
        assert!(!purl.as_str().contains("distro="));
    }

    // -----------------------------------------------------------------------
    // Negative tests
    // -----------------------------------------------------------------------
    #[test]
    fn unknown_path_returns_none() {
        assert!(resolve_path("/tmp/build/output.o").is_none());
    }

    #[test]
    fn partial_cargo_path_returns_none() {
        assert!(resolve_path("/home/user/.cargo/registry/cache/").is_none());
    }

    #[test]
    fn malformed_deb_returns_none() {
        // Missing architecture field
        assert!(resolve_path("/var/cache/apt/archives/jq_1.7.1.deb").is_none());
    }
}
