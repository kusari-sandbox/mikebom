//! Read Go package metadata from compiled binaries' embedded
//! `runtime/debug.BuildInfo` blob.
//!
//! Format (Go 1.18+ "inline" variant — the only shape this milestone
//! implements):
//!
//! ```text
//! offset  size  contents
//!    0    14    magic bytes: b"\xff Go buildinf:"
//!   14     1    pointer size (4 or 8)  ← ignored for inline format
//!   15     1    flags bitmap (bit 0: endianness, bit 1: inline)
//!   16    16    reserved / alignment padding
//!   32    —     two varint-prefixed UTF-8 strings (first: mod info,
//!               second: build info key/value pairs)
//! ```
//!
//! The pre-1.18 pointer-indirection format is detected and flagged as
//! `Unsupported` — the scanner emits a file-level diagnostic component
//! per FR-015 rather than fabricating entries from a format we haven't
//! implemented. Stripped binaries (ELF section name gone but magic
//! still present) work fine because we also fall back to memmem scan.

use std::path::{Path, PathBuf};

use mikebom_common::types::purl::{encode_purl_segment, Purl};
use object::{Object, ObjectSection};

use super::PackageDbEntry;

/// Magic byte sequence that prefixes every embedded Go BuildInfo blob.
/// `go tool objdump -s runtime.buildInfo` reveals this; the source of
/// truth is Go's `src/debug/buildinfo/buildinfo.go`.
const BUILDINFO_MAGIC: &[u8] = b"\xff Go buildinf:";

/// Size cap on the binaries we probe. 500 MB covers kernel-sized Go
/// artefacts while keeping a bounded memmem search.
const MAX_BINARY_SIZE_BYTES: u64 = 500 * 1024 * 1024;

/// Minimum file size worth probing. Anything below 1 KB is a shell
/// script or an empty placeholder — not a Go binary.
const MIN_BINARY_SIZE_BYTES: u64 = 1024;

/// Outcome of a single-binary BuildInfo extraction. Feeds directly into
/// the `mikebom:buildinfo-status` property at serialization time per
/// contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildInfoStatus {
    /// Everything parsed — use the embedded module list.
    Ok,
    /// The magic bytes weren't found anywhere in the file. Almost
    /// certainly not a Go binary.
    NotGoBinary,
    /// Magic present but the format isn't the 1.18+ inline variant we
    /// implement. Emit a file-level diagnostic component.
    Unsupported,
    /// Magic present and format is the right variant but the payload
    /// bytes are truncated / corrupt. Emit a file-level diagnostic.
    Missing,
}

/// What a successful BuildInfo extraction yields.
#[derive(Clone, Debug)]
pub struct GoBinaryInfo {
    /// Path of the binary we read (absolute, in rootfs coordinates).
    pub path: PathBuf,
    /// `path` line — the main package import path.
    pub main_package: Option<String>,
    /// `mod` line — the main module coordinate: (path, version, h1-hash).
    pub main_module: Option<(String, String, Option<String>)>,
    /// `dep` lines — embedded dependency modules.
    pub deps: Vec<(String, String, Option<String>)>,
    /// `build GOVERSION` key — e.g. `go1.22.1`. Surfaced for logs only.
    pub go_version: Option<String>,
}

/// Errors the binary reader can produce. The public `read` path
/// swallows these into `BuildInfoStatus` variants — they're only useful
/// to the unit tests.
#[derive(Debug, thiserror::Error)]
pub enum GoBinaryError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("file exceeds {cap}-byte probe limit ({observed} bytes)")]
    FileTooLarge { observed: u64, cap: u64 },
    #[error("file below {min}-byte minimum probe size")]
    FileTooSmall { min: u64 },
    #[error("no BuildInfo magic in file")]
    NotGoBinary,
    #[error("pre-Go-1.18 pointer-indirection BuildInfo not supported")]
    LegacyPointerFormat,
    #[error("truncated or malformed BuildInfo payload")]
    MalformedPayload,
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Tri-state detection result for a single binary probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DetectResult {
    Found { buildinfo_offset: usize },
    NotGoBinary,
    AmbiguousError,
}

/// Is `path` a Go binary? First tries the `object` crate's section
/// lookup (fast, precise), then falls back to a memmem scan for the
/// magic bytes (handles stripped binaries where the section name is
/// gone). Size-bounded by [`MAX_BINARY_SIZE_BYTES`].
pub fn detect_is_go(path: &Path) -> DetectResult {
    let Ok(meta) = std::fs::metadata(path) else {
        return DetectResult::AmbiguousError;
    };
    let size = meta.len();
    if size < MIN_BINARY_SIZE_BYTES || size > MAX_BINARY_SIZE_BYTES {
        return DetectResult::NotGoBinary;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return DetectResult::AmbiguousError;
    };

    // Tier 1: named-section lookup via `object`.
    if let Some(offset) = find_buildinfo_section(&bytes) {
        return DetectResult::Found {
            buildinfo_offset: offset,
        };
    }

    // Tier 2: memmem scan for the magic prefix. Handles stripped
    // binaries (section header gone) and anything the object crate
    // can't classify.
    if let Some(offset) = memmem(&bytes, BUILDINFO_MAGIC) {
        return DetectResult::Found {
            buildinfo_offset: offset,
        };
    }

    DetectResult::NotGoBinary
}

fn find_buildinfo_section(bytes: &[u8]) -> Option<usize> {
    let obj = object::File::parse(bytes).ok()?;
    for section in obj.sections() {
        let Ok(name) = section.name() else {
            continue;
        };
        if name == ".go.buildinfo" || name == "__go_buildinfo" {
            let data = section.data().ok()?;
            // The section's file offset is where the blob lives in the
            // raw file. We resolve it back to an absolute offset by
            // locating the data bytes inside the raw file view.
            if let Some(rel) = memmem(bytes, &data[..BUILDINFO_MAGIC.len().min(data.len())]) {
                return Some(rel);
            }
        }
    }
    None
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// BuildInfo decoder
// ---------------------------------------------------------------------------

/// Parse a BuildInfo blob starting at `offset` inside `bytes`. Returns
/// the structured form. The caller is responsible for emitting SBOM
/// components.
pub fn decode_buildinfo(bytes: &[u8], offset: usize) -> Result<GoBinaryInfo, GoBinaryError> {
    let blob = bytes
        .get(offset..)
        .ok_or(GoBinaryError::MalformedPayload)?;
    if blob.len() < 32 || !blob.starts_with(BUILDINFO_MAGIC) {
        return Err(GoBinaryError::MalformedPayload);
    }
    let _ptr_size = blob[14];
    let flags = blob[15];
    let inline_format = flags & 0x2 != 0;
    if !inline_format {
        return Err(GoBinaryError::LegacyPointerFormat);
    }

    // After the 32-byte header, two varint-length-prefixed byte
    // strings. First is the version / build-settings blob (Go version,
    // compiler flags, VCS metadata). Second is the mod-info block with
    // path / mod / dep / => lines, wrapped in 16-byte sentinel
    // framing. The raw bytes on the second string aren't valid UTF-8
    // — the outer 16 bytes on each side contain opaque framing data
    // — so we do byte-level trimming before attempting UTF-8.
    let mut cursor = &blob[32..];
    let (vers_bytes, rest) = read_uvarint_bytes(cursor)?;
    cursor = rest;
    let (mod_bytes, _) = read_uvarint_bytes(cursor).unwrap_or((&[][..], cursor));

    let vers_info = std::str::from_utf8(vers_bytes)
        .unwrap_or("")
        .to_string();
    let trimmed_mod_bytes = trim_mod_sentinel_bytes(mod_bytes);
    let mod_info = std::str::from_utf8(trimmed_mod_bytes)
        .unwrap_or("")
        .to_string();

    let (main_package, main_module, deps) = parse_mod_info(&mod_info);
    let go_version = parse_go_version_from_build_info(&vers_info);

    Ok(GoBinaryInfo {
        path: PathBuf::new(), // caller fills in
        main_package,
        main_module,
        deps,
        go_version,
    })
}

/// Read a uvarint length, then that many bytes as a raw slice.
/// Returns the byte slice + the remaining tail. Caller decides whether
/// to UTF-8 decode after any necessary framing removal.
fn read_uvarint_bytes(bytes: &[u8]) -> Result<(&[u8], &[u8]), GoBinaryError> {
    let (len, rest) = read_uvarint(bytes)?;
    let len = len as usize;
    if rest.len() < len {
        return Err(GoBinaryError::MalformedPayload);
    }
    Ok(rest.split_at(len))
}

/// Standard uvarint (Go `encoding/binary`): groups of 7 bits, MSB flag
/// signals continuation. Max 9 bytes.
fn read_uvarint(bytes: &[u8]) -> Result<(u64, &[u8]), GoBinaryError> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i >= 9 {
            return Err(GoBinaryError::MalformedPayload);
        }
        if b < 0x80 {
            value |= (b as u64) << shift;
            return Ok((value, &bytes[i + 1..]));
        }
        value |= ((b & 0x7f) as u64) << shift;
        shift += 7;
    }
    Err(GoBinaryError::MalformedPayload)
}

/// Decode the `mod` section text. Format (LF-separated):
///
/// ```text
/// path\tMAIN_PACKAGE
/// mod\tMAIN_MODULE\tMAIN_VERSION\tMAIN_HASH
/// dep\tMOD\tVERSION\tHASH
/// dep\tMOD\tVERSION\tHASH
/// =>\tREPLACE_MOD\tREPLACE_VERSION\tREPLACE_HASH   (optional; applies to prior dep)
/// ```
///
/// The Go toolchain also wraps the whole payload between sentinel
/// characters `\n\x30...\x31` — we trim those if present and parse
/// everything between them.
#[allow(clippy::type_complexity)]
fn parse_mod_info(
    s: &str,
) -> (
    Option<String>,
    Option<(String, String, Option<String>)>,
    Vec<(String, String, Option<String>)>,
) {
    // The caller in `decode_buildinfo` already trims at the byte level,
    // but we also accept pre-trimmed text (from unit tests that don't
    // wrap their synthetic blobs in sentinels).
    let body = s;
    let mut main_package = None;
    let mut main_module = None;
    let mut deps: Vec<(String, String, Option<String>)> = Vec::new();
    for line in body.lines() {
        let mut parts = line.splitn(4, '\t');
        match parts.next() {
            Some("path") => {
                if let Some(p) = parts.next() {
                    main_package = Some(p.to_string());
                }
            }
            Some("mod") => {
                let path = parts.next().map(str::to_string);
                let version = parts.next().map(str::to_string);
                let hash = parts.next().map(str::to_string).filter(|h| !h.is_empty());
                if let (Some(p), Some(v)) = (path, version) {
                    main_module = Some((p, v, hash));
                }
            }
            Some("dep") => {
                let path = parts.next().map(str::to_string);
                let version = parts.next().map(str::to_string);
                let hash = parts.next().map(str::to_string).filter(|h| !h.is_empty());
                if let (Some(p), Some(v)) = (path, version) {
                    deps.push((p, v, hash));
                }
            }
            Some("=>") => {
                // Replace directive — overrides the most-recently-pushed
                // dep with the replacement coordinate.
                let path = parts.next().map(str::to_string);
                let version = parts.next().map(str::to_string);
                let hash = parts.next().map(str::to_string).filter(|h| !h.is_empty());
                if let (Some(p), Some(v)) = (path, version) {
                    if let Some(last) = deps.last_mut() {
                        *last = (p, v, hash);
                    }
                }
            }
            _ => {}
        }
    }
    (main_package, main_module, deps)
}

/// Strip the 16-byte sentinel prefix + 16-byte sentinel suffix that
/// Go's `runtime` embeds around the mod-info string. Go source
/// (`debug/buildinfo/buildinfo.go`):
///
/// ```text
/// if len(mod) >= 33 && mod[len(mod)-17] == '\n' {
///     mod = mod[16 : len(mod)-16]
/// }
/// ```
///
/// When the shape doesn't match (synthetic blob, shorter payload, no
/// trailing LF), we fall through to the original bytes so older /
/// test-crafted blobs still parse downstream.
fn trim_mod_sentinel_bytes(bytes: &[u8]) -> &[u8] {
    if bytes.len() >= 33 && bytes[bytes.len() - 17] == b'\n' {
        return &bytes[16..bytes.len() - 16];
    }
    bytes
}

fn parse_go_version_from_build_info(s: &str) -> Option<String> {
    // The first BuildInfo string IS the Go version (e.g. "go1.22.1"),
    // possibly followed by a LF-separated list of `key\tvalue` build
    // setting lines. Take the first line as the version.
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    let first_line = trimmed.lines().next()?.trim();
    if first_line.is_empty() {
        return None;
    }
    Some(first_line.to_string())
}

// ---------------------------------------------------------------------------
// Read-one-binary API
// ---------------------------------------------------------------------------

/// Probe a single file for BuildInfo. `(status, info)` — info is only
/// populated when `status == Ok`.
pub fn read_binary(path: &Path) -> (BuildInfoStatus, Option<GoBinaryInfo>) {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return (BuildInfoStatus::NotGoBinary, None),
    };
    let size = meta.len();
    if size < MIN_BINARY_SIZE_BYTES || size > MAX_BINARY_SIZE_BYTES {
        return (BuildInfoStatus::NotGoBinary, None);
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return (BuildInfoStatus::NotGoBinary, None),
    };
    let offset = match detect_is_go(path) {
        DetectResult::Found { buildinfo_offset } => buildinfo_offset,
        DetectResult::NotGoBinary => return (BuildInfoStatus::NotGoBinary, None),
        DetectResult::AmbiguousError => return (BuildInfoStatus::Missing, None),
    };
    match decode_buildinfo(&bytes, offset) {
        Ok(mut info) => {
            info.path = path.to_path_buf();
            (BuildInfoStatus::Ok, Some(info))
        }
        Err(GoBinaryError::LegacyPointerFormat) => (BuildInfoStatus::Unsupported, None),
        Err(_) => (BuildInfoStatus::Missing, None),
    }
}

// ---------------------------------------------------------------------------
// scan_fs public entry
// ---------------------------------------------------------------------------

/// Walk `rootfs` for executable files, probe each for BuildInfo, emit
/// analyzed-tier `pkg:golang/...` entries for every module found.
/// Stripped binaries / unsupported formats produce file-level
/// diagnostic entries with `source_type` set to the status string.
///
/// v9 Phase O: `claimed_paths` + `claimed_inodes` (populated by the
/// package-db readers before this call — dpkg/apk/pip/rpm) let us
/// suppress diagnostic emissions for binaries already owned by a
/// package manager. Without this, the Go toolchain's `link`/`compile`
/// tools (shipped by Fedora's `golang` RPM with intentionally
/// unsupported BuildInfo) leak as bare `pkg:generic/link` PURLs and
/// conformance-regress every Fedora-based fixture. Binaries that
/// parse successfully (BuildInfoStatus::Ok) are still emitted
/// regardless of claims — they carry real module information that
/// the package metadata doesn't.
pub fn read(
    rootfs: &Path,
    _include_dev: bool,
    claimed_paths: &std::collections::HashSet<std::path::PathBuf>,
    #[cfg(unix)] claimed_inodes: &std::collections::HashSet<(u64, u64)>,
) -> Vec<PackageDbEntry> {
    let mut out: Vec<PackageDbEntry> = Vec::new();
    let mut seen_purls: std::collections::HashSet<String> = std::collections::HashSet::new();
    walk_for_binaries(
        rootfs,
        0,
        &mut out,
        &mut seen_purls,
        claimed_paths,
        #[cfg(unix)]
        claimed_inodes,
    );
    if !out.is_empty() {
        tracing::info!(
            rootfs = %rootfs.display(),
            entries = out.len(),
            "extracted Go binary BuildInfo components",
        );
    } else {
        tracing::debug!(rootfs = %rootfs.display(), "no Go binaries found");
    }
    out
}

const MAX_BINARY_WALK_DEPTH: usize = 10;

fn walk_for_binaries(
    dir: &Path,
    depth: usize,
    out: &mut Vec<PackageDbEntry>,
    seen_purls: &mut std::collections::HashSet<String>,
    claimed_paths: &std::collections::HashSet<std::path::PathBuf>,
    #[cfg(unix)] claimed_inodes: &std::collections::HashSet<(u64, u64)>,
) {
    if depth >= MAX_BINARY_WALK_DEPTH {
        return;
    }
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_dir() {
            if should_skip_binary_descent(&path) {
                continue;
            }
            walk_for_binaries(
                &path,
                depth + 1,
                out,
                seen_purls,
                claimed_paths,
                #[cfg(unix)]
                claimed_inodes,
            );
            continue;
        }
        if !meta.is_file() || meta.len() < MIN_BINARY_SIZE_BYTES {
            continue;
        }

        let (status, info) = read_binary(&path);
        match status {
            BuildInfoStatus::Ok => {
                // Successful BuildInfo parse — emit regardless of
                // claim status, since real module information beats
                // a package-db claim that lacks module granularity.
                if let Some(info) = info {
                    emit_entries_from_info(&info, out, seen_purls);
                }
            }
            BuildInfoStatus::Unsupported | BuildInfoStatus::Missing => {
                // v9 Phase O: skip the file-level diagnostic when the
                // binary is already owned by a package manager
                // (typically golang RPM or apt golang-go's toolchain
                // tools). The diagnostic PURL `pkg:generic/<basename>`
                // carries no module info — suppressing it for claimed
                // binaries removes a class of conformance FPs.
                let status_str = match status {
                    BuildInfoStatus::Unsupported => "unsupported",
                    BuildInfoStatus::Missing => "missing",
                    _ => unreachable!(),
                };
                if crate::scan_fs::binary::is_path_claimed(
                    &path,
                    claimed_paths,
                    #[cfg(unix)]
                    claimed_inodes,
                ) {
                    tracing::debug!(
                        binary = %path.display(),
                        status = status_str,
                        "go binary is package-claimed — suppressing diagnostic",
                    );
                    continue;
                }
                tracing::warn!(
                    binary = %path.display(),
                    status = status_str,
                    "go binary has no readable BuildInfo",
                );
                emit_file_level_diagnostic(&path, status_str, out);
            }
            BuildInfoStatus::NotGoBinary => {}
        }
    }
}

fn should_skip_binary_descent(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return true;
    };
    if name.starts_with('.') {
        return true;
    }
    if matches!(
        name,
        "vendor" | "node_modules" | "target" | "__pycache__" | "proc" | "sys"
    ) {
        return true;
    }
    // Skip the Go module cache for the same reason `golang.rs` does
    // (build-time residue, not runtime artifacts). Go binaries
    // rarely live under `pkg/mod/` in practice — `go install` drops
    // them in `go/bin/` — but we match the source-walker's skip
    // rules to keep the two readers' scope consistent.
    let components: Vec<&str> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    for window in components.windows(3) {
        if window == ["go", "pkg", "mod"] {
            return true;
        }
    }
    false
}

fn emit_entries_from_info(
    info: &GoBinaryInfo,
    out: &mut Vec<PackageDbEntry>,
    seen_purls: &mut std::collections::HashSet<String>,
) {
    let source_path = info.path.to_string_lossy().into_owned();
    let main_depends: Vec<String> = info
        .deps
        .iter()
        .map(|(p, _, _)| p.clone())
        .collect();
    if let Some((ref path, ref version, _)) = info.main_module {
        if let Some(purl) = build_golang_purl(path, version) {
            let key = purl.as_str().to_string();
            if seen_purls.insert(key) {
                out.push(PackageDbEntry {
                    purl,
                    name: path.clone(),
                    version: version.clone(),
                    arch: None,
                    source_path: source_path.clone(),
                    depends: main_depends.clone(),
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
                    parent_purl: None,
                    npm_role: None,
                    hashes: Vec::new(),
                    sbom_tier: Some("analyzed".to_string()),
                });
            }
        }
    }
    for (path, version, _hash) in &info.deps {
        if let Some(purl) = build_golang_purl(path, version) {
            let key = purl.as_str().to_string();
            if seen_purls.insert(key) {
                out.push(PackageDbEntry {
                    purl,
                    name: path.clone(),
                    version: version.clone(),
                    arch: None,
                    source_path: source_path.clone(),
                    depends: Vec::new(),
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
                    parent_purl: None,
                    npm_role: None,
                    hashes: Vec::new(),
                    sbom_tier: Some("analyzed".to_string()),
                });
            }
        }
    }
}

fn emit_file_level_diagnostic(
    path: &Path,
    status: &str,
    out: &mut Vec<PackageDbEntry>,
) {
    // File-level diagnostic. We emit a generic-ecosystem PURL so dedup
    // doesn't collapse with a real module coord. The
    // `mikebom:buildinfo-status` property is driven off `source_type`
    // here, which the CycloneDX builder already understands.
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string());
    // purl-spec: name segment is percent-encoded. File names may
    // carry `+` or other non-allowed chars.
    let purl_str = format!("pkg:generic/{}", encode_purl_segment(&file_name));
    let Ok(purl) = Purl::new(&purl_str) else {
        return;
    };
    out.push(PackageDbEntry {
        purl,
        name: file_name,
        version: "unknown".to_string(),
        arch: None,
        source_path: path.to_string_lossy().into_owned(),
        depends: Vec::new(),
        maintainer: None,
        licenses: Vec::new(),
        is_dev: None,
        requirement_range: None,
        source_type: None,
        buildinfo_status: Some(status.to_string()),
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
        hashes: Vec::new(),
        sbom_tier: Some("analyzed".to_string()),
    });
}

fn build_golang_purl(module: &str, version: &str) -> Option<Purl> {
    // purl-spec § Character encoding: Go versions like
    // `v1.2.3+incompatible` MUST encode `+` → `%2B`.
    let s = format!(
        "pkg:golang/{}@{}",
        encode_purl_segment(module),
        encode_purl_segment(version),
    );
    Purl::new(&s).ok()
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    fn encode_uvarint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while v >= 0x80 {
            out.push(((v as u8) & 0x7f) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
        out
    }

    fn build_inline_buildinfo(mod_info: &str, build_info: &str) -> Vec<u8> {
        // Order matches Go's debug/buildinfo: first string is the
        // version / build-settings blob, second is the mod info block.
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(BUILDINFO_MAGIC);
        blob.push(8); // pointer size (8 = 64-bit)
        blob.push(0x2); // inline format flag
        blob.extend_from_slice(&[0u8; 16]); // padding to 32 bytes
        let build_bytes = build_info.as_bytes();
        blob.extend(encode_uvarint(build_bytes.len() as u64));
        blob.extend_from_slice(build_bytes);
        let mod_bytes = mod_info.as_bytes();
        blob.extend(encode_uvarint(mod_bytes.len() as u64));
        blob.extend_from_slice(mod_bytes);
        blob
    }

    // --- uvarint -----------------------------------------------------------

    #[test]
    fn uvarint_zero() {
        assert_eq!(read_uvarint(&[0]).unwrap().0, 0);
    }

    #[test]
    fn uvarint_round_trip() {
        for v in [1u64, 127, 128, 300, 16384, 1_000_000] {
            let enc = encode_uvarint(v);
            let (dec, _) = read_uvarint(&enc).unwrap();
            assert_eq!(dec, v, "round-trip failed for {v}");
        }
    }

    #[test]
    fn uvarint_rejects_runaway() {
        let bad = vec![0xffu8; 10]; // 10 continuation bytes — past the 9-byte limit
        assert!(read_uvarint(&bad).is_err());
    }

    // --- decode_buildinfo --------------------------------------------------

    #[test]
    fn decodes_inline_buildinfo_three_deps() {
        let mod_info = "path\texample.com/app\n\
                        mod\texample.com/app\tv0.0.0\t\n\
                        dep\tgithub.com/spf13/cobra\tv1.7.0\th1:abc=\n\
                        dep\tgithub.com/sirupsen/logrus\tv1.9.0\th1:def=\n\
                        dep\tgopkg.in/yaml.v3\tv3.0.1\th1:xyz=\n";
        // vers string is just the Go version (optionally followed by
        // LF-separated build-setting lines).
        let build_info = "go1.22.1";
        let blob = build_inline_buildinfo(mod_info, build_info);
        let info = decode_buildinfo(&blob, 0).expect("decode");
        assert_eq!(info.main_package.as_deref(), Some("example.com/app"));
        assert_eq!(
            info.main_module.as_ref().map(|(p, _, _)| p.as_str()),
            Some("example.com/app")
        );
        assert_eq!(info.deps.len(), 3);
        assert_eq!(info.go_version.as_deref(), Some("go1.22.1"));
    }

    #[test]
    fn decodes_empty_deps() {
        let mod_info = "path\tstandalone\nmod\tstandalone\tv0.0.0\t\n";
        let build_info = "";
        let blob = build_inline_buildinfo(mod_info, build_info);
        let info = decode_buildinfo(&blob, 0).expect("decode");
        assert_eq!(info.deps.len(), 0);
    }

    #[test]
    fn truncated_blob_returns_err() {
        let mut blob = build_inline_buildinfo("path\tx\n", "");
        blob.truncate(20);
        assert!(matches!(
            decode_buildinfo(&blob, 0),
            Err(GoBinaryError::MalformedPayload)
        ));
    }

    #[test]
    fn pre_1_18_pointer_format_flagged_as_unsupported() {
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(BUILDINFO_MAGIC);
        blob.push(8);
        blob.push(0x0); // no inline flag
        blob.extend_from_slice(&[0u8; 16]);
        blob.extend_from_slice(&[0u8; 16]); // two 8-byte pointers
        assert!(matches!(
            decode_buildinfo(&blob, 0),
            Err(GoBinaryError::LegacyPointerFormat)
        ));
    }

    #[test]
    fn replace_directive_overrides_last_dep() {
        let mod_info = "path\tx\n\
                        mod\tx\tv0.0.0\t\n\
                        dep\tgithub.com/old/lib\tv1.0.0\th1:a=\n\
                        =>\tgithub.com/new/lib\tv2.0.0\th1:b=\n";
        let blob = build_inline_buildinfo(mod_info, "");
        let info = decode_buildinfo(&blob, 0).expect("decode");
        assert_eq!(info.deps.len(), 1);
        assert_eq!(info.deps[0].0, "github.com/new/lib");
        assert_eq!(info.deps[0].1, "v2.0.0");
    }

    // --- detect / read_binary ----------------------------------------------

    #[test]
    fn detect_on_non_binary_returns_not_go() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("hello.sh");
        // Above the 1 KB minimum so it gets probed.
        std::fs::write(&p, vec![b'a'; 2048]).unwrap();
        assert_eq!(detect_is_go(&p), DetectResult::NotGoBinary);
    }

    #[test]
    fn detect_on_synthetic_go_binary_finds_offset() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("synth");
        let mut bin = vec![0u8; 4096];
        let blob = build_inline_buildinfo("path\tx\nmod\tx\tv0.0.0\t\n", "");
        bin.extend_from_slice(&blob);
        std::fs::write(&p, &bin).unwrap();
        match detect_is_go(&p) {
            DetectResult::Found { .. } => (),
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn read_binary_on_synthetic_file_emits_main_and_deps() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("hello");
        let mut bin = vec![0u8; 4096];
        let mod_info = "path\texample.com/hello\n\
                        mod\texample.com/hello\tv0.0.0\t\n\
                        dep\tgithub.com/a/b\tv1.2.3\th1:hash=\n";
        bin.extend_from_slice(&build_inline_buildinfo(mod_info, ""));
        std::fs::write(&p, &bin).unwrap();
        let (status, info) = read_binary(&p);
        assert_eq!(status, BuildInfoStatus::Ok);
        let info = info.unwrap();
        assert_eq!(info.deps.len(), 1);
        assert_eq!(info.deps[0].0, "github.com/a/b");
    }

    #[test]
    fn read_rootfs_with_one_go_binary_and_one_noise_file() {
        let dir = tempfile::tempdir().unwrap();
        let go_bin = dir.path().join("app");
        let mut bin = vec![0u8; 4096];
        bin.extend_from_slice(&build_inline_buildinfo(
            "path\texample.com/app\nmod\texample.com/app\tv0.0.0\t\ndep\tgh/x/y\tv1\tok=\n",
            "",
        ));
        std::fs::write(&go_bin, &bin).unwrap();

        let noise = dir.path().join("README.txt");
        std::fs::write(&noise, vec![b'n'; 4096]).unwrap();

        let entries = read(
            dir.path(),
            false,
            &std::collections::HashSet::new(),
            #[cfg(unix)]
            &std::collections::HashSet::new(),
        );
        assert!(entries.iter().any(|e| e.name == "example.com/app"));
        assert!(entries.iter().any(|e| e.name == "gh/x/y"));
        assert!(entries.iter().all(|e| e.source_type.as_deref() != Some("go-buildinfo-missing")));
    }

    #[test]
    fn pre_1_18_binary_emits_diagnostic_entry() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("legacy");
        let mut bin = vec![0u8; 4096];
        // Legacy pointer-format header.
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(BUILDINFO_MAGIC);
        blob.push(8);
        blob.push(0x0);
        blob.extend_from_slice(&[0u8; 30]);
        bin.extend_from_slice(&blob);
        std::fs::write(&p, &bin).unwrap();
        let entries = read(
            dir.path(),
            false,
            &std::collections::HashSet::new(),
            #[cfg(unix)]
            &std::collections::HashSet::new(),
        );
        assert!(entries
            .iter()
            .any(|e| e.buildinfo_status.as_deref() == Some("unsupported")));
    }

    /// v9 Phase O — a Go binary with unsupported BuildInfo MUST NOT
    /// emit a diagnostic when its path is in the shared claim set
    /// (simulating an rpm-owned Go toolchain tool on Fedora). The
    /// corresponding unclaimed control case still emits the
    /// diagnostic to confirm the claim check is the sole reason for
    /// suppression.
    #[test]
    fn claimed_unsupported_binary_suppresses_diagnostic() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("link");
        // Build a synthetic Go binary with legacy pointer-format
        // BuildInfo — triggers BuildInfoStatus::Unsupported.
        let mut bin = vec![0u8; 4096];
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(BUILDINFO_MAGIC);
        blob.push(8);
        blob.push(0x0);
        blob.extend_from_slice(&[0u8; 30]);
        bin.extend_from_slice(&blob);
        std::fs::write(&p, &bin).unwrap();

        // Unclaimed: diagnostic emits.
        let unclaimed = read(
            dir.path(),
            false,
            &std::collections::HashSet::new(),
            #[cfg(unix)]
            &std::collections::HashSet::new(),
        );
        assert!(
            unclaimed
                .iter()
                .any(|e| e.buildinfo_status.as_deref() == Some("unsupported")),
            "unclaimed binary should still emit the diagnostic (control)"
        );

        // Claimed: diagnostic suppressed.
        let mut claimed: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        claimed.insert(p.clone());
        #[cfg(unix)]
        let claimed_inodes: std::collections::HashSet<(u64, u64)> =
            std::collections::HashSet::new();
        let claimed_entries = read(
            dir.path(),
            false,
            &claimed,
            #[cfg(unix)]
            &claimed_inodes,
        );
        assert!(
            !claimed_entries
                .iter()
                .any(|e| e.buildinfo_status.as_deref() == Some("unsupported")),
            "claimed binary must NOT emit a diagnostic"
        );
    }
}