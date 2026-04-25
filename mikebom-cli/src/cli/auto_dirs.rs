//! Auto-detect artifact directories from the traced command.
//!
//! A user running `mikebom trace run --auto-dirs -- cargo install ripgrep`
//! shouldn't need to know that cargo's cache lives at
//! `$CARGO_HOME/registry/cache`. We inspect the command argv, match the
//! first interesting basename against a known-tool table, and return the
//! set of directories the post-trace artifact scan should walk.
//!
//! The matcher is deliberately simple: exact basename match only, with a
//! small set of wrapper prefixes handled by recursion. Ambiguous cases
//! (`bash -c "cargo install ..."`) return no dirs and log a warn so the
//! user sees they're not getting auto-detection and can pass
//! `--artifact-dir` explicitly.

// `detect` is invoked from `cli/scan.rs::execute_scan` Linux-only
// trace flow; the helpers it calls are all only reachable from there.
#![allow(dead_code)]

use std::path::PathBuf;

/// Scan a command argv for known build tools and return the artifact
/// directories that tool normally writes into. Returns an empty vector
/// when the command doesn't match any known tool.
pub fn detect(command: &[String]) -> Vec<PathBuf> {
    if command.is_empty() {
        return Vec::new();
    }

    // Peel off common wrapper invocations so we can look at the real tool.
    // `env VAR=x cargo install` → `cargo install`.
    // `python -m pip install x` → treat the module as the tool.
    // `bash -c "cargo install"` → too dynamic; skip with a warn.
    if let Some(inner) = unwrap_wrapper(command) {
        return detect(&inner);
    }

    let argv0 = &command[0];
    let tool = std::path::Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(argv0);

    let dirs = dirs_for_tool(tool, command);
    for d in &dirs {
        tracing::info!(
            tool,
            dir = %d.display(),
            "auto-dir detected",
        );
    }
    dirs
}

/// Translate wrapper invocations like `env`, `python -m pip`, `/usr/bin/env`
/// into the underlying command so detection works transparently.
/// Returns `Some(inner)` only for wrappers we recognise; the caller falls
/// through to standard detection on `None`.
fn unwrap_wrapper(command: &[String]) -> Option<Vec<String>> {
    let argv0 = std::path::Path::new(&command[0])
        .file_name()
        .and_then(|s| s.to_str())?;

    match argv0 {
        "env" | "/usr/bin/env" => {
            // Skip any leading `VAR=value` assignments.
            let rest: Vec<String> = command[1..]
                .iter()
                .skip_while(|a| a.contains('='))
                .cloned()
                .collect();
            if rest.is_empty() {
                None
            } else {
                Some(rest)
            }
        }
        "python" | "python3" => {
            // `python -m pip install x` → treat as `pip install x`.
            if command.len() >= 3 && command[1] == "-m" {
                let mut rest = vec![command[2].clone()];
                rest.extend(command[3..].iter().cloned());
                Some(rest)
            } else {
                None
            }
        }
        "bash" | "sh" | "zsh" => {
            if command.len() >= 2 && command[1] == "-c" {
                tracing::warn!(
                    command = ?command,
                    "--auto-dirs: shell-wrapped command; skipping auto-detection. \
                     Pass --artifact-dir explicitly if the inner build writes artifacts."
                );
            }
            // Never try to tokenise a `-c` arg — too many ways for it to
            // mean something we can't infer.
            Some(vec![]) // empty → detect() recurses on empty → returns []
        }
        _ => None,
    }
}

/// Known-tool → artifact-dir table. Each entry may additionally inspect
/// `argv` (e.g. go only caches for `build|mod|get|install`) to decide
/// whether the dir is actually relevant.
fn dirs_for_tool(tool: &str, command: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();

    match tool {
        "cargo" => {
            out.push(cargo_home().join("registry/cache"));
        }
        "pip" | "pip3" => {
            // Downloaded wheels live in pip's http cache.
            if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
                out.push(home.join(".cache/pip/http-v2"));
                out.push(home.join(".cache/pip/http"));
            }
            // If a venv is active, scan its site-packages.
            if let Some(venv) = std::env::var_os("VIRTUAL_ENV").map(PathBuf::from) {
                out.push(venv.join("lib"));
            }
        }
        "npm" => {
            out.push(PathBuf::from("node_modules"));
            if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
                out.push(home.join(".npm/_cacache"));
            }
        }
        "pnpm" => {
            out.push(PathBuf::from("node_modules/.pnpm"));
            if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
                out.push(home.join(".pnpm-store"));
            }
        }
        "yarn" => {
            out.push(PathBuf::from("node_modules"));
            if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
                out.push(home.join(".yarn/cache"));
            }
        }
        "go" => {
            let fetches = matches!(
                command.get(1).map(|s| s.as_str()),
                Some("build" | "mod" | "get" | "install" | "test")
            );
            if fetches {
                let gopath = std::env::var_os("GOPATH")
                    .map(PathBuf::from)
                    .or_else(|| {
                        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("go"))
                    });
                if let Some(p) = gopath {
                    out.push(p.join("pkg/mod"));
                }
            }
        }
        "apt-get" | "apt" => {
            out.push(PathBuf::from("/var/cache/apt/archives"));
        }
        "curl" | "wget" => {
            // Both write to CWD by default with -O / no -o; the trace
            // mode respects the traced command's cwd, so picking "." at
            // auto-detect time is wrong. Skip — require explicit
            // --artifact-dir for these.
        }
        _ => {}
    }

    out
}

fn cargo_home() -> PathBuf {
    if let Some(home) = std::env::var_os("CARGO_HOME") {
        return PathBuf::from(home);
    }
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".cargo"))
        .unwrap_or_else(|| PathBuf::from(".cargo"))
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    fn cmd(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn cargo_install_yields_registry_cache() {
        let dirs = detect(&cmd(&["cargo", "install", "ripgrep"]));
        assert!(!dirs.is_empty());
        let lossy: Vec<String> =
            dirs.iter().map(|p| p.to_string_lossy().into_owned()).collect();
        assert!(
            lossy.iter().any(|p| p.contains("registry/cache")),
            "expected registry/cache in {lossy:?}"
        );
    }

    #[test]
    fn empty_command_returns_empty() {
        assert!(detect(&[]).is_empty());
    }

    #[test]
    fn unknown_tool_returns_empty() {
        assert!(detect(&cmd(&["my-weird-script"])).is_empty());
    }

    #[test]
    fn bash_c_wrapper_returns_empty() {
        // Shell-wrapped commands are too dynamic to introspect.
        let dirs = detect(&cmd(&["bash", "-c", "cargo install ripgrep"]));
        assert!(dirs.is_empty());
    }

    #[test]
    fn env_wrapper_unwraps_to_inner_tool() {
        let dirs = detect(&cmd(&["env", "FOO=bar", "cargo", "install", "ripgrep"]));
        assert!(!dirs.is_empty());
        assert!(dirs.iter().any(|p| p.to_string_lossy().contains("registry/cache")));
    }

    #[test]
    fn python_m_pip_unwraps_to_pip() {
        // HOME is set in the test harness
        let dirs = detect(&cmd(&["python3", "-m", "pip", "install", "requests"]));
        // At least one of pip's expected dirs should appear
        let lossy: Vec<String> =
            dirs.iter().map(|p| p.to_string_lossy().into_owned()).collect();
        assert!(
            lossy.iter().any(|p| p.contains(".cache/pip")),
            "expected .cache/pip dir in {lossy:?}"
        );
    }

    #[test]
    fn go_build_yields_gopath_pkg_mod() {
        let dirs = detect(&cmd(&["go", "build", "./..."]));
        assert!(
            dirs.iter().any(|p| p.to_string_lossy().contains("pkg/mod")),
            "expected pkg/mod in {dirs:?}"
        );
    }

    #[test]
    fn go_version_does_not_yield_pkg_mod() {
        // Not a fetching subcommand — should not add pkg/mod.
        let dirs = detect(&cmd(&["go", "version"]));
        assert!(
            dirs.iter().all(|p| !p.to_string_lossy().contains("pkg/mod")),
            "pkg/mod should be absent: {dirs:?}"
        );
    }

    #[test]
    fn apt_get_yields_apt_archives() {
        let dirs = detect(&cmd(&["apt-get", "install", "jq"]));
        assert!(dirs.iter().any(|p| p == std::path::Path::new("/var/cache/apt/archives")));
    }

    #[test]
    fn curl_skips_cwd() {
        // Detecting "." is wrong at this layer — requires explicit dir.
        assert!(detect(&cmd(&["curl", "-O", "https://example.com/foo.deb"])).is_empty());
    }
}
