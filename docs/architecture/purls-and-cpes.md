# PURLs and CPEs

mikebom is uncompromising about PURL correctness and pragmatic about CPE
coverage. The rules for each identifier are separate and the rationale is
different.

## PURLs — the canonical form

PURL (Package URL) is the primary identifier on every component. Consumers
that round-trip PURLs through the `packageurl-python` or `packageurl-go`
reference implementations will either reject, silently rewrite, or
mis-index PURLs that disagree with the reference canonical form. Once the
hash changes, the SBOM's signature no longer verifies. So mikebom's ground
truth for PURL encoding is the behavior of those two reference libraries,
not the prose of the purl-spec where it's ambiguous.

**Key file:** `mikebom-common/src/types/purl.rs` (the `Purl` type performs
re-canonicalization at construction time) plus per-ecosystem PURL
construction scattered across `scan_fs/package_db/*.rs`.

### Canonicalization rules

These apply uniformly across all ecosystems:

1. **Qualifiers sorted alphabetically.** `Purl::new` re-canonicalizes the
   qualifier section, so `?epoch=1&arch=x86_64&distro=fedora-40` becomes
   `?arch=x86_64&distro=fedora-40&epoch=1`. Required by purl-spec's
   how-to-build guide ("Sort this list of qualifier strings
   lexicographically"). Already-sorted inputs pass through unchanged, which
   preserves caller-side `encode_purl_segment` work.

2. **Percent-encoding follows the reference implementations.**
   - `+` in version → `%2B` (canonical).
   - `+` in name (`libstdc++6` → `libstdc%2B%2B6`) → `%2B`.
   - `:` in version (epoch separator) → **literal** (`1:2.38.1`), not
     `%3A`.
   - `~` in version → **literal**, not `%7E`.

3. **RPM `epoch=0` omitted.** RPM treats absent and 0 as equivalent for
   version comparison; `rpm -qa`'s default display omits; the purl-spec RPM
   example never shows `epoch=0`. mikebom drops the qualifier when epoch is
   `Some(0)`. See
   [design-notes §PURL canonicalization](../design-notes.md#purl-canonicalization).

4. **`distro=<codename>` is a plain codename.** `bookworm`, not
   `debian-12`. `noble`, not `ubuntu-24.04`. Sourced from `/etc/os-release`
   `VERSION_CODENAME` (with `UBUNTU_CODENAME` fallback for older Ubuntu
   images) or from `--deb-codename`.

5. **No non-identity qualifiers.** `download_url`, `upstream`, `source`, and
   `repository_url` never appear — they don't identify the package, they
   describe where it came from, and that belongs in `evidence` or
   `externalReferences`.

### Asymmetry between PURL and `component.version`

The PURL version field is percent-encoded (`%2B` for `+`). The CycloneDX
`component.version` field and the synthesized CPEs carry the **literal**
character. The two are different audiences — PURL is for machine round-trip
through the reference parser; `version` and CPE are for human display and
NVD matching.

```jsonc
{
  "name": "base-files",
  "version": "12.4+deb12u13",                                     // human/NVD
  "purl": "pkg:deb/debian/base-files@12.4%2Bdeb12u13?arch=arm64&distro=bookworm",
  "cpe":  "cpe:2.3:a:debian:base-files:12.4\\+deb12u13:*:..."     // CPE-escaped literal
}
```

### Per-ecosystem notes

- **deb**: `pkg:deb/debian/<name>@<version>?arch=<arch>&distro=<codename>`.
  Epoch goes inside `<version>` (`1:2.38.1`), never as a qualifier.
- **rpm**: `pkg:rpm/<vendor>/<name>@<version>?arch=<arch>&distro=<vendor>-<ver>`.
  Vendor is the distro slug (`redhat`, `rocky`, `fedora`, `suse`, `opensuse`).
  `epoch=0` omitted.
- **maven**: `pkg:maven/<groupId>/<artifactId>@<version>`. Reverse-DNS
  groupId is part of the identity — `jsr305` has multiple valid groupIds.
- **npm**: `pkg:npm/<@scope>/<name>@<version>` for scoped, `pkg:npm/<name>@<version>`
  for unscoped. Namespace is the `@scope` segment.
- **pypi**: `pkg:pypi/<name>@<version>`. Name is PEP 503–normalized (lowercase,
  runs of non-alphanum collapsed to `-`).
- **golang**: `pkg:golang/<module-prefix>/<final-segment>@v<version>`.
  Module-prefix is url-encoded in ClearlyDefined coords but literal in PURL.
- **cargo**: `pkg:cargo/<name>@<version>`. No namespace (crates.io is flat).
- **gem**: `pkg:gem/<name>@<version>`.
- **apk**: `pkg:apk/alpine/<name>@<version>?arch=<arch>&distro=<version>`.

## CPEs — multi-candidate emission

NVD's CPE dictionary is the target. mikebom synthesizes CPEs locally using
**syft-style heuristic vendor candidates**: each component gets multiple
CPE candidates per component, not just one, because no single heuristic wins
across all ecosystems.

**Key file:** `mikebom-cli/src/generate/cpe.rs::synthesize_cpes`.

### Why multiple candidates

The `jq` tool currently lives under `cpe:2.3:a:jqlang:jq:...` in NVD, used
to live under `cpe:2.3:a:jq_project:jq:...`, and syft sometimes synthesizes
`cpe:2.3:a:debian:jq:...` because that's what the install metadata points
at. A downstream matcher taking the union of all candidates against NVD
will find whichever entry actually exists. A single-candidate approach
misses the match in a majority of cases.

### Candidate sets per ecosystem

| Ecosystem | Candidates |
|---|---|
| **deb** | `[debian, <name>]` |
| **apk** | `[alpinelinux, <name>]` |
| **rpm** | `[<purl-namespace>, <name>]` (e.g. `[redhat, kernel]`) |
| **gem** | `[<name>]` |
| **cargo** | `[<name>]` |
| **npm** | `[<name>]` plus `[<scope-without-@>]` for scoped packages (e.g. `@angular/core` → `[core, angular]`) |
| **pypi** | `[<name>, python-<name>]` (NVD commonly namespaces Python packages as `python-foo`) |
| **golang** | `[<name>, <purl-namespace>]` (namespace is the module path prefix) |
| **maven** | `[<groupId>, <last-segment-of-groupId>, <artifactId>]` (e.g. `org.apache.commons` → `apache`) |
| **nuget** | `[<name>]` |
| other | `[]` — no opinion, empty CPE set |

### Emission format

- The **first candidate** lands on `component.cpe` in the CycloneDX output
  (this is the field most tools look at).
- The **full candidate list** lands on `component.properties` under
  `mikebom:cpe-candidates`.

So a deb package always has two CPE candidates (`debian:<name>` plus
`<name>:<name>`), a Maven package has up to three, a scoped npm package has
two, and so on.

### CPE formatting

Per CPE 2.3 §6.2 formatted-string binding:

- `cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*` for application
  components (mikebom emits `a` — application — for every candidate; never
  hardware (`h`) or OS (`o`) today).
- Escape: `\`, `*`, `?`, `!`, `"`, `#`, `$`, `%`, `&`, `'`, `(`, `)`, `+`,
  `,`, `/`, `:`, `;`, `<`, `=`, `>`, `@`, `[`, `]`, `^`, backtick, `{`, `|`,
  `}`, `~` all escape with a leading `\`.
- Preserve: ASCII alphanumerics, `-`, `.`, `_` pass through.

`cpe_escape` in `generate/cpe.rs` implements this. Vendor and product
segments lowercase before escaping; version preserves case.

## Why the two rule-sets differ

PURLs are uniquely canonical and machine-verifiable — the reference
implementations define the one right answer. mikebom can and does insist
on that.

CPEs have no reference-canonical form. NVD's dictionary is hand-curated,
vendor slugs vary, and some packages have multiple valid CPEs. Emitting
multiple candidates per component is a practical accommodation — it costs a
few bytes per component in the SBOM and it unlocks NVD matches that a
single-heuristic approach would miss.
