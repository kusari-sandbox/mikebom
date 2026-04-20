# Component Output Contract — Milestone 003

Per-ecosystem CycloneDX 1.6 component shape. Every example is what one component from that ecosystem looks like after `mikebom sbom scan` writes the JSON. Fields not shown here default to the milestone-002 conventions (supplier, licenses, hashes, cpes, evidence, properties).

Every component across all five ecosystems carries:

- `bom-ref`: the PURL string, unchanged from milestones 001–002.
- `purl`: canonical form, passes packageurl-python round-trip.
- `properties[]` includes `mikebom:sbom-tier` with one of `"source"` / `"deployed"` / `"analyzed"` / `"design"`.
- `evidence.identity.confidence` set per R13 tier mapping (0.95 source / 0.85 deployed / 0.85 analyzed-from-binary / 0.70 design).

## 1. Go module (source tier)

Source: `go.mod` + `go.sum` at a scanned project root.

```json
{
  "type": "library",
  "bom-ref": "pkg:golang/github.com/spf13/cobra@v1.7.0",
  "name": "github.com/spf13/cobra",
  "version": "v1.7.0",
  "purl": "pkg:golang/github.com/spf13/cobra@v1.7.0",
  "hashes": [],
  "licenses": [{ "license": { "id": "Apache-2.0" } }],
  "evidence": {
    "identity": {
      "field": "purl",
      "confidence": 0.95,
      "methods": [
        { "technique": "manifest-analysis", "confidence": 0.95, "value": "/tmp/scan/go.sum#L12" }
      ]
    }
  },
  "properties": [
    { "name": "mikebom:sbom-tier", "value": "source" }
  ]
}
```

## 2. Go module (analyzed tier, from BuildInfo)

Source: `runtime/debug.BuildInfo` in a compiled binary. Licenses are enriched from deps.dev online, absent offline.

```json
{
  "type": "library",
  "bom-ref": "pkg:golang/github.com/spf13/cobra@v1.7.0",
  "name": "github.com/spf13/cobra",
  "version": "v1.7.0",
  "purl": "pkg:golang/github.com/spf13/cobra@v1.7.0",
  "evidence": {
    "identity": {
      "field": "purl",
      "confidence": 0.85,
      "methods": [
        { "technique": "binary-analysis", "confidence": 0.85, "value": "/tmp/scan/bin/hello" }
      ]
    }
  },
  "properties": [
    { "name": "mikebom:sbom-tier", "value": "analyzed" }
  ]
}
```

### 2a. Stripped Go binary component (file-level diagnostic)

When BuildInfo extraction fails, the binary itself is emitted as a single component with the diagnostic property:

```json
{
  "type": "file",
  "name": "stripped-hello",
  "purl": "pkg:generic/stripped-hello@unknown",
  "hashes": [
    { "alg": "SHA-256", "content": "<file-sha256>" }
  ],
  "properties": [
    { "name": "mikebom:buildinfo-status", "value": "missing" }
  ]
}
```

## 3. RPM package (deployed tier)

Source: `/var/lib/rpm/rpmdb.sqlite` row.

```json
{
  "type": "library",
  "bom-ref": "pkg:rpm/redhat/glibc@2.34-100.el9?arch=x86_64",
  "name": "glibc",
  "version": "2.34-100.el9",
  "purl": "pkg:rpm/redhat/glibc@2.34-100.el9?arch=x86_64",
  "licenses": [{ "license": { "expression": "LGPL-2.1-or-later AND LGPL-2.1-only AND GPL-2.0-only" } }],
  "supplier": { "name": "Red Hat, Inc. <security@redhat.com>" },
  "evidence": {
    "identity": {
      "field": "purl",
      "confidence": 0.85,
      "methods": [
        { "technique": "manifest-analysis", "confidence": 0.85, "value": "/tmp/scan/var/lib/rpm/rpmdb.sqlite" }
      ]
    }
  },
  "properties": [
    { "name": "mikebom:sbom-tier", "value": "deployed" }
  ]
}
```

Epoch = 0 is omitted per packageurl-python canonical form. For a package with epoch ≠ 0 (e.g. epoch=1), the PURL becomes `pkg:rpm/redhat/<name>@1:2.34-100.el9?arch=x86_64`.

## 4. Maven component (source tier from pom.xml)

```json
{
  "type": "library",
  "bom-ref": "pkg:maven/com.google.guava/guava@32.1.3-jre",
  "group": "com.google.guava",
  "name": "guava",
  "version": "32.1.3-jre",
  "purl": "pkg:maven/com.google.guava/guava@32.1.3-jre",
  "licenses": [{ "license": { "id": "Apache-2.0" } }],
  "evidence": {
    "identity": {
      "field": "purl",
      "confidence": 0.95,
      "methods": [
        { "technique": "manifest-analysis", "confidence": 0.95, "value": "/tmp/scan/pom.xml" }
      ]
    }
  },
  "properties": [
    { "name": "mikebom:sbom-tier", "value": "source" }
  ]
}
```

## 4a. Maven component (analyzed tier from JAR)

```json
{
  "type": "library",
  "bom-ref": "pkg:maven/org.slf4j/slf4j-api@1.7.36",
  "group": "org.slf4j",
  "name": "slf4j-api",
  "version": "1.7.36",
  "purl": "pkg:maven/org.slf4j/slf4j-api@1.7.36",
  "licenses": [{ "license": { "id": "MIT" } }],
  "evidence": {
    "identity": {
      "field": "purl",
      "confidence": 0.85,
      "methods": [
        { "technique": "binary-analysis", "confidence": 0.85, "value": "/tmp/scan/dist/app.jar!META-INF/maven/org.slf4j/slf4j-api/pom.properties" }
      ]
    }
  },
  "properties": [
    { "name": "mikebom:sbom-tier", "value": "analyzed" }
  ]
}
```

## 4b. Maven component (design tier, unresolved property)

```json
{
  "type": "library",
  "bom-ref": "pkg:maven/com.example/internal-lib@",
  "group": "com.example",
  "name": "internal-lib",
  "version": "",
  "purl": "pkg:maven/com.example/internal-lib@",
  "properties": [
    { "name": "mikebom:sbom-tier", "value": "design" },
    { "name": "mikebom:requirement-range", "value": "${project.version}" }
  ]
}
```

## 5. Cargo crate (source tier)

```json
{
  "type": "library",
  "bom-ref": "pkg:cargo/serde@1.0.195",
  "name": "serde",
  "version": "1.0.195",
  "purl": "pkg:cargo/serde@1.0.195",
  "hashes": [
    { "alg": "SHA-256", "content": "f5ffc7d19f7e3c86a68bdf7f4a6ab4d9f7b5d2c8d3b6f4c5e6a8d7b9c1a3e5d7" }
  ],
  "evidence": {
    "identity": {
      "field": "purl",
      "confidence": 0.95,
      "methods": [
        { "technique": "manifest-analysis", "confidence": 0.95, "value": "/tmp/scan/Cargo.lock#L143" }
      ]
    }
  },
  "properties": [
    { "name": "mikebom:sbom-tier", "value": "source" }
  ]
}
```

Git-sourced crates omit `hashes[]` and add `{ "name": "mikebom:source-type", "value": "git" }`.

## 6. Gem (source tier)

```json
{
  "type": "library",
  "bom-ref": "pkg:gem/rake@13.1.0",
  "name": "rake",
  "version": "13.1.0",
  "purl": "pkg:gem/rake@13.1.0",
  "evidence": {
    "identity": {
      "field": "purl",
      "confidence": 0.95,
      "methods": [
        { "technique": "manifest-analysis", "confidence": 0.95, "value": "/tmp/scan/Gemfile.lock" }
      ]
    }
  },
  "properties": [
    { "name": "mikebom:sbom-tier", "value": "source" }
  ]
}
```

Git-sourced gems add `{ "name": "mikebom:source-type", "value": "git" }`. Path-sourced gems add `"path"`.
