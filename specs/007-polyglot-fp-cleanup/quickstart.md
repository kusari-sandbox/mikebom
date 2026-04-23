# Quickstart: Polyglot FP Cleanup

Three independently-shippable slices. Each can be merged, measured, and deployed on its own.

## Prerequisites

- Branch: `007-polyglot-fp-cleanup` (already checked out by `/speckit.specify`)
- Tree: clean relative to `main` at commit `5b38b98` (post-G3 merge)
- Polyglot bake-off fixture available at the standard path (or use synthetic repros — see below)

## Slice 1 (P1): Fedora sidecar POM reading

### Synthetic repro

```bash
mkdir -p /tmp/slice1/rootfs/usr/share/maven/lib /tmp/slice1/rootfs/usr/share/maven-poms
# Tiny JAR with no META-INF/maven/ — just empty placeholder
zip -j /tmp/slice1/rootfs/usr/share/maven/lib/guice-5.1.0.jar /dev/null 2>/dev/null || true

cat > /tmp/slice1/rootfs/usr/share/maven-poms/JPP-guice.pom <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.google.inject</groupId>
  <artifactId>guice</artifactId>
  <version>5.1.0</version>
</project>
EOF

./target/release/mikebom sbom scan --offline --path /tmp/slice1/rootfs --output /tmp/slice1.cdx.json
jq '[.components[] | select(.purl // "" | startswith("pkg:maven/"))] | .[].purl' /tmp/slice1.cdx.json
```

**Expected (post-Slice 1)**: `pkg:maven/com.google.inject/guice@5.1.0` appears. Pre-slice: the JAR appears only as a `pkg:generic/` file component.

### Bake-off delta

- Run the post-Slice 1 binary against polyglot-builder-image.
- Expect: Maven exact-match scoreboard rises from 101/114 → ≥113/114; `embedded_pom_only` bucket drops from 12 → ≤1 (the one remaining would be a JAR whose sidecar POM declares a parent we cannot resolve offline).

## Slice 2 (P2): Go test-scope filter (intersection)

### Synthetic repro

```bash
mkdir -p /tmp/slice2/opt/goapp /tmp/slice2/opt/goapp/internal
cat > /tmp/slice2/opt/goapp/go.mod <<'EOF'
module example.com/slicetwo

go 1.26

require (
    github.com/sirupsen/logrus v1.9.4
    github.com/stretchr/testify v1.11.1
)
EOF

cat > /tmp/slice2/opt/goapp/go.sum <<'EOF'
github.com/sirupsen/logrus v1.9.4 h1:...
github.com/sirupsen/logrus v1.9.4/go.mod h1:...
github.com/stretchr/testify v1.11.1 h1:...
github.com/stretchr/testify v1.11.1/go.mod h1:...
EOF

cat > /tmp/slice2/opt/goapp/main.go <<'EOF'
package main

import "github.com/sirupsen/logrus"

func main() {
    logrus.Info("hello")
}
EOF

cat > /tmp/slice2/opt/goapp/main_test.go <<'EOF'
package main

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestMain(t *testing.T) {
    assert.Equal(t, 1, 1)
}
EOF

./target/release/mikebom sbom scan --offline --path /tmp/slice2 --output /tmp/slice2.cdx.json
jq '[.components[] | select(.purl // "" | startswith("pkg:golang/")) | .purl] | sort' /tmp/slice2.cdx.json
```

**Expected (post-Slice 2)**: `logrus@v1.9.4` appears; `testify` does NOT. Pre-slice: both appear.

### Bake-off delta

- Run post-Slice 2 binary against polyglot-builder-image.
- Expect: `declared_not_cached` bucket drops from 5 → 1 (the remaining one is the project-self case closed in Slice 3).

## Slice 3 (P3): Go main-module exclusion

### Synthetic repro

```bash
mkdir -p /tmp/slice3/opt/goapp
cat > /tmp/slice3/opt/goapp/go.mod <<'EOF'
module example.com/polyglot-fixture

go 1.26

require github.com/sirupsen/logrus v1.9.4
EOF
# ... go.sum + main.go as in Slice 2

./target/release/mikebom sbom scan --offline --path /tmp/slice3 --output /tmp/slice3.cdx.json
jq '[.components[] | select(.purl // "" | contains("polyglot-fixture"))]' /tmp/slice3.cdx.json
```

**Expected (post-Slice 3)**: empty array. Pre-slice: one element with `pkg:golang/example.com/polyglot-fixture@(devel)` or similar.

### Bake-off delta

- `declared_not_cached` bucket → 0.

## Cumulative success criteria (all three slices merged)

1. `cargo test -p mikebom` — 1013 + at least 9 new tests (3 unit per slice or contract × 3 ≈ 9, plus integration) all pass.
2. `cargo build --release -p mikebom` clean.
3. Polyglot bake-off finding count: 23 → ≤6.
4. Per-ecosystem scoreboards: cargo/gem/pypi/rpm/binary all unchanged at 100%; maven ≥113/114; golang zero FPs.
5. No regression in existing scan tests (milestones 001–006).

## Rollback

Each slice is a separate PR. If a slice causes a regression, revert just that PR; the others remain on main. The filter architecture (G3 + G4 + G5 composed via `read_all`) is designed so any one filter can no-op without affecting the others.
