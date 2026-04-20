# Quickstart — Python + npm Ecosystem Support

This document shows how to exercise the new Python + npm scanners after implementation lands. It's intended for reviewers validating acceptance criteria and for downstream users trying out the milestone.

## Prerequisites

- Rust stable toolchain (for building mikebom).
- Either a `python3` venv with real packages installed, or a `poetry.lock` / `Pipfile.lock` / `requirements.txt` on disk.
- Either a `package-lock.json` v2/v3 or a `pnpm-lock.yaml` on disk, or a populated `node_modules/` tree.
- (For image-mode examples) `docker` and enough disk space to `docker save` a few hundred MB.
- (Optional) internet access for deps.dev enrichment. Omit by passing `--offline`.

## Build

```bash
cd /path/to/mikebom
cargo build --release
# binary: target/release/mikebom
```

## Directory scan — Python venv

```bash
# In an existing Python project with an installed venv:
./target/release/mikebom sbom scan --path . --output python.cdx.json --json
```

Expect:

```jsonc
{
  "components": 75,      // varies by project
  "relationships": 120,  // dependencies[] edges from Requires-Dist
  "generation_context": "filesystem-scan",
  "target_name": "my-python-project"
}
```

Verify:

```bash
# Every pypi PURL is reference-impl conformant
python3 -c "
import json
from packageurl import PackageURL
b = json.load(open('python.cdx.json'))
bad = [c['purl'] for c in b['components'] if c['purl'].startswith('pkg:pypi/')
       and PackageURL.from_string(c['purl']).to_string() != c['purl']]
print(f'Non-conformant: {len(bad)}')  # should print 0
"

# License coverage
python3 -c "
import json
b = json.load(open('python.cdx.json'))
pypi = [c for c in b['components'] if c['purl'].startswith('pkg:pypi/')]
with_lic = sum(1 for c in pypi if c.get('licenses'))
print(f'pypi licenses: {with_lic}/{len(pypi)}')  # expect ≥95% per SC-005
"
```

## Directory scan — Node.js project

### Default (prod only)

```bash
cd node-project
./target/release/mikebom sbom scan --path . --output npm-prod.cdx.json --json
```

### Include dev dependencies

```bash
./target/release/mikebom sbom scan --path . --include-dev --output npm-all.cdx.json --json

# Compare counts
python3 -c "
import json
prod = json.load(open('npm-prod.cdx.json'))
dev = json.load(open('npm-all.cdx.json'))
print(f'prod-only: {len(prod[\"components\"])}')
print(f'with-dev:  {len(dev[\"components\"])}')
print(f'dev-flagged in dev run: {sum(1 for c in dev[\"components\"] if any(p.get(\"name\") == \"mikebom:dev-dependency\" for p in c.get(\"properties\", [])))}')
"
```

## Directory scan — uninstalled project (FR-007a fallback)

```bash
# Directory has a package.json but no lockfile and no node_modules/
./target/release/mikebom sbom scan --path . --output fallback.cdx.json --json

# Verify fallback shape
python3 -c "
import json
b = json.load(open('fallback.cdx.json'))
for c in b['components'][:3]:
    range_prop = next((p['value'] for p in c.get('properties',[])
                       if p['name'] == 'mikebom:requirement-range'), None)
    print(f'{c[\"name\"]!r}: version={c[\"version\"]!r}, range={range_prop!r}, confidence={c[\"evidence\"][\"identity\"][\"confidence\"]}')
"
# Expect: version = '', confidence = 0.70, range populated
```

## Directory scan — refusal path (legacy lockfile)

```bash
cd project-with-v1-lockfile
./target/release/mikebom sbom scan --path . --output sbom.cdx.json
# Exit code: non-zero
# Stderr: error: package-lock.json v1 not supported; regenerate with npm ≥7
# No sbom.cdx.json is written

# Fix path for the user
rm -rf node_modules && npm install  # npm ≥7 writes v2/v3
./target/release/mikebom sbom scan --path . --output sbom.cdx.json
# Now succeeds
```

## Image scan — Python application

```bash
# Build or pull a Python app image
docker pull tiangolo/uvicorn-gunicorn-fastapi:python3.12-slim
docker save tiangolo/uvicorn-gunicorn-fastapi:python3.12-slim -o fastapi.tar

./target/release/mikebom sbom scan --image fastapi.tar --output fastapi.cdx.json --json
```

Expect a mixed SBOM:

```bash
python3 -c "
import json
b = json.load(open('fastapi.cdx.json'))
eco_counts = {}
for c in b['components']:
    p = c['purl']
    eco = p.split('/')[0].split(':',1)[1] if p.startswith('pkg:') else 'other'
    eco_counts[eco] = eco_counts.get(eco, 0) + 1
print(eco_counts)
# Expect: {'deb': ~60, 'pypi': ~40} — numbers vary

complete = [r for r in b['compositions'] if r['aggregate'] == 'complete']
print(f'complete-aggregate compositions: {len(complete)}')
# Expect: ≥ 2 (one for deb, one for pypi)
"
```

## Image scan — Node.js application

```bash
docker pull node:20-alpine
docker save node:20-alpine -o node.tar

./target/release/mikebom sbom scan --image node.tar --output node.cdx.json --json

# Expect apk + npm components, with separate composition records for each
```

## Offline verification

```bash
# Run the same scan twice
./target/release/mikebom sbom scan --path python-project --output online.cdx.json
./target/release/mikebom --offline sbom scan --path python-project --output offline.cdx.json

# Expect: same component count, same purls, same hashes.
# Difference: online has deps.dev tool refs in evidence.identity.tools[];
# offline has none.
python3 -c "
import json
online = json.load(open('online.cdx.json'))
offline = json.load(open('offline.cdx.json'))
assert len(online['components']) == len(offline['components'])
tool_refs_online = sum(1 for c in online['components']
                       for t in c['evidence']['identity'].get('tools', [])
                       if 'deps.dev' in t.get('ref',''))
tool_refs_offline = sum(1 for c in offline['components']
                        for t in c['evidence']['identity'].get('tools', [])
                        if 'deps.dev' in t.get('ref',''))
print(f'online deps.dev refs: {tool_refs_online}, offline: {tool_refs_offline}')
# Expect: online > 0, offline == 0
"
```

## Tests

```bash
# Unit tests (all new modules)
cargo test --workspace

# Fixture-based integration tests
cargo test --workspace --test scan_fixtures
# Walks tests/fixtures/python/ and tests/fixtures/npm/ subtrees
# Asserts component count, PURL conformance, license coverage per fixture

# Clippy (no warnings allowed per constitution)
cargo clippy --all-targets --all-features -- -D warnings
```

## Troubleshooting

**"package-lock.json v1 not supported"**: The project has an old lockfile. Regenerate with `rm -rf node_modules && npm install` using npm ≥7 (default since late 2020).

**Zero Python components found but I have a pyproject.toml**: By design. `pyproject.toml` `[project.dependencies]` lists build specs, not resolved versions. Install the project (`pip install -e .` or `poetry install`) so there's a venv to scan, or commit a `poetry.lock` / `requirements.txt`.

**Dev dependencies showing up unexpectedly**: Check if you passed `--include-dev` anywhere. The default is prod-only. Dev components carry `mikebom:dev-dependency = true` so you can also filter them post-hoc with `jq`.

**Image scan missing app's node_modules**: The scanner walks `<image-WORKDIR>/node_modules/` when `WORKDIR` is readable from the image config. If the app is installed somewhere non-standard, file a follow-up for that path pattern.
