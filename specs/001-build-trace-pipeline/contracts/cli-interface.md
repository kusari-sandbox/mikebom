# CLI Interface Contract

**Tool**: `mikebom`
**Version**: 0.1.0

## Global Behavior

- All commands write structured logs to stderr via `RUST_LOG` env var
- Output files default to current directory; overridden with `--output`
- Exit code 0 on success; non-zero on any error (fail-closed)
- JSON output on stdout when `--json` flag is used (for scripting)

## Subcommands

### `mikebom scan`

Trace a build process via eBPF and produce an in-toto attestation.

```
mikebom scan [OPTIONS] [-- <COMMAND>...]

Arguments:
  [COMMAND]...              Build command to trace (spawned in isolated cgroup)

Options:
  --target-pid <PID>        Trace an already-running process (mutually exclusive with COMMAND)
  --output <PATH>           Attestation output path [default: mikebom.attestation.json]
  --trace-children          Also trace child processes of the target
  --libssl-path <PATH>      Custom path to libssl.so (auto-detected by default)
  --go-binary <PATH>        Path to Go binary for Go TLS probes
  --ring-buffer-size <SIZE> Network ring buffer size [default: 8MB]
  --timeout <SECONDS>       Maximum trace duration (0 = unlimited) [default: 0]
  --json                    Output attestation summary as JSON to stdout
```

**Exit codes**:
- 0: Trace completed, attestation produced
- 1: eBPF probe attachment failed
- 2: No dependency activity observed (fail-closed)
- 3: Ring buffer overflow with critical event loss
- 4: Target process not found or inaccessible
- 5: Insufficient privileges (not root / no CAP_BPF)

**Requires**: root or CAP_BPF

### `mikebom generate`

Generate an SBOM from an attestation file.

```
mikebom generate [OPTIONS] <ATTESTATION_FILE>

Arguments:
  <ATTESTATION_FILE>        Path to attestation JSON file

Options:
  --format <FORMAT>         Output format [default: cyclonedx-json]
                            Values: cyclonedx-json, cyclonedx-xml, spdx-json
  --output <PATH>           SBOM output path [default: mikebom.cdx.json]
  --enrich                  Also run enrichment (license, VEX, supplier)
  --deps-dev-timeout <MS>   Timeout per deps.dev API call [default: 5000]
  --skip-purl-validation    Skip online PURL existence validation
  --vex-overrides <PATH>    VEX override file for manual triage states
  --json                    Output generation summary as JSON to stdout
```

**Exit codes**:
- 0: SBOM generated successfully
- 1: Attestation file invalid or unreadable
- 2: Resolution produced zero components
- 3: Generated SBOM fails schema validation (internal error)

**Does NOT require**: root or CAP_BPF

### `mikebom enrich`

Add license, VEX, and supplier data to an existing SBOM.

```
mikebom enrich [OPTIONS] <SBOM_FILE>

Arguments:
  <SBOM_FILE>               Path to CycloneDX or SPDX SBOM file

Options:
  --output <PATH>           Output path [default: overwrite input]
  --skip-vex                Skip VEX enrichment
  --skip-licenses           Skip license enrichment
  --skip-supplier           Skip supplier metadata enrichment
  --vex-overrides <PATH>    VEX override file for manual triage states
  --deps-dev-timeout <MS>   Timeout per deps.dev API call [default: 5000]
  --json                    Output enrichment summary as JSON to stdout
```

**Exit codes**:
- 0: Enrichment completed (partial enrichment is still success)
- 1: SBOM file invalid or unreadable

**Does NOT require**: root or CAP_BPF

### `mikebom run`

Trace a build, resolve, enrich, and generate SBOM in one step.

```
mikebom run [OPTIONS] -- <COMMAND>...

Arguments:
  <COMMAND>...              Build command to trace

Options:
  (Combines all scan + generate + enrich options)
  --format <FORMAT>         SBOM output format [default: cyclonedx-json]
  --sbom-output <PATH>      SBOM output path [default: mikebom.cdx.json]
  --attestation-output <PATH> Attestation output path [default: mikebom.attestation.json]
  --no-enrich               Skip enrichment step
  --json                    Output summary as JSON to stdout
```

**Exit codes**: Same as scan (trace failures) + generate (resolution failures)

**Requires**: root or CAP_BPF

### `mikebom validate`

Validate an attestation or SBOM file for conformance.

```
mikebom validate [OPTIONS] <FILE>

Arguments:
  <FILE>                    Attestation or SBOM file to validate

Options:
  --format <FORMAT>         Override auto-detection: attestation, cyclonedx, spdx
  --strict                  Fail on warnings (default: warnings reported but exit 0)
  --json                    Output validation report as JSON to stdout
```

**Checks performed**:
- Attestation: schema conformance, trace_integrity analysis, timestamp validity
- CycloneDX: JSON schema validation, PURL conformance per component, CISA 2025 field presence
- SPDX: JSON-LD schema validation, element completeness

**Exit codes**:
- 0: All checks pass (or warnings only without --strict)
- 1: Validation errors found
- 2: File unreadable or format unrecognized

**Does NOT require**: root or CAP_BPF
