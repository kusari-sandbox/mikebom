# External Schema References

This milestone vendors three external JSON schemas for offline test-time validation. The vendored copies live at `mikebom-cli/tests/fixtures/schemas/`. They are **schema fixtures only** — not redistributed in built artifacts — so vendoring does not violate any redistribution constraint.

| Schema | Vendored filename | Upstream source URL | Spec version | Purpose in this milestone |
|--------|-------------------|---------------------|--------------|---------------------------|
| SPDX 2.3 JSON | `tests/fixtures/schemas/spdx-2.3.json` | https://raw.githubusercontent.com/spdx/spdx-spec/support/2.3/schemas/spdx-schema.json | SPDX 2.3 (Draft 7) | Validate produced `mikebom.spdx.json` in `tests/spdx_schema_validation.rs` (FR-005, SC-002). |
| SPDX 3.0.1 JSON | `tests/fixtures/schemas/spdx-3.0.1.json` | https://spdx.org/schema/3.0.1/spdx-json-schema.json | SPDX 3.0.1 (Draft 2020-12) | Validate produced `mikebom.spdx3-experimental.json` in `tests/spdx3_stub.rs` (FR-019a, SC-008). |
| OpenVEX 0.2.0 | `tests/fixtures/schemas/openvex-0.2.0.json` | https://raw.githubusercontent.com/openvex/spec/main/openvex_json_schema.json | OpenVEX 0.2.0 (Draft 2020-12) | Validate produced `mikebom.openvex.json` in `tests/openvex_sidecar.rs` (FR-016a). |
| SPDX 2.3 reference example | `tests/fixtures/reference/SPDXJSONExample-v2.3.spdx.json` | https://raw.githubusercontent.com/spdx/spdx-spec/support/2.3.1/examples/SPDXJSONExample-v2.3.spdx.json | SPDX 2.3 | Warning-baseline reference for SC-002; validated by `tests/spdx_schema_validation.rs` to compute the expected warning-category set. |

## Validator

All three schemas are exercised via the `jsonschema = "0.46"` crate (pure Rust, JSON Schema Draft 2020-12). See plan.md → Primary Dependencies and research R5.

## Refresh policy

- **SPDX 2.3** schema is stable; refresh only on a confirmed errata release from the SPDX project.
- **SPDX 3.0.1** schema MAY be refreshed when SPDX 3.0.x errata land; SPDX 3.1 final stabilization triggers a follow-up milestone (the stub may then be retargeted to 3.1, with the data-placement map updated in lockstep).
- **OpenVEX 0.2.0** schema MAY be refreshed when OpenVEX publishes an errata; an OpenVEX 0.3+ release triggers a follow-up milestone.

Each refresh updates the vendored file plus this table; no other code changes are required.
