# RPM file fixtures — milestone 004 US1

Real `.rpm` files from public mirrors used by `scan_rpm_file.rs` integration tests. Fetched once, committed after sha256 verification.

Expected fixture bodies (land via T016/T018 implementation + T042 fixture refresh):

- `openssl-libs-3.0.7-28.el9_4.x86_64.rpm` — Red Hat, vendor slug `redhat`
- `zlib-1.2.13-5.el9.x86_64.rpm` — Red Hat
- `bash-5.1.8-9.el9.x86_64.rpm` — Red Hat
- `coreutils-8.32-34.el9.x86_64.rpm` — Red Hat
- `fedora-curl-8.2.1-fc39.x86_64.rpm` — Fedora, vendor slug `fedora`
- `rocky-linux-release-9.3-1.1.el9.rocky.x86_64.rpm` — Rocky, vendor slug `rocky`
- `malformed-truncated-header.rpm` — synthetic (generated at test time; not committed)
- `srpm-openssl-3.0.7-28.el9.src.rpm` — Red Hat SRPM (for `arch=src` coverage)

Regeneration script: `refresh.sh` (checked in; idempotent; NOT run in CI).
