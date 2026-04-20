# BDB rpmdb fixtures — milestone 004 US4

Expected fixture bodies (land via T066):

- `amzn2-minimal/var/lib/rpm/Packages` — BDB-backed rpmdb with ≥20 synthetic records; `etc/os-release` carries `ID=amzn`.
- `centos7-minimal/var/lib/rpm/Packages` — similar, `ID=centos`.
- `transitional-both/` — contains BOTH `var/lib/rpm/rpmdb.sqlite` (reused from milestone 003) AND `var/lib/rpm/Packages`. Used to verify `sqlite wins` conflict rule (FR-019c).
- `malformed-bdb/var/lib/rpm/Packages` — first page corrupted. Used to verify fail-graceful contract.
- `generate_bdb.py` — Python helper (checked in) that emits BDB Packages files from a JSON row dump.
