# ELF binary fixtures — milestone 004 US2

Expected fixture bodies (land via T042):

- `dyn-linked-busybox` — dynamically-linked ELF with ≥3 `DT_NEEDED` entries.
- `with-note-package-rpm` — ELF carrying a `.note.package` section with `{"type":"rpm","name":"curl","version":"8.2.1","distro":"Fedora","architecture":"x86_64"}`.
- `with-note-package-alpm` — ELF carrying a `.note.package` section with `{"type":"alpm",...}`.
- `static-stripped` — statically-linked, symbol-table-free ELF (no evidence beyond file-level).
- `openssl-embed-3.0.11` — tiny Rust binary that embeds the OpenSSL 3.0.11 ID string as a `&'static [u8]` in `.rodata`.
- `false-positive-control-rust-bin` — Rust binary that mentions "OpenSSL" only in a `.comment` section (SC-005 control).
- `inject_note_package.sh` — helper that uses `objcopy --add-section .note.package=<payload.bin>` to synthesise the `.note.package` fixtures above.
