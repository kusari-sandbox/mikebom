# PE binary fixtures — milestone 004 US2

Expected fixture bodies (land via T044 + T005 rebuild.sh):

- `dyn-linked-win64.exe` — Rust cross-compile (`x86_64-pc-windows-gnu`) linking against `kernel32` and `advapi32`; regular IMPORT table populated.
- `with-delay-load.exe` — uses `#[link(kind = "dylib")]` + MinGW `--delay-load-dll` so both IMPORT + Delay-Load IMPORT directories are populated.
- `static-stripped.exe` — Rust release build with `lto = "fat"` and post-compile `strip`; four-signal stripped detection positive.
- `rebuild.sh` — helper that invokes `cargo build --release --target x86_64-pc-windows-gnu`. Checked in; runs locally only. The `.exe` outputs are committed so CI does not need a cross-compile toolchain.
