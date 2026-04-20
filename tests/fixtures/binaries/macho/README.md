# Mach-O binary fixtures — milestone 004 US2

Expected fixture bodies (land via T043):

- `dyn-linked-aarch64` — aarch64 Mach-O dylib with `LC_LOAD_DYLIB` entries for `/usr/lib/libSystem.B.dylib` and `@rpath/libssl.48.dylib`.
- `fat-universal` — fat (universal) binary with x86_64 + aarch64 slices; install-names invariant across slices.
- `rebuild.sh` — helper using `rustc --target aarch64-apple-darwin ... ; lipo -create ...`. Checked in; idempotent.
