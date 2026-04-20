#!/usr/bin/env bash
# Debian ecosystem demo.
#
# Why curl instead of apt-get install? On Debian bookworm apt's `https`
# transport is linked against GnuTLS, not OpenSSL. Our uprobes hook
# `SSL_read`/`SSL_write` on libssl, so the TLS plaintext of an apt https
# download never reaches userspace. curl is linked against OpenSSL — the
# very library mikebom attaches to — and its HTTP requests flow right
# through our probes. We still resolve exactly the same URI set apt would
# use by asking apt for its download plan with `--print-uris`; only the
# transport is swapped.
set -euo pipefail

WORK="${OUT_DIR:-$(mktemp -d)}"
mkdir -p "$WORK"
echo "== debian demo ==" 1>&2
echo "workdir: $WORK" 1>&2

MIKEBOM="${MIKEBOM_BIN:-/mikebom/target/release/mikebom}"
DL_DIR="$WORK/debs"
mkdir -p "$DL_DIR"

PACKAGES=(ripgrep jq fd-find make curl)

# Apt may need refreshed lists; cheap if already current.
apt-get update -qq >/dev/null

echo ">> resolve URIs apt would download" 1>&2
# --print-uris emits lines like: 'http://deb.debian.org/debian/pool/.../foo.deb' foo.deb <size> SHA256:<hash>
mapfile -t URIS < <(apt-get install --print-uris --yes --no-install-recommends "${PACKAGES[@]}" \
  | awk -F"'" "/^'http/ {print \$2}" \
  | sed "s#^http://#https://#")

if [[ ${#URIS[@]} -eq 0 ]]; then
  echo "!! apt-get --print-uris produced no URLs — system may already have all packages" 1>&2
  echo "   (try a broader package set or a pristine container)" 1>&2
  exit 5
fi
echo "   ${#URIS[@]} package URIs to download" 1>&2

echo ">> trace curl downloads via mikebom" 1>&2
# Sequential curl calls — separate TLS session per URL — so each HTTP
# request becomes its own Connection in the attestation. HTTP/1.1 keep-
# alive on `--remote-name-all` collapses 5 requests into one TLS session,
# which our aggregator's per-ssl-pointer keying has to split back out.
# Individual curl invocations sidestep that entirely.
cd_cmd="cd '$DL_DIR' && for u in ${URIS[*]}; do curl --http1.1 -sSL -O \"\$u\"; done"
RUST_LOG=info "$MIKEBOM" trace run \
  --attestation-output "$WORK/mikebom.attestation.json" \
  --sbom-output        "$WORK/mikebom.cdx.json" \
  --trace-children \
  --skip-purl-validation \
  --no-enrich \
  --timeout 300 \
  --artifact-dir "$DL_DIR" \
  -- bash -c "$cd_cmd"

echo ">> build ground truth from downloaded .debs" 1>&2
: > "$WORK/truth.txt"
for f in "$DL_DIR"/*.deb; do
  [[ -e "$f" ]] || continue
  base=$(basename "$f" .deb)
  name=${base%%_*}
  rest=${base#*_}
  version=${rest%_*}
  arch=${rest##*_}
  version=${version//%3a/:}
  printf 'pkg:deb/debian/%s@%s?arch=%s\n' "$name" "$version" "$arch" >> "$WORK/truth.txt"
done
echo "   $(wc -l < "$WORK/truth.txt") packages in truth set" 1>&2
if [[ ! -s "$WORK/truth.txt" ]]; then
  echo "!! no .deb files landed in $DL_DIR — curl must have failed" 1>&2
  exit 6
fi

echo ">> syft scan of downloaded .debs" 1>&2
syft "dir:$DL_DIR" -o cyclonedx-json="$WORK/syft.cdx.json" -q || {
  echo "!! syft failed" 1>&2; exit 3;
}

echo ">> trivy scan of downloaded .debs" 1>&2
trivy fs --format cyclonedx --output "$WORK/trivy.cdx.json" --quiet "$DL_DIR" || {
  echo "!! trivy failed" 1>&2; exit 4;
}

echo ">> compare" 1>&2
"$MIKEBOM" sbom compare \
  --mikebom "$WORK/mikebom.cdx.json" \
  --syft    "$WORK/syft.cdx.json" \
  --trivy   "$WORK/trivy.cdx.json" \
  --truth   "$WORK/truth.txt" \
  --ecosystem deb \
  --output  "$WORK/report.md" \
  --json

echo "== report =="
cat "$WORK/report.md"
