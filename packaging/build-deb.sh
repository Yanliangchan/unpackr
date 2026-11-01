#!/usr/bin/env bash
# Build unpackr_<version>_<arch>.deb for amd64 and arm64 from source.
# Usage: packaging/build-deb.sh VERSION ARCH   (ARCH: amd64|arm64)
set -euo pipefail
ver="${1:?version}"; arch="${2:?arch}"
case "$arch" in amd64|arm64) ;; *) echo "unsupported arch $arch" >&2; exit 2;; esac
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/dist"; stage="$(mktemp -d)"; trap 'rm -rf "$stage"' EXIT
epoch="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct 2>/dev/null || date +%s)}"
date_iso="$(date -u -d "@$epoch" +%Y-%m-%d)"
mkdir -p "$out" "$stage/usr/bin" "$stage/usr/share/man/man1" "$stage/DEBIAN" \
  "$stage/usr/share/bash-completion/completions" "$stage/usr/share/zsh/vendor-completions" \
  "$stage/usr/share/fish/vendor_completions.d" "$stage/usr/share/doc/unpackr"
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath \
  -ldflags "-s -w -X github.com/Yanliangchan/unpackr/internal/version.Version=$ver" -o "$stage/usr/bin/unpackr" ./cmd/unpackr)
# Generated assets come from a host-native build (the binary may be arm64).
gen="$(mktemp -d)"
(cd "$root" && CGO_ENABLED=0 go run -ldflags "-X github.com/Yanliangchan/unpackr/internal/version.Version=$ver" ./cmd/unpackr gen-packaging --dir "$gen" --date "$date_iso")
gzip -9n -c "$gen/unpackr.1" > "$stage/usr/share/man/man1/unpackr.1.gz"
install -m0644 "$gen/unpackr.bash" "$stage/usr/share/bash-completion/completions/unpackr"
install -m0644 "$gen/_unpackr" "$stage/usr/share/zsh/vendor-completions/_unpackr"
install -m0644 "$gen/unpackr.fish" "$stage/usr/share/fish/vendor_completions.d/unpackr.fish"
rm -rf "$gen"
install -m0644 "$root/LICENSE" "$stage/usr/share/doc/unpackr/copyright"
install -m0644 "$root/README.md" "$stage/usr/share/doc/unpackr/README.md"
install -m0644 "$root/docs/THIRD-PARTY.md" "$stage/usr/share/doc/unpackr/THIRD-PARTY.md"
size=$(du -sk "$stage/usr" | cut -f1)
sed -e "s/@VERSION@/$ver/" -e "s/@ARCH@/$arch/" -e "s/@SIZE@/$size/" "$root/packaging/debian/control" > "$stage/DEBIAN/control"
find "$stage" -exec touch -h -d "@$epoch" {} +
find "$stage" -type d -exec chmod 0755 {} +
chmod 0755 "$stage/usr/bin/unpackr"
dpkg-deb --root-owner-group -Zxz --build "$stage" "$out/unpackr_${ver}_${arch}.deb" >/dev/null
echo "$out/unpackr_${ver}_${arch}.deb"
