#!/usr/bin/env sh
# Install UNPACKR from a release directory containing unpackr_<ver>_<arch>.deb
# and SHA256SUMS. Usage: ./install.sh [DIR]   (default: current directory)
set -eu
dir="${1:-.}"
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
deb=$(ls "$dir"/unpackr_*_"$arch".deb 2>/dev/null | head -n1 || true)
[ -n "$deb" ] || { echo "no unpackr_*_${arch}.deb in $dir" >&2; exit 1; }
[ -f "$dir/SHA256SUMS" ] || { echo "SHA256SUMS missing; refusing to install unverified package" >&2; exit 1; }
(cd "$dir" && grep " $(basename "$deb")\$" SHA256SUMS | sha256sum -c -) || { echo "checksum verification failed" >&2; exit 1; }
sudo=""; [ "$(id -u)" -eq 0 ] || sudo=sudo
$sudo dpkg -i "$deb"
echo "installed: $(unpackr --version)"
