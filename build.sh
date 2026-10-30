#!/usr/bin/env bash
# usage: ./build.sh [amd64|arm64]    (builds natively for the machine's own arch; CI builds both)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ARCH="${1:-$(dpkg --print-architecture)}"
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO=sudo
$SUDO apt-get update
$SUDO apt-get install -y git live-build simple-cdd cdebootstrap curl devscripts
WORK="$HERE/build-$ARCH"; rm -rf "$WORK"; mkdir -p "$WORK"
git clone --depth 1 https://gitlab.com/kalilinux/build-scripts/live-build-config.git "$WORK/lbc"
cp -r "$HERE/kali-config/variant-nullsec" "$WORK/lbc/kali-config/"
if grep -q '^ID=kali' /etc/os-release; then
  "$HERE/prune-packages.sh" "$WORK/lbc/kali-config/variant-nullsec/package-lists"
else
  echo "WARNING: not on Kali, cannot validate package names (build may fail on a typo)"
fi
cd "$WORK/lbc"
./build.sh --arch "$ARCH" --variant nullsec --verbose
mkdir -p "$HERE/out"; cp images/*.iso "$HERE/out/"
echo "ISO ready in $HERE/out"
