#!/usr/bin/env bash
# NULLSEC OS builder. Run on Kali/Debian/Ubuntu, ~30GB free, internet.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$HERE/build"
sudo apt-get update
sudo apt-get install -y git live-build simple-cdd cdebootstrap curl devscripts
rm -rf "$WORK"; mkdir -p "$WORK"
git clone --depth 1 https://gitlab.com/kalilinux/build-scripts/live-build-config.git "$WORK/lbc"
cp -r "$HERE/kali-config/variant-nullsec" "$WORK/lbc/kali-config/"
cd "$WORK/lbc"
./build.sh --variant nullsec --verbose
mkdir -p "$HERE/out"; cp images/*.iso "$HERE/out/"
echo "ISO ready in $HERE/out"
