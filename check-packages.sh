#!/usr/bin/env bash
# report-only version of prune
for f in "$(dirname "$0")"/kali-config/variant-nullsec/package-lists/*.list.chroot; do
  grep -vE '^\s*(#|$)' "$f" | while read -r p; do apt-cache show "$p" >/dev/null 2>&1 || echo "MISSING: $p"; done
done
