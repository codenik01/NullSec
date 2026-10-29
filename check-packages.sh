#!/usr/bin/env bash
# Run on Kali: lists packages in the list that don't exist in the repo.
grep -vE '^\s*(#|$)' "$(dirname "$0")/kali-config/variant-nullsec/package-lists/nullsec.list.chroot" |
while read -r p; do apt-cache show "$p" >/dev/null 2>&1 || echo "MISSING: $p"; done
