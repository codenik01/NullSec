#!/usr/bin/env bash
# Drops package names that don't exist in the repo so one typo can't kill a 30-minute build.
# usage: prune-packages.sh <package-lists-dir>   (must run on Kali, native arch)
set -euo pipefail
for f in "$1"/*.list.chroot; do
  tmp=$(mktemp)
  while IFS= read -r line; do
    case "$line" in ''|\#*) echo "$line" >> "$tmp"; continue;; esac
    if apt-cache show "$line" >/dev/null 2>&1; then echo "$line" >> "$tmp"; else echo "pruned (not in repo): $line" >&2; fi
  done < "$f"
  mv "$tmp" "$f"
done
