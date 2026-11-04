#!/bin/bash
# Regression: tool-pack installs failed with "could not get lock" when a background apt job ran at boot.
HERE=$(cd "$(dirname "$0")/.." && pwd); T=$(mktemp -d); trap 'kill %1 2>/dev/null; rm -rf "$T"' EXIT; f=0
ok(){ if [ "$2" = 0 ]; then echo "PASS  $1"; else echo "FAIL  $1"; f=$((f+1)); fi; }
sed -n '/^apt_wait()/,/^}/p' "$HERE/overlay/usr/local/bin/ns-install" > "$T/fn.sh"
cp /bin/sleep "$T/apt-get"                                    # a process whose name is 'apt-get', like a running updater
"$T/apt-get" 5 & sleep 0.3
start=$(date +%s); out=$(bash -c "source $T/fn.sh; apt_wait" 2>&1); rc=$?; el=$(( $(date +%s) - start ))
[ $rc = 0 ] && [ $el -ge 3 ] && echo "$out" | grep -q "waiting for another package"; ok "waits while an 'apt-get' process runs, then proceeds (waited ${el}s)" $?
start=$(date +%s); bash -c "source $T/fn.sh; apt_wait"; el=$(( $(date +%s) - start )); [ $el -le 1 ]; ok "returns immediately when nothing is running" $?
grep -q "DPkg::Lock::Timeout=300" "$HERE/overlay/usr/local/bin/ns-install"; ok "apt calls also carry a dpkg lock timeout" $?
n=$(grep -c "apt-get update" "$HERE/overlay/usr/local/bin/ns-install"); [ "$n" -le 1 ]; ok "package index is updated in ONE place (once per session), not per tool" $?
[ $f -eq 0 ] && echo "APTWAIT: ALL PASSED" || echo "APTWAIT: $f FAILED"; exit $f
