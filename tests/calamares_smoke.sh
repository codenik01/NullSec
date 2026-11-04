#!/bin/bash
# Starts the REAL Calamares (headless) on the NullOS installer configuration and checks it loads branding and every
# module without errors or deprecated keys. Skips (never fails) when Calamares is not installed or /etc/calamares is in use.
HERE=$(cd "$(dirname "$0")/.." && pwd); f=0
ok(){ if [ "$2" = 0 ]; then echo "PASS  $1"; else echo "FAIL  $1"; f=$((f+1)); fi; }
command -v calamares >/dev/null || { echo "SKIP  calamares not installed"; echo "CALSMOKE: SKIPPED"; exit 0; }
[ "$(id -u)" = 0 ] || { echo "SKIP  needs root to place /etc/calamares"; echo "CALSMOKE: SKIPPED"; exit 0; }
[ -e /etc/calamares ] && { echo "SKIP  /etc/calamares already exists; not touching it"; echo "CALSMOKE: SKIPPED"; exit 0; }
cp -r "$HERE/overlay/etc/calamares" /etc/calamares; trap 'rm -rf /etc/calamares' EXIT
L=$(mktemp); (cd /tmp && QT_QPA_PLATFORM=offscreen timeout 20 calamares -d >"$L" 2>&1)
[ "$(grep -c 'ERROR' "$L")" = 0 ]; ok "Calamares starts on the NullOS config with 0 ERROR lines" $?
grep -q 'Loaded branding component "nullos"' "$L"; ok "NullOS branding loads" $?
[ "$(grep -c 'ViewModule.*loading complete' "$L")" -ge 6 ]; ok "all 6 interactive pages load (welcome, locale, keyboard, partition, users, summary)" $?
grep -q 'CppJobModule "shellprocess@prepare" loading complete' "$L"; ok "the NullOS prepare step (shellprocess@prepare) loads" $?
[ "$(grep -c 'deprecated' "$L")" = 0 ]; ok "no deprecated configuration keys" $?
rm -f "$L"; [ $f -eq 0 ] && echo "CALSMOKE: ALL PASSED" || echo "CALSMOKE: $f FAILED"; exit $f
