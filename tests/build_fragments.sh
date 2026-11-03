#!/bin/bash
# The end-of-build shell fragments in build-iso.sh run under `set -euo pipefail`, in CI, after a 5-minute build.
# A bug there only shows up at the very end, so run them here against fake inputs, including a failing `du`.
HERE=$(cd "$(dirname "$0")/.." && pwd); T=$(mktemp -d); trap 'rm -rf "$T"' EXIT; f=0
python3 - "$HERE/build-iso.sh" "$T" <<'PY'
import sys
s = open(sys.argv[1]).read(); t = sys.argv[2]
a = s.index("# measured AFTER cleanup"); b = s.index('echo "== 5/6 compress"'); open(t + "/frag1.sh", "w").write(s[a:b])
a = s.index('ISO_BYTES=$(stat -c %s'); b = s.index("\nPY\n", s.index('print("release metadata written')) + 4; open(t + "/frag2.sh", "w").write(s[a:b])
PY
mkdir -p "$T/out" "$T/rootfs/var/lib/dpkg" "$T/iso/casper"; cp /var/lib/dpkg/status "$T/rootfs/var/lib/dpkg/" 2>/dev/null || : > "$T/rootfs/var/lib/dpkg/status"
ok(){ if [ "$2" = 0 ]; then echo "PASS  $1"; else echo "FAIL  $1"; f=$((f+1)); fi; }
bash -c "set -euo pipefail; R=$T/rootfs; OUT=$T/out; ARCH=amd64; source $T/frag1.sh"; ok "size+manifest lines run clean" $?
bash -c "set -euo pipefail; du(){ return 1; }; R=$T/rootfs; OUT=$T/out; ARCH=amd64; source $T/frag1.sh; [ \"\$INSTALLED_BYTES\" = 0 ]"; ok "a failing du cannot kill the build (the CI failure)" $?
head -c 2000000 /dev/zero > "$T/out/nullos-amd64.iso"; head -c 50000 /dev/zero > "$T/iso/casper/filesystem.squashfs"
bash -c "set -euo pipefail; HERE=$HERE; ARCH=amd64; OUT=$T/out; ISO=$T/iso; INSTALLED_BYTES=1; source $T/frag2.sh" >/dev/null; ok "release-metadata block runs clean" $?
python3 -c "import json;d=json.load(open('$T/out/nullos-amd64.release.json'));assert d['iso_bytes']==2000000 and len(d['iso_sha256'])==64"; ok "release.json has exact size + sha256" $?
grep -n 'du -sb' "$HERE/build-iso.sh" | grep -v -- '--one-file-system' >/dev/null && { echo "FAIL  a 'du -sb' without --one-file-system exists in build-iso.sh"; f=$((f+1)); } || echo "PASS  every du in build-iso.sh is --one-file-system"
[ $f -eq 0 ] && echo "BUILDFRAG: ALL PASSED" || echo "BUILDFRAG: $f FAILED"; exit $f
