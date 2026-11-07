#!/bin/bash
# Regression: Ubuntu published linux-image-generic -> 6.8.0-149 before 149's modules existed; the build died with
# "linux-modules-extra-6.8.0-149-generic but it is not installable". The kernel guard must pin the newest COMPLETE kernel.
HERE=$(cd "$(dirname "$0")/.." && pwd); T=$(mktemp -d); trap 'rm -rf "$T"' EXIT; f=0
ok(){ if [ "$2" = 0 ]; then echo "PASS  $1"; else echo "FAIL  $1"; f=$((f+1)); fi; }
python3 - "$HERE/build-iso.sh" "$T/guard.sh" <<'PY'
import sys
s=open(sys.argv[1]).read(); a=s.index("# --- kernel guard begin ---"); b=s.index("# --- kernel guard end ---")
open(sys.argv[2],"w").write(s[a:b])
PY
[ -s "$T/guard.sh" ]; ok "kernel guard block found in build-iso.sh" $?
mkdir -p "$T/bin"
cat > "$T/bin/apt-cache" <<'STUB'
#!/bin/bash
# fixture lines: "<package> <candidate|none>"
case "$1" in
  pkgnames) awk -v p="$2" 'index($1,p)==1{print $1}' "$FIX";;
  policy) c=$(awk -v n="$2" '$1==n{print $2}' "$FIX"); echo "$2:"; echo "  Installed: (none)"; echo "  Candidate: ${c:-(none)}";;
esac
STUB
cat > "$T/bin/apt-get" <<'STUB'
#!/bin/bash
[ "$1" = -s ] || exit 0; shift; shift   # -s install
for a in "$@"; do
  if [ "$a" = linux-image-generic ]; then [ "${META_OK:-0}" = 1 ] || exit 100; continue; fi
  c=$(awk -v n="$a" '$1==n{print $2}' "$FIX"); [ -n "$c" ] && [ "$c" != none ] || exit 100
done; exit 0
STUB
chmod +x "$T/bin/"*
fix(){ : > "$T/fix"; echo "linux-image-generic ${SERIES:-6.8.0-149.149}" >> "$T/fix"; for v in "$@"; do n=${v%%:*}; st=${v##*:}; echo "linux-image-$n-generic 1.0" >> "$T/fix"
  if [ "$st" = full ]; then echo "linux-modules-$n-generic 1.0" >> "$T/fix"; echo "linux-modules-extra-$n-generic 1.0" >> "$T/fix"
  else echo "linux-modules-$n-generic none" >> "$T/fix"; echo "linux-modules-extra-$n-generic none" >> "$T/fix"; fi; done; }
run(){ # $1=META_OK ; prints guard output; leaves $T/w/pkgs.ok
  rm -rf "$T/w"; mkdir -p "$T/w"; printf 'bash\ncurl\nlinux-image-generic\ninitramfs-tools\n' > "$T/w/pkgs.ok"
  FIX="$T/fix" META_OK=$1 PATH="$T/bin:$PATH" W="$T/w" R="$T/r" bash -c 'set -euo pipefail; chroot(){ shift; "$@"; }; source '"$T/guard.sh"'; echo "PINNED=[$KERNEL_PINNED]"' 2>&1; }
# 1. exactly the situation in the CI log: newest kernel (149) has no modules, meta not installable
fix 6.8.0-145:full 6.8.0-147:full 6.8.0-149:broken; out=$(run 0); rc=$?
echo "$out" | grep -q "PINNED=\[6.8.0-147\]"; ok "broken newest kernel (149): pins the newest COMPLETE one (147)" $?
grep -qx "linux-modules-extra-6.8.0-147-generic" "$T/w/pkgs.ok" && grep -qx "linux-image-6.8.0-147-generic" "$T/w/pkgs.ok" && grep -qx "linux-modules-6.8.0-147-generic" "$T/w/pkgs.ok"; ok "…image, modules and modules-extra of 147 are requested" $?
! grep -qx "linux-image-generic" "$T/w/pkgs.ok" && ! grep -q "149" "$T/w/pkgs.ok"; ok "…the unusable metapackage and kernel 149 are NOT requested" $?
grep -qx bash "$T/w/pkgs.ok" && grep -qx curl "$T/w/pkgs.ok" && grep -qx initramfs-tools "$T/w/pkgs.ok"; ok "…every other package is untouched" $?
echo "$out" | grep -q "WARN: linux-image-generic is not installable"; ok "…and the build says why, loudly" $?
# 2. healthy archive: nothing changes
fix 6.8.0-147:full 6.8.0-149:full; out=$(run 1)
echo "$out" | grep -q "PINNED=\[\]" && [ "$(cat "$T/w/pkgs.ok")" = "$(printf 'bash\ncurl\nlinux-image-generic\ninitramfs-tools')" ]; ok "healthy archive: the guard does nothing (normal linux-image-generic path)" $?
# 3. metapackage broken for another reason but the newest kernel is complete: pin that one
fix 6.8.0-147:full 6.8.0-149:full; out=$(run 0); echo "$out" | grep -q "PINNED=\[6.8.0-149\]"; ok "newest kernel complete but meta unusable: pins the newest (149)" $?
# 4. no complete kernel at all: fail early with a clear message instead of a confusing apt error
fix 6.8.0-147:broken 6.8.0-149:broken; out=$(run 0); echo "$out" | grep -q "FATAL: the archive has no complete generic kernel"; ok "no complete kernel anywhere: stops with a clear FATAL" $?
# 4b. THE TRAP found on the real archive: a newer, complete kernel of a DIFFERENT series (HWE 6.17) must never be chosen
fix 6.8.0-147:full 6.8.0-149:broken 6.17.0-42:full; out=$(run 0); echo "$out" | grep -q "PINNED=\[6.8.0-147\]"; ok "a newer complete kernel of another series (6.17 HWE) is NOT chosen; stays on 6.8.0" $?
! grep -q "6.17" "$T/w/pkgs.ok"; ok "…and no 6.17 package is requested" $?
SERIES=6.17.0-42.50 fix 6.8.0-147:full 6.17.0-41:full 6.17.0-42:broken; out=$(run 0); echo "$out" | grep -q "PINNED=\[6.17.0-41\]"; ok "if the metapackage's series IS 6.17, it stays on 6.17" $?
# 5. version ordering is numeric (6.8.0-1000 > 6.8.0-999 > 6.8.0-99)
fix 6.8.0-99:full 6.8.0-999:full 6.8.0-1000:broken; out=$(run 0); echo "$out" | grep -q "PINNED=\[6.8.0-999\]"; ok "versions are compared numerically, not as text" $?
# 6. the REAL archive as it is on this machine: whatever the state, the resulting kernel request must be installable
if command -v apt-cache >/dev/null && [ -n "$(ls /var/lib/apt/lists/*Packages* 2>/dev/null | head -1)" ]; then
  rm -rf "$T/w"; mkdir -p "$T/w"; printf 'bash\nlinux-image-generic\n' > "$T/w/pkgs.ok"
  out=$(W="$T/w" R="$T/r" bash -c 'set -euo pipefail; chroot(){ shift; "$@"; }; source '"$T/guard.sh"'; echo "PINNED=[$KERNEL_PINNED]"' 2>&1); echo "   real archive: $(echo "$out" | grep -E 'PINNED|WARN|FATAL' | tr '\n' ' ' | cut -c1-150)"
  apt-get -s install $(grep -E '^linux-' "$T/w/pkgs.ok") >/dev/null 2>&1; ok "REAL archive: the kernel packages the build would request are installable right now" $?
else echo "SKIP  no apt index: real-archive check skipped"; fi
[ $f -eq 0 ] && echo "KERNELGUARD: ALL PASSED" || echo "KERNELGUARD: $f FAILED"; exit $f
