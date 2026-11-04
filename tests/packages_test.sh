#!/bin/bash
# Regression: a comment in packages.txt was treated as ~20 package names ('and', 'the', ... are real packages) and broke the build.
HERE=$(cd "$(dirname "$0")/.." && pwd); f=0; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
ok(){ if [ "$2" = 0 ]; then echo "PASS  $1"; else echo "FAIL  $1"; f=$((f+1)); fi; }
# the exact token expression the build uses
expr=$(grep -m1 'for p in \$(' "$HERE/build-iso.sh" | sed -E 's/.*for p in (\$\(.*\)); do.*/\1/')
tokens(){ HERE=$1 bash -c "for p in $expr; do echo \$p; done"; }
printf 'bash  # trailing comment words and symbols ---\n# full-line comment (Calamares) needs to install it\ncurl\n' > "$T/packages.txt"
[ "$(tokens "$T")" = "$(printf 'bash\ncurl')" ]; ok "the build ignores # comments (only real tokens survive)" $?
bad=$(tokens "$HERE" | grep -vE '^[a-z0-9][a-z0-9+.-]+$'); [ -z "$bad" ]; ok "every package token is a valid Debian package name ${bad:+(bad: $bad)}" $?
d=$(tokens "$HERE" | sort | uniq -d | tr '\n' ' '); [ -z "$d" ] || echo "WARN  duplicate package entries (harmless to apt): $d"
grep -q '#' "$HERE/packages.txt"; [ $? -ne 0 ]; ok "packages.txt contains no comment characters at all (belt and braces)" $?
if command -v apt-cache >/dev/null && [ -n "$(ls /var/lib/apt/lists/*Packages* 2>/dev/null | head -1)" ]; then
  # tokens unknown to the amd64 archive must be a known arch-specific name, never a stray word
  allow='^(grub-efi-arm64-bin|grub-efi-arm64-signed)$'
  unk=$(tokens "$HERE" | while read -r p; do apt-cache policy "$p" 2>/dev/null | awk '/Candidate/ && $2!="(none)"{f=1} END{exit !f}' || echo "$p"; done | grep -vE "$allow")
  [ -z "$unk" ]; ok "every package exists in the Ubuntu archive (amd64) ${unk:+(unknown: $(echo $unk | tr '\n' ' '))}" $?
else echo "SKIP  no apt index here: archive existence check skipped"; fi
[ $f -eq 0 ] && echo "PACKAGES: ALL PASSED" || echo "PACKAGES: $f FAILED"; exit $f
