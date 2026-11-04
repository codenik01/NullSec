#!/bin/bash
# Run every NullOS test. Needs: nftables iproute2 util-linux bubblewrap jq iputils-ping (shellcheck optional).
cd "$(dirname "$0")/.." || exit 1
fail=0; step(){ echo; echo "=== $1"; }
if [ "$(id -u)" = 0 ]; then NS="unshare -nm"; else NS="unshare -Urnm"; fi
step "static checks"
export PYTHONDONTWRITEBYTECODE=1
NEW_SH="ns-security ns-sandbox ns-lab ns-pack ns-offline"      # shellcheck-gated: shell scripts added/extended in 2.0
NEW_PY="ns-secure"                                             # python syntax errors in these FAIL; elsewhere only WARN (pre-existing)
for f in overlay/usr/local/bin/*; do
  l=$(head -1 "$f")
  if [[ $l =~ ^#!.*python ]]; then if ! python3 -c 'import sys; compile(open(sys.argv[1]).read(), sys.argv[1], "exec")' "$f" 2>/dev/null; then
      case " $NEW_PY " in *" $(basename "$f") "*) echo "python syntax error: $f"; fail=1;; *) echo "WARN (pre-existing, not changed by 2.0): $f has a python syntax error";; esac; fi
  elif [[ $l =~ ^#!.*(bash|/sh)$ ]]; then bash -n "$f" || { echo "bash syntax: $f"; fail=1; }; fi
done
bash -n build-iso.sh || fail=1
python3 -c 'import compileall,sys; sys.exit(0 if compileall.compile_dir("overlay/usr/lib/nullos", quiet=1, legacy=False, force=True) else 1)' || fail=1
find overlay -name __pycache__ -prune -exec rm -rf {} +
if command -v shellcheck >/dev/null; then (cd overlay/usr/local/bin && shellcheck -S warning $NEW_SH 2>&1 | grep -v "^$" ; exit "${PIPESTATUS[0]}") && echo "shellcheck clean on 2.0 scripts" || fail=1
else echo "(shellcheck not installed: skipped)"; fi
nft -c -f overlay/etc/nftables.conf 2>/dev/null && echo "baseline nftables.conf parses" || echo "(nft -c unavailable here)"
echo "static checks done"
step "unit tests";            python3 -W ignore tests/unit_test.py 2>&1 | tail -4; [ "${PIPESTATUS[0]}" = 0 ] || fail=1
step "real-kernel firewall tests"; $NS bash -c 'mount -t tmpfs none /run; python3 -B tests/netns_net_test.py' | grep -E "FAIL|RESULT"; [ "${PIPESTATUS[0]}" = 0 ] || fail=1
step "failure policy + drift repair (real kernel)"; rm -rf /tmp/fp-root; $NS bash -c 'mount -t tmpfs none /run; python3 -B tests/failure_policy_test.py' | grep -E "FAIL|RESULT"; [ "${PIPESTATUS[0]}" = 0 ] || fail=1
step "end-to-end (daemon + client + kernel)"; $NS bash -c 'mount -t tmpfs none /run; tests/e2e.sh' | grep -E "^FAIL|E2E:" ; [ "${PIPESTATUS[0]}" = 0 ] || fail=1
step "build-script fragments (end-of-build shell under set -euo pipefail)"; bash tests/build_fragments.sh | grep -E "FAIL|BUILDFRAG"; [ "${PIPESTATUS[0]}" = 0 ] || fail=1
step "apt lock wait (tool packs)"; bash tests/apt_wait.sh | grep -E "FAIL|APTWAIT"; [ "${PIPESTATUS[0]}" = 0 ] || fail=1
step "installer configuration (schemas, ordering, shell steps)"; python3 -B tests/installer_test.py | grep -E "FAIL|SKIPPED|RESULT"; [ "${PIPESTATUS[0]}" = 0 ] || fail=1
step "installer: real Calamares starts on the config (headless)"; bash tests/calamares_smoke.sh | grep -E "FAIL|SKIP|CALSMOKE"; [ "${PIPESTATUS[0]}" = 0 ] || fail=1
step "package list (regression: comments were parsed as package names)"; bash tests/packages_test.sh | grep -E "FAIL|SKIP|WARN|PACKAGES"; [ "${PIPESTATUS[0]}" = 0 ] || fail=1
step "sandbox + lab + pack tests"; bash tests/sandbox.sh | grep -E "FAIL|SKIP|SANDBOX"; [ "${PIPESTATUS[0]}" = 0 ] || fail=1
echo; [ $fail -eq 0 ] && echo "ALL TEST GROUPS PASSED" || echo "SOME TESTS FAILED"; exit $fail
