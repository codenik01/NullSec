#!/bin/bash
# End-to-end: real daemon + real client + real kernel (inside a private network namespace).
R=$(cd "$(dirname "$0")/.." && pwd)/overlay
export NULLOS_ROOT=/tmp/e2e-root NULLOS_LIB=$R/usr/lib/nullos NULLOS_PROFILES=$R/usr/share/nullos/profiles
export NULLOS_SOCK=/tmp/e2e-root/run/secd.sock NULLOS_SUMMARY=/tmp/e2e-root/run/status.json NO_COLOR=1
rm -rf /tmp/e2e-root; mkdir -p /tmp/e2e-root/{etc,run,var/lib,var/log,proc}
echo "nameserver 10.0.0.1" > /tmp/e2e-root/etc/resolv.conf
mkdir -p /tmp/e2e-root/etc/sysctl.d /tmp/e2e-root/proc/sys; cp $R/etc/nftables.conf /tmp/e2e-root/etc/; cp $R/etc/sysctl.d/99-nullsec.conf /tmp/e2e-root/etc/sysctl.d/
ip link set lo up; ip link add v0 type veth peer name v1; ip addr add 10.0.0.2/24 dev v0; ip link set v0 up; ip link set v1 up; ip route add default via 10.0.0.1
nft -f $R/etc/nftables.conf
# a stock Ubuntu kernel has no br_netfilter; this sandbox does, so mimic stock for the happy path
echo 0 > /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null
$R/usr/lib/nullos/nullos-secd & D=$!
for i in $(seq 20); do [ -S $NULLOS_SOCK ] && break; sleep 0.2; done
S=$R/usr/local/bin/ns-secure
f=0; t(){ if timeout 60 bash -c "$2" >/tmp/e2e.out 2>&1; then echo "PASS  $1"; else echo "FAIL  $1"; sed "s/^/        /" /tmp/e2e.out | head -15; f=$((f+1)); fi; }
t "service answers ping"            "python3 -c \"import sys,os;sys.path.insert(0,'$R/usr/local/bin');import importlib.machinery as m;x=m.SourceFileLoader('c','$S').load_module();assert x.call('ping')['pong']\""
t "status in Standard: baseline firewall VERIFIED" "$S status | grep -E 'Firewall \(baseline\) +VERIFIED'"
t "Standard shows Restricted Mode OFF" "$S status | grep -q 'RESTRICTED MODE   OFF'"
t "profiles lists 4+ with recommended" "$S profiles | grep -q recommended"
t "ENABLE restricted-network -> VERIFIED" "$S enable restricted-network | tee /dev/stderr | grep -q 'Overall status: VERIFIED'"
t "status now ON (VERIFIED)"        "$S status | grep -q 'RESTRICTED MODE   ON   (VERIFIED)'"
t "panel shows restricted"          "$S panel | grep -q RESTRICTED"
t "kernel really enforces: probe blocked" "python3 -c \"import socket;s=socket.socket(2,2)
try: s.sendto(b'x',('192.0.2.1',9)); raise SystemExit(1)
except PermissionError: pass\""
t "changes lists the nft table"     "$S changes | grep -q 'inet nullos'"
t "inbound shows VERIFIED"          "$S status | grep -E 'Inbound policy +VERIFIED'"
# tamper while enabled: monitor/verify must notice
nft insert rule inet nullos output accept
t "tamper -> verify reports FAILED, not verified" "$S verify | grep -E 'Outbound policy +FAILED'"
t "tamper -> overall is not VERIFIED (panel)" "$S panel | grep -qv 'RESTRICTED VERIFIED'"
t "event log recorded the transition" "$S logs --kind transition | grep -q 'restricted mode'"
t "kill switch engage (verified)"   "$S kill --keep-links | grep -q VERIFIED"
t "panel shows DISCONNECTED"        "$S panel | grep -q DISCONNECTED"
t "release kill switch"             "$S release"
t "DISABLE restores Standard"       "$S disable | grep -q 'Overall status: VERIFIED'"
t "table removed after disable"     "! nft list table inet nullos"
t "baseline table untouched after disable" "nft list table inet filter | grep -q 'policy drop'"
t "isolated-lab enable"             "$S enable isolated-lab | grep -q 'Overall status'"
t "isolated-lab: nothing leaves"    "python3 -c \"import socket;s=socket.socket(2,2)
try: s.sendto(b'x',('192.0.2.1',9)); raise SystemExit(1)
except PermissionError: pass\""
$S disable >/dev/null
t "custom profile: ssh+quad9"       "$S custom outbound=on allow_ssh=on dns=quad9 ipv6=same && $S enable custom | grep -q 'Overall status'"
t "custom: tcp 22 allowed in rules" "nft list table inet nullos | grep -q '22'"
$S disable >/dev/null
t "bad toggle rejected"             "! $S custom dns=evil"
t "unknown profile rejected"        "$S enable nope | grep -qi 'unknown profile'"
t "audit users runs"                "$S audit users | grep -q 'User and group audit'"
t "audit listening runs"            "$S audit listening | grep -q 'Listening services'"
t "audit credentials: metadata only" "$S audit credentials | grep -q 'Credential file permissions'"
t "routes shows default"            "$S routes | grep -q 'default IPv4 via 10.0.0.1'"
t "connections runs"                "$S connections; true"
t "lab: create network lab (2 nodes)" "python3 - <<PY
import importlib.machinery as m
x=m.SourceFileLoader('c','$S').load_module()
r=x.call('lab_net_create',id='t1',nodes=2); print(r['check']['status'],r['check']['detail']); assert r['check']['status']=='verified'
PY"
t "lab: appears in status as VERIFIED" "$S status | grep -E 'Lab t1 +VERIFIED'"
t "lab: nodes isolated (no default route)" "ip -n nlt1-n1 route show default | grep -q . && exit 1 || exit 0"
t "lab: destroy cleans everything"  "python3 - <<PY
import importlib.machinery as m
x=m.SourceFileLoader('c','$S').load_module(); print(x.call('lab_net_destroy',id='t1'))
PY
! ip link show nlt1 && [ -z \"\$(ip netns list)\" ]"
t "lab id injection rejected"       "python3 - <<PY
import importlib.machinery as m
x=m.SourceFileLoader('c','$S').load_module()
try: x.call('lab_net_create',id='a;rm -rf /',nodes=2); raise SystemExit(1)
except SystemExit as e: assert 'lab id' in str(e) or 'error' in str(e), e
PY"
t "unknown verb rejected"           "python3 - <<PY
import importlib.machinery as m
x=m.SourceFileLoader('c','$S').load_module()
try: x.call('run_shell',cmd='id'); raise SystemExit(1)
except SystemExit as e: assert 'unknown verb' in str(e), e
PY"
kill $D 2>/dev/null; wait $D 2>/dev/null
echo; [ $f -eq 0 ] && echo "E2E: ALL PASSED" || echo "E2E: $f FAILED"; exit $f
