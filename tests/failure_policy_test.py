"""Phase 5 (failure policy), against a real kernel: when a required control cannot be verified the mode must
NOT be reported as active, and a profile with on_failure=fallback-deny must fall back to a full network deny."""
import os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__)); OVL = os.path.join(HERE, "..", "overlay")
os.environ.setdefault("NULLOS_ROOT", "/tmp/fp-root"); os.environ.setdefault("NULLOS_PROFILES", os.path.join(OVL, "usr/share/nullos/profiles"))
sys.path.insert(0, os.path.join(OVL, "usr/lib/nullos"))
from secd import core, net, service
fails = 0
def ok(c, m):
    global fails; print(("PASS  " if c else "FAIL  ") + m); fails += 0 if c else 1
def sh(c): return subprocess.run(c, shell=True, capture_output=True, text=True)
for d in ("etc", "run", "var/lib", "var/log"): os.makedirs(core.P("/" + d), exist_ok=True)
open(core.P("/etc/resolv.conf"), "w").write("nameserver 10.0.0.1\n")
sh("ip link set lo up; ip link add v0 type veth peer name v1; ip addr add 10.0.0.2/24 dev v0; ip link set v0 up; ip link set v1 up; ip route add default via 10.0.0.1")
sh("nft -f " + os.path.join(OVL, "etc/nftables.conf"))
svc = service.Service()
real = net.verify_firewall
def broken(profile, script):          # a required control that cannot be confirmed
    return [core.check("net.outbound", "Outbound policy", core.FAILED, "simulated: cannot confirm", "network", True, True, False, True),
            core.check("net.ruleset", "Ruleset", core.FAILED, "simulated", "network", True, True, False, True)]
net.verify_firewall = broken
r = svc.enable("restricted-network", "test")                       # on_failure = report
ok(r["overall"] == "failed" and not r["ok"], "restricted-network with a failed required control -> overall FAILED, ok=False (%s)" % r["overall"])
ok(net.table_json(net.KILL_TABLE) is None, "profile policy 'report': no automatic deny is applied")
svc.disable("test")
r = svc.enable("isolated-lab", "test")                             # on_failure = fallback-deny
ph = {p["phase"]: p for p in r["phases"]}
ok(not r["ok"] and r["overall"] in ("failed", "degraded"), "isolated-lab with a failed required control is not reported active (%s)" % r["overall"])
ok("failure-policy" in ph and ph["failure-policy"]["ok"], "failure-policy phase ran and succeeded: %s" % ph.get("failure-policy", {}).get("detail"))
ok(net.table_json(net.KILL_TABLE) is not None and svc.state["fallback_deny"], "fallback deny table is really in the kernel")
ok(net.probe(4, 9) == "blocked" and net.probe(4, 443) == "blocked", "…and nothing can leave while protection is unverified")
net.verify_firewall = real
svc.disable("test")
ok(net.table_json(net.KILL_TABLE) is None and not svc.state["fallback_deny"], "disabling Restricted Mode releases the fallback deny")
ok(net.probe(4, 9) == "sent", "Standard connectivity restored")
ok(net.table_json("filter") is not None, "baseline firewall intact throughout")
# a user kill switch must survive disable (it is the user's explicit decision)
svc.kill(False, "test"); svc.enable("restricted-network", "test"); svc.disable("test")
ok(net.table_json(net.KILL_TABLE) is not None, "user's Emergency Disconnect is NOT silently undone by mode changes")
svc.release("test")
# nftables reload (which 'flush ruleset's everything) must be detected and repaired by the monitor
svc.enable("restricted-network", "test"); sh("nft flush ruleset; nft -f " + os.path.join(OVL, "etc/nftables.conf"))
ok(net.table_json(net.TABLE) is None, "simulated 'systemctl reload nftables' wiped the Restricted Mode table")
svc.tick()
ok(net.table_json(net.TABLE) is not None, "monitor tick detected the silent revert and re-applied the policy")
ok(any(e["kind"] == "drift" for e in core.LOG.tail(20)), "…and recorded a drift event in the security log")
print("\nRESULT:", "ALL PASSED" if not fails else "%d FAILED" % fails); sys.exit(1 if fails else 0)
