"""Integration test for secd.net against a REAL kernel (run inside `unshare -Urn`).
Not a mock: loads rulesets with nft, reads them back, probes with real sockets."""
import json, os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__)); OVL = os.path.join(HERE, "..", "overlay")
sys.path.insert(0, os.path.join(OVL, "usr/lib/nullos"))
os.environ.setdefault("NULLOS_ROOT", "/tmp/nroot-x")
os.environ.setdefault("NULLOS_PROFILES", os.path.join(OVL, "usr/share/nullos/profiles"))
from secd import core, net

fails = 0
def ok(cond, msg):
    global fails
    print(("PASS  " if cond else "FAIL  ") + msg)
    if not cond: fails += 1

def sh(c): return subprocess.run(c, shell=True, capture_output=True, text=True)

# network fixture: veth with an address and a default route (so probes have a route)
sh("ip link set lo up; ip link add v0 type veth peer name v1; ip addr add 10.0.0.2/24 dev v0; ip link set v0 up; ip link set v1 up; ip route add default via 10.0.0.1")
os.makedirs(os.path.dirname(core.P("/etc/resolv.conf")), exist_ok=True); os.makedirs(core.P("/run"), exist_ok=True)
open(core.P("/etc/resolv.conf"), "w").write("nameserver 10.0.0.1\n")
# baseline like NullOS ships
sh("nft -f " + os.path.join(OVL, "etc/nftables.conf"))

profiles = core.load_profiles()
ok(set(profiles) >= {"standard", "restricted-network", "privacy-focused", "isolated-lab"}, "all shipped profiles load: %s" % sorted(profiles))

# 1. every shipped profile generates a ruleset the real nft parser accepts
for pid, p in profiles.items():
    s = net.build_ruleset(p)
    if s is None:
        ok(pid == "standard", "%s: no firewall ruleset (baseline only)" % pid); continue
    r = subprocess.run(["nft", "-c", "-f", "-"], input=s, capture_output=True, text=True)
    ok(r.returncode == 0, "%s: ruleset accepted by nft -c %s" % (pid, r.stderr.strip()[:150]))

# 2. apply restricted-network, verify honestly
p = profiles["restricted-network"]
good, detail, change, script = net.apply_firewall(p)
ok(good, "apply restricted-network: %s" % detail)
res = {c["id"]: c for c in net.verify_firewall(p, script)}
for k, c in res.items(): print("      %-14s %-10s %s" % (k, c["status"], c["detail"][:110]))
ok(res["net.ruleset"]["status"] == "verified", "ruleset fingerprint matches throw-away-namespace reference")
ok(res["net.outbound"]["status"] == "verified", "outbound VERIFIED (invariants + fingerprint + probe)")
ok(res["net.inbound"]["status"] == "verified", "inbound VERIFIED")
ok(res["net.dns"]["status"] == "verified", "dns VERIFIED")
ok(res["net.ipv6"]["status"] in ("unsupported", "verified"), "ipv6 reported truthfully (%s)" % res["net.ipv6"]["status"])
ok(net.probe(4, 9) == "blocked", "behavioural probe: forbidden UDP is refused (EPERM)")
ok(net.probe(4, 53) == "blocked", "behavioural probe: DNS to non-configured resolver refused")
# the baseline filter table is untouched
ok(net.table_json("filter") is not None, "baseline 'inet filter' table still present (we never replaced it)")

# 3. TAMPERING must be detected: delete one rule
objs = net.table_json("nullos")
h = None
for o in objs:
    if "rule" in o and o["rule"]["chain"] == "output" and any("drop" in e for e in o["rule"]["expr"]) and len(o["rule"]["expr"]) > 1:
        h = o["rule"]["handle"]; break
sh("nft delete rule inet nullos output handle %d" % h)
res2 = {c["id"]: c for c in net.verify_firewall(p, script)}
ok(res2["net.ruleset"]["status"] == "failed", "tamper (rule deleted) -> fingerprint FAILED")
ok(res2["net.outbound"]["status"] == "failed", "tamper (rule deleted) -> outbound FAILED, not 'verified'")

# 4. a permissive 'accept all' injected into output must be caught by invariants AND probe
good, _, _, script = net.apply_firewall(p)
sh("nft insert rule inet nullos output accept")
res3 = {c["id"]: c for c in net.verify_firewall(p, script)}
ok(res3["net.outbound"]["status"] == "failed", "injected 'accept' -> outbound FAILED: %s" % res3["net.outbound"]["detail"][:90])
ok(net.probe(4, 9) == "sent", "…and the probe confirms traffic now leaks")

# 5. table removed entirely
good, _, _, script = net.apply_firewall(p)
net.remove_firewall()
res4 = {c["id"]: c for c in net.verify_firewall(p, script)}
ok(all(c["status"] == "failed" for c in res4.values()), "table removed -> every control FAILED (never silently 'ok')")
ok(net.probe(4, 9) == "sent", "after removal the probe sees traffic leave (Standard behaviour restored)")
ok(net.table_json("filter") is not None, "baseline still intact after removal")

# 6. DNS drift: resolver appears that policy doesn't permit
good, _, _, script = net.apply_firewall(p)
open(core.P("/etc/resolv.conf"), "w").write("nameserver 10.0.0.1\nnameserver 203.0.113.9\n")
res5 = {c["id"]: c for c in net.verify_firewall(p, script)}
ok(res5["net.dns"]["status"] == "degraded", "unpermitted resolver in resolv.conf -> DNS DEGRADED: %s" % res5["net.dns"]["detail"][:100])
open(core.P("/etc/resolv.conf"), "w").write("nameserver 10.0.0.1\n")

# 7. isolated lab: nothing leaves, lab net 10.77/16 is allowed
pl = profiles["isolated-lab"]
good, d, _, script = net.apply_firewall(pl)
ok(good, "apply isolated-lab: %s" % d)
r = {c["id"]: c for c in net.verify_firewall(pl, script)}
ok(r["net.outbound"]["status"] == "verified", "isolated-lab outbound VERIFIED")
ok(net.probe(4, 9) == "blocked", "isolated-lab: no packet leaves")
net.remove_firewall()

# 8. kill switch
ok(net.verify_kill()["status"] == "inactive", "kill switch inactive by default")
good, d = net.apply_kill(disconnect=False)
k = net.verify_kill()
ok(good and k["status"] == "verified", "kill switch engage -> VERIFIED: %s" % k["detail"])
ok(net.probe(4, 9) == "blocked" and net.probe(4, 443) == "blocked", "kill switch: probes blocked")
ok(net.release_kill() and net.verify_kill()["status"] == "inactive", "kill switch released -> inactive")
ok(net.probe(4, 9) == "sent", "traffic flows again after release")

# 9. atomic replace: re-applying twice leaves exactly one table, no duplicates
net.apply_firewall(p); net.apply_firewall(p)
ok(sh("nft list tables").stdout.count("table inet nullos\n") == 1, "re-apply is idempotent (single table)")
net.remove_firewall()

# 10. a broken ruleset must NOT change anything (atomicity)
before = net.table_json("filter")
bad = dict(p); bad["controls"] = dict(p["controls"])
r = subprocess.run(["nft", "-f", "-"], input="table inet nullos\ndelete table inet nullos\ntable inet nullos { chain output { type filter hook output priority -10; policy drop; bogus rule } }\n", capture_output=True, text=True)
ok(r.returncode != 0 and net.table_json("nullos") is None, "invalid ruleset is rejected atomically (nothing half-applied)")
ok(net.digest(before) == net.digest(net.table_json("filter")), "baseline unchanged by a failed apply")

print("\nRESULT:", "ALL PASSED" if fails == 0 else "%d FAILED" % fails)
sys.exit(1 if fails else 0)
