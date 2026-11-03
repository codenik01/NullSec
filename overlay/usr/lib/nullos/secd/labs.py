"""Network labs: an isolated virtual network of namespaces joined by a private bridge.

Created by the privileged service (needs CAP_NET_ADMIN); there is deliberately no verb that
runs a command as root. Nodes are reached by `ns-lab run`, which executes as the calling user.
This is *container-grade* isolation (shared kernel) and is labelled as such; stronger
isolation needs a VM (see `ns-lab vm`).
"""
import json
import os
import re
import time

from . import core
from .core import ACTIVE, DEGRADED, FAILED, UNKNOWN, VERIFIED, check, run

LAB_DIR = core.STATE_DIR + "/labs"
_ID = re.compile(r"^[a-z][a-z0-9]{0,7}$")


def _path(lid):
    return "%s/%s.json" % (LAB_DIR, lid)


def valid_id(lid):
    return isinstance(lid, str) and bool(_ID.match(lid))


def load_labs():
    labs = []
    try:
        for n in sorted(os.listdir(LAB_DIR)):
            if n.endswith(".json"):
                try:
                    labs.append(json.load(open(os.path.join(LAB_DIR, n))))
                except (OSError, ValueError):
                    pass
    except OSError:
        pass
    return labs


def _next_subnet(labs):
    used = {l.get("subnet_index") for l in labs}
    for i in range(1, 250):
        if i not in used:
            return i
    return None


def create(lid, nodes=2):
    if not valid_id(lid):
        return False, "lab id must be 1-8 chars: a-z then a-z0-9"
    if not isinstance(nodes, int) or isinstance(nodes, bool) or not 1 <= nodes <= 6:
        return False, "nodes must be 1..6"
    labs = load_labs()
    if any(l["id"] == lid for l in labs):
        return False, "lab %s already exists" % lid
    if not core.have("ip"):
        return False, "iproute2 'ip' not found"
    idx = _next_subnet(labs)
    if idx is None:
        return False, "no free lab subnet"
    br = "nl" + lid
    made_ns, made_br = [], False
    def undo():
        for ns in made_ns:
            run(["ip", "netns", "del", ns])
        if made_br:
            run(["ip", "link", "del", br])
    rc, _, e = run(["ip", "link", "add", br, "type", "bridge"])
    if rc:
        return False, "cannot create bridge: %s" % e.strip()[:120]
    made_br = True
    run(["ip", "addr", "add", "10.77.%d.1/24" % idx, "dev", br])
    run(["ip", "link", "set", br, "up"])
    nl = []
    for i in range(1, nodes + 1):
        ns, hv, nv = "%s-n%d" % (br, i), "v%s%d" % (lid, i), "p%s%d" % (lid, i)
        steps = [["ip", "netns", "add", ns],
                 ["ip", "link", "add", hv, "type", "veth", "peer", "name", nv],
                 ["ip", "link", "set", nv, "netns", ns],
                 ["ip", "link", "set", hv, "master", br],
                 ["ip", "link", "set", hv, "up"],
                 ["ip", "-n", ns, "link", "set", "lo", "up"],
                 ["ip", "-n", ns, "link", "set", nv, "name", "eth0"],
                 ["ip", "-n", ns, "addr", "add", "10.77.%d.%d/24" % (idx, 10 + i), "dev", "eth0"],
                 ["ip", "-n", ns, "link", "set", "eth0", "up"]]
        for s in steps:
            rc, _, e = run(s)
            if s[:3] == ["ip", "netns", "add"] and rc == 0:
                made_ns.append(ns)
            if rc:
                undo()
                return False, "step failed (%s): %s" % (" ".join(s[1:4]), e.strip()[:120])
        nl.append({"name": "n%d" % i, "netns": ns, "ip": "10.77.%d.%d" % (idx, 10 + i)})
    rec = {"id": lid, "type": "network", "bridge": br, "subnet": "10.77.%d.0/24" % idx, "subnet_index": idx,
           "host_ip": "10.77.%d.1" % idx, "nodes": nl, "created": int(time.time()),
           "isolation": "network namespaces + private bridge (shared kernel; not a VM)"}
    core.atomic_write(_path(lid), json.dumps(rec, indent=1))
    return True, rec


def destroy(lid):
    if not valid_id(lid):
        return False, "bad lab id"
    try:
        rec = json.load(open(_path(lid)))
    except (OSError, ValueError):
        return False, "no such lab"
    for n in rec.get("nodes", []):
        run(["ip", "netns", "del", n["netns"]])
    run(["ip", "link", "del", rec["bridge"]])
    try:
        os.unlink(_path(lid))
    except OSError:
        pass
    left = [n["netns"] for n in rec.get("nodes", []) if os.path.exists("/run/netns/" + n["netns"])]
    rc, _, _ = run(["ip", "link", "show", rec["bridge"]])
    if left or rc == 0:
        return False, "cleanup incomplete: %s%s" % (",".join(left), " bridge remains" if rc == 0 else "")
    return True, "lab %s removed (bridge, namespaces, veth pairs)" % lid


def verify(rec):
    """Isolation checks, from the inside: no default route in any node, bridge has only lab ports,
    nodes can reach each other."""
    lid = rec["id"]
    problems, notes = [], []
    rc, _, _ = run(["ip", "link", "show", rec["bridge"]])
    if rc:
        return check("lab." + lid, "Lab %s" % lid, FAILED, "bridge %s is gone" % rec["bridge"], "labs", True, True, False)
    rc, out, _ = run(["ip", "-j", "link", "show", "master", rec["bridge"]])
    try:
        ports = [x["ifname"] for x in json.loads(out)]
    except ValueError:
        ports = []
    allowed = {"v%s%d" % (lid, i + 1) for i in range(len(rec["nodes"]))}
    stray = [p for p in ports if p not in allowed]
    if stray:
        problems.append("bridge has non-lab port(s): %s (uplink?)" % ",".join(stray))
    for n in rec["nodes"]:
        rc, out, _ = run(["ip", "-n", n["netns"], "route", "show", "default"])
        if rc:
            problems.append("%s: namespace missing" % n["name"])
        elif out.strip():
            problems.append("%s has a default route (could reach beyond the lab)" % n["name"])
    if len(rec["nodes"]) >= 2 and not problems:
        a, b = rec["nodes"][0], rec["nodes"][1]
        rc, _, _ = run(["ip", "netns", "exec", a["netns"], "ping", "-c1", "-W1", b["ip"]], timeout=6)
        if rc == 127:
            notes.append("node-to-node connectivity not tested (ping not installed)")
        else:
            notes.append("node-to-node ping %s" % ("ok" if rc == 0 else "FAILED"))
            if rc != 0:
                brnf = None
                try:
                    brnf = open("/proc/sys/net/bridge/bridge-nf-call-iptables").read().strip()
                except OSError:
                    pass
                if brnf == "1":
                    problems.append("nodes cannot reach each other: br_netfilter is loaded and sends bridged traffic through the host "
                                    "forward chain (policy drop). Fix: sysctl -w net.bridge.bridge-nf-call-iptables=0 (affects Docker/libvirt bridges too)")
                else:
                    problems.append("nodes cannot reach each other")
    if problems:
        return check("lab." + lid, "Lab %s" % lid, FAILED if any("default route" in p or "uplink" in p for p in problems) else DEGRADED,
                     "; ".join(problems), "labs", True, True, False, True, [rec["isolation"]], rec)
    return check("lab." + lid, "Lab %s" % lid, VERIFIED, "isolated: no uplink, no default route; %s" % "; ".join(notes or ["single node"]),
                 "labs", True, True, True, True, [rec["isolation"], "A container-grade boundary shares the host kernel: use a VM for hostile code."], rec)
