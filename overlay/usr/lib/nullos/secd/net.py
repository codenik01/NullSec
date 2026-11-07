"""NetworkPolicy module: firewall, DNS, IPv4/IPv6, MAC randomization, kill switch,
IP & route protection, connection visibility.

Design rule: nothing here reports success because a command returned 0. Every control is
verified by (1) loading the *intended* ruleset into a throw-away network namespace and
comparing it with what the kernel is really enforcing, (2) checking structural invariants
of the effective rules, and (3) where possible a behavioural probe (a UDP packet to an
RFC 5737 / RFC 3849 documentation address must be refused with EPERM by our OUTPUT policy).
"""
import errno
import fnmatch
import hashlib
import ipaddress
import json
import os
import re
import socket

from . import core
from .core import (ACTIVE, DEGRADED, FAILED, INACTIVE, UNKNOWN, UNSUPPORTED, VERIFIED, check, ctl, run)

TABLE = "nullos"
KILL_TABLE = "nullos_kill"
TESTNET4 = "192.0.2.1"     # RFC 5737 documentation range, never routed
TESTNET6 = "2001:db8::1"   # RFC 3849 documentation range
NM_MAC_CONF = core.P("/etc/NetworkManager/conf.d/30-nullos-mac.conf")
NM_DNS_CONF = core.P("/etc/NetworkManager/conf.d/31-nullos-dns.conf")
_UUID = re.compile(r"^[0-9a-fA-F-]{36}$")
_IFNAME = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")


# ----------------------------------------------------------------------------------
# environment helpers
# ----------------------------------------------------------------------------------
def ipv6_supported():
    if not os.path.exists("/proc/net/if_inet6"):
        return False
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).close()
        return True
    except OSError:
        return False


def read_resolvers(path=None):
    path = path or core.P("/etc/resolv.conf")
    v4, v6 = [], []
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    try:
                        ip = ipaddress.ip_address(parts[1].split("%")[0])
                    except ValueError:
                        continue
                    if ip.is_loopback:
                        continue
                    lst = v4 if ip.version == 4 else v6
                    if str(ip) not in lst:
                        lst.append(str(ip))
    except OSError:
        pass
    return v4, v6


def dns_allowed(profile):
    """The resolver addresses the DNS policy permits (v4, v6)."""
    d = ctl(profile, "dns")
    if not d:
        return [], []
    servers = [ipaddress.ip_address(s) for s in d.get("servers", [])]
    v4 = [str(s) for s in servers if s.version == 4]
    v6 = [str(s) for s in servers if s.version == 6]
    if d.get("mode", "system") == "system":
        r4, r6 = read_resolvers()
        v4 += [x for x in r4 if x not in v4]
        v6 += [x for x in r6 if x not in v6]
    return v4, v6


# ----------------------------------------------------------------------------------
# ruleset generation
# ----------------------------------------------------------------------------------
def _set(name, typ, items, interval=False):
    fl = " flags interval;" if interval else ""
    return "  set %s { type %s;%s elements = { %s } }\n" % (name, typ, fl, ", ".join(items))


def build_ruleset(profile, dns4=None, dns6=None):
    """Return an nft script that (atomically) replaces table inet nullos."""
    ob, ib, dn, v6c = (ctl(profile, n) for n in ("outbound", "inbound", "dns", "ipv6"))
    if not (ob or ib or dn or v6c):
        return None
    v6block = bool(v6c and v6c.get("mode") == "block")
    if dns4 is None and dns6 is None:
        dns4, dns6 = dns_allowed(profile)
    dns4, dns6 = dns4 or [], dns6 or []
    vpn = list(ob.get("vpn_interfaces", [])) if ob else []
    s = ["table inet %s\ndelete table inet %s\ntable inet %s {\n" % (TABLE, TABLE, TABLE)]
    hosts = [ipaddress.ip_network(h, strict=False) for h in (ob.get("allow_hosts", []) if ob else [])]
    h4 = [str(h) for h in hosts if h.version == 4]
    h6 = [str(h) for h in hosts if h.version == 6]
    if dns4:
        s.append(_set("dns4", "ipv4_addr", dns4))
    if dns6:
        s.append(_set("dns6", "ipv6_addr", dns6))
    if h4:
        s.append(_set("allow4", "ipv4_addr", h4, True))
    if h6:
        s.append(_set("allow6", "ipv6_addr", h6, True))

    if ib:
        s.append("  chain input {\n    type filter hook input priority -10; policy drop;\n")
        s.append('    iifname "lo" accept\n')
        if v6block:
            s.append("    meta nfproto ipv6 drop\n")
        s.append("    ct state established,related accept\n    ct state invalid drop\n")
        s.append("    udp sport 67 udp dport 68 accept\n")
        if not v6block:
            s.append("    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept\n")
            s.append("    ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept\n")
        if ib.get("allow_ping"):
            s.append("    icmp type echo-request accept\n")
            if not v6block:
                s.append("    icmpv6 type echo-request accept\n")
        if not ib.get("drop_new_on_vpn", True):
            for v in (vpn or ["tun*", "wg*"]):
                s.append('    iifname "%s" accept\n' % v)
        s.append("  }\n")

    s.append("  chain output {\n    type filter hook output priority -10; policy %s;\n" % ("drop" if ob else "accept"))
    s.append('    oifname "lo" accept\n')
    if v6block:
        s.append("    meta nfproto ipv6 drop\n")
    s.append("    ct state invalid drop\n")
    vpn_rules = ['    oifname "%s" accept\n' % v for v in vpn]
    if not dn or dn.get("allow_via_vpn", True):
        s.extend(vpn_rules)
    if dn:
        if dns4:
            s.append("    ip daddr @dns4 udp dport 53 accept\n    ip daddr @dns4 tcp dport 53 accept\n")
            if not dn.get("block_dot", True):
                s.append("    ip daddr @dns4 tcp dport 853 accept\n")
        if dns6:
            s.append("    ip6 daddr @dns6 udp dport 53 accept\n    ip6 daddr @dns6 tcp dport 53 accept\n")
            if not dn.get("block_dot", True):
                s.append("    ip6 daddr @dns6 tcp dport 853 accept\n")
        s.append("    meta l4proto { tcp, udp } th dport 53 drop\n")
        if dn.get("block_dot", True):
            s.append("    meta l4proto { tcp, udp } th dport 853 drop\n")
        if not dn.get("allow_via_vpn", True):
            s.extend(vpn_rules)
    if ob:
        s.append("    ct state established,related accept\n")
        s.append("    udp sport 68 udp dport 67 accept\n")
        if not v6block:
            s.append("    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, mld2-listener-report } accept\n")
            s.append("    ip6 daddr ff02::1:2 udp sport 546 udp dport 547 accept\n")
        if ob.get("allow_tcp"):
            s.append("    tcp dport { %s } accept\n" % ", ".join(str(p) for p in ob["allow_tcp"]))
        if ob.get("allow_udp"):
            s.append("    udp dport { %s } accept\n" % ", ".join(str(p) for p in ob["allow_udp"]))
        if h4:
            s.append("    ip daddr @allow4 accept\n")
        if h6 and not v6block:
            s.append("    ip6 daddr @allow6 accept\n")
        if ob.get("allow_icmp", True):
            s.append("    icmp type echo-request accept\n")
            if not v6block:
                s.append("    icmpv6 type echo-request accept\n")
        s.append("    drop\n")
    s.append("  }\n}\n")
    return "".join(s)


def build_kill_ruleset():
    return ("table inet %(k)s\ndelete table inet %(k)s\ntable inet %(k)s {\n"
            "  chain input { type filter hook input priority -20; policy drop; iifname \"lo\" accept; }\n"
            "  chain output { type filter hook output priority -20; policy drop; oifname \"lo\" accept; }\n"
            "  chain forward { type filter hook forward priority -20; policy drop; }\n}\n") % {"k": KILL_TABLE}


# ----------------------------------------------------------------------------------
# reading and normalising the kernel's effective ruleset
# ----------------------------------------------------------------------------------
def table_json(name):
    rc, out, _ = run(["nft", "-j", "list", "table", "inet", name])
    if rc != 0:
        return None
    try:
        return [o for o in json.loads(out)["nftables"] if "metainfo" not in o]
    except (ValueError, KeyError):
        return None


def _strip(o):
    if isinstance(o, dict):
        return {k: _strip(v) for k, v in o.items() if k not in ("handle", "counter")}
    if isinstance(o, list):
        items = [_strip(x) for x in o]
        items = [x for x in items if x != {}]
        if items and all(isinstance(x, (str, int)) for x in items):
            return sorted(items, key=str)
        return items
    return o


def digest(objs):
    """Stable fingerprint of a table: handles, counters and set-element order removed."""
    norm = []
    for o in objs:
        o = _strip(o)
        if "set" in o and isinstance(o["set"].get("elem"), list):
            o["set"]["elem"] = sorted(o["set"]["elem"], key=lambda x: json.dumps(x, sort_keys=True))
        norm.append(o)
    return hashlib.sha256(json.dumps(norm, sort_keys=True).encode()).hexdigest()


def expected_digest(script, table):
    """Load the intended script into a throw-away network namespace and fingerprint what
    the real nft parser/kernel produce. Independent of the live system's state."""
    if not script or not core.have("unshare") or not core.have("nft"):
        return None
    rc, out, _ = run(["unshare", "-n", "sh", "-c",
                      'nft -f - && nft -j list table inet "$1"', "sh", table], stdin=script, timeout=20)
    if rc != 0:
        return None
    try:
        objs = [o for o in json.loads(out[out.index('{"nftables"'):])["nftables"] if "metainfo" not in o]
    except (ValueError, KeyError):
        return None
    return digest(objs)


def expected_digest_file(path, table):
    """Same idea for an on-disk nftables.conf (the Standard baseline)."""
    try:
        with open(path) as f:
            text = f.read()
    except OSError:
        return None
    return expected_digest(text, table)


# ---- structural parsing of the effective rules ----------------------------------------
def _flat(v):
    if isinstance(v, dict):
        if "set" in v:
            return [x for e in v["set"] for x in _flat(e)]
        if "prefix" in v:
            return ["%s/%s" % (v["prefix"]["addr"], v["prefix"]["len"])]
        if "range" in v:
            return ["%s-%s" % tuple(v["range"])]
        return [json.dumps(v, sort_keys=True)]
    if isinstance(v, list):
        return [x for e in v for x in _flat(e)]
    return [v]


def _left(m):
    l = m.get("left", {})
    for k in ("payload", "meta", "ct"):
        if k in l:
            x = l[k]
            return k + "." + (x.get("protocol", "") + "." + x.get("field", "") if k == "payload" else x.get("key", ""))
    return "?"


def parse_table(objs):
    t = {"chains": {}, "sets": {}, "family": None}
    for o in objs:
        if "table" in o:
            t["family"] = o["table"].get("family")
        if "chain" in o:
            c = o["chain"]
            t["chains"][c["name"]] = {"hook": c.get("hook"), "prio": c.get("prio"),
                                      "policy": c.get("policy"), "rules": []}
        if "set" in o:
            st = o["set"]
            t["sets"][st["name"]] = [str(x) for x in _flat(st.get("elem", []))]
    for o in objs:
        if "rule" in o and o["rule"]["chain"] in t["chains"]:
            verdict, matches = None, []
            for e in o["rule"]["expr"]:
                for v in ("accept", "drop", "reject", "return", "jump", "goto"):
                    if v in e:
                        verdict = v
                if "match" in e:
                    m = e["match"]
                    matches.append((_left(m), m.get("op", "=="), [str(x) for x in _flat(m.get("right"))]))
            t["chains"][o["rule"]["chain"]]["rules"].append((verdict, matches))
    return t


_DPORT = ("payload.udp.dport", "payload.tcp.dport", "payload.th.dport")


def _is_dns_rule(matches, ports=("53",)):
    return any(l in _DPORT and any(p in r for p in ports) for l, op, r in matches)


def _iface_only(matches, key):
    return bool(matches) and all(l == key for l, _, _ in matches)


def invariants(objs, profile, dns4, dns6):
    """Structural checks of the *effective* table against the profile (not against our
    own generated text). Returns {control: (ok, detail)}."""
    t = parse_table(objs)
    res = {}
    out = t["chains"].get("output")
    inp = t["chains"].get("input")
    ob, ib, dn, v6c = (ctl(profile, n) for n in ("outbound", "inbound", "dns", "ipv6"))
    vpn = list(ob.get("vpn_interfaces", [])) if ob else []
    if t["family"] != "inet":
        return {k: (False, "table is not family inet; IPv4/IPv6 parity cannot be guaranteed")
                for k in ("outbound", "inbound", "dns", "ipv6") if ctl(profile, k)}

    def hooked(ch, hook):
        return ch is not None and ch["hook"] == hook

    if ob:
        if not hooked(out, "output"):
            res["outbound"] = (False, "output chain missing or not hooked")
        elif out["policy"] != "drop":
            res["outbound"] = (False, "output policy is %s, expected drop" % out["policy"])
        else:
            bad = None
            for verdict, m in out["rules"]:
                if verdict == "accept" and not m:
                    bad = "unconditional accept rule in output"
                if verdict == "accept" and _iface_only(m, "meta.oifname"):
                    names = [x for _, _, r in m for x in r]
                    if any(n != "lo" and not any(fnmatch.fnmatch(n, p) for p in vpn) for n in names):
                        bad = "output accepts an interface the policy does not allow: %s" % names
            res["outbound"] = (bad is None, bad or "default-deny output; only policy-listed accepts present")
    if ib:
        if not hooked(inp, "input"):
            res["inbound"] = (False, "input chain missing or not hooked")
        elif inp["policy"] != "drop":
            res["inbound"] = (False, "input policy is %s, expected drop" % inp["policy"])
        else:
            bad = None
            for verdict, m in inp["rules"]:
                if verdict == "accept" and not m:
                    bad = "unconditional accept rule in input"
                if verdict == "accept" and _iface_only(m, "meta.iifname"):
                    names = [x for _, _, r in m for x in r]
                    allowed_vpn = not ib.get("drop_new_on_vpn", True)
                    if any(n != "lo" and not (allowed_vpn and any(fnmatch.fnmatch(n, p) for p in (vpn or ["tun*", "wg*"]))) for n in names):
                        bad = "input accepts an interface blindly: %s" % names
            res["inbound"] = (bad is None, bad or "default-deny input; no blanket interface accepts")
    if dn:
        if not hooked(out, "output"):
            res["dns"] = (False, "output chain missing")
        else:
            rules = out["rules"]
            allowed = set(dns4) | set(dns6)
            bad = None
            drop_idx = None
            for i, (verdict, m) in enumerate(rules):
                if verdict == "drop" and _is_dns_rule(m) and drop_idx is None:
                    drop_idx = i
                if verdict == "accept" and _is_dns_rule(m, ("53", "853")):
                    ok = any(l in ("payload.ip.daddr", "payload.ip6.daddr") and all(x.startswith("@") for x in r) for l, _, r in m)
                    if not ok:
                        bad = "DNS accepted without a resolver restriction"
            if drop_idx is None:
                bad = bad or "no rule drops DNS to unauthorised resolvers"
            else:
                for i, (verdict, m) in enumerate(rules[:drop_idx]):
                    if verdict == "accept" and not _is_dns_rule(m) and not _iface_only(m, "meta.oifname"):
                        if not any(l == "meta.oifname" for l, _, _ in m):
                            bad = bad or "a general accept precedes the DNS drop rule"
                            break
            for sname in ("dns4", "dns6"):
                extra = set(t["sets"].get(sname, [])) - allowed
                if extra:
                    bad = bad or "resolver set contains unauthorised address(es): %s" % ", ".join(sorted(extra))
            res["dns"] = (bad is None, bad or "DNS only to configured resolvers; other DNS/DoT dropped")
    if v6c:
        if v6c.get("mode") == "block":
            ok_out = (out is None) or any(v == "drop" and ("meta.nfproto", "==", ["ipv6"]) in m for v, m in out["rules"])
            ok_in = (inp is None) or any(v == "drop" and ("meta.nfproto", "==", ["ipv6"]) in m for v, m in inp["rules"])
            res["ipv6"] = (ok_out and ok_in, "IPv6 dropped in input and output" if ok_out and ok_in else "IPv6 block rule missing")
        else:
            res["ipv6"] = (True, "table family inet: same rules apply to IPv4 and IPv6")
    return res


# ----------------------------------------------------------------------------------
# behavioural probes
# ----------------------------------------------------------------------------------
def route_dev(family, dst):
    rc, out, _ = run(["ip", "-j", "-%d" % family, "route", "get", dst])
    if rc != 0:
        return None
    try:
        return json.loads(out)[0].get("dev")
    except (ValueError, IndexError, AttributeError):
        return None


def probe(family, port, vpn_patterns=()):
    """Send one UDP byte to a documentation address. EPERM => our firewall refused it.
    Returns blocked | sent | noroute | unsupported | skipped."""
    dst = TESTNET4 if family == 4 else TESTNET6
    if family == 6 and not ipv6_supported():
        return "unsupported"
    dev = route_dev(family, dst)
    if dev is None:
        return "noroute"
    if any(fnmatch.fnmatch(dev, p) for p in vpn_patterns):
        return "skipped"  # traffic legitimately leaves through an allowed tunnel
    try:
        s = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(1)
        try:
            s.sendto(b"\0", (dst, port))
        finally:
            s.close()
        return "sent"
    except PermissionError:
        return "blocked"
    except OSError as e:
        if e.errno == errno.EPERM:
            return "blocked"
        if e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
            return "noroute"
        if e.errno == errno.EAFNOSUPPORT:
            return "unsupported"
        return "noroute"


def _probe_port(profile):
    ob = ctl(profile, "outbound") or {}
    for p in (9, 7, 19):
        if p not in ob.get("allow_udp", []):
            return p
    return 9


def _combine(inv, match, probes, what):
    """Fold invariants + fingerprint + probes into one honest status."""
    ok, detail = inv
    if not ok:
        return FAILED, detail
    if match is False:
        return FAILED, "kernel ruleset differs from the intended policy (was it changed or reverted?)"
    for fam, st in probes.items():
        if st == "sent":
            return FAILED, "probe: %s packet that policy forbids was NOT blocked (IPv%d)" % (what, fam)
    notes = []
    for fam, st in probes.items():
        if st == "blocked":
            notes.append("IPv%d probe blocked" % fam)
        elif st in ("noroute", "skipped"):
            notes.append("IPv%d probe %s" % (fam, "skipped (no route)" if st == "noroute" else "skipped (tunnel route)"))
    if match is None:
        return ACTIVE, detail + "; could not derive expected ruleset to compare, so not fully verified"
    return VERIFIED, detail + ("; " + ", ".join(notes) if notes else "")


# ----------------------------------------------------------------------------------
# apply / remove / verify (the Restricted Mode network controls)
# ----------------------------------------------------------------------------------
def firewall_wanted(profile):
    return any(ctl(profile, n) for n in ("outbound", "inbound", "dns", "ipv6"))


def apply_firewall(profile):
    """Returns (ok, detail, change, script). nft loads the script as one transaction,
    so a failure leaves the previous rules untouched."""
    if not core.have("nft"):
        return False, "nft is not installed", None, None
    dns4, dns6 = dns_allowed(profile)
    script = build_ruleset(profile, dns4, dns6)
    if not script:
        return True, "no firewall control requested", None, None
    rc, _, err = run(["nft", "-c", "-f", "-"], stdin=script)
    if rc != 0:
        return False, "ruleset rejected by nft: %s" % err.strip()[:200], None, script
    rc, _, err = run(["nft", "-f", "-"], stdin=script)
    if rc != 0:
        return False, "nft could not apply the ruleset: %s" % err.strip()[:200], None, script
    n = sum(1 for ln in script.splitlines() if ln.startswith("    "))
    return True, "applied", {"control": "firewall", "what": "nft table inet %s (%d rules)" % (TABLE, n),
                             "revert": "nft delete table inet %s" % TABLE}, script


def remove_firewall():
    if table_json(TABLE) is None:
        return True
    rc, _, _ = run(["nft", "delete", "table", "inet", TABLE])
    return rc == 0


def verify_firewall(profile, script):
    """Per-control checks for outbound/inbound/dns/ipv6 plus the ruleset fingerprint."""
    out = []
    wanted = [n for n in ("outbound", "inbound", "dns", "ipv6") if ctl(profile, n)]
    titles = {"outbound": "Outbound policy", "inbound": "Inbound policy", "dns": "DNS policy", "ipv6": "IPv4 / IPv6 parity"}
    objs = table_json(TABLE)
    if objs is None:
        for n in wanted:
            out.append(check("net." + n, titles[n], FAILED, "table inet %s is missing: rules were never applied or were removed" % TABLE,
                             "network", True, None, False, ctl(profile, n).get("required", False)))
        return out
    dns4, dns6 = dns_allowed(profile)
    # the allowed-resolver set is whatever the *applied* script carried (system resolvers may drift)
    applied4 = re.findall(r"set dns4 .*?elements = \{ (.*?) \}", script or "")
    applied6 = re.findall(r"set dns6 .*?elements = \{ (.*?) \}", script or "")
    a4 = [x.strip() for x in applied4[0].split(",")] if applied4 else []
    a6 = [x.strip() for x in applied6[0].split(",")] if applied6 else []
    exp = expected_digest(script, TABLE) if script else None
    live = digest(objs)
    match = None if exp is None else (exp == live)
    inv = invariants(objs, profile, a4, a6)
    port = _probe_port(profile)
    vpn = (ctl(profile, "outbound") or {}).get("vpn_interfaces", [])
    # fingerprint row
    out.append(check("net.ruleset", "Ruleset matches intended policy",
                     VERIFIED if match else (FAILED if match is False else UNKNOWN),
                     "kernel rules are identical to the intended policy" if match else
                     ("kernel rules DIFFER from the intended policy" if match is False else
                      "could not build a reference ruleset (unshare/nft unavailable)"),
                     "network", True, True, match, True))
    for n in wanted:
        req = bool(ctl(profile, n).get("required"))
        i = inv.get(n, (False, "no invariant result"))
        probes, limits, extra = {}, [], None
        if n == "outbound":
            probes = {4: probe(4, port, vpn)}
            if ipv6_supported():
                probes[6] = probe(6, port, vpn)
            limits = ["Applications that tunnel through an allowed protocol (e.g. DNS-over-HTTPS on 443) are not distinguished from web traffic."]
        elif n == "dns":
            probes = {4: probe(4, 53, vpn)}
            if ipv6_supported():
                probes[6] = probe(6, 53, vpn)
            limits = ["DNS-over-HTTPS inside port 443 and application-specific resolvers cannot be told apart from web traffic."]
            r4, r6 = read_resolvers()
            stray = [x for x in r4 + r6 if x not in set(a4) | set(a6)]
            if stray:
                st, det = _combine(i, match, probes, "DNS")
                if st in (VERIFIED, ACTIVE):
                    st, det = DEGRADED, "resolv.conf lists %s, which the DNS policy does not permit; DNS to it is blocked" % ", ".join(stray)
                out.append(check("net.dns", titles[n], st, det, "network", True, True, False, req, limits))
                continue
        elif n == "inbound":
            limits = ["Inbound enforcement is verified by inspecting the effective rules; it is not probed from an external host."]
        elif n == "ipv6":
            if not ipv6_supported():
                out.append(check("net.ipv6", titles[n], UNSUPPORTED, "IPv6 is not available in this kernel/environment, nothing to enforce",
                                 "network", True, False, None, False))
                continue
            probes = {6: probe(6, port, vpn)} if (ctl(profile, "ipv6") or {}).get("mode") == "block" or ctl(profile, "outbound") else {}
        st, det = _combine(i, match, probes, n)
        out.append(check("net." + n, titles[n], st, det, "network", True, True, st == VERIFIED, req, limits))
    return out


# ---- kill switch ------------------------------------------------------------------------
def apply_kill(disconnect=True):
    if not core.have("nft"):
        return False, "nft is not installed"
    script = build_kill_ruleset()
    rc, _, err = run(["nft", "-f", "-"], stdin=script)
    if rc != 0:
        return False, "nft failed: %s" % err.strip()[:200]
    if disconnect and core.have("nmcli"):
        rc, out, _ = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "dev"])
        for line in out.splitlines():
            p = line.split(":")
            if len(p) >= 3 and p[2] == "connected" and p[1] in ("ethernet", "wifi") and _IFNAME.match(p[0]):
                run(["nmcli", "dev", "disconnect", p[0]])
    return True, "deny policy applied"


def release_kill():
    if table_json(KILL_TABLE) is None:
        return True
    rc, _, _ = run(["nft", "delete", "table", "inet", KILL_TABLE])
    return rc == 0


def verify_kill():
    objs = table_json(KILL_TABLE)
    if objs is None:
        return check("net.kill", "Network kill switch", INACTIVE, "not engaged", "network", False, False, None)
    t = parse_table(objs)
    ok = all(t["chains"].get(c, {}).get("policy") == "drop" and t["chains"][c]["hook"] == c for c in ("input", "output"))
    p4 = probe(4, 9)
    if not ok:
        return check("net.kill", "Network kill switch", FAILED, "kill table present but chains are not default-drop", "network", True, True, False)
    if p4 == "sent":
        return check("net.kill", "Network kill switch", FAILED, "deny policy present but a probe packet still left the host", "network", True, True, False)
    return check("net.kill", "Network kill switch", VERIFIED,
                 "ENGAGED: all traffic except loopback is denied" + ("; probe blocked" if p4 == "blocked" else "; probe skipped (no route)"),
                 "network", True, True, True)


# ----------------------------------------------------------------------------------
# MAC randomization (NetworkManager)
# ----------------------------------------------------------------------------------
def nm_available():
    if not core.have("nmcli"):
        return False
    rc, out, _ = run(["nmcli", "-t", "-f", "RUNNING", "general"])
    return rc == 0 and "running" in out


def nm_devices():
    rc, out, _ = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "dev"])
    res = []
    for line in out.splitlines():
        p = line.split(":")
        if len(p) >= 3 and p[1] in ("ethernet", "wifi") and _IFNAME.match(p[0]):
            res.append({"dev": p[0], "type": p[1], "state": p[2]})
    return res


def mac_info(dev):
    rc, out, _ = run(["ip", "-j", "-d", "link", "show", "dev", dev])
    cur = perm = None
    try:
        j = json.loads(out)[0]
        cur = j.get("address")
        perm = j.get("permaddr")
    except (ValueError, IndexError):
        pass
    assign = None
    try:
        with open("/sys/class/net/%s/addr_assign_type" % dev) as f:
            assign = int(f.read().strip())
    except (OSError, ValueError):
        pass
    randomized = bool(perm) or assign == 3
    return {"current": cur, "permanent": perm or (cur if assign == 0 else None), "assign_type": assign, "randomized": randomized}


def mac_conf_text(c):
    return ("# managed by NullOS Security Center (nullos-secd); removed when Restricted Mode is turned off\n"
            "[device]\nwifi.scan-rand-mac-address=yes\n"
            "[connection]\nwifi.cloned-mac-address=%s\nethernet.cloned-mac-address=%s\nipv6.ip6-privacy=2\n"
            % (c.get("wifi", "preserve"), c.get("ethernet", "preserve")))


def _active_connections():
    rc, out, _ = run(["nmcli", "-t", "-f", "UUID,TYPE,DEVICE", "con", "show", "--active"])
    res = []
    for line in out.splitlines():
        p = line.split(":")
        if len(p) >= 3 and _UUID.match(p[0]) and p[1] in ("802-3-ethernet", "802-11-wireless"):
            res.append(p[0])
    return res


def _reconnect():
    for u in _active_connections():
        run(["nmcli", "con", "up", "uuid", u], timeout=30)


def apply_mac(profile):
    c = ctl(profile, "mac")
    if not nm_available():
        return None, "NetworkManager is not running; MAC randomization is not supported here", None
    if not nm_devices():
        return None, "no Wi-Fi or Ethernet device found", None
    try:
        core.atomic_write(NM_MAC_CONF, mac_conf_text(c), 0o644)
    except OSError as e:
        return False, "could not write %s: %s" % (NM_MAC_CONF, e), None
    run(["nmcli", "general", "reload", "conf"])
    pending = True
    if c.get("reconnect", True):
        _reconnect()
        pending = False
    return True, "configured (wifi=%s ethernet=%s)%s" % (c.get("wifi"), c.get("ethernet"),
                                                         "; takes effect on next (re)connect" if pending else ""), \
        {"control": "mac", "what": "wrote %s" % NM_MAC_CONF, "revert": "remove the file and reconnect"}


def remove_mac(reconnect=True):
    existed = os.path.exists(NM_MAC_CONF)
    try:
        os.unlink(NM_MAC_CONF)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    if existed and nm_available():
        run(["nmcli", "general", "reload", "conf"])
        if reconnect:
            _reconnect()
    return True


def verify_mac(profile, conf=None):
    conf = conf or NM_MAC_CONF
    c = ctl(profile, "mac")
    req = bool(c.get("required"))
    lim = ["Randomization hides the hardware address from the local network only; it does not hide you on other layers.",
           "Per-connection profiles that define their own MAC override the global setting."]
    if not nm_available():
        return check("net.mac", "MAC randomization", UNSUPPORTED, "NetworkManager is not running", "network", True, False, None, req, lim)
    devs = nm_devices()
    if not devs:
        return check("net.mac", "MAC randomization", UNSUPPORTED, "no Wi-Fi/Ethernet device present", "network", True, False, None, req, lim)
    if not os.path.exists(conf):
        return check("net.mac", "MAC randomization", FAILED, "NetworkManager drop-in is missing", "network", True, False, False, req, lim)
    rows, bad, pend = [], [], []
    for d in devs:
        want = c.get(d["type"], "preserve")
        if want == "preserve":
            continue
        mi = mac_info(d["dev"])
        rows.append({"dev": d["dev"], "type": d["type"], "state": d["state"], **mi})
        if d["state"] != "connected":
            pend.append(d["dev"])
        elif not mi["randomized"]:
            bad.append(d["dev"])
    if bad:
        return check("net.mac", "MAC randomization", DEGRADED,
                     "configured, but %s still use the hardware address (driver/profile refused, or reconnect pending)" % ", ".join(bad),
                     "network", True, True, False, req, lim, rows)
    if pend and len(pend) == len(rows):
        return check("net.mac", "MAC randomization", ACTIVE, "configured; will apply when %s connect(s)" % ", ".join(pend),
                     "network", True, True, None, req, lim, rows)
    return check("net.mac", "MAC randomization", VERIFIED,
                 "address in use differs from the hardware address on %s" % ", ".join(r["dev"] for r in rows if r["state"] == "connected"),
                 "network", True, True, True, req, lim, rows)


def apply_dns_global(profile):
    d = ctl(profile, "dns")
    if not d or d.get("mode") != "pinned":
        return None
    if not nm_available():
        return None
    text = ("# managed by NullOS Security Center\n[global-dns-domain-*]\nservers=%s\n" % ",".join(d["servers"]))
    try:
        core.atomic_write(NM_DNS_CONF, text, 0o644)
    except OSError:
        return None
    run(["nmcli", "general", "reload"])
    return {"control": "dns", "what": "wrote %s (resolvers pinned)" % NM_DNS_CONF, "revert": "remove the file"}


def remove_dns_global():
    existed = os.path.exists(NM_DNS_CONF)
    try:
        os.unlink(NM_DNS_CONF)
    except FileNotFoundError:
        pass
    if existed and nm_available():
        run(["nmcli", "general", "reload"])


# ----------------------------------------------------------------------------------
# IP & route protection (no fake "randomize IP")
# ----------------------------------------------------------------------------------
_VPN_IF = re.compile(r"^(tun|tap|wg|ppp|vpn|ipsec)\d*")


def ip_json(*args):
    rc, out, _ = run(["ip", "-j"] + list(args))
    try:
        return json.loads(out) if rc == 0 else []
    except ValueError:
        return []


def routes_info():
    addrs = []
    for itf in ip_json("addr"):
        for a in itf.get("addr_info", []):
            if itf["ifname"] == "lo":
                continue
            addrs.append({"dev": itf["ifname"], "family": 4 if a["family"] == "inet" else 6,
                          "addr": "%s/%s" % (a["local"], a["prefixlen"]), "scope": a.get("scope"),
                          "method": "dynamic (DHCP/SLAAC)" if a.get("dynamic") else "static/other"})
    d4 = [r for r in ip_json("-4", "route", "show", "default")]
    d6 = [r for r in ip_json("-6", "route", "show", "default")] if ipv6_supported() else []
    vpns = [i["ifname"] for i in ip_json("link") if _VPN_IF.match(i["ifname"]) and "UP" in i.get("flags", [])]
    default = {"4": [{"dev": r.get("dev"), "via": r.get("gateway")} for r in d4],
               "6": [{"dev": r.get("dev"), "via": r.get("gateway")} for r in d6]}
    notes = []
    if vpns:
        v4_vpn = any(r["dev"] in vpns for r in default["4"])
        v6_vpn = any(r["dev"] in vpns for r in default["6"])
        if default["4"] and not v4_vpn:
            notes.append("VPN interface %s is up but the IPv4 default route does not use it" % ",".join(vpns))
        if default["6"] and not v6_vpn and v4_vpn:
            notes.append("IPv6 default route bypasses the VPN: possible IPv6 leak")
    return {"addresses": addrs, "default_routes": default, "vpn_interfaces": vpns, "notes": notes,
            "limits": ["NullOS cannot choose your public IP: it is assigned by your network/ISP/VPN. A VPN changes what remote hosts see but does not guarantee anonymity."]}


def route_signature():
    ri = routes_info()
    return json.dumps({"d": ri["default_routes"], "v": ri["vpn_interfaces"]}, sort_keys=True)


# ----------------------------------------------------------------------------------
# connection visibility / listening services
# ----------------------------------------------------------------------------------
_PROC = re.compile(r'\("([^"]+)",pid=(\d+)')


def sockets(listening):
    rc, out, _ = run(["ss", "-H", "-tuanp" if not listening else "-tulnp"])
    res = []
    for line in out.splitlines():
        p = line.split()
        if len(p) < 6:
            continue
        proto, state, local, peer = p[0], p[1], p[4], p[5]
        if not listening and state not in ("ESTAB", "SYN-SENT", "SYN-RECV", "TIME-WAIT") and proto.startswith("tcp"):
            continue
        if not listening and proto.startswith("udp") and peer.endswith(":*"):
            continue
        m = _PROC.search(" ".join(p[6:]))
        res.append({"proto": proto, "state": state, "local": local, "peer": peer,
                    "process": m.group(1) if m else None, "pid": int(m.group(2)) if m else None})
    return res
