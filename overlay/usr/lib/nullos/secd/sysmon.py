"""IntegrityMonitor: baseline firewall verification, kernel hardening, AppArmor status,
service exposure, privileged services, users/groups, packages, updates, critical-config
monitoring, privileged-operation audit.

These are audits and verifications, not an intrusion-detection engine. A changed file is
reported as "changed since baseline", never as "malicious": administrators and legitimate
software change settings too.
"""
import glob
import json
import os
import re
import time

from . import core, net
from .core import (ACTIVE, DEGRADED, FAILED, INACTIVE, UNKNOWN, UNSUPPORTED, VERIFIED, check, run)

P = core.P


# ---- baseline (Standard) firewall: compare kernel state with /etc/nftables.conf ------------
def baseline_firewall():
    lim = ["Rules you add at runtime (e.g. opening a listener port) are legitimate and are reported as a difference, not as an attack."]
    if not core.have("nft"):
        return check("sys.firewall", "Firewall (baseline)", UNSUPPORTED, "nft is not installed", "system", True, False, None, True, lim)
    objs = net.table_json("filter")
    if objs is None:
        return check("sys.firewall", "Firewall (baseline)", FAILED,
                     "table inet filter is not loaded: default-deny inbound is NOT in effect (is nftables.service running?)",
                     "system", True, False, False, True, lim)
    t = net.parse_table(objs)
    ch = t["chains"].get("input")
    if not ch or ch["hook"] != "input" or ch["policy"] != "drop":
        return check("sys.firewall", "Firewall (baseline)", FAILED, "input chain is not default-drop", "system", True, True, False, True, lim)
    exp = net.expected_digest_file(P("/etc/nftables.conf"), "filter")
    if exp is None:
        return check("sys.firewall", "Firewall (baseline)", ACTIVE,
                     "default-deny inbound confirmed; could not compare with /etc/nftables.conf", "system", True, True, None, True, lim)
    if exp == net.digest(objs):
        return check("sys.firewall", "Firewall (baseline)", VERIFIED, "effective rules match /etc/nftables.conf; default-deny inbound", "system", True, True, True, True, lim)
    return check("sys.firewall", "Firewall (baseline)", ACTIVE,
                 "default-deny inbound confirmed; effective rules differ from /etc/nftables.conf (changed at runtime)", "system", True, True, None, True, lim)


# ---- kernel hardening (sysctl) -------------------------------------------------------------
def kernel_hardening():
    want = {}
    for path in sorted(glob.glob(P("/etc/sysctl.d/*nullsec*.conf"))):
        with open(path) as f:
            for ln in f:
                ln = ln.strip()
                if ln and not ln.startswith("#") and "=" in ln:
                    k, v = ln.split("=", 1)
                    want[k.strip()] = v.strip()
    if not want:
        return check("sys.sysctl", "Kernel hardening", UNKNOWN, "no NullOS sysctl policy found", "system")
    ok, bad, missing = 0, [], []
    for k, v in want.items():
        try:
            with open(("/proc/sys/" + k.replace(".", "/"))) as f:
                cur = f.read().strip()
        except OSError:
            missing.append(k)
            continue
        if cur == v:
            ok += 1
        else:
            bad.append("%s=%s (want %s)" % (k, cur, v))
    if bad:
        return check("sys.sysctl", "Kernel hardening", DEGRADED, "%d/%d settings differ: %s" % (len(bad), len(want), "; ".join(bad[:4])), "system", True, True, False, False, data={"bad": bad})
    if ok == 0:
        return check("sys.sysctl", "Kernel hardening", UNSUPPORTED, "none of the settings exist on this kernel", "system")
    note = "; %d unsupported by this kernel" % len(missing) if missing else ""
    return check("sys.sysctl", "Kernel hardening", VERIFIED, "%d/%d sysctl settings in effect%s" % (ok, len(want), note), "system", True, True, True, False)


# ---- AppArmor ------------------------------------------------------------------------------
def apparmor():
    lim = ["Enforcing profiles exist only for the applications that have one; this does not prove a given application is confined."]
    en = ("/sys/module/apparmor/parameters/enabled")
    if not os.path.exists(en):
        return check("sys.apparmor", "AppArmor", UNSUPPORTED, "this kernel has no AppArmor", "system", False, False, None, False, lim)
    with open(en) as f:
        if f.read().strip() != "Y":
            return check("sys.apparmor", "AppArmor", INACTIVE, "AppArmor is disabled in the kernel", "system", False, False, None, False, lim)
    try:
        with open(("/sys/kernel/security/apparmor/profiles")) as f:
            lines = [l for l in f.read().splitlines() if l.strip()]
    except OSError:
        return check("sys.apparmor", "AppArmor", UNKNOWN, "enabled, but the loaded-profile list is not readable", "system", False, None, None, False, lim)
    enf = sum(1 for l in lines if l.endswith("(enforce)"))
    comp = sum(1 for l in lines if l.endswith("(complain)"))
    if not lines:
        return check("sys.apparmor", "AppArmor", INACTIVE,
                     "enabled in the kernel, but no profiles are loaded (is apparmor.service running? try: sudo systemctl restart apparmor)",
                     "system", False, False, None, False, lim)
    st = DEGRADED if comp else ACTIVE
    try:
        with open("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") as f:
            userns = f.read().strip()
    except OSError:
        userns = None
    lim = lim + ["Unprivileged user namespaces are %s (needed by ns-sandbox and browser sandboxes; set kernel.apparmor_restrict_unprivileged_userns=1 in /etc/sysctl.d/99-nullsec.conf to restrict them)."
                 % ("allowed" if userns == "0" else "restricted" if userns == "1" else "not controlled by AppArmor")]
    return check("sys.apparmor", "AppArmor", st, "%d profile(s) enforcing, %d complain-only; 'ns-sandbox' adds confinement for tools that have no profile" % (enf, comp),
                 "system", False, True, None, False, lim)


# ---- services ------------------------------------------------------------------------------
def _addr_port(s):
    a, _, p = s.rpartition(":")
    return a.strip("[]"), p


def _accepted_ports():
    ports, iface_open = set(), []
    policy_ok = True
    for tname in ("filter", net.TABLE):
        objs = net.table_json(tname)
        if not objs:
            continue
        t = net.parse_table(objs)
        ch = t["chains"].get("input")
        if not ch:
            continue
        if ch["policy"] != "drop":
            policy_ok = False
        for verdict, m in ch["rules"]:
            if verdict != "accept":
                continue
            for l, _, r in m:
                if l in net._DPORT:
                    ports.update(r)
            if m and all(l == "meta.iifname" for l, _, _ in m):
                iface_open += [x for _, _, r in m for x in r if x != "lo"]
    return ports, sorted(set(iface_open)), policy_ok


def listening_audit():
    socks = net.sockets(True)
    ports, iface_open, policy_ok = _accepted_ports()
    rows, exposed = [], 0
    for s in socks:
        a, p = _addr_port(s["local"])
        loop = a.startswith("127.") or a == "::1"
        wild = a in ("0.0.0.0", "*", "::", "")
        if loop:
            exp = "loopback only"
        elif p in ports:
            exp, exposed = "reachable: a firewall rule allows port %s" % p, exposed + 1
        elif not policy_ok:
            exp, exposed = "reachable: input policy is not default-deny", exposed + 1
        elif iface_open:
            exp = "blocked by default-deny, except via %s" % ",".join(iface_open)
        else:
            exp = "blocked by default-deny input policy"
        rows.append({"proto": s["proto"], "local": s["local"], "process": s["process"], "pid": s["pid"],
                     "bound": "wildcard" if wild else ("loopback" if loop else "address"), "exposure": exp})
    st = DEGRADED if exposed else VERIFIED
    return check("sys.listening", "Listening services", st,
                 "%d listening socket(s); %d reachable from the network" % (len(rows), exposed), "system", False, None, exposed == 0,
                 False, ["Exposure is derived from the effective firewall rules; it is not a port scan."], rows)


def privileged_services():
    if not core.have("systemctl"):
        return check("sys.services", "Privileged services", UNSUPPORTED, "systemd not available", "system")
    rc, out, _ = run(["systemctl", "list-units", "--type=service", "--state=running", "--plain", "--no-legend", "--no-pager"])
    units = [l.split()[0] for l in out.splitlines() if l.split()][:80]
    if rc != 0 or not units:
        return check("sys.services", "Privileged services", UNKNOWN, "could not list running services", "system")
    rc, out, _ = run(["systemctl", "show", "--property=Id,User,NoNewPrivileges,ProtectSystem,PrivateTmp"] + units, timeout=30)
    rows = []
    for blk in out.strip().split("\n\n"):
        kv = dict(l.split("=", 1) for l in blk.splitlines() if "=" in l)
        if not kv.get("Id"):
            continue
        root = kv.get("User", "") in ("", "root")
        hard = kv.get("NoNewPrivileges") == "yes" or kv.get("ProtectSystem") in ("yes", "full", "strict")
        rows.append({"unit": kv["Id"], "user": kv.get("User") or "root", "hardened": hard, "root_unhardened": root and not hard})
    n = sum(1 for r in rows if r["root_unhardened"])
    return check("sys.services", "Privileged services", ACTIVE, "%d running service(s); %d run as root without sandboxing options" % (len(rows), n),
                 "system", False, None, None, False, ["Inventory only: unhardened does not mean vulnerable."], rows)


# ---- accounts ------------------------------------------------------------------------------
def users_audit():
    f = []
    live = False
    try:
        with open("/proc/cmdline") as cf:
            live = "boot=casper" in cf.read()
    except OSError:
        pass
    try:
        with open(P("/etc/passwd")) as fh:
            for ln in fh:
                p = ln.rstrip("\n").split(":")
                if len(p) >= 7 and p[2] == "0" and p[0] != "root":
                    f.append({"sev": "high", "what": "extra uid-0 account: %s" % p[0]})
    except OSError:
        pass
    try:
        with open(P("/etc/shadow")) as fh:
            for ln in fh:
                p = ln.split(":")
                if len(p) > 1 and p[1] == "":
                    f.append({"sev": "info" if live else "high", "what": "account %s has an empty password%s" % (p[0], " (by design in the live session)" if live else "")})
    except OSError:
        pass
    try:
        with open(P("/etc/group")) as fh:
            for ln in fh:
                p = ln.rstrip("\n").split(":")
                if p[0] in ("sudo", "adm", "wheel", "docker") and len(p) > 3 and p[3]:
                    f.append({"sev": "info", "what": "group %s: %s" % (p[0], p[3])})
    except OSError:
        pass
    for path in [P("/etc/sudoers")] + sorted(glob.glob(P("/etc/sudoers.d/*"))):
        try:
            with open(path) as fh:
                for ln in fh:
                    if "NOPASSWD" in ln and not ln.lstrip().startswith("#"):
                        f.append({"sev": "info" if live else "warn", "what": "passwordless sudo in %s: %s" % (os.path.basename(path), ln.strip()[:80])})
        except OSError:
            pass
    high = [x for x in f if x["sev"] == "high"]
    warn = [x for x in f if x["sev"] == "warn"]
    st = DEGRADED if high or warn else VERIFIED
    return check("sys.users", "User and group audit", st, "%d high, %d warning, %d informational finding(s)" % (len(high), len(warn), len(f) - len(high) - len(warn)),
                 "system", False, None, st == VERIFIED, False, [], f)


# ---- packages / updates ----------------------------------------------------------------------
KEY_PKGS = ["sudo", "openssh-client", "nftables", "libpam-modules", "libpam-runtime", "network-manager", "coreutils", "bash", "apt", "dpkg"]
_IGN = re.compile(r"^/usr/share/(doc|locale|man|info)/")


def packages_check():
    findings = []
    srcs = [P("/etc/apt/sources.list")] + sorted(glob.glob(P("/etc/apt/sources.list.d/*")))
    for path in srcs:
        try:
            txt = open(path).read()
        except OSError:
            continue
        if re.search(r"trusted\s*=\s*yes|allow-insecure|allow-downgrade-to-insecure", txt, re.I):
            findings.append({"sev": "high", "what": "%s disables signature checking" % os.path.basename(path)})
        if re.search(r"kali\.org|parrot(sec|linux)", txt, re.I):
            findings.append({"sev": "warn", "what": "%s mixes a Kali/Parrot repository into Ubuntu (unsupported)" % os.path.basename(path)})
    if core.have("dpkg"):
        rc, out, _ = run(["dpkg", "-V"] + KEY_PKGS, timeout=60)
        for ln in out.splitlines():
            m = re.match(r"^(\S{9})\s+(c\s+)?(\S.*)$", ln)
            if not m or m.group(2):
                continue
            flags, path = m.group(1), m.group(3).strip()
            if _IGN.match(path):
                continue
            if "5" in flags or flags.startswith("missing"):
                findings.append({"sev": "warn", "what": "package file differs from its recorded checksum: %s" % path})
    else:
        return check("sys.packages", "Package integrity", UNSUPPORTED, "dpkg not available", "system")
    high = [x for x in findings if x["sev"] == "high"]
    st = DEGRADED if findings else VERIFIED
    return check("sys.packages", "Package integrity", st,
                 "%d finding(s): apt sources are signed and %d key packages match their checksums" % (len(findings), len(KEY_PKGS)) if not findings else "%d finding(s)" % len(findings),
                 "system", False, None, st == VERIFIED, False,
                 ["dpkg -V compares files to checksums stored on the same disk; an attacker with root could alter both. Signed apt metadata is the stronger guarantee."], findings)


def updates_status():
    lists = glob.glob(P("/var/lib/apt/lists/*Packages*")) + glob.glob(P("/var/lib/apt/lists/*Packages.*"))
    if not lists:
        return check("sys.updates", "Security updates", UNKNOWN,
                     "no package index present (the live image ships without one). Run 'ns-pack update' with internet access, then verify again", "system")
    age = time.time() - max(os.path.getmtime(x) for x in lists)
    rc, out, _ = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=60)
    if rc != 0:
        return check("sys.updates", "Security updates", UNKNOWN, "apt could not simulate an upgrade", "system")
    inst = [l for l in out.splitlines() if l.startswith("Inst ")]
    sec = [l for l in inst if "-security" in l]
    days = int(age // 86400)
    st = DEGRADED if sec else (ACTIVE if days > 7 else VERIFIED)
    return check("sys.updates", "Security updates", st, "%d update(s) pending, %d security; package index is %d day(s) old" % (len(inst), len(sec), days),
                 "system", False, None, st == VERIFIED, False, ["Based on the local package index; it does not contact the network."],
                 [l.split()[1] for l in sec][:50])


# ---- critical configuration monitor ----------------------------------------------------------
WATCH = ["/etc/nftables.conf", "/etc/sudoers", "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/hosts",
         "/usr/local/bin/ns-session", "/etc/lightdm/lightdm.conf.d/99-nullsec.conf"]
WATCH_GLOBS = ["/etc/sudoers.d/*", "/etc/sysctl.d/*", "/etc/NetworkManager/conf.d/*", "/etc/pam.d/*", "/etc/apt/sources.list.d/*",
               "/etc/nullos/*", "/etc/nullos/profiles.d/*", "/usr/share/nullos/profiles/*"]


def config_snapshot():
    paths = [P(p) for p in WATCH]
    for g in WATCH_GLOBS:
        paths += glob.glob(P(g))
    snap = {}
    for p in sorted(set(paths)):
        try:
            snap[p[len(core.ROOT):]] = core.sha256_file(p) if os.path.isfile(p) else "missing"
        except OSError:
            snap[p[len(core.ROOT):]] = "unreadable"
    return snap


def config_diff(base, now):
    return {"changed": sorted(k for k in now if k in base and base[k] != now[k]),
            "added": sorted(k for k in now if k not in base),
            "removed": sorted(k for k in base if k not in now)}


def config_monitor(state):
    now = config_snapshot()
    base = state.get("baseline", {}).get("files")
    if not base:
        state.setdefault("baseline", {})["files"] = now
        return check("sys.config", "Critical configuration", VERIFIED, "baseline recorded for %d files" % len(now), "system", False, True, True)
    d = config_diff(base, now)
    n = sum(len(v) for v in d.values())
    if not n:
        return check("sys.config", "Critical configuration", VERIFIED, "no change to %d monitored files since baseline" % len(now), "system", False, True, True)
    return check("sys.config", "Critical configuration", DEGRADED, "%d change(s) since baseline (not necessarily malicious: review, then 'ns-secure baseline accept')" % n,
                 "system", False, True, False, False, ["A change can be an administrator or a package update."], d)


# ---- privileged operations (sudo) ------------------------------------------------------------
_SUDO = re.compile(r"(\S+)\s*:\s*(?:.*?;\s*)?(?:TTY=\S+\s*;\s*)?(?:PWD=.*?;\s*)?USER=(\S+)\s*;\s*COMMAND=(\S+)")


def privileged_ops(n=50):
    if not core.have("journalctl"):
        return check("sys.privops", "Privileged-operation audit", UNSUPPORTED, "journalctl not available", "system")
    rc, out, _ = run(["journalctl", "-t", "sudo", "-n", str(n * 3), "-o", "cat", "--no-pager", "-q"], timeout=15)
    rows = []
    for ln in out.splitlines():
        m = _SUDO.search(ln)
        if m:  # command *arguments* are deliberately not kept: they may contain secrets
            rows.append({"user": m.group(1), "as": m.group(2), "command": os.path.basename(m.group(3))})
    if rc != 0 or not out.strip():
        return check("sys.privops", "Privileged-operation audit", UNKNOWN, "no sudo records in the journal yet", "system")
    return check("sys.privops", "Privileged-operation audit", ACTIVE, "%d recent sudo operation(s) recorded (command names only; arguments are never stored)" % len(rows),
                 "system", False, None, None, False, ["Only sudo is covered; direct root logins are not."], rows[-n:])
