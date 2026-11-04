"""NullOS security service: mode transitions, verification, monitor, socket server."""
import copy
import json
import os
import socket
import socketserver
import struct
import threading
import time

from . import apps, core, labs, net, sysmon
from .core import (ACTIVE, DEGRADED, FAILED, INACTIVE, LOG, UNKNOWN, UNSUPPORTED, VERIFIED, check, ctl)

BASE_MAC_CONF = core.P("/etc/NetworkManager/conf.d/00-nullsec-mac.conf")


# ------------------------------------------------------------------------------------------
# Custom profile (spec 4.3 "Custom: select individual supported controls")
# ------------------------------------------------------------------------------------------
TOGGLES = {
    "outbound": (bool, True), "inbound": (bool, True), "allow_ssh": (bool, False), "allow_ping": (bool, True),
    "vpn_trusted": (bool, True), "dns": (str, "system", ("off", "system", "quad9")), "block_dot": (bool, True),
    "ipv6": (str, "same", ("same", "block")), "mac": (bool, False), "usb_storage": (bool, False),
    "clipboard": (bool, False),
}


def build_custom(t):
    clean = {}
    for k, spec in TOGGLES.items():
        v = t.get(k, spec[1])
        if not isinstance(v, spec[0]) or (len(spec) > 2 and v not in spec[2]):
            raise core.ProfileError("bad value for %s" % k)
        clean[k] = v
    unknown = set(t) - set(TOGGLES)
    if unknown:
        raise core.ProfileError("unknown toggle(s): %s" % ", ".join(sorted(unknown)))
    c = {}
    if clean["outbound"]:
        c["outbound"] = {"enabled": True, "required": True, "default": "drop",
                         "allow_tcp": [80, 443] + ([22] if clean["allow_ssh"] else []), "allow_udp": [123], "allow_hosts": [],
                         "allow_icmp": clean["allow_ping"], "vpn_interfaces": ["tun*", "wg*"] if clean["vpn_trusted"] else []}
    if clean["inbound"]:
        c["inbound"] = {"enabled": True, "required": True, "drop_new_on_vpn": True, "allow_ping": False}
    if clean["dns"] != "off":
        d = {"enabled": True, "required": True, "mode": "system", "servers": [], "block_dot": clean["block_dot"], "allow_via_vpn": True}
        if clean["dns"] == "quad9":
            d.update(mode="pinned", servers=["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"])
        c["dns"] = d
    c["ipv6"] = {"enabled": True, "required": True, "mode": clean["ipv6"]}
    if clean["mac"]:
        c["mac"] = {"enabled": True, "required": False, "wifi": "random", "ethernet": "random", "reconnect": True}
    if clean["usb_storage"]:
        c["usb_storage"] = {"enabled": True, "required": False, "mode": "block-desktop-mount"}
    if clean["clipboard"]:
        c["clipboard"] = {"enabled": True, "required": False, "mode": "block"}
    c["monitor"] = {"enabled": True, "required": False, "interval": 30}
    p = {"schema": 1, "id": "custom", "name": "Custom", "version": "1.0.0",
         "description": "Your own selection of supported controls.", "on_failure": "report", "controls": c}
    core.validate_profile(p)
    return p, clean


# ------------------------------------------------------------------------------------------
class Service:
    def __init__(self):
        self.lock = threading.RLock()
        self.conf = core.load_conf()
        self.state = core.load_state()
        self.profiles = core.load_profiles()
        self.stop = threading.Event()
        self.started = time.time()
        self.monitor_alive = False
        self.last = {"dns": None, "route": None, "cfg": None}
        self.reapply_log = []
        self.last_checks = []

    # ---- helpers ---------------------------------------------------------------------
    def reload_profiles(self):
        self.profiles = core.load_profiles()

    def active_profile(self):
        if self.state["mode"] != "restricted":
            return None
        return self.profiles.get(self.state["profile"])

    def _save(self):
        core.save_state(self.state)

    @staticmethod
    def overall(checks):
        req = [c for c in checks if c["required"]]
        fw_failed = any(c["status"] == FAILED and c["id"] in ("net.ruleset", "net.outbound", "net.inbound") for c in req)
        if any(c["status"] == FAILED for c in req):
            return FAILED if fw_failed else DEGRADED
        if any(c["status"] in (UNKNOWN, INACTIVE, DEGRADED, UNSUPPORTED) for c in req):
            return DEGRADED
        if any(c["status"] == ACTIVE for c in req):
            return ACTIVE
        return VERIFIED

    def write_summary(self, checks=None):
        checks = checks if checks is not None else self.last_checks
        prof = self.active_profile()
        ov = self.overall([c for c in checks if c["area"] in ("network", "host")]) if prof else self.overall(
            [c for c in checks if c["id"] == "sys.firewall"])
        d = {"ts": int(time.time()), "mode": self.state["mode"], "profile": self.state["profile"], "overall": ov,
             "kill": bool(self.state["kill"]), "secd": "running", "version": core.VERSION,
             "counts": {s: sum(1 for c in checks if c["status"] == s) for s in core.ALL_STATUS}}
        try:
            core.atomic_write(core.SUMMARY_FILE, json.dumps(d), 0o644)
        except OSError:
            pass
        return d

    def sync_managed_baseline(self):
        """Files this service writes itself (NetworkManager drop-ins) are part of the policy, not a 'change'."""
        files = self.state.get("baseline", {}).get("files")
        if not files:
            return
        snap = sysmon.config_snapshot()
        for p in (net.NM_MAC_CONF, net.NM_DNS_CONF):
            key = p[len(core.ROOT):]
            if key in snap:
                files[key] = snap[key]
            else:
                files.pop(key, None)

    # ---- verification ----------------------------------------------------------------
    def verify_profile(self, profile):
        checks = []
        if net.firewall_wanted(profile):
            checks += net.verify_firewall(profile, self.state["expected"].get("script"))
        if ctl(profile, "mac"):
            checks.append(net.verify_mac(profile))
        if ctl(profile, "usb_storage"):
            checks.append(apps.verify_usb(profile))
        if ctl(profile, "clipboard"):
            checks.append(apps.verify_clipboard(profile))
        return checks

    def standard_network_rows(self, fw):
        v4, v6 = net.read_resolvers()
        rows = [check("net.outbound", "Outbound policy", INACTIVE, "Standard: no additional outbound restrictions", "network"),
                check("net.inbound", "Inbound policy", fw["status"], "Default firewall rules: " + fw["detail"], "network", False, fw["applied"], fw["verified"]),
                net.verify_mac({"controls": {"mac": {"enabled": True, "required": False, "wifi": "random", "ethernet": "preserve"}}}, BASE_MAC_CONF),
                check("net.dns", "DNS policy", INACTIVE, "System configuration (resolvers: %s)" % (", ".join(v4 + v6) or "none yet"), "network")]
        return rows

    def collect(self):
        """Everything the Security Center shows, from live inspection."""
        fw = sysmon.baseline_firewall()
        prof = self.active_profile()
        checks = self.verify_profile(prof) if prof else self.standard_network_rows(fw)
        if self.state["mode"] != "restricted" or not any(c["id"] == "net.inbound" for c in checks):
            pass
        checks.append(net.verify_kill())
        checks += [fw, sysmon.kernel_hardening(), sysmon.apparmor(), sysmon.config_monitor(self.state)]
        checks.append(check("sys.monitor", "Integrity monitor", ACTIVE if self.monitor_alive else INACTIVE,
                            "background verification every %ss" % self._interval() if self.monitor_alive else "not running", "system"))
        for rec in labs.load_labs():
            checks.append(labs.verify(rec))
        self.last_checks = checks
        return checks

    def _interval(self):
        p = self.active_profile()
        if p and ctl(p, "monitor"):
            return ctl(p, "monitor").get("interval", 30)
        return int(self.conf.get("monitor_interval", 30))

    # ---- verbs ---------------------------------------------------------------------------
    def status(self):
        with self.lock:
            checks = self.collect()
            summ = self.write_summary(checks)
            prof = self.active_profile() or self.profiles.get("standard") or {"name": "Standard", "version": "1.0.0"}
            return {"mode": self.state["mode"], "profile": self.state["profile"], "profile_name": prof.get("name"),
                    "profile_version": prof.get("version"), "overall": summ["overall"], "kill": self.state["kill"],
                    "fallback_deny": bool(self.state.get("fallback_deny")), "applied_at": self.state["applied_at"],
                    "checks": checks, "service": {"version": core.VERSION, "uptime": int(time.time() - self.started),
                                                  "monitor": self.monitor_alive}}

    def verify(self):
        with self.lock:
            LOG.write("info", "verify", "manual verification requested", mode=self.state["mode"])
            return self.status()

    def profiles_list(self):
        return [{"id": p["id"], "name": p["name"], "version": p["version"], "description": p.get("description", ""),
                 "source": p.get("source"), "recommended": p["id"] == "restricted-network",
                 "controls": sorted(k for k in p["controls"] if p["controls"][k].get("enabled") and k != "monitor")}
                for p in self.profiles.values()]

    def enable(self, pid, who="?"):
        with self.lock:
            self.reload_profiles()
            prof = self.profiles.get(pid)
            phases = []
            if not prof:
                return {"ok": False, "phases": [{"phase": "preflight", "ok": False, "detail": "unknown profile %r" % pid}], "overall": FAILED}
            if pid == "standard":
                return self.disable(who)
            LOG.write("info", "transition", "enable requested", profile=pid, version=prof["version"], by=who)
            # 1. preflight
            issues = []
            if net.firewall_wanted(prof) and not core.have("nft"):
                issues.append("nft is not installed, so the firewall controls cannot be applied")
            d = ctl(prof, "dns")
            ob = ctl(prof, "outbound")
            if d and ob and d.get("mode") == "system" and not any(net.read_resolvers()):
                phases.append({"phase": "preflight", "ok": True,
                               "detail": "no DNS resolver is configured yet: DNS stays blocked until one appears (it will be allowed automatically)"})
            if ob and 53 in ob.get("allow_tcp", []) + ob.get("allow_udp", []) and d:
                issues.append("profile allows port 53 outbound, which would bypass the DNS policy")
            if issues:
                phases.append({"phase": "preflight", "ok": False, "detail": "; ".join(issues)})
                LOG.write("error", "transition", "preflight failed", profile=pid, issues=issues)
                return {"ok": False, "phases": phases, "overall": FAILED, "checks": []}
            phases.append({"phase": "preflight", "ok": True, "detail": "profile valid; required services available"})
            # 2. apply (firewall first: it is atomic, so a failure leaves the system exactly as it was)
            changes, notes = [], []
            script = None
            if net.firewall_wanted(prof):
                ok, detail, change, script = net.apply_firewall(prof)
                if not ok:
                    phases.append({"phase": "apply", "ok": False, "detail": "firewall: " + detail + " (nothing was changed)"})
                    LOG.write("error", "transition", "firewall apply failed", profile=pid, error=detail)
                    self.state["last_result"] = {"ts": int(time.time()), "profile": pid, "ok": False, "detail": detail}
                    self._save()
                    return {"ok": False, "phases": phases, "overall": FAILED, "checks": []}
                changes.append(change)
            else:
                net.remove_firewall()
            if ctl(prof, "mac"):
                ok, detail, change = net.apply_mac(prof)
                notes.append(("mac", ok, detail))
                changes.append(change)
            else:
                net.remove_mac(reconnect=True)
            ch = net.apply_dns_global(prof) if ctl(prof, "dns") else None
            if ch:
                changes.append(ch)
            else:
                net.remove_dns_global()
            if ctl(prof, "usb_storage"):
                ok, detail, change = apps.apply_usb()
                notes.append(("usb_storage", ok, detail))
                changes.append(change)
            else:
                apps.remove_usb()
            if ctl(prof, "clipboard"):
                ok, detail, change = apps.apply_clipboard()
                notes.append(("clipboard", ok, detail))
                changes.append(change)
            else:
                apps.remove_clipboard()
            changes = [c for c in changes if c]
            phases.append({"phase": "apply", "ok": all(n[1] is not False for n in notes),
                           "detail": "; ".join("%s: %s" % (n[0], n[2]) for n in notes) or "network policy applied"})
            self.state.update(mode="restricted", profile=pid, profile_version=prof["version"], requested_at=int(time.time()),
                              applied_at=int(time.time()), changes=changes, expected={"script": script}, fallback_deny=False)
            self.sync_managed_baseline()
            self._save()
            # 3. verify
            time.sleep(0.3)
            checks = self.collect()
            ov = self.overall([c for c in checks if c["area"] in ("network", "host")])
            bad = [c for c in checks if c["required"] and c["status"] not in (VERIFIED, ACTIVE)]
            phases.append({"phase": "verify", "ok": not bad, "detail": "%d control(s) checked; %d required control(s) not verified" % (
                len([c for c in checks if c["area"] in ("network", "host")]), len(bad))})
            # 5. failure policy
            if ov in (FAILED, DEGRADED) and prof.get("on_failure") == "fallback-deny" and any(c["status"] == FAILED for c in bad):
                ok, detail = net.apply_kill(disconnect=False)
                kv = net.verify_kill()
                self.state["fallback_deny"] = ok and kv["status"] == VERIFIED
                self._save()
                phases.append({"phase": "failure-policy", "ok": self.state["fallback_deny"],
                               "detail": "profile policy 'fallback-deny': %s" % (
                                   "all traffic denied until the policy can be verified" if self.state["fallback_deny"]
                                   else "could not apply the fallback deny policy: " + detail + " - PROTECTION CANNOT BE VERIFIED")})
                checks = self.collect()
            LOG.write("info" if ov in (VERIFIED, ACTIVE) else "warn", "transition", "restricted mode %s" % ov, profile=pid,
                      changes=[c["what"] for c in changes], failed=[c["id"] for c in bad])
            self.state["last_result"] = {"ts": int(time.time()), "profile": pid, "ok": ov in (VERIFIED, ACTIVE), "overall": ov}
            self._save()
            self.write_summary(checks)
            return {"ok": ov in (VERIFIED, ACTIVE), "phases": phases, "overall": ov, "checks": checks, "changes": changes}

    def disable(self, who="?"):
        with self.lock:
            LOG.write("info", "transition", "disable requested", by=who, was=self.state["profile"])
            phases = []
            net.remove_firewall()
            net.remove_mac(reconnect=True)
            net.remove_dns_global()
            apps.remove_usb()
            apps.remove_clipboard()
            if self.state.get("fallback_deny"):
                if not self.state["kill"]:
                    net.release_kill()
                self.state["fallback_deny"] = False
            phases.append({"phase": "deactivate", "ok": True,
                           "detail": "removed Restricted Mode controls; Standard policy restored (baseline firewall untouched)"})
            self.state.update(mode="standard", profile="standard", profile_version=None, applied_at=int(time.time()),
                              requested_at=int(time.time()), changes=[], expected={})
            self.sync_managed_baseline()
            self._save()
            checks = self.collect()
            fw = next(c for c in checks if c["id"] == "sys.firewall")
            phases.append({"phase": "verify", "ok": fw["status"] in (VERIFIED, ACTIVE), "detail": "baseline firewall: %s" % fw["status"]})
            LOG.write("info", "transition", "standard mode restored", baseline_firewall=fw["status"])
            self.write_summary(checks)
            return {"ok": fw["status"] in (VERIFIED, ACTIVE), "phases": phases, "overall": fw["status"], "checks": checks}

    def restore(self, who="?"):
        """Restore Defaults: re-apply the chosen profile exactly as shipped (custom is reset)."""
        with self.lock:
            pid = self.state["profile"]
            if pid == "custom":
                try:
                    os.unlink(core.CUSTOM_FILE)
                except OSError:
                    pass
                self.reload_profiles()
                return self.enable("restricted-network", who)
            if self.state["mode"] != "restricted":
                return self.disable(who)
            return self.enable(pid, who)

    def kill(self, disconnect=True, who="?"):
        with self.lock:
            ok, detail = net.apply_kill(disconnect)
            self.state["kill"] = bool(ok)
            self.state["kill_disconnect"] = bool(disconnect)
            self._save()
            c = net.verify_kill()
            LOG.write("warn", "kill", "emergency disconnect " + ("engaged" if ok else "FAILED"), by=who, detail=detail, status=c["status"])
            self.write_summary(self.collect())
            return {"ok": ok and c["status"] == VERIFIED, "check": c, "detail": detail}

    def release(self, who="?"):
        with self.lock:
            ok = net.release_kill()
            self.state["kill"] = False
            self.state["fallback_deny"] = False
            self._save()
            c = net.verify_kill()
            LOG.write("warn", "kill", "emergency disconnect released", by=who, ok=ok)
            self.write_summary(self.collect())
            return {"ok": ok, "check": c, "detail": "network deny policy removed; reconnect from the network menu (ns-net)"}

    def custom_set(self, toggles, who="?"):
        with self.lock:
            p, clean = build_custom(toggles)
            core.atomic_write(core.CUSTOM_FILE, json.dumps(p, indent=1))
            self.reload_profiles()
            LOG.write("info", "profile", "custom profile saved", by=who, toggles=clean)
            return {"toggles": clean, "profile": p["id"]}

    def custom_get(self):
        cur = {k: v[1] for k, v in TOGGLES.items()}
        try:
            p = json.load(open(core.CUSTOM_FILE))
            c = p["controls"]
            cur.update(outbound="outbound" in c, inbound="inbound" in c, mac="mac" in c, usb_storage="usb_storage" in c,
                       clipboard="clipboard" in c, ipv6=c.get("ipv6", {}).get("mode", "same"),
                       dns="off" if "dns" not in c else ("quad9" if c["dns"]["mode"] == "pinned" else "system"),
                       allow_ssh=22 in c.get("outbound", {}).get("allow_tcp", []), allow_ping=c.get("outbound", {}).get("allow_icmp", True),
                       vpn_trusted=bool(c.get("outbound", {}).get("vpn_interfaces")), block_dot=c.get("dns", {}).get("block_dot", True))
        except (OSError, ValueError, KeyError):
            pass
        return {"toggles": cur, "choices": {k: list(v[2]) for k, v in TOGGLES.items() if len(v) > 2}}

    def audit(self, name):
        table = {"users": sysmon.users_audit, "packages": sysmon.packages_check, "updates": sysmon.updates_status,
                 "services": sysmon.privileged_services, "listening": sysmon.listening_audit, "config": lambda: sysmon.config_monitor(self.state),
                 "privileged": apps.privileged_processes, "credentials": apps.credential_audit, "environment": apps.env_secret_names,
                 "mounts": apps.mounts_audit, "sudo": sysmon.privileged_ops, "apparmor": sysmon.apparmor}
        if name == "all":
            with self.lock:
                out = [fn() for fn in table.values()]
                self._save()
                return out
        if name not in table:
            raise ValueError("unknown audit %r (choose: %s)" % (name, ", ".join(sorted(table))))
        with self.lock:
            r = table[name]()
            self._save()
            return [r]

    def baseline_accept(self, who="?"):
        with self.lock:
            self.state.setdefault("baseline", {})["files"] = sysmon.config_snapshot()
            self._save()
            LOG.write("info", "config", "monitored-file baseline accepted", by=who)
            return {"files": len(self.state["baseline"]["files"])}

    def cred_fix(self, who="?"):
        with self.lock:
            fixed, skipped = apps.credential_fix()
            LOG.write("info", "credentials", "tightened permissions", by=who, count=len(fixed), paths=fixed[:20])
            return {"fixed": fixed, "skipped": skipped}

    def lab_create(self, lid, nodes, who="?"):
        with self.lock:
            ok, res = labs.create(lid, nodes)
            LOG.write("info" if ok else "error", "lab", "network lab create %s" % ("ok" if ok else "failed"), id=lid, by=who, detail=res if not ok else "")
            if not ok:
                raise ValueError(res)
            return {"lab": res, "check": labs.verify(res)}

    def lab_destroy(self, lid, who="?"):
        with self.lock:
            ok, msg = labs.destroy(lid)
            LOG.write("info" if ok else "error", "lab", "network lab destroy %s" % ("ok" if ok else "failed"), id=lid, by=who, detail=msg)
            if not ok:
                raise ValueError(msg)
            return {"detail": msg}

    # ---- continuous verification -------------------------------------------------------
    def _may_reapply(self):
        now = time.time()
        self.reapply_log = [t for t in self.reapply_log if now - t < 300]
        if len(self.reapply_log) >= 3:
            return False
        self.reapply_log.append(now)
        return True

    def tick(self):
        with self.lock:
            v4, v6 = net.read_resolvers()
            dns_sig = json.dumps([v4, v6])
            if self.last["dns"] is not None and dns_sig != self.last["dns"]:
                LOG.write("info", "dns-change", "resolver configuration changed", resolvers=v4 + v6)
            self.last["dns"] = dns_sig
            rs = net.route_signature()
            if self.last["route"] is not None and rs != self.last["route"]:
                LOG.write("warn", "route-change", "default route or VPN interface set changed", routes=json.loads(rs))
            self.last["route"] = rs
            if self.state["kill"] and net.table_json(net.KILL_TABLE) is None:
                LOG.write("warn", "drift", "kill-switch rules disappeared (nftables reloaded?); re-applying")
                net.apply_kill(self.state.get("kill_disconnect", False))
            prof = self.active_profile()
            if prof:
                checks = self.verify_profile(prof)
                bad = [c for c in checks if c["id"] in ("net.ruleset", "net.outbound", "net.inbound", "net.dns") and c["status"] in (FAILED, DEGRADED)]
                if bad:
                    LOG.write("warn", "drift", "Restricted Mode controls no longer verify", failing=[(c["id"], c["status"]) for c in bad])
                    if net.firewall_wanted(prof) and self._may_reapply():
                        ok, detail, _, script = net.apply_firewall(prof)
                        if ok:
                            self.state["expected"]["script"] = script
                            self._save()
                        LOG.write("info" if ok else "error", "drift", "re-applied network policy" if ok else "re-apply FAILED: " + detail)
            checks = self.collect()
            cfg = next((c for c in checks if c["id"] == "sys.config"), None)
            if cfg and cfg["status"] == DEGRADED:
                sig = json.dumps(cfg["data"], sort_keys=True)
                if sig != self.last["cfg"]:
                    LOG.write("warn", "config-change", cfg["detail"], **{k: v[:10] for k, v in cfg["data"].items()})
                    self.last["cfg"] = sig
            self.write_summary(checks)

    def monitor(self):
        self.monitor_alive = True
        LOG.write("info", "service", "monitor started", interval=self._interval())
        while not self.stop.wait(max(5, self._interval())):
            try:
                self.tick()
            except Exception as e:  # the monitor must survive anything
                LOG.write("error", "monitor", "tick failed: %s" % e)
        self.monitor_alive = False

    def startup(self):
        with self.lock:
            LOG.write("info", "service", "nullos-secd starting", version=core.VERSION, mode=self.state["mode"], profile=self.state["profile"])
            try:
                prof = self.active_profile()
                if prof and net.firewall_wanted(prof) and net.table_json(net.TABLE) is None:
                    ok, detail, _, script = net.apply_firewall(prof)
                    if ok:
                        self.state["expected"]["script"] = script
                    LOG.write("info" if ok else "error", "service", "restored Restricted Mode network policy at start-up" if ok else detail)
                if self.state["kill"] and net.table_json(net.KILL_TABLE) is None:
                    net.apply_kill(self.state.get("kill_disconnect", False))
                self._save()
                self.write_summary(self.collect())
            except Exception as e:
                LOG.write("error", "service", "start-up reconcile failed: %s" % e)


# ------------------------------------------------------------------------------------------
# socket server
# ------------------------------------------------------------------------------------------
class Handler(socketserver.StreamRequestHandler):
    timeout = 120

    def reply(self, obj):
        self.wfile.write((json.dumps(obj) + "\n").encode())

    def handle(self):
        svc = self.server.svc
        cred = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", cred)
        if not core.authorized(uid, gid, svc.conf):
            LOG.write("warn", "auth", "request refused: caller not authorised", uid=uid)
            return self.reply({"ok": False, "error": "not authorised: you must be root or a member of: %s" % ", ".join(svc.conf.get("authorized_groups", ["sudo"]))})
        raw = self.rfile.readline(65537)
        if len(raw) > 65536:
            return self.reply({"ok": False, "error": "request too large"})
        try:
            req = json.loads(raw)
            verb, args = req["verb"], req.get("args", {}) or {}
            if not isinstance(verb, str) or not isinstance(args, dict):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            return self.reply({"ok": False, "error": "malformed request"})
        who = "uid=%d" % uid
        try:
            self.reply({"ok": True, "result": dispatch(svc, verb, args, who)})
        except (ValueError, core.ProfileError) as e:
            self.reply({"ok": False, "error": str(e)})
        except Exception as e:
            LOG.write("error", "service", "verb %s crashed: %s" % (verb, e))
            self.reply({"ok": False, "error": "internal error (logged)"})


def _s(args, key, default=None):
    v = args.get(key, default)
    if v is not None and not isinstance(v, str):
        raise ValueError("%s must be a string" % key)
    return v


def dispatch(svc, verb, args, who):
    if verb == "ping":
        return {"pong": True, "version": core.VERSION}
    if verb == "status":
        return svc.status()
    if verb == "verify":
        return svc.verify()
    if verb == "profiles":
        return svc.profiles_list()
    if verb == "enable":
        pid = _s(args, "profile")
        if not pid or not core._ID.match(pid):
            raise ValueError("bad profile id")
        return svc.enable(pid, who)
    if verb == "disable":
        return svc.disable(who)
    if verb == "restore":
        return svc.restore(who)
    if verb == "kill":
        return svc.kill(bool(args.get("disconnect", True)), who)
    if verb == "release":
        return svc.release(who)
    if verb == "logs":
        n = args.get("n", 100)
        if not isinstance(n, int) or isinstance(n, bool):
            raise ValueError("n must be a number")
        kind = _s(args, "kind")
        return LOG.tail(n, kind)
    if verb == "changes":
        return {"changes": svc.state.get("changes", []), "profile": svc.state["profile"], "applied_at": svc.state["applied_at"],
                "last_result": svc.state.get("last_result")}
    if verb == "audit":
        return svc.audit(_s(args, "name", "all"))
    if verb == "baseline_accept":
        return svc.baseline_accept(who)
    if verb == "cred_fix":
        return svc.cred_fix(who)
    if verb == "routes":
        return net.routes_info()
    if verb == "connections":
        return net.sockets(False)
    if verb == "mac":
        p = svc.active_profile() or {"controls": {"mac": {"enabled": True, "required": False, "wifi": "random", "ethernet": "preserve"}}}
        conf = None if svc.active_profile() and ctl(svc.active_profile(), "mac") else BASE_MAC_CONF
        return net.verify_mac(p, conf)
    if verb == "custom_get":
        return svc.custom_get()
    if verb == "custom_set":
        t = args.get("toggles")
        if not isinstance(t, dict):
            raise ValueError("toggles must be an object")
        return svc.custom_set(t, who)
    if verb == "lab_net_create":
        return svc.lab_create(_s(args, "id"), args.get("nodes", 2), who)
    if verb == "lab_net_destroy":
        return svc.lab_destroy(_s(args, "id"), who)
    if verb == "lab_list":
        return [labs.verify(r) for r in labs.load_labs()]
    raise ValueError("unknown verb %r" % verb)


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def serve():
    svc = Service()
    os.makedirs(core.RUN_DIR, exist_ok=True)
    os.makedirs(core.STATE_DIR, exist_ok=True)
    try:
        os.unlink(core.SOCK_PATH)
    except FileNotFoundError:
        pass
    old = os.umask(0o117)
    srv = Server(core.SOCK_PATH, Handler)
    os.umask(old)
    try:
        import grp
        gid = grp.getgrnam((svc.conf.get("authorized_groups") or ["sudo"])[0]).gr_gid
        os.chown(core.SOCK_PATH, 0, gid)
    except (KeyError, OSError, ImportError):
        pass
    os.chmod(core.SOCK_PATH, 0o660)
    srv.svc = svc
    svc.startup()
    threading.Thread(target=svc.monitor, daemon=True).start()
    try:
        srv.serve_forever()
    finally:
        svc.stop.set()
        try:
            os.unlink(core.SOCK_PATH)
        except OSError:
            pass


def selftest():
    """Build-time/boot-time sanity checks that need no privileges and no network."""
    import glob
    prof = core.load_profiles()
    want = {"standard", "restricted-network", "privacy-focused", "isolated-lab"}
    missing = want - set(prof)
    assert not missing, "profiles missing or invalid: %s" % missing
    for pid, p in prof.items():
        s = net.build_ruleset(p, ["9.9.9.9"], ["2620:fe::fe"])
        assert (s is None) == (pid == "standard"), pid
    build_custom({})
    if core.have("nft"):
        for pid, p in prof.items():
            s = net.build_ruleset(p, ["9.9.9.9"], ["2620:fe::fe"])
            if s:
                rc, _, err = core.run(["nft", "-c", "-f", "-"], stdin=s)
                # -c needs netlink privileges inside some build chroots; only syntax errors are fatal
                assert rc == 0 or "Operation not permitted" in err or "Netlink" in err or "No such file" in err, "%s: %s" % (pid, err)
    print("nullos-secd selftest ok (%d profiles, version %s)" % (len(prof), core.VERSION))
