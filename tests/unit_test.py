"""Unit tests for the security-critical pure logic (no kernel needed)."""
import json, os, shutil, stat, subprocess, sys, tempfile, time, unittest
HERE = os.path.dirname(os.path.abspath(__file__)); OVL = os.path.join(HERE, "..", "overlay")
TMP = tempfile.mkdtemp(prefix="nullos-unit-")
os.environ["NULLOS_ROOT"] = TMP
os.environ["NULLOS_PROFILES"] = os.path.join(OVL, "usr/share/nullos/profiles")
sys.path.insert(0, os.path.join(OVL, "usr/lib/nullos"))
from secd import core, net, sysmon, apps, service  # noqa: E402


def prof(**ctl):
    return {"schema": 1, "id": "t", "name": "t", "version": "1.0.0", "controls": ctl}
ON = {"enabled": True, "required": True}


class Profiles(unittest.TestCase):
    def test_shipped_profiles_valid(self):
        p = core.load_profiles()
        self.assertTrue({"standard", "restricted-network", "privacy-focused", "isolated-lab"} <= set(p))
    def test_rejects_garbage(self):
        bad = [dict(prof(), id="Bad ID"), dict(prof(), schema=2), prof(bogus=ON),
               prof(outbound=dict(ON, allow_tcp=[0])), prof(outbound=dict(ON, allow_tcp=["80"])),
               prof(outbound=dict(ON, allow_hosts=["1.2.3.4; reboot"])), prof(dns=dict(ON, mode="pinned")),
               prof(dns=dict(ON, servers=["not-an-ip"])), prof(ipv6=dict(ON, mode="maybe")),
               prof(monitor=dict(ON, interval=1)), prof(outbound=dict(ON, vpn_interfaces=['tun*"; drop'])),
               prof(outbound=dict(ON, allow_tcp=[1] * 65))]
        for b in bad:
            with self.assertRaises(core.ProfileError, msg=json.dumps(b)[:80]):
                core.validate_profile(b)
    def test_custom_toggles(self):
        p, clean = service.build_custom({"allow_ssh": True, "dns": "quad9"})
        self.assertIn(22, p["controls"]["outbound"]["allow_tcp"])
        self.assertEqual(p["controls"]["dns"]["mode"], "pinned")
        for t in ({"dns": "evil"}, {"outbound": "yes"}, {"nope": True}, {"ipv6": 6}):
            with self.assertRaises(core.ProfileError): service.build_custom(t)


class Ruleset(unittest.TestCase):
    def test_default_deny_and_dns_order(self):
        s = net.build_ruleset(core.load_profiles()["restricted-network"], ["9.9.9.9"], [])
        self.assertIn("policy drop", s)
        self.assertLess(s.index("th dport 53 drop"), s.index("ct state established,related accept", s.index("chain output")))
        self.assertIn("ip daddr @dns4 udp dport 53 accept", s)
        self.assertNotIn("dns6", s)                      # no empty set emitted
    def test_no_resolver_means_dns_blocked_not_open(self):
        s = net.build_ruleset(core.load_profiles()["restricted-network"], [], [])
        self.assertNotIn("dport 53 accept", s); self.assertIn("th dport 53 drop", s)
    def test_ipv6_block(self):
        s = net.build_ruleset(core.load_profiles()["isolated-lab"], [], [])
        self.assertEqual(s.count("meta nfproto ipv6 drop"), 2); self.assertNotIn("nd-neighbor", s)
    def test_standard_has_no_ruleset(self):
        self.assertIsNone(net.build_ruleset(core.load_profiles()["standard"]))
    def test_never_touches_baseline_table(self):
        for p in core.load_profiles().values():
            s = net.build_ruleset(p, ["9.9.9.9"], []) or ""
            self.assertNotIn("inet filter", s); self.assertNotIn("flush ruleset", s)


class Verifier(unittest.TestCase):
    """The verifier must refuse to say 'verified' for permissive rules (synthetic nft JSON)."""
    def objs(self, out_rules, policy="drop"):
        o = [{"table": {"family": "inet", "name": "nullos"}},
             {"chain": {"name": "output", "table": "nullos", "family": "inet", "hook": "output", "prio": -10, "policy": policy}}]
        for r in out_rules:
            o.append({"rule": {"family": "inet", "table": "nullos", "chain": "output", "expr": r}})
        return o
    P = prof(outbound=dict(ON, vpn_interfaces=[]))
    def test_unconditional_accept(self):
        ok, why = net.invariants(self.objs([[{"accept": None}]]), self.P, [], [])["outbound"]
        self.assertFalse(ok); self.assertIn("unconditional", why)
    def test_policy_accept(self):
        self.assertFalse(net.invariants(self.objs([], "accept"), self.P, [], [])["outbound"][0])
    def test_open_interface(self):
        r = [[{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "eth0"}}, {"accept": None}]]
        self.assertFalse(net.invariants(self.objs(r), self.P, [], [])["outbound"][0])
    def test_loopback_only_is_fine(self):
        r = [[{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "lo"}}, {"accept": None}]]
        self.assertTrue(net.invariants(self.objs(r), self.P, [], [])["outbound"][0])
    def test_dns_accept_without_resolver_restriction(self):
        r = [[{"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 53}}, {"accept": None}]]
        ok, why = net.invariants(self.objs(r), prof(dns=ON), [], [])["dns"]
        self.assertFalse(ok)
    def test_digest_ignores_counters_and_handles(self):
        a = [{"rule": {"handle": 4, "expr": [{"counter": {"packets": 1, "bytes": 2}}, {"drop": None}]}}]
        b = [{"rule": {"handle": 9, "expr": [{"counter": {"packets": 50, "bytes": 90}}, {"drop": None}]}}]
        self.assertEqual(net.digest(a), net.digest(b))
        c = [{"rule": {"handle": 9, "expr": [{"accept": None}]}}]
        self.assertNotEqual(net.digest(a), net.digest(c))
    def test_overall_never_green_on_failed_required(self):
        S = service.Service
        mk = lambda st, req=True, i="net.dns": {"id": i, "status": st, "required": req}
        self.assertEqual(S.overall([mk("verified"), mk("verified")]), "verified")
        self.assertEqual(S.overall([mk("verified"), mk("failed")]), "degraded")
        self.assertEqual(S.overall([mk("failed", i="net.outbound")]), "failed")
        self.assertEqual(S.overall([mk("verified"), mk("unknown")]), "degraded")
        self.assertEqual(S.overall([mk("verified"), mk("unsupported")]), "degraded")
        self.assertEqual(S.overall([mk("verified"), mk("failed", req=False)]), "verified")
        self.assertEqual(S.overall([mk("verified"), mk("active")]), "active")


class Safety(unittest.TestCase):
    def test_redaction(self):
        r = core.redact({"password": "hunter2", "api_token": "x", "ok": "fine", "n": {"secret_key": "s", "a": 1}})
        s = json.dumps(r); self.assertNotIn("hunter2", s); self.assertNotIn('"s"', s); self.assertIn("fine", s)
    def test_log_rotation_and_tail(self):
        core.LOG.MAX = 2000
        for i in range(80): core.LOG.write("info", "t", "event %d" % i, password="nope")
        self.assertTrue(os.path.exists(core.LOG_FILE + ".1"))
        self.assertNotIn("nope", open(core.LOG_FILE).read())
        self.assertEqual(core.LOG.tail(3)[-1]["msg"], "event 79")
    def test_authorization(self):
        self.assertTrue(core.authorized(0, 0))
        self.assertFalse(core.authorized(65534, 65534, {"authorized_groups": ["sudo"]}))
    def test_state_roundtrip_is_private(self):
        s = core.load_state(); s["mode"] = "restricted"; core.save_state(s)
        self.assertEqual(core.load_state()["mode"], "restricted")
        self.assertEqual(stat.S_IMODE(os.stat(core.STATE_FILE).st_mode), 0o600)
    def test_dispatch_rejects_unknown_and_bad_args(self):
        svc = service.Service()
        for v, a in (("run_shell", {"cmd": "id"}), ("enable", {"profile": "../../etc/passwd"}), ("enable", {"profile": 5}),
                     ("logs", {"n": "x"}), ("custom_set", {"toggles": "x"}), ("audit", {"name": "rm -rf"})):
            with self.assertRaises((ValueError, core.ProfileError)): service.dispatch(svc, v, a, "t")
    def test_lab_ids(self):
        from secd import labs
        for bad in ("", "A1", "1a", "a;b", "a b", "toolongname1", "../x", None, 5): self.assertFalse(labs.valid_id(bad), bad)
        self.assertTrue(labs.valid_id("lab1"))


class Credentials(unittest.TestCase):
    def setUp(self):
        import pwd
        self.home = tempfile.mkdtemp(prefix="home-", dir=TMP)
        self.me = pwd.getpwuid(os.getuid())
        os.makedirs(self.home + "/.ssh", mode=0o755)
        open(self.home + "/.ssh/id_ed25519", "w").write("TOPSECRETKEYMATERIAL"); os.chmod(self.home + "/.ssh/id_ed25519", 0o644)
        open(self.home + "/.aws_dummy", "w").close()
        os.makedirs(self.home + "/.aws"); open(self.home + "/.aws/credentials", "w").write("aws_secret_access_key=ZZZ"); os.chmod(self.home + "/.aws/credentials", 0o600)
        self._h = apps._homes; apps._homes = lambda: [("u", os.getuid(), self.home)]
    def tearDown(self): apps._homes = self._h
    def test_flags_loose_ok_strict_and_never_reads_contents(self):
        real_open = open
        def guard(p, *a, **k):
            if isinstance(p, str) and self.home in p: raise AssertionError("credential audit opened a file: " + p)
            return real_open(p, *a, **k)
        import builtins; builtins.open = guard
        try: found = apps.credential_scan()
        finally: builtins.open = real_open
        by = {os.path.basename(f["path"]): f for f in found}
        self.assertTrue(by["id_ed25519"]["issue"]); self.assertTrue(by["id_ed25519"]["fixable"])
        self.assertTrue(by[".ssh"]["issue"])
        self.assertIsNone(by["credentials"]["issue"])
    def test_fix_tightens_only_group_other_bits(self):
        os.environ["NULLOS_ROOT"] = ""   # paths in findings are absolute
        core.ROOT = ""
        try:
            fixed, skipped = apps.credential_fix()
        finally: core.ROOT = TMP
        self.assertEqual(stat.S_IMODE(os.stat(self.home + "/.ssh/id_ed25519").st_mode) & 0o077, 0)
        self.assertEqual(open(self.home + "/.ssh/id_ed25519").read(), "TOPSECRETKEYMATERIAL")   # content untouched
    def test_env_audit_reports_names_not_values(self):
        p = subprocess.Popen(["sleep", "30"], env={"PATH": "/usr/bin", "MY_API_TOKEN": "VALUE-MUST-NOT-LEAK", "HARMLESS": "x"})
        old = apps.MIN_UID; apps.MIN_UID = 0          # include root-owned processes so the test is not vacuous
        try:
            time.sleep(0.3)
            res = apps.env_secret_names()
            blob = json.dumps(res)
            self.assertIn("MY_API_TOKEN", blob)                   # the NAME is reported
            self.assertNotIn("VALUE-MUST-NOT-LEAK", blob)         # the VALUE never is
            self.assertNotIn("HARMLESS", blob)                    # harmless variables are not listed
            self.assertEqual(res["status"], "degraded")
        finally: apps.MIN_UID = old; p.kill()


class ManagedFiles(unittest.TestCase):
    """Regression: the Privacy profile wrote two NetworkManager drop-ins and the monitor reported them as
    'changes since baseline' (a false alarm on the service's own work)."""
    def test_own_dropins_are_not_flagged(self):
        os.makedirs(os.path.dirname(net.NM_MAC_CONF), exist_ok=True)
        svc = service.Service(); svc.state = core.load_state(); svc.state["baseline"] = {}
        self.assertEqual(sysmon.config_monitor(svc.state)["status"], "verified")       # records baseline
        open(net.NM_MAC_CONF, "w").write("[connection]\nwifi.cloned-mac-address=random\n")
        open(net.NM_DNS_CONF, "w").write("[global-dns-domain-*]\nservers=9.9.9.9\n")
        self.assertEqual(sysmon.config_monitor(svc.state)["status"], "degraded")       # unsynced = would false-alarm
        svc.sync_managed_baseline()
        self.assertEqual(sysmon.config_monitor(svc.state)["status"], "verified")       # synced = quiet
        open(core.P("/etc/hosts"), "w").write("127.0.0.1 evil\n")                      # a REAL foreign change is still caught
        r = sysmon.config_monitor(svc.state); self.assertEqual(r["status"], "degraded"); self.assertIn("/etc/hosts", json.dumps(r["data"]))
        os.unlink(net.NM_MAC_CONF); os.unlink(net.NM_DNS_CONF); svc.sync_managed_baseline()
        self.assertNotIn(net.NM_MAC_CONF[len(core.ROOT):], svc.state["baseline"]["files"])


class AppArmorStatus(unittest.TestCase):
    """Regression for the screenshot: '17 enforcing, 4 complain-only' was shown as DEGRADED."""
    def run_aa(self, enabled, profiles):
        d = tempfile.mkdtemp(dir=TMP); e = d + "/enabled"; p = d + "/profiles"
        if enabled is not None: open(e, "w").write(enabled)
        if profiles is not None: open(p, "w").write(profiles)
        old = (sysmon.AA_ENABLED, sysmon.AA_PROFILES); sysmon.AA_ENABLED, sysmon.AA_PROFILES = e, p
        try: return sysmon.apparmor()
        finally: sysmon.AA_ENABLED, sysmon.AA_PROFILES = old
    def test_ubuntu_default_is_active_not_degraded(self):
        prof = "".join("profile%d (enforce)\n" % i for i in range(17)) + "".join("snap%d (complain)\n" % i for i in range(4))
        r = self.run_aa("Y\n", prof)
        self.assertEqual(r["status"], "active"); self.assertIn("17 profile(s) enforcing", r["detail"]); self.assertIn("4 in complain mode", r["detail"])
    def test_nothing_enforcing_is_degraded(self): self.assertEqual(self.run_aa("Y\n", "a (complain)\nb (complain)\n")["status"], "degraded")
    def test_no_profiles_is_inactive(self): self.assertEqual(self.run_aa("Y\n", "")["status"], "inactive")
    def test_disabled(self): self.assertEqual(self.run_aa("N\n", "")["status"], "inactive")
    def test_not_in_kernel(self):
        old = sysmon.AA_ENABLED; sysmon.AA_ENABLED = TMP + "/nonexistent"
        try: self.assertEqual(sysmon.apparmor()["status"], "unsupported")
        finally: sysmon.AA_ENABLED = old


class Monitor(unittest.TestCase):
    def test_config_diff(self):
        d = sysmon.config_diff({"a": "1", "b": "2", "c": "3"}, {"a": "1", "b": "X", "d": "4"})
        self.assertEqual(d, {"changed": ["b"], "added": ["d"], "removed": ["c"]})
    def test_users_audit_flags_uid0_and_empty_password(self):
        os.makedirs(core.P("/etc"), exist_ok=True)
        open(core.P("/etc/passwd"), "w").write("root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/:/bin/sh\n")
        open(core.P("/etc/shadow"), "w").write("root:!:1:::::\nbob::1:::::\n")
        r = sysmon.users_audit()
        txt = json.dumps(r["data"]); self.assertIn("extra uid-0 account: toor", txt); self.assertIn("empty password", txt)
        self.assertEqual(r["status"], "degraded")


if __name__ == "__main__":
    try: unittest.main(verbosity=1)
    finally: shutil.rmtree(TMP, ignore_errors=True)
