"""NullOS security service - shared core.

Paths, the status vocabulary, the event log, persistent state, profile loading and
validation, caller authorisation and a safe command runner.  Standard library only.
"""
import grp
import hashlib
import ipaddress
import json
import os
import pwd
import re
import subprocess
import syslog
import tempfile
import threading
import time

VERSION = "1.0.0"

# NULLOS_ROOT relocates every path (used by the test-suite; empty on a real system).
ROOT = os.environ.get("NULLOS_ROOT", "")


def P(path):
    return ROOT + path


STATE_DIR = P("/var/lib/nullos")
LOG_DIR = P("/var/log/nullos")
RUN_DIR = P("/run/nullos")
SOCK_PATH = os.environ.get("NULLOS_SOCK", RUN_DIR + "/secd.sock")
STATE_FILE = STATE_DIR + "/state.json"
CUSTOM_FILE = STATE_DIR + "/custom.json"
LOG_FILE = LOG_DIR + "/security.log"
SUMMARY_FILE = os.environ.get("NULLOS_SUMMARY", RUN_DIR + "/status.json")
CONF_FILE = P("/etc/nullos/secd.conf")
PROFILE_DIRS = [os.environ.get("NULLOS_PROFILES", P("/usr/share/nullos/profiles")),
                P("/etc/nullos/profiles.d")]
SYS_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"

# ---- status vocabulary (spec 4.2) -------------------------------------------------
VERIFIED, ACTIVE, INACTIVE = "verified", "active", "inactive"
UNSUPPORTED, FAILED, UNKNOWN, DEGRADED = "unsupported", "failed", "unknown", "degraded"
ALL_STATUS = (VERIFIED, ACTIVE, INACTIVE, UNSUPPORTED, FAILED, UNKNOWN, DEGRADED)


def check(cid, title, status, detail="", area="system", requested=None, applied=None,
          verified=None, required=False, limits=None, data=None):
    """One control result.  requested/applied/verified are kept separate on purpose:
    a click proves nothing, an accepted request proves nothing, only inspection does."""
    assert status in ALL_STATUS, status
    return {"id": cid, "title": title, "area": area, "status": status, "detail": detail,
            "requested": requested, "applied": applied, "verified": verified,
            "required": required, "limits": list(limits or []), "data": data}


# ---- command runner ---------------------------------------------------------------
def run(cmd, timeout=15, stdin=None):
    """Run a fixed argv (never a shell string). Returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin,
                           env={"PATH": SYS_PATH, "LC_ALL": "C", "LANG": "C"})
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "%s: not found" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "%s: timed out" % cmd[0]
    except OSError as e:
        return 126, "", "%s: %s" % (cmd[0], e)


def have(binary):
    for d in SYS_PATH.split(":"):
        if os.access(os.path.join(d, binary), os.X_OK):
            return True
    return False


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write(path, data, mode=0o600):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---- event log (spec 5.3: security event log; 5.4: never log secret values) --------
_SECRET_KEY = re.compile(r"(pass|secret|token|key|cred|cookie|auth)", re.I)


def redact(obj, depth=0):
    if depth > 6:
        return "[truncated]"
    if isinstance(obj, dict):
        return {str(k): ("[redacted]" if _SECRET_KEY.search(str(k)) and not str(k).endswith("_name")
                         else redact(v, depth + 1)) for k, v in list(obj.items())[:60]}
    if isinstance(obj, (list, tuple)):
        return [redact(v, depth + 1) for v in list(obj)[:60]]
    if isinstance(obj, bytes):
        return "[bytes]"
    if isinstance(obj, str):
        return obj[:400]
    return obj


class EventLog:
    MAX = 1024 * 1024
    KEEP = 3

    def __init__(self):
        self.lock = threading.Lock()

    def write(self, level, kind, msg, **data):
        rec = {"ts": int(time.time()), "level": level, "kind": kind, "msg": msg[:300],
               "data": redact(data)}
        line = json.dumps(rec, sort_keys=True)
        with self.lock:
            try:
                os.makedirs(LOG_DIR, exist_ok=True)
                try:
                    if os.path.getsize(LOG_FILE) > self.MAX:
                        for i in range(self.KEEP, 0, -1):
                            src = LOG_FILE + ("." + str(i - 1) if i > 1 else "")
                            if os.path.exists(src):
                                os.replace(src, LOG_FILE + "." + str(i))
                except OSError:
                    pass
                fd = os.open(LOG_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
                with os.fdopen(fd, "a") as f:
                    f.write(line + "\n")
            except OSError:
                pass  # logging must never take the service down
        try:
            syslog.openlog("nullos-secd")
            syslog.syslog({"error": syslog.LOG_ERR, "warn": syslog.LOG_WARNING}.get(level, syslog.LOG_INFO),
                          "%s: %s" % (kind, msg[:300]))
        except Exception:
            pass
        return rec

    def tail(self, n=100, kind=None):
        n = max(1, min(int(n), 1000))
        out = []
        try:
            with open(LOG_FILE) as f:
                lines = f.readlines()[-(n * 4):]
        except OSError:
            return out
        for ln in lines:
            try:
                r = json.loads(ln)
            except ValueError:
                continue
            if kind is None or r.get("kind") == kind:
                out.append(r)
        return out[-n:]


LOG = EventLog()


# ---- persistent state ---------------------------------------------------------------
DEFAULT_STATE = {"mode": "standard", "profile": "standard", "profile_version": None,
                 "requested_at": None, "applied_at": None, "kill": False,
                 "kill_disconnect": False, "changes": [], "expected": {}, "baseline": {},
                 "last_result": None, "pending_reconnect": []}


def load_state():
    try:
        with open(STATE_FILE) as f:
            s = json.load(f)
        merged = dict(DEFAULT_STATE)
        merged.update(s)
        return merged
    except (OSError, ValueError):
        return json.loads(json.dumps(DEFAULT_STATE))


def save_state(s):
    atomic_write(STATE_FILE, json.dumps(s, indent=1, sort_keys=True))


def load_conf():
    conf = {"authorized_groups": ["sudo"], "monitor_interval": 30}
    try:
        with open(CONF_FILE) as f:
            conf.update(json.load(f))
    except (OSError, ValueError):
        pass
    return conf


# ---- profiles (versioned, documented, validated: spec 4.3 / 8) -----------------------
class ProfileError(ValueError):
    pass


CONTROLS = ("outbound", "inbound", "dns", "ipv6", "mac", "usb_storage", "clipboard", "monitor")
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
_IFPAT = re.compile(r"^[a-z][a-z0-9]{0,9}\*?$")


def _bool(d, k, default=False):
    v = d.get(k, default)
    if not isinstance(v, bool):
        raise ProfileError("%s must be true/false" % k)
    return v


def _ports(d, k):
    v = d.get(k, [])
    if not isinstance(v, list) or len(v) > 64:
        raise ProfileError("%s must be a list of at most 64 ports" % k)
    for p in v:
        if not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535:
            raise ProfileError("%s: invalid port %r" % (k, p))
    return v


def validate_profile(p):
    """Strict validation. Anything unknown is an error: a profile must not silently
    claim a control the service does not implement."""
    if not isinstance(p, dict):
        raise ProfileError("profile must be an object")
    if p.get("schema") != 1:
        raise ProfileError("unsupported schema")
    if not isinstance(p.get("id"), str) or not _ID.match(p["id"]):
        raise ProfileError("bad id")
    if not isinstance(p.get("name"), str) or not 1 <= len(p["name"]) <= 48:
        raise ProfileError("bad name")
    if not isinstance(p.get("version"), str) or not _SEMVER.match(p["version"]):
        raise ProfileError("bad version (want x.y.z)")
    if not isinstance(p.get("description", ""), str) or len(p.get("description", "")) > 400:
        raise ProfileError("bad description")
    if p.get("on_failure", "report") not in ("report", "fallback-deny"):
        raise ProfileError("bad on_failure")
    ctl = p.get("controls")
    if not isinstance(ctl, dict):
        raise ProfileError("controls missing")
    for name, c in ctl.items():
        if name not in CONTROLS:
            raise ProfileError("unknown control %r" % name)
        if not isinstance(c, dict):
            raise ProfileError("control %s must be an object" % name)
        _bool(c, "enabled")
        _bool(c, "required")
        if name == "outbound":
            if c.get("default", "drop") not in ("drop",):
                raise ProfileError("outbound.default must be drop")
            _ports(c, "allow_tcp")
            _ports(c, "allow_udp")
            _bool(c, "allow_icmp", True)
            hosts = c.get("allow_hosts", [])
            if not isinstance(hosts, list) or len(hosts) > 64:
                raise ProfileError("allow_hosts: at most 64 entries")
            for h in hosts:
                try:
                    ipaddress.ip_network(h, strict=False)
                except (ValueError, TypeError):
                    raise ProfileError("allow_hosts: bad address %r" % (h,))
            vi = c.get("vpn_interfaces", [])
            if not isinstance(vi, list) or len(vi) > 8 or not all(isinstance(x, str) and _IFPAT.match(x) for x in vi):
                raise ProfileError("vpn_interfaces: bad pattern")
        elif name == "inbound":
            _bool(c, "drop_new_on_vpn", True)
            _bool(c, "allow_ping", False)
        elif name == "dns":
            if c.get("mode", "system") not in ("system", "pinned"):
                raise ProfileError("dns.mode must be system or pinned")
            _bool(c, "block_dot", True)
            _bool(c, "allow_via_vpn", True)
            sv = c.get("servers", [])
            if not isinstance(sv, list) or len(sv) > 8:
                raise ProfileError("dns.servers: at most 8")
            for s in sv:
                try:
                    ipaddress.ip_address(s)
                except (ValueError, TypeError):
                    raise ProfileError("dns.servers: bad address %r" % (s,))
            if c.get("mode") == "pinned" and not sv:
                raise ProfileError("dns.mode pinned needs servers")
        elif name == "ipv6":
            if c.get("mode", "same") not in ("same", "block"):
                raise ProfileError("ipv6.mode must be same or block")
        elif name == "mac":
            for k in ("wifi", "ethernet"):
                if c.get(k, "preserve") not in ("preserve", "random", "stable"):
                    raise ProfileError("mac.%s: bad value" % k)
            _bool(c, "reconnect", True)
        elif name == "usb_storage":
            if c.get("mode", "block-desktop-mount") != "block-desktop-mount":
                raise ProfileError("usb_storage.mode unsupported")
        elif name == "clipboard":
            if c.get("mode", "block") != "block":
                raise ProfileError("clipboard.mode unsupported")
        elif name == "monitor":
            iv = c.get("interval", 30)
            if not isinstance(iv, int) or isinstance(iv, bool) or not 10 <= iv <= 3600:
                raise ProfileError("monitor.interval must be 10..3600")
    return p


def ctl(profile, name):
    """Return the control dict if enabled, else None."""
    c = profile.get("controls", {}).get(name)
    return c if c and c.get("enabled") else None


def load_profiles():
    """Shipped profiles first, then /etc/nullos/profiles.d (a same id there overrides)
    and the generated custom profile. Invalid files are skipped and logged."""
    out = {}
    files = []
    for i, d in enumerate(PROFILE_DIRS):
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        files += [(os.path.join(d, n), "builtin" if i == 0 else "local") for n in names if n.endswith(".json")]
    if os.path.exists(CUSTOM_FILE):
        files.append((CUSTOM_FILE, "custom"))
    for path, src in files:
        try:
            with open(path) as f:
                prof = validate_profile(json.load(f))
            prof["source"] = src
            out[prof["id"]] = prof
        except (OSError, ValueError) as e:  # ProfileError is a ValueError
            LOG.write("warn", "profile", "skipped invalid profile file", file=os.path.basename(path), error=str(e))
    return out


# ---- authorisation -------------------------------------------------------------------
def caller_groups(uid, gid):
    try:
        name = pwd.getpwuid(uid).pw_name
        return {grp.getgrgid(g).gr_name for g in os.getgrouplist(name, gid)}
    except (KeyError, OSError):
        return set()


def authorized(uid, gid, conf=None):
    """root, or a member of an authorised group (default: sudo). The socket file mode
    is the first gate, this is the second."""
    if uid == 0:
        return True
    conf = conf or load_conf()
    return bool(caller_groups(uid, gid) & set(conf.get("authorized_groups", ["sudo"])))
