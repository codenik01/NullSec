"""Application/process protection, credential audit and host-integration controls."""
import os
import pwd
import re
import signal
import stat

from . import core
from .core import (ACTIVE, DEGRADED, FAILED, INACTIVE, UNKNOWN, UNSUPPORTED, VERIFIED, check, run)

P = core.P
USB_RULE = P("/etc/udev/rules.d/90-nullos-usb-storage.rules")
CLIP_FLAG = core.P("/run/nullos/block-clipboard")


def _procs():
    try:
        pids = [p for p in os.listdir(("/proc")) if p.isdigit()]
    except OSError:
        return
    for p in pids:
        try:
            with open(("/proc/%s/status" % p)) as f:
                st = dict(l.split(":\t", 1) for l in f.read().splitlines() if ":\t" in l)
            yield int(p), st
        except (OSError, ValueError):
            continue


def _readlink(path):
    try:
        return os.readlink(path)
    except OSError:
        return None


# ---- privilege audit -----------------------------------------------------------------------
def privileged_processes():
    rows = []
    for pid, st in _procs():
        try:
            uids = st["Uid"].split()
            euid = int(uids[1])
            cap = int(st.get("CapEff", "0").strip(), 16)
        except (KeyError, ValueError, IndexError):
            continue
        ppid = int(st.get("PPid", "0") or 0)
        if pid == 2 or ppid == 2:
            continue  # kernel threads
        if euid != 0 and cap == 0:
            continue
        exe = _readlink(("/proc/%d/exe" % pid)) or "?"
        try:
            aa = open(("/proc/%d/attr/current" % pid)).read().strip().split(" (")[0] or "unconfined"
        except OSError:
            aa = "unknown"
        sev = "info"
        if re.match(r"^(/home/|/tmp/|/var/tmp/|/dev/shm/)", exe):
            sev = "high"
        elif exe.endswith("(deleted)"):
            sev = "warn"
        try:
            user = pwd.getpwuid(euid).pw_name
        except KeyError:
            user = str(euid)
        rows.append({"pid": pid, "name": st.get("Name", "?"), "user": user, "caps": "%016x" % cap, "exe": exe,
                     "confinement": aa, "no_new_privs": st.get("NoNewPrivs", "?").strip() == "1", "sev": sev})
    bad = [r for r in rows if r["sev"] != "info"]
    st = DEGRADED if bad else ACTIVE
    return check("app.privileged", "Privileged processes", st,
                 "%d process(es) with root or capabilities; %d running from writable or deleted locations" % (len(rows), len(bad)),
                 "apps", False, None, None, False,
                 ["A process listed as unconfined simply has no AppArmor profile; that is normal without the apparmor package."], rows)


MIN_UID = 1000   # only ordinary users' processes are inspected
_ENVNAME = re.compile(r"(?i)^[A-Z0-9_]*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL)[A-Z0-9_]*$")


def env_secret_names():
    """Names of secret-looking environment variables in user processes. Values are never kept."""
    rows = []
    for pid, st in _procs():
        try:
            if int(st["Uid"].split()[1]) < MIN_UID:
                continue
            with open(("/proc/%d/environ" % pid), "rb") as f:
                raw = f.read(65536)
        except (OSError, KeyError, ValueError):
            continue
        names = sorted({e.split(b"=", 1)[0].decode("ascii", "ignore") for e in raw.split(b"\0") if b"=" in e} )
        hit = [n for n in names if _ENVNAME.match(n)]
        del raw
        if hit:
            rows.append({"pid": pid, "name": st.get("Name", "?"), "variables": hit})
    st = DEGRADED if rows else VERIFIED
    return check("cred.env", "Secrets in environment variables", st, "%d process(es) carry secret-looking variable names" % len(rows),
                 "credentials", False, None, st == VERIFIED, False, ["Only variable NAMES are reported; values are never stored or logged."], rows)


# ---- credential audit --------------------------------------------------------------------
CRED_FILES = [".aws/credentials", ".aws/config", ".azure", ".config/gcloud", ".kube/config", ".docker/config.json",
              ".netrc", ".git-credentials", ".pgpass", ".config/gh/hosts.yml", ".gnupg", ".mozilla", ".config/chromium"]
_KEYNAME = re.compile(r"^(id_[a-z0-9_]+|identity|.*\.pem|.*\.key)$")


def _homes():
    res = []
    try:
        for p in pwd.getpwall():
            if (p.pw_uid >= 1000 and p.pw_uid < 60000 or p.pw_uid == 0) and os.path.isdir(P(p.pw_dir)):
                res.append((p.pw_name, p.pw_uid, P(p.pw_dir)))
    except OSError:
        pass
    return res


def credential_scan():
    """Metadata only: path, mode, owner. File contents are never opened."""
    found = []
    for user, uid, home in _homes():
        cands = []
        ssh = os.path.join(home, ".ssh")
        if os.path.isdir(ssh) and not os.path.islink(ssh):
            cands.append((ssh, True))
            try:
                for e in os.scandir(ssh):
                    if e.is_file(follow_symlinks=False) and _KEYNAME.match(e.name) and not e.name.endswith(".pub"):
                        cands.append((e.path, False))
            except OSError:
                pass
        for rel in CRED_FILES:
            p = os.path.join(home, rel)
            if os.path.lexists(p):
                cands.append((p, os.path.isdir(p) and not os.path.islink(p)))
        for p, isdir in cands:
            try:
                s = os.lstat(p)
            except OSError:
                continue
            if stat.S_ISLNK(s.st_mode):
                found.append({"user": user, "path": p[len(core.ROOT):], "mode": "symlink", "issue": "symlink (not followed)", "fixable": False})
                continue
            mode = stat.S_IMODE(s.st_mode)
            issue = None
            if mode & 0o077:
                issue = "readable/writable by group or others (%s)" % oct(mode)[2:].zfill(4)
            elif s.st_uid != uid:
                issue = "not owned by %s" % user
            found.append({"user": user, "path": p[len(core.ROOT):], "mode": oct(mode)[2:].zfill(4), "issue": issue,
                          "fixable": bool(issue and issue.startswith("readable") and s.st_uid == uid)})
    return found


def credential_audit():
    f = credential_scan()
    bad = [x for x in f if x["issue"]]
    st = DEGRADED if bad else VERIFIED
    return check("cred.files", "Credential file permissions", st, "%d sensitive location(s) found, %d with loose permissions" % (len(f), len(bad)),
                 "credentials", False, None, st == VERIFIED, False,
                 ["Only metadata is read. A secret the current user can read is readable by every program that user runs; permissions alone do not stop that. Use ns-sandbox for untrusted tools."], f)


def credential_fix():
    """Tighten permissions on audit findings. The service re-derives the list itself;
    the client never supplies a path."""
    fixed, skipped = [], []
    for x in credential_scan():
        if not x["fixable"]:
            continue
        p = core.P(x["path"])
        try:
            s = os.lstat(p)
            if stat.S_ISLNK(s.st_mode):
                continue
            new = stat.S_IMODE(s.st_mode) & 0o700   # drop all group/other bits, keep owner bits
            if not new:
                new = 0o700 if stat.S_ISDIR(s.st_mode) else 0o600
            os.chmod(p, new)
            fixed.append(x["path"])
        except OSError as e:
            skipped.append("%s: %s" % (x["path"], e.strerror))
    return fixed, skipped


# ---- host/guest integration -------------------------------------------------------------------
SHARE_FS = ("vboxsf", "9p", "virtiofs", "fuse.vmhgfs-fuse", "vmhgfs", "fuse.sshfs", "nfs", "nfs4", "cifs")


def virt_type():
    rc, out, _ = run(["systemd-detect-virt"])
    v = out.strip()
    return None if rc != 0 or v in ("", "none") else v


def mounts_audit():
    rows = []
    try:
        with open(("/proc/mounts")) as f:
            for ln in f:
                p = ln.split()
                if len(p) >= 3 and p[2] in SHARE_FS:
                    rows.append({"source": p[0], "mountpoint": p[1], "type": p[2]})
    except OSError:
        return check("host.mounts", "Shared-folder / network mounts", UNKNOWN, "cannot read mount table", "host")
    return check("host.mounts", "Shared-folder / network mounts", ACTIVE if rows else VERIFIED,
                 "%d shared or network mount(s) visible to this system" % len(rows), "host", False, None, not rows, False,
                 ["The guest cannot see every host-side sharing mechanism; configure the hypervisor to remove shares."], rows)


_CLIP_PROCS = ("spice-vdagent", "vmware-user", "vmware-user-suid-wrapper", "vmtoolsd")


def _clip_agents():
    found = []
    for pid, st in _procs():
        name = st.get("Name", "").strip()
        try:
            cmd = open(("/proc/%d/cmdline" % pid), "rb").read().replace(b"\0", b" ").decode("ascii", "ignore")
        except OSError:
            cmd = ""
        if name in ("spice-vdagent", "vmware-user", "vmware-user-suid-wrapper") or (name == "VBoxClient" and ("--clipboard" in cmd or "--draganddrop" in cmd)):
            found.append((pid, name))
    return found


def apply_clipboard():
    v = virt_type()
    if not v:
        return None, "not running in a virtual machine: no guest clipboard agent to stop", None
    try:
        os.makedirs(os.path.dirname(CLIP_FLAG), exist_ok=True)
        open(CLIP_FLAG, "w").close()
    except OSError as e:
        return False, "could not create %s: %s" % (CLIP_FLAG, e), None
    run(["systemctl", "stop", "spice-vdagentd.service", "spice-vdagentd.socket"])
    for pid, _ in _clip_agents():
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    return True, "guest clipboard/drag-and-drop agents stopped", {"control": "clipboard", "what": "stopped guest clipboard agents (%s)" % v,
                                                                   "revert": "restart agents (ns-autostart)"}


def remove_clipboard():
    try:
        os.unlink(CLIP_FLAG)
    except OSError:
        pass
    run(["systemctl", "start", "spice-vdagentd.socket"])
    return True


def verify_clipboard(profile):
    req = bool((profile.get("controls", {}).get("clipboard") or {}).get("required"))
    lim = ["Only the guest side can be checked. Clipboard and shared-folder features implemented by the hypervisor must also be disabled in VirtualBox/VMware/UTM/QEMU settings."]
    v = virt_type()
    if not v:
        return check("host.clipboard", "Clipboard sharing", UNSUPPORTED, "not a virtual machine: nothing to restrict", "host", True, False, None, req, lim)
    running = _clip_agents()
    if running or not os.path.exists(CLIP_FLAG):
        return check("host.clipboard", "Clipboard sharing", FAILED if not running else DEGRADED,
                     "guest agent still running: %s" % ", ".join(n for _, n in running) if running else "block flag missing", "host", True, True, False, req, lim)
    return check("host.clipboard", "Clipboard sharing", ACTIVE, "guest agents stopped (hypervisor: %s); host-side sharing is not verifiable from inside the guest" % v,
                 "host", True, True, None, req, lim)


def usb_rule_text():
    return ('# managed by NullOS Security Center: desktop (udisks) ignores USB mass storage\n'
            'SUBSYSTEM=="block", ENV{ID_BUS}=="usb", ENV{UDISKS_IGNORE}="1"\n')


def apply_usb():
    try:
        core.atomic_write(USB_RULE, usb_rule_text(), 0o644)
    except OSError as e:
        return False, "could not write %s: %s" % (USB_RULE, e), None
    run(["udevadm", "control", "--reload"])
    run(["udevadm", "trigger", "--subsystem-match=block", "--action=change"])
    return True, "udev rule installed", {"control": "usb_storage", "what": "wrote %s" % USB_RULE, "revert": "remove the file"}


def remove_usb():
    existed = os.path.exists(USB_RULE)
    try:
        os.unlink(USB_RULE)
    except OSError:
        pass
    if existed:
        run(["udevadm", "control", "--reload"])
        run(["udevadm", "trigger", "--subsystem-match=block", "--action=change"])
    return True


def verify_usb(profile):
    req = bool((profile.get("controls", {}).get("usb_storage") or {}).get("required"))
    lim = ["Blocks desktop mounting through udisks (Files, auto-mount). Root can still mount a device by hand and the kernel storage driver stays loaded; it is not a hardware port lock."]
    if not os.path.exists(USB_RULE):
        return check("host.usb", "USB storage policy", FAILED, "udev rule is missing", "host", True, False, False, req, lim)
    if not core.have("udevadm"):
        return check("host.usb", "USB storage policy", UNKNOWN, "rule installed; udevadm unavailable to test", "host", True, True, None, req, lim)
    usb, ignored = 0, 0
    try:
        names = os.listdir(("/sys/class/block"))
    except OSError:
        names = []
    for n in names:
        if not re.match(r"^[a-z0-9]+$", n):
            continue
        rc, out, _ = run(["udevadm", "info", "-q", "property", "-n", "/dev/" + n])
        if "ID_BUS=usb" in out:
            usb += 1
            if "UDISKS_IGNORE=1" in out:
                ignored += 1
    if usb == 0:
        return check("host.usb", "USB storage policy", ACTIVE, "rule installed; no USB storage attached right now to test it on", "host", True, True, None, req, lim)
    if ignored == usb:
        return check("host.usb", "USB storage policy", VERIFIED, "%d attached USB storage device(s) are ignored by the desktop" % usb, "host", True, True, True, req, lim)
    return check("host.usb", "USB storage policy", DEGRADED, "%d of %d attached USB storage device(s) are still visible to the desktop" % (usb - ignored, usb), "host", True, True, False, req, lim)
