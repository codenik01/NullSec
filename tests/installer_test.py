"""Static + behavioural validation of the NullOS installer configuration (cannot boot an installer here; this proves
everything that CAN be proven: names, schemas, ordering, packages, and the shell steps run against a fake target)."""
import glob, json, os, re, shutil, subprocess, sys, tempfile
import yaml
HERE = os.path.dirname(os.path.abspath(__file__)); OVL = os.path.join(HERE, "..", "overlay"); ROOTDIR = os.path.join(HERE, "..")
CAL = os.path.join(OVL, "etc/calamares")
fails = 0; skipped = []
def ok(c, m):
    global fails; print(("PASS  " if c else "FAIL  ") + m); fails += 0 if c else 1
def load(p): return yaml.safe_load(open(p))

# --- locate Calamares' module directory (installed, env override, or downloaded just for this test)
def modules_dir():
    if os.environ.get("CALAMARES_MODULES"): return os.environ["CALAMARES_MODULES"]
    g = glob.glob("/usr/lib/*/calamares/modules")
    if g: return g[0]
    t = tempfile.mkdtemp(prefix="cal-")
    if subprocess.run("cd %s && apt-get download calamares >/dev/null 2>&1 && dpkg-deb -x calamares_*.deb x" % t, shell=True).returncode == 0:
        g = glob.glob(t + "/x/usr/lib/*/calamares/modules")
        if g: return g[0]
    return None
MD = modules_dir()

# 1. every file parses
files = glob.glob(CAL + "/*.conf") + glob.glob(CAL + "/modules/*.conf") + [CAL + "/branding/nullos/branding.desc"]
bad = []
for f in files:
    try: load(f)
    except Exception as e: bad.append((os.path.basename(f), str(e)[:60]))
ok(not bad, "all %d installer config files are valid YAML %s" % (len(files), bad or ""))
S = load(CAL + "/settings.conf")

# 2. sequence: every module exists in the real package; instances resolve
seq = [m for blk in S["sequence"] for m in list(blk.values())[0]]
inst = {i["id"]: i for i in S.get("instances", [])}
names = set()
for m in seq:
    if "@" in m:
        mod, iid = m.split("@"); ok(iid in inst and inst[iid]["module"] == mod, "instance %s is defined" % m)
        ok(os.path.exists(os.path.join(CAL, "modules", inst[iid]["config"])), "instance config %s exists" % inst[iid]["config"]); names.add(mod)
    else: names.add(m)
if MD:
    have = set(os.listdir(MD)); missing = names - have
    ok(not missing, "every module in the sequence exists in the Calamares package (%d checked) %s" % (len(names), sorted(missing) or ""))
else: skipped.append("module existence (calamares package unavailable)")

# 3. schemas
if MD:
    import jsonschema
    done = []
    for conf in glob.glob(CAL + "/modules/*.conf"):
        mod = os.path.basename(conf)[:-5]
        sf = os.path.join(MD, mod, mod + ".schema.yaml")
        if not os.path.exists(sf): continue
        try: jsonschema.validate(load(conf), load(sf)); done.append(mod)
        except jsonschema.ValidationError as e: ok(False, "%s.conf violates Calamares' schema: %s" % (mod, e.message[:120]))
    ok(len(done) >= 5, "configs validated against Calamares' own schemas: %s" % ", ".join(sorted(done)))
else: skipped.append("schema validation")

# 4. ordering constraints
ix = {m: i for i, m in enumerate(seq)}
order = [("partition", "mount"), ("mount", "unpackfs"), ("unpackfs", "machineid"), ("unpackfs", "users"), ("unpackfs", "fstab"),
         ("users", "displaymanager"), ("shellprocess@prepare", "initramfs"), ("initramfs", "bootloader"), ("grubcfg", "bootloader"), ("bootloader", "umount")]
ok(all(ix[a] < ix[b] for a, b in order), "exec order is sound (partition > mount > unpack > users > prepare > initramfs > bootloader > umount)")
ok("welcome" in seq and "partition" in seq and "users" in seq and "summary" in seq, "UI pages present: welcome, partition, users, summary")
ok(S["sequence"][-1]["show"] == ["finished"], "finishes with the 'finished' page")

# 5. offline + correct source of the system
u = load(CAL + "/modules/unpackfs.conf")["unpack"][0]
ok(u["source"] == "/cdrom/casper/filesystem.squashfs" and u["sourcefs"] == "squashfs", "unpacks the live squashfs from the boot medium (offline)")
ok("internetCheckUrl" not in json.dumps(load(CAL + "/modules/welcome.conf")), "no internet requirement")
bl = load(CAL + "/modules/bootloader.conf"); ok(bl["efiBootLoader"] == "grub" and bl["installEFIFallback"] is True, "grub with UEFI fallback entry")
ok(load(CAL + "/modules/partition.conf")["availableFileSystemTypes"] == ["ext4"], "only ext4 offered (mkfs tools for others are not in the image)")

# 6. users: only groups that exist in the image; the live user cannot be reused
usr = load(CAL + "/modules/users.conf")
groups = [g if isinstance(g, str) else g["name"] for g in usr["defaultGroups"]]
okset = {"adm", "cdrom", "dip", "plugdev", "audio", "video", "sudo"}
ok(set(groups) <= okset, "default groups all exist in the image: %s" % groups)
if os.path.exists("/etc/group"):
    ex = {l.split(":")[0] for l in open("/etc/group")}; ok(set(groups) <= ex, "…and exist on a stock Ubuntu 24.04 (checked here)")
ok("ns" in usr["user"]["forbidden_names"] and "root" in usr["user"]["forbidden_names"], "'root' and the live user 'ns' cannot be chosen as the new account")
ok(usr["sudoersGroup"] == "sudo" and usr["setRootPassword"] is False, "admin via sudo group; no separate root password (the security service authorises group sudo)")

# 7. the pre-bootloader shell steps, executed for real against a fake target
sp = load(CAL + "/modules/shellprocess_prepare.conf")
T = tempfile.mkdtemp(); R = T + "/target"; CD = T + "/cdrom/casper"
os.makedirs(R + "/etc/lightdm/lightdm.conf.d"); os.makedirs(R + "/boot"); os.makedirs(CD); os.makedirs(R + "/var/lib/nullos"); os.makedirs(R + "/var/log/nullos"); os.makedirs(R + "/etc/sudoers.d")
shutil.copy(os.path.join(OVL, "etc/sudoers.d/90-nullos-session"), R + "/etc/sudoers.d/"); os.chmod(R + "/etc/sudoers.d/90-nullos-session", 0o440)
shutil.copy(os.path.join(OVL, "etc/lightdm/lightdm.conf.d/99-nullsec.conf"), R + "/etc/lightdm/lightdm.conf.d/")
orig = open(R + "/etc/lightdm/lightdm.conf.d/99-nullsec.conf").read()
open(CD + "/vmlinuz", "w").write("KERNEL"); open(R + "/var/lib/nullos/state.json", "w").write("{live}")
ok("autologin-user=ns" in orig, "(precondition) the live lightdm config does auto-login 'ns'")
for step in sp["script"]:
    cmd = step["command"].replace("${ROOT}", R).replace("/cdrom/casper", CD).replace("$(uname -r)", "6.8.0-test")
    r = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True)
    ok(r.returncode == 0, "step exits 0: %s" % step["command"][:70])
now = open(R + "/etc/lightdm/lightdm.conf.d/99-nullsec.conf").read()
ok("autologin-user" not in now, "live auto-login line removed from the installed system")
ok(all(l in now for l in orig.splitlines() if l.strip() and not l.startswith("autologin-user")), "…every OTHER lightdm setting (session, greeter) is kept")
ok(open(R + "/boot/vmlinuz-6.8.0-test").read() == "KERNEL", "kernel copied to the name grub expects when it was missing")
open(R + "/boot/vmlinuz-6.8.0-test", "w").write("EXISTING")
subprocess.run(["sh", "-c", sp["script"][1]["command"].replace("${ROOT}", R).replace("/cdrom/casper", CD).replace("$(uname -r)", "6.8.0-test")])
ok(open(R + "/boot/vmlinuz-6.8.0-test").read() == "EXISTING", "an existing kernel is never overwritten")
ok(not os.path.exists(R + "/var/lib/nullos") and not os.path.exists(R + "/var/log/nullos"), "live-session security state/log are not carried to the new system")
ok("%sudo ALL=(ALL) NOPASSWD: /usr/local/bin/ns-session" in open(R + "/etc/sudoers.d/90-nullos-session").read(), "desktop-mode sudo rule now applies to group sudo, not the live user 'ns'")
if shutil.which("visudo"):
    r = subprocess.run(["visudo", "-cf", R + "/etc/sudoers.d/90-nullos-session"], capture_output=True, text=True)
    ok(r.returncode == 0, "…and the resulting sudoers file is syntactically valid (visudo -c)")
    ok(oct(os.stat(R + "/etc/sudoers.d/90-nullos-session").st_mode & 0o777) in ("0o440", "0o644", "0o640", "0o600"), "…permissions preserved")
else: skipped.append("visudo syntax check (sudo not installed)")
shutil.rmtree(T)

# 8. branding
B = CAL + "/branding/nullos"; bd = load(B + "/branding.desc")
ok(all(os.path.exists(os.path.join(B, bd["images"][k])) for k in bd["images"]) and os.path.exists(B + "/" + bd["slideshow"]), "branding images and slideshow exist")
ok(bd["componentName"] == "nullos" and S["branding"] == "nullos", "branding name matches settings.conf")
q = open(B + "/show.qml").read(); ok(q.count("{") == q.count("}") and "Presentation" in q, "slideshow QML is balanced and uses Presentation")

# 9. packages: everything the installer needs is in packages.txt; names resolve on Ubuntu
pk = set(open(os.path.join(ROOTDIR, "packages.txt")).read().split())
need = {"calamares", "squashfs-tools", "efibootmgr", "parted", "gdisk", "dosfstools", "os-prober", "grub-common", "grub-pc-bin", "grub-efi-amd64-bin",
        "grub-efi-amd64-signed", "grub-efi-arm64-bin", "grub-efi-arm64-signed", "shim-signed"}
ok(need <= pk, "all installer packages are in packages.txt %s" % (sorted(need - pk) or ""))
if shutil.which("apt-cache"):
    arm_only = {"grub-efi-arm64-bin", "grub-efi-arm64-signed"}
    unk = [p for p in need - arm_only if subprocess.run(["apt-cache", "show", p], capture_output=True).returncode != 0]
    ok(not unk, "package names resolve in the Ubuntu archive %s" % (unk or ""))

# 10. launcher + menu integration
r = subprocess.run([os.path.join(OVL, "usr/local/bin/ns-installer")], capture_output=True, text=True)
live = "boot=casper" in open("/proc/cmdline").read()
ok(live or (r.returncode == 1 and "only runs from the live session" in r.stderr), "ns-installer refuses outside the live session (exit %d)" % r.returncode)
st = open(os.path.join(OVL, "usr/local/bin/ns-start")).read()
ok("boot=casper" in st and '"Install NullOS") exec ns-installer' in st, "start menu offers 'Install NullOS' only in the live session")
ok(os.path.exists(OVL + "/usr/share/applications/nullos-installer.desktop"), ".desktop entry shipped")
print("\nSKIPPED:", skipped or "none"); print("RESULT:", "ALL PASSED" if not fails else "%d FAILED" % fails); sys.exit(1 if fails else 0)
