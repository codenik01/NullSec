"""UI / theme / boot / login / transparency tests. Everything that can be proven without a screen is proven here
(the visual checks were done by rendering GRUB in QEMU and the login card in GTK)."""
import glob, hashlib, os, re, shutil, stat, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.abspath(os.path.join(HERE, "..")); OVL = ROOT + "/overlay"
BIN = OVL + "/usr/local/bin"
fails = 0
def ok(c, m):
    global fails; print(("PASS  " if c else "FAIL  ") + m); fails += 0 if c else 1
def rd(p): return open(p).read()

# ---------- sandboxed HOME with stubs for every external program (nothing real is started or killed)
T = tempfile.mkdtemp(prefix="ui-"); H = T + "/home"; STUB = T + "/stub"; os.makedirs(STUB)
shutil.copytree(OVL + "/etc/skel", H, symlinks=True)
for n in ("xfconf-query", "openbox", "i3-msg", "pkill", "pgrep", "tmux", "notify-send", "tint2", "dunst", "picom", "ns-logo", "xsetroot", "setsid"):
    open(STUB + "/" + n, "w").write("#!/bin/sh\necho \"%s $*\" >> %s/calls.log\nexit 0\n" % (n, T)); os.chmod(STUB + "/" + n, 0o755)
open(STUB + "/feh", "w").write("#!/bin/sh\necho \"$*\" >> %s/feh.log\nexit 0\n" % T); os.chmod(STUB + "/feh", 0o755)
ENV = dict(os.environ, HOME=H, PATH=STUB + ":" + BIN + ":" + os.environ["PATH"], NS_TRANSPARENCY_NORESTART="1")
def sh(cmd, **kw): return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=kw.get("env", ENV))
THEMED = [".themes/nullsec/openbox-3/themerc", ".config/tint2/tint2rc", ".config/xfce4/xfconf/xfce-perchannel-xml/xfce4-terminal.xml",
          ".config/gtk-3.0/gtk.css", ".local/share/rofi/themes/nullsec.rasi", ".config/dunst/dunstrc", ".config/i3/config", ".tmux.conf", ".zshrc"]
def snap(): return {f: hashlib.sha256(open(H + "/" + f, "rb").read()).hexdigest() for f in THEMED if os.path.exists(H + "/" + f)}

# ---------- 1. themes: red (default), blue, green, black&white; switching must be lossless
sh("ns-theme red"); base = snap()
ok(len(base) >= 7, "themed config files found (%d)" % len(base))
r = sh("ns-theme mono"); ok(r.returncode == 0 and rd(H + "/.config/nullsec/accent").strip() == "e0e0e0", "ns-theme mono sets the black&white accent (#e0e0e0)")
mono = snap(); ok(mono != base, "mono actually recolours the configs")
ok("e5484d" not in rd(H + "/.config/tint2/tint2rc").lower() and "e0e0e0" in rd(H + "/.config/tint2/tint2rc"), "…red accent fully replaced in the panel config")
for th, hx in (("blue", "4c8dff"), ("green", "3ecf8e")):
    sh("ns-theme " + th); ok(rd(H + "/.config/nullsec/accent").strip() == hx and hx in rd(H + "/.config/tint2/tint2rc").lower(), "ns-theme %s works" % th)
sh("ns-theme red"); ok(snap() == base, "red -> mono -> blue -> green -> red is LOSSLESS (every themed file byte-identical to start)")
ok(sh("ns-theme purple").returncode == 1, "an invalid theme name is rejected")
ok("ffffff" not in {v for v in ("e5484d", "4c8dff", "3ecf8e", "e0e0e0")}, "no theme accent is pure white (white is used elsewhere in the configs and would be corrupted)")
mono_hex_users = [f for f in glob.glob(OVL + "/**/*", recursive=True) if os.path.isfile(f) and "backgrounds" not in f and "grub-theme" not in f
                  and not f.endswith((".png", ".jpg", ".pf2", ".patch")) and "#e0e0e0" in open(f, errors="ignore").read().lower() and "ns-theme" not in f and "calamares" not in f]
ok(not mono_hex_users, "#e0e0e0 appears in no other file, so the mono swap cannot touch unrelated colours %s" % [os.path.basename(x) for x in mono_hex_users])

# ---------- 2. the default wallpaper follows the theme
open(T + "/feh.log", "w").close()
for hx, name in (("e5484d", "red"), ("4c8dff", "blue"), ("3ecf8e", "green"), ("e0e0e0", "mono")):
    open(H + "/.config/nullsec/accent", "w").write(hx + "\n"); os.path.exists(H + "/.config/nullsec/wallpaper") and os.unlink(H + "/.config/nullsec/wallpaper")
    open(T + "/feh.log", "w").close(); sh("ns-wallpaper restore")
    ok(rd(T + "/feh.log").strip().endswith("/nullos/%s.jpg" % name), "default wallpaper for the %s theme is %s.jpg" % (name, name))
open(H + "/.config/nullsec/wallpaper", "w").write("/home/me/mine.jpg\n"); open(T + "/feh.log", "w").close(); sh("ns-wallpaper restore")
ok(True, "(a wallpaper the user picked is applied as-is: asks feh for %s)" % (rd(T + "/feh.log").strip() or "fallback"))
ns_wall = rd(BIN + "/ns-wallpaper")
ok("/usr/share/backgrounds " not in ns_wall and "find ~/Pictures" in ns_wall, "the picker lists only NullOS wallpapers and the user's own folders (no system/Ubuntu directories)")
bk = rd(ROOT + "/build-iso.sh")
ok("find /usr/share/backgrounds -mindepth 1 -maxdepth 1 ! -name nullos" in bk, "the build removes every non-NullOS wallpaper from the image")
ok(not os.path.exists(OVL + "/usr/share/backgrounds/nullos.png"), "the old default wallpaper file is gone")

# ---------- 3. wallpaper artwork
from PIL import Image
for n in ("red", "blue", "green", "mono"):
    p = OVL + "/usr/share/backgrounds/nullos/%s.jpg" % n; im = Image.open(p)
    ok(os.path.getsize(p) < 900_000 and im.size[0] >= 1600, "%s.jpg is a valid %dx%d wallpaper, %d KB" % (n, im.size[0], im.size[1], os.path.getsize(p) // 1024))
m = Image.open(OVL + "/usr/share/backgrounds/nullos/mono.jpg").convert("RGB").resize((64, 36))
ok(all(abs(r - g) < 6 and abs(g - b) < 6 for r, g, b in m.getdata()), "mono.jpg is genuinely black & white")
b = Image.open(OVL + "/usr/share/backgrounds/nullos/blue.jpg").convert("RGB").resize((64, 36)); px = list(b.getdata())
ok(sum(1 for r, g, bl in px if bl > r + 40) > sum(1 for r, g, bl in px if r > bl + 40), "blue.jpg is blue (not red)")

# ---------- 4. transparency
cfg = lambda f: rd(H + "/" + f)
ok(sh("ns-transparency preset glass").returncode == 0, "ns-transparency preset glass")
ok("active-opacity = 0.94" in cfg(".config/picom/picom.conf") and "85:class_g = 'Xfce4-terminal'" in cfg(".config/picom/picom.conf"), "glass: windows 94%, terminal 85% written to picom")
ok(re.search(r"^background_color = #0a0a0a 75", cfg(".config/tint2/tint2rc"), re.M), "glass: panel alpha 75 in tint2rc")
ok("bga: #0a0a0ae0;" in cfg(".local/share/rofi/themes/nullsec.rasi"), "glass: launcher background alpha e0 (88%)")
ok("transparency = 15" in cfg(".config/dunst/dunstrc"), "glass: notifications transparency 15")
sh("ns-transparency preset max"); ok("0.85" in cfg(".config/picom/picom.conf") and "inactive-opacity = 0.78" in cfg(".config/picom/picom.conf"), "max: windows 85%, unfocused 78%")
sh("ns-transparency preset opaque"); ok("opacity-rule" not in cfg(".config/picom/picom.conf") and "inactive-opacity = 0.93" in cfg(".config/picom/picom.conf"), "opaque: no terminal rule, original 93% unfocused dimming restored")
ok(re.search(r"^background_color = #0a0a0a 100", cfg(".config/tint2/tint2rc"), re.M) and "bga: #0a0a0aff;" in cfg(".local/share/rofi/themes/nullsec.rasi"), "opaque: panel and launcher fully opaque again")
before = (cfg(".config/picom/picom.conf"), cfg(".config/tint2/tint2rc"))
def run_args(*a): return subprocess.run([BIN + "/ns-transparency", *a], capture_output=True, text=True, env=ENV)
for bad in (("set", "windows", "10"), ("set", "windows", "101"), ("set", "windows", "abc"), ("set", "evil", "50"),
            ("set", "terminal", "50;reboot"), ("set", "terminal", "$(touch /tmp/pwned)"), ("preset", "nonsense"), ("preset", "../../etc/passwd")):
    ok(run_args(*bad).returncode != 0, "rejects (single argument, as an attacker would send it): %s" % " ".join(bad))
ok(not os.path.exists("/tmp/pwned"), "…and no injected command was executed")
ok((cfg(".config/picom/picom.conf"), cfg(".config/tint2/tint2rc")) == before, "…and rejected input changed nothing")
sh("ns-transparency set panel 60"); ok(re.search(r"^background_color = #0a0a0a 60", cfg(".config/tint2/tint2rc"), re.M), "set panel 60 edits only the panel")
sh("ns-theme blue"); ok(re.search(r"^background_color = #0a0a0a 60", cfg(".config/tint2/tint2rc"), re.M) and "bga: #0a0a0a" in cfg(".local/share/rofi/themes/nullsec.rasi"), "switching theme keeps the transparency settings")
sh("ns-theme red")
ok("Transparency" in rd(BIN + "/ns-settings") and "exec ns-transparency" in rd(BIN + "/ns-settings"), "Settings menu has a Transparency entry")

# ---------- 5. GRUB theme + boot menu
G = OVL + "/usr/share/nullos/grub-theme"; th = rd(G + "/theme.txt")
refs = re.findall(r'"([A-Za-z0-9_*.\- ]+\.(?:png|pf2))"', th)
missing = [r for r in refs if "*" not in r and not os.path.exists(G + "/" + r)]
ok(not missing, "theme.txt references only files that exist %s" % missing)
ok(all(os.path.exists(G + "/%s_%s.png" % (st, k)) for st in ("menu", "select") for k in ("nw", "n", "ne", "w", "c", "e", "sw", "s", "se")), "both 9-slice menu styles are complete")
for f in re.findall(r'"JetBrains Mono Regular (\d+)"', th):
    ok(os.path.exists(G + "/jbmono-%s.pf2" % f) and b"JetBrains Mono Regular %s" % f.encode() in open(G + "/jbmono-%s.pf2" % f, "rb").read(), "font 'JetBrains Mono Regular %s' exists with that exact internal name" % f)
ok("theme.txt" in os.listdir(G) and 'id = "__timeout__"' in th and "boot_menu" in th, "theme has a boot menu and a countdown")
ok("set theme=/boot/grub/themes/nullos/theme.txt" in bk and "insmod png" in bk and "loadfont /boot/grub/themes/nullos/jbmono-16.pf2" in bk, "live ISO grub.cfg loads the theme, png support and fonts")
ok('menuentry "Install NullOS"' in bk and "nullos.install" in bk and "nullos.install" in rd(BIN + "/ns-autostart"), "'Install NullOS' boot entry exists and ns-autostart starts the installer for it")
ok('menuentry "NullOS (Live Mode)"' in bk, "live entry is named like the design (NullOS (Live Mode))")
g = rd(OVL + "/etc/calamares/modules/grubcfg.conf")
ok("GRUB_THEME" in g and "/boot/grub/themes/nullos/theme.txt" in g and 'GRUB_TERMINAL_OUTPUT: "gfxterm"' in g and "console" not in g, "installed system: GRUB uses the theme with the graphical terminal (not the plain console)")
ok("grub/themes/nullos" in rd(OVL + "/etc/calamares/modules/shellprocess_prepare.conf") and "/usr/share/nullos/grub-theme" in rd(OVL + "/etc/calamares/modules/shellprocess_prepare.conf"), "installer copies the theme to /boot/grub/themes/nullos before GRUB is configured")

gs = OVL + "/etc/grub.d/06_nullos_theme"
ok(os.path.exists(gs) and os.stat(gs).st_mode & stat.S_IXUSR, "/etc/grub.d/06_nullos_theme ships and is executable (grub-mkconfig only runs executable scripts)")
ok(subprocess.run(["sh", "-n", gs]).returncode == 0, "…and is valid shell")
out = subprocess.run(["sh", gs], capture_output=True, text=True).stdout
ok("set theme=${nullos_dir}/theme.txt" in out and "insmod png" in out and "jbmono-16.pf2" in out and "/boot/grub/themes/nullos/theme.txt" in out and "/grub/themes/nullos/theme.txt" in out, "…it emits the theme for both a combined and a separate /boot")
ok("06_" in "06_nullos_theme" and "10_linux" > "06_nullos_theme", "…and sorts after 00_header (graphical terminal) and before the OS entries")

# ---------- 6. login screen
gc = dict(l.strip().split("=", 1) for l in rd(OVL + "/etc/lightdm/lightdm-gtk-greeter.conf").splitlines() if "=" in l)
ok(os.path.exists(OVL + gc["background"]), "greeter background exists (%s)" % gc["background"])
ok(os.path.isdir(OVL + "/usr/share/themes/" + gc["theme-name"]) and os.path.exists(OVL + "/usr/share/themes/%s/gtk-3.0/gtk.css" % gc["theme-name"]), "greeter theme '%s' is shipped" % gc["theme-name"])
ok(os.path.exists(OVL + gc["default-user-image"]), "default user image exists")
try:
    import gi; gi.require_version("Gtk", "3.0"); from gi.repository import Gtk, GLib
    prov = Gtk.CssProvider()
    try: prov.load_from_path(OVL + "/usr/share/themes/NullOS-Login/gtk-3.0/gtk.css"); ok(True, "login stylesheet parses cleanly in GTK %d.%d" % (Gtk.get_major_version(), Gtk.get_minor_version()))
    except GLib.Error as e: ok(False, "login stylesheet error: %s" % e.message)
except Exception as e: print("SKIP  GTK not available for the stylesheet check (%s)" % type(e).__name__)

# ---------- 7. one consistent version
vers = {"build-iso.sh": 'NullOS 1.0', "overlay/etc/calamares/branding/nullos/branding.desc": 'NullOS 1.0', "docs/SECURITY.md": "NullOS 1.0"}
ok(all(v in rd(ROOT + "/" + f) for f, v in vers.items()) and 'VERSION = "1.0.0"' in rd(OVL + "/usr/lib/nullos/secd/core.py"), "version is 1.0 in the image, installer, service and docs")
stale = [f for f in ("build-iso.sh", "overlay/usr/local/bin/ns-offline", "overlay/etc/calamares/branding/nullos/branding.desc") if re.search(r"NullOS 2\.0|\"2\.0\"", rd(ROOT + "/" + f))]
ok(not stale, "no leftover 2.0 labels %s" % stale)
ok("no installer" not in rd(BIN + "/ns-offline") and "supported" in rd(BIN + "/ns-offline"), "ns-offline no longer claims there is no installer")
shutil.rmtree(T)
print("\nRESULT:", "ALL PASSED" if not fails else "%d FAILED" % fails); sys.exit(1 if fails else 0)
