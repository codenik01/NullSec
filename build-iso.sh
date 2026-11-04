#!/usr/bin/env bash
# NullOS ISO builder.  usage: sudo bash build-iso.sh [amd64|arm64]   (native arch only)
# Needs root, ~14GB free disk, internet. Output: ./out/nullos-<arch>.iso
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
ARCH="${1:-$(dpkg --print-architecture)}"
[ "$ARCH" = "$(dpkg --print-architecture)" ] || { echo "build natively: this machine is $(dpkg --print-architecture)"; exit 1; }
W="$HERE/work-$ARCH"; R="$W/rootfs"; ISO="$W/iso"; OUT="$HERE/out"
case "$ARCH" in
  amd64) MIRROR=http://archive.ubuntu.com/ubuntu;      GRUBPKG="grub-pc-bin grub-efi-amd64-bin";;
  arm64) MIRROR=http://ports.ubuntu.com/ubuntu-ports;  GRUBPKG="grub-efi-arm64-bin";;
  *) echo "unsupported arch"; exit 1;;
esac
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq debootstrap squashfs-tools xorriso mtools dosfstools grub-common curl ca-certificates $GRUBPKG
cleanup() { for m in dev/pts dev proc sys; do umount -lf "$R/$m" 2>/dev/null || true; done; }
trap cleanup EXIT
rm -rf "$W"; mkdir -p "$W" "$OUT" "$ISO"/{casper,boot/grub,.disk}

echo "== 1/6 base system"
debootstrap --arch="$ARCH" --variant=minbase --components=main,universe noble "$R" "$MIRROR"
cat > "$R/etc/apt/sources.list" <<EOF
deb $MIRROR noble main universe multiverse
deb $MIRROR noble-updates main universe multiverse
deb $MIRROR noble-security main universe multiverse
EOF
mount --bind /dev "$R/dev"; mount -t devpts devpts "$R/dev/pts"; mount -t proc proc "$R/proc"; mount -t sysfs sys "$R/sys"
cp /etc/resolv.conf "$R/etc/resolv.conf"
printf '#!/bin/sh\nexit 101\n' > "$R/usr/sbin/policy-rc.d"; chmod +x "$R/usr/sbin/policy-rc.d"

echo "== 2/6 packages (names missing on this arch are skipped)"
chroot "$R" apt-get update -qq
: > "$W/pkgs.ok"
for p in $(sed 's/#.*//' "$HERE/packages.txt"); do   # comments (#) are ignored
  if [ -n "$(chroot "$R" apt-cache policy "$p" 2>/dev/null | awk '/Candidate/ && $2!="(none)"{print $2}')" ]; then echo "$p" >> "$W/pkgs.ok"; else echo "skip (not available on $ARCH): $p"; fi
done
cp "$W/pkgs.ok" "$R/pkgs.txt"
chroot "$R" /bin/bash -c 'apt-get install -y --no-install-recommends $(tr "\n" " " < /pkgs.txt)'

echo "== 2b/6 extras: firefox (Mozilla repo), fastfetch, trim unneeded firmware"
FFA=$([ "$ARCH" = arm64 ] && echo aarch64 || echo amd64)
if curl -fsSL -o "$R/tmp/ff.deb" "https://github.com/fastfetch-cli/fastfetch/releases/latest/download/fastfetch-linux-$FFA.deb"; then
  chroot "$R" dpkg -i /tmp/ff.deb || echo "WARN: fastfetch install failed (neofetch still works)"
else echo "WARN: fastfetch download failed (neofetch still works)"; fi
rm -f "$R/tmp/ff.deb"
chroot "$R" /bin/bash -c '
set -e; export DEBIAN_FRONTEND=noninteractive
install -d -m755 /etc/apt/keyrings
wget -qO /etc/apt/keyrings/packages.mozilla.org.asc https://packages.mozilla.org/apt/repo-signing-key.gpg
echo "deb [signed-by=/etc/apt/keyrings/packages.mozilla.org.asc] https://packages.mozilla.org/apt mozilla main" > /etc/apt/sources.list.d/mozilla.list
printf "Package: *\nPin: origin packages.mozilla.org\nPin-Priority: 1000\n" > /etc/apt/preferences.d/mozilla
apt-get update -qq
apt-get install -y --no-install-recommends firefox' || echo "WARN: firefox not installed (run: ns-pack add firefox after boot)"
for p in linux-firmware-nvidia-graphics linux-firmware-mellanox-spectrum linux-firmware-marvell-prestera linux-firmware-qualcomm-misc linux-firmware-qualcomm-graphics linux-firmware-netronome linux-firmware-qlogic; do
  chroot "$R" dpkg --purge --force-depends "$p" >/dev/null 2>&1 || true
done
chroot "$R" /bin/bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get purge -y ubuntu-wallpapers-noble >/dev/null 2>&1; apt-get autoremove -y --purge >/dev/null 2>&1' || true

echo "== 3/6 overlay + finalize"
cp -a "$HERE/overlay/." "$R/"
chmod +x "$R"/usr/local/bin/ns* 2>/dev/null || true
cat > "$R/fin.sh" <<'FIN'
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
echo nullos > /etc/hostname; sed -i 's/127.0.1.1.*/127.0.1.1 nullos/' /etc/hosts 2>/dev/null || true
locale-gen en_US.UTF-8 >/dev/null; update-locale LANG=en_US.UTF-8
# NOTE: a regular file, never a symlink to the binary (that overwrote lightdm once)
rm -f /etc/X11/default-display-manager; echo /usr/sbin/lightdm > /etc/X11/default-display-manager
systemctl enable lightdm NetworkManager nftables nullos-groups >/dev/null 2>&1 || true
# NullOS Security Center: enable the service and refuse to build an image where it cannot work
chmod +x /usr/lib/nullos/nullos-secd
python3 -m compileall -q /usr/lib/nullos || { echo "FATAL: nullos-secd does not compile"; exit 1; }
/usr/lib/nullos/nullos-secd --selftest || { echo "FATAL: nullos-secd selftest failed"; exit 1; }
systemctl enable nullos-secd >/dev/null 2>&1 || { echo "FATAL: cannot enable nullos-secd"; exit 1; }
systemctl set-default graphical.target
for s in bluetooth cups cups-browsed avahi-daemon ModemManager apport snapd; do systemctl disable $s 2>/dev/null || true; systemctl mask $s 2>/dev/null || true; done
sed -i 's/^NAME=.*/NAME="NullOS"/' /etc/os-release
sed -i 's/^DISTRIB_DESCRIPTION=.*/DISTRIB_DESCRIPTION="NullOS"/' /etc/lsb-release 2>/dev/null || true
chmod 440 /etc/sudoers.d/90-nullos-session 2>/dev/null || true
chmod +x /usr/local/bin/ns*
install -d /etc/skel/.config/neofetch
TERM=xterm neofetch --print_config > /etc/skel/.config/neofetch/config.conf 2>/dev/null || true
HOME=/etc/skel /usr/local/bin/ns-logo e5484d || true
mkdir -p /var/lib/apt/lists/partial
/usr/local/bin/ns-genmenu /etc/skel/.config/openbox/menu.xml
# plymouth (boot/shutdown splash) can stall shutdown in VMs. casper AND lightdm depend on it, so it must stay
# installed (purging it removes both). Switch its services off instead.
for u in plymouth-start plymouth-quit plymouth-quit-wait plymouth-read-write plymouth-switch-root plymouth-reboot plymouth-poweroff plymouth-halt plymouth-kexec; do
  systemctl mask $u.service >/dev/null 2>&1 || true
done
for p in casper lightdm lightdm-gtk-greeter i3-wm openbox dbus-user-session; do
  dpkg -s $p 2>/dev/null | grep -q 'Status: install ok installed' || { echo "FATAL: $p is not installed"; exit 1; }
done
chmod -x /etc/update-motd.d/* 2>/dev/null || true
sed -i 's/^PRETTY_NAME=.*/PRETTY_NAME="NullOS 2.0"/; s/^VERSION=.*/VERSION="2.0"/' /etc/os-release
echo "NullOS 2.0" > /etc/nullos-release
update-initramfs -u -k all
rm -f /usr/sbin/policy-rc.d /pkgs.txt /fin.sh
apt-get clean; rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /usr/share/doc/* /usr/share/info/* /tmp/* /root/.cache /var/log/apt/* 2>/dev/null || true
find /usr/share/locale -mindepth 1 -maxdepth 1 ! -name 'en*' ! -name locale.alias -exec rm -rf {} + 2>/dev/null || true
mkdir -p /var/lib/apt/lists/partial; : > /etc/machine-id; rm -f /etc/resolv.conf; : > /etc/resolv.conf
FIN
chroot "$R" /bin/bash /fin.sh

echo "== 4/6 sanity checks"
chroot "$R" /bin/bash -c 'lsinitramfs /boot/initrd.img-* | grep -q "scripts/casper"' || { echo "FATAL: casper missing from initramfs"; exit 1; }
head -c4 "$R/usr/sbin/lightdm" | grep -q ELF || { echo "FATAL: /usr/sbin/lightdm is not a binary"; exit 1; }
[ -f "$R/etc/X11/default-display-manager" ] && [ ! -L "$R/etc/X11/default-display-manager" ] || { echo "FATAL: default-display-manager"; exit 1; }
for b in xfce4-terminal i3 openbox tint2 rofi zsh nmap thunar mousepad pipewire wireplumber bwrap jq nft apparmor_parser; do chroot "$R" which $b >/dev/null || { echo "FATAL: $b missing"; exit 1; }; done
K=$(ls -1 "$R"/boot/vmlinuz-* | sort -V | tail -1); I=$(ls -1 "$R"/boot/initrd.img-* | sort -V | tail -1)
cp "$K" "$ISO/casper/vmlinuz"; cp "$I" "$ISO/casper/initrd"; chmod 644 "$ISO/casper/vmlinuz"
# installer components: a missing piece is reported loudly and recorded in release.json, but does not stop the build
INSTALLER=1; for b in calamares unsquashfs grub-install efibootmgr parted sgdisk; do chroot "$R" which $b >/dev/null 2>&1 || { echo "WARN: installer component missing: $b"; INSTALLER=0; }; done
[ -f "$R/etc/calamares/settings.conf" ] || { echo "WARN: /etc/calamares/settings.conf missing"; INSTALLER=0; }
echo "installer: $([ $INSTALLER = 1 ] && echo ready || echo NOT READY)"
[ -x "$R/usr/lib/nullos/nullos-secd" ] && [ -f "$R/etc/systemd/system/nullos-secd.service" ] && [ -f "$R/usr/share/nullos/profiles/restricted-network.json" ] \
  || { echo "FATAL: Security Center files missing from the image"; exit 1; }
cleanup
# measured AFTER cleanup: while /proc,/sys,/dev are still bind-mounted in the chroot, du walks the live host /proc and fails.
# Release metadata must never be able to fail the build, so every step here is best-effort.
mkdir -p "$OUT"
INSTALLED_BYTES=$(du -sb --one-file-system "$R" 2>/dev/null | cut -f1 || true); INSTALLED_BYTES=${INSTALLED_BYTES:-0}
dpkg-query --admindir="$R/var/lib/dpkg" -W -f='${Package}\t${Version}\n' 2>/dev/null | sort > "$OUT/nullos-$ARCH.packages.txt" || : > "$OUT/nullos-$ARCH.packages.txt"

echo "== 5/6 compress"
mksquashfs "$R" "$ISO/casper/filesystem.squashfs" -comp zstd -Xcompression-level 10 -b 256K -noappend -e boot/initrd.img.old boot/vmlinuz.old
echo "NullOS live" > "$ISO/.disk/info"
cp "$HERE/grub-bg.jpg" "$ISO/boot/grub/bg.jpg" 2>/dev/null || true
cat > "$ISO/boot/grub/grub.cfg" <<'EOF'
set default=0
set timeout=5
insmod all_video
insmod gfxterm
insmod jpeg
set gfxmode=auto
terminal_output gfxterm
background_image /boot/grub/bg.jpg
set menu_color_normal=light-gray/black
set menu_color_highlight=black/light-red

menuentry "NullOS live" {
    linux /casper/vmlinuz boot=casper quiet loglevel=3 plymouth.enable=0 noprompt ---
    initrd /casper/initrd
}
menuentry "NullOS live (safe graphics)" {
    linux /casper/vmlinuz boot=casper nomodeset plymouth.enable=0 noprompt ---
    initrd /casper/initrd
}
menuentry "NullOS live (load into RAM)" {
    linux /casper/vmlinuz boot=casper toram quiet loglevel=3 plymouth.enable=0 noprompt ---
    initrd /casper/initrd
}
EOF

echo "== 6/6 iso"
grub-mkrescue -o "$OUT/nullos-$ARCH.iso" "$ISO" -- -volid NULLOS
ls -lh "$OUT/nullos-$ARCH.iso"
# release metadata: exact sizes are measured, never assumed (design target ~1.4 GB for the ISO)
ISO_BYTES=$(stat -c %s "$OUT/nullos-$ARCH.iso"); SQ_BYTES=$(stat -c %s "$ISO/casper/filesystem.squashfs")
( cd "$OUT" && sha256sum "nullos-$ARCH.iso" > "nullos-$ARCH.iso.sha256" )
INSTALLER=${INSTALLER:-0} ISO_BYTES=$ISO_BYTES SQ_BYTES=$SQ_BYTES INSTALLED_BYTES=$INSTALLED_BYTES ARCH=$ARCH OUT=$OUT HERE=$HERE python3 - <<'PY'
import hashlib, json, os, subprocess, time
out, arch = os.environ["OUT"], os.environ["ARCH"]
iso = os.path.join(out, "nullos-%s.iso" % arch)
h = hashlib.sha256()
with open(iso, "rb") as f:
    for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
try: commit = subprocess.check_output(["git", "-C", os.environ["HERE"], "rev-parse", "--short", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
except Exception: commit = None
pk = open(os.path.join(out, "nullos-%s.packages.txt" % arch)).read().count("\n")
target = 1_400_000_000
json.dump({"name": "NullOS", "version": "2.0", "arch": arch, "built_utc": time.strftime("%FT%TZ", time.gmtime()), "commit": commit,
           "iso_bytes": int(os.environ["ISO_BYTES"]), "iso_sha256": h.hexdigest(), "squashfs_bytes": int(os.environ["SQ_BYTES"]),
           "installed_bytes_uncompressed": int(os.environ["INSTALLED_BYTES"]), "package_count": pk, "design_target_iso_bytes": target,
           "within_design_target": int(os.environ["ISO_BYTES"]) <= target, "graphical_installer": os.environ.get("INSTALLER") == "1",
           "offline": {"live_environment": "bundled applications work without internet", "offline_installation": "not applicable (live image)",
                       "offline_operation": "base system and bundled tools yes; ns-pack, updates and online services need internet"}},
          open(os.path.join(out, "nullos-%s.release.json" % arch), "w"), indent=1)
print("release metadata written: nullos-%s.release.json" % arch)
PY
