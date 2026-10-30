#!/usr/bin/env bash
# NULLSEC ISO builder.  usage: sudo ./build-iso.sh [amd64|arm64]   (native arch only)
# Needs root, ~12GB free disk, internet. Output: ./out/nullsec-<arch>.iso
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
apt-get install -y -qq debootstrap squashfs-tools xorriso mtools dosfstools grub-common $GRUBPKG
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
for p in $(cat "$HERE/packages.txt"); do
  if [ -n "$(chroot "$R" apt-cache policy "$p" 2>/dev/null | awk '/Candidate/ && $2!="(none)"{print $2}')" ]; then echo "$p" >> "$W/pkgs.ok"; else echo "skip (not available on $ARCH): $p"; fi
done
cp "$W/pkgs.ok" "$R/pkgs.txt"
chroot "$R" /bin/bash -c 'apt-get install -y --no-install-recommends $(tr "\n" " " < /pkgs.txt)'
echo "== 3/6 overlay + finalize"
cp -a "$HERE/overlay/." "$R/"
cat > "$R/fin.sh" <<'FIN'
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
echo nullsec > /etc/hostname; sed -i 's/127.0.1.1.*/127.0.1.1 nullsec/' /etc/hosts 2>/dev/null || true
locale-gen en_US.UTF-8 >/dev/null; update-locale LANG=en_US.UTF-8
# NOTE: regular file, never a symlink to the binary (that overwrote lightdm once)
rm -f /etc/X11/default-display-manager; echo /usr/sbin/lightdm > /etc/X11/default-display-manager
systemctl enable lightdm NetworkManager nftables >/dev/null 2>&1 || true
systemctl set-default graphical.target
for s in bluetooth cups cups-browsed avahi-daemon ModemManager apport snapd; do systemctl disable $s 2>/dev/null || true; systemctl mask $s 2>/dev/null || true; done
/usr/local/bin/ns-genmenu /etc/skel/.config/openbox/menu.xml
update-initramfs -u -k all
rm -f /usr/sbin/policy-rc.d /pkgs.txt /fin.sh
apt-get clean; rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /usr/share/doc/* /usr/share/man/* /usr/share/info/* /tmp/* /root/.cache /var/log/apt/* 2>/dev/null || true
find /usr/share/locale -mindepth 1 -maxdepth 1 ! -name 'en*' ! -name locale.alias -exec rm -rf {} + 2>/dev/null || true
: > /etc/machine-id; rm -f /etc/resolv.conf; : > /etc/resolv.conf
FIN
chroot "$R" /bin/bash /fin.sh
echo "== 4/6 sanity checks"
head -c4 "$R/usr/sbin/lightdm" | grep -q ELF || { echo "FATAL: /usr/sbin/lightdm is not a binary"; exit 1; }
[ -f "$R/etc/X11/default-display-manager" ] && [ ! -L "$R/etc/X11/default-display-manager" ] || { echo "FATAL: default-display-manager"; exit 1; }
for b in alacritty openbox tint2 rofi zsh nmap; do chroot "$R" which $b >/dev/null || { echo "FATAL: $b missing"; exit 1; }; done
K=$(ls -1 "$R"/boot/vmlinuz-* | sort -V | tail -1); I=$(ls -1 "$R"/boot/initrd.img-* | sort -V | tail -1)
cp "$K" "$ISO/casper/vmlinuz"; cp "$I" "$ISO/casper/initrd"; chmod 644 "$ISO/casper/vmlinuz"
cleanup
echo "== 5/6 compress"
mksquashfs "$R" "$ISO/casper/filesystem.squashfs" -comp zstd -Xcompression-level 10 -b 256K -noappend -e boot/initrd.img.old boot/vmlinuz.old
echo "nullsec live" > "$ISO/.disk/info"
cat > "$ISO/boot/grub/grub.cfg" <<'EOF'
set default=0
set timeout=5
set menu_color_normal=light-gray/black
set menu_color_highlight=black/light-red
insmod all_video
terminal_output console
menuentry "nullsec live" {
    linux /casper/vmlinuz boot=casper quiet loglevel=3 ---
    initrd /casper/initrd
}
menuentry "nullsec live (safe graphics)" {
    linux /casper/vmlinuz boot=casper nomodeset ---
    initrd /casper/initrd
}
menuentry "nullsec live (load into RAM)" {
    linux /casper/vmlinuz boot=casper toram quiet loglevel=3 ---
    initrd /casper/initrd
}
EOF
echo "== 6/6 iso"
grub-mkrescue -o "$OUT/nullsec-$ARCH.iso" "$ISO" -- -volid NULLSEC
ls -lh "$OUT/nullsec-$ARCH.iso"
