#!/usr/bin/env bash
# FAST PATH (minutes, no ISO): turn a running Kali VM into NULLSEC.
# usage: ./apply.sh [--ui-only] [--harden]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; V="$HERE/kali-config/variant-nullsec"; INC="$V/includes.chroot"
UI_ONLY=0; HARDEN=0
for a in "$@"; do case $a in --ui-only) UI_ONLY=1;; --harden) HARDEN=1;; esac; done
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO=sudo
U="${SUDO_USER:-$USER}"; H="$(getent passwd "$U" | cut -d: -f6)"
export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update
lists=("$V/package-lists/nullsec-ui.list.chroot" "$V/package-lists/nullsec-vm.list.chroot")
[ "$UI_ONLY" -eq 0 ] && lists+=("$V/package-lists/nullsec-tools.list.chroot")
want=()
for l in "${lists[@]}"; do
  while read -r p; do
    case "$p" in ''|\#*) continue;; esac
    if apt-cache show "$p" >/dev/null 2>&1; then want+=("$p"); else echo "skip (not in repo): $p"; fi
  done < "$l"
done
$SUDO apt-get install -y --no-install-recommends "${want[@]}"
$SUDO cp -a "$INC/usr/." /usr/
for f in sysctl.d NetworkManager lightdm issue motd; do $SUDO cp -a "$INC/etc/$f" /etc/; done
$SUDO sed -i "s/^autologin-user=.*/autologin-user=$U/" /etc/lightdm/lightdm.conf.d/99-nullsec.conf
echo /usr/sbin/lightdm | $SUDO tee /etc/X11/default-display-manager >/dev/null
$SUDO systemctl enable lightdm 2>/dev/null || true
$SUDO cp -a --backup=numbered "$INC/etc/skel/." "$H/"
$SUDO chown -R "$U": "$H/.config" "$H/.zshrc" "$H/.tmux.conf"
$SUDO runuser -u "$U" -- /usr/local/bin/ns-genmenu "$H/.config/openbox/menu.xml"
$SUDO chsh -s /usr/bin/zsh "$U" || true
if [ "$HARDEN" -eq 1 ]; then $SUDO cp "$INC/etc/nftables.conf" /etc/nftables.conf; $SUDO systemctl enable --now nftables; fi
echo "done. reboot. (firewall: re-run with --harden; undo UI: restore *.~1~ backups in your home)"
