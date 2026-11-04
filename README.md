# NullOS 2.0 (build kit v5)
Black, minimal security OS on Ubuntu 24.04 (Ubuntu's own kernel). amd64 + arm64. Default = tiling desktop (i3) with Hyprland-style gaps, borders, auto-dwindle tiling and a dropdown terminal. Floating mode (Openbox, title bars) is one click away.

## Login
User `ns`, no password, passwordless sudo.

## Panel (top)
[NullOS logo] = start menu (apps, settings, power) | [term] | [net] | [tools] | workspaces + windows | tray | clock. Right-click the logo = power menu.

## Keys (Super; Alt works for the core ones)
Super+Enter terminal | Super+Space start menu | Super+D apps | Super+T security tools | Super+N network | Super+B browser | Super+E files
Super+Q close | Super+V float | Super+F fullscreen | Super+W tabbed/split | Super+arrows (or h/j/k/l) focus | +Shift move | Super+R resize mode
Super+1..9 workspace, +Shift move window | Super+Tab next workspace | Super+- scratchpad | F12 dropdown terminal | Super+Shift+S screenshot | Super+Shift+T theme | Super+Shift+E power
Mouse: Super+left-drag moves floating windows, Super+right-drag resizes.

## Terminal
Right-click = Copy / Paste / Paste Selection / Open Tab / Preferences. Selecting text copies it.
Commands: ifconfig, ip, ping, neofetch, fastfetch (`ff`), nano, ssh, htop, tree, unzip, dig, whois, lspci, lsusb, man ...

## Apps
Files (Thunar), Settings (xfce4-settings: appearance, display, keyboard, mouse), Wi-Fi/network (ns-net + tray applet), Audio (pavucontrol), Archives (engrampa), Text editor (mousepad), Screenshot, Power manager, Task manager, Images (ristretto), Calculator (mate-calc), PDF (atril), Firefox.

## Look
`ns-theme red|blue|green|<hex>` recolours panel, borders, menus, terminal, GTK apps, prompt, fastfetch/neofetch logo. `ns-wallpaper` picks the wallpaper (default = NullOS Cyber Fortress). `ns-mode tiling|floating` switches layout. `ns-fx off` disables fade effects. `ns-dpi 144` for Retina text.

## Security Center (new in 2.0), Super+S
One switch for **Restricted Mode** plus profiles, an emergency disconnect, audits, sandboxes and labs, with every status *verified* against the real system.
`ns-secure status|enable|disable|kill|release|audit|logs ...`, `ns-sandbox`, `ns-lab`, `ns-pack`, `ns-offline`. Full guide and limits: `docs/SECURITY.md`. Installing to disk: `docs/INSTALLER.md`. Tests: `sudo bash tests/run-all.sh`.

## Build
`sudo bash build-iso.sh amd64|arm64` (native arch) or GitHub Actions > build-iso.

## Changelog 2.0.2
- NEW **Graphical installer** (Calamares): start menu > Install NullOS (live session only). Offline, UEFI+BIOS, NullOS-branded. See `docs/INSTALLER.md` (includes what still needs a real-install test).
- FIX the installed system must not inherit live-only settings: lightdm auto-login of `ns` and the `ns`-only sudo rule are rewritten during install.

## Changelog 2.0.1
- FIX output no longer wraps into the first column on narrow terminals.
- FIX the monitor no longer reports the service's own NetworkManager drop-ins as 'changes since baseline'.
- FIX tool packs: `ns-install`/`ns-pack` wait for the apt/dpkg lock held by background updaters (was: "could not get lock") and update the package index once per session.
- FIX labs: service no longer uses a private mount namespace (could hide lab namespaces); stale bridge/namespaces from a failed attempt are cleaned instead of failing with "File exists".
- NEW AppArmor installed (`apparmor`, `apparmor-utils`); userns restriction kept off so ns-sandbox/Firefox keep working.

## Changelog 2.0
- NEW Security Center + `nullos-secd` service, 4 profiles + custom, verification engine, kill switch, drift repair, lab networks, `ns-sandbox`, credential/privilege/service/user/package audits, `ns-pack` search/info/profiles, `ns-offline`, release metadata.
- Existing files touched (all small, see docs/CHANGES-existing-files.patch): `ns-start`, `ns-genmenu` (+Security Center; `firefox-esr` -> `ns-browser`), `ns-autostart` (respect clipboard block), i3 config (Super+S), tint2 (live status item), `ns-install` (+prowler, scoutsuite), `packages.txt` (+bubblewrap), `build-iso.sh`, workflow. `/etc/nftables.conf` is unchanged.

## Changelog 1.0
- Sound fixed: dbus-user-session + rtkit added (the audio manager could not start without a user session bus). Live user is in the audio/video groups, card is unmuted at login (`ns-audio fix|test|status`).
- Shutdown/reboot no longer waits for ENTER ("remove the installation medium"); shorter systemd stop timeouts.
- No more busy/spinning cursor after launching apps (startup notification disabled in i3, Openbox and the panel).
- Screen never blanks, Firefox/Thunar are the defaults, tray volume icon, OS reports itself as NullOS 1.0.
- UTM: add a Sound device (Intel HDA) under Devices if sound is still silent. Run `ns-diag` and share ~/nullsec-diag.txt if anything misbehaves.
