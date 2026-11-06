# NullOS 1.0
Black, minimal security OS on Ubuntu 24.04 (Ubuntu's own kernel). amd64 + arm64. Default = tiling desktop (i3) with gaps, borders, auto-dwindle tiling and a dropdown terminal. Floating mode (Openbox, title bars) is one click away. Four themes, a verified Security Center, and a graphical installer.

## Try it, then install it
Boot the ISO: **NullOS (Live Mode)** to try it, or **Install NullOS** to go straight to the installer. In the live session the user is `ns` (no password, passwordless sudo). To install to disk: start menu > **Install NullOS**. Installation is fully offline (UEFI and BIOS); you create your own account and the installed system boots to a themed GRUB menu and login screen. Details, and what to test: `docs/INSTALLER.md`.

## Panel (top)
[NullOS logo] = start menu (apps, settings, power) | [term] | [net] | [tools] | [sec] live security status | workspaces + windows | tray | clock. Right-click the logo = power menu.

## Keys (Super; Alt works for the core ones)
Super+Enter terminal | Super+Space start menu | Super+D apps | Super+T security tools | **Super+S Security Center** | Super+N network | Super+B browser | Super+E files
Super+Q close | Super+V float | Super+F fullscreen | Super+W tabbed/split | Super+arrows (or h/j/k/l) focus | +Shift move | Super+R resize mode
Super+1..9 workspace, +Shift move window | Super+Tab next workspace | Super+- scratchpad | F12 dropdown terminal | Super+Shift+S screenshot | Super+Shift+T theme | Super+Shift+E power
Mouse: Super+left-drag moves floating windows, Super+right-drag resizes.

## Look
* **Themes**: `ns-theme red|blue|green|mono` (or Settings > Theme). **red is the default**; mono = black & white. It recolours panel, borders, menus, terminal, GTK apps, prompt, logo **and the wallpaper**. Switching is lossless.
* **Wallpapers**: `ns-wallpaper` (Settings > Wallpaper). Only NullOS artwork is shipped (red, blue, green, black & white); you can pick your own pictures from ~/Pictures, ~/Downloads, ~/Desktop.
* **Transparency**: Settings > Transparency, or `ns-transparency preset opaque|subtle|glass|max`, `ns-transparency set windows|terminal|panel|menus|notifications 30-100`. Windows, terminal, top bar, launcher menus and notifications are controlled separately; your choices persist across theme changes.
* Layout `ns-mode tiling|floating`, effects `ns-fx off`, HiDPI text `ns-dpi 144`.
* Boot menu and login screen use the NullOS theme (artwork generator: `python3 tools/make-assets.py`).

## Security Center, Super+S
Restricted Mode with profiles, an emergency disconnect, audits, sandboxes and labs, where every status is *verified* against the real system. `ns-secure status|enable|disable|kill|release|audit|logs ...`, `ns-sandbox`, `ns-lab`, `ns-pack`, `ns-offline`. Guide and limits: `docs/SECURITY.md`.

## Terminal and apps
Right-click = Copy / Paste / Paste Selection / Open Tab / Preferences. Files (Thunar), Settings, Wi-Fi (ns-net + tray applet), Audio (pavucontrol), Archives, Text editor (mousepad), Screenshot, Task manager, Images, Calculator, PDF, Firefox. Tool packs: `ns-pack install network|web|forensics|re|cloud`.

## Build and test
`sudo bash build-iso.sh amd64|arm64` (native arch) or GitHub Actions > build-iso. Each build writes `nullos-<arch>.release.json` (exact size, checksum, installer flag). `sudo bash tests/run-all.sh` runs every test group.

## Known limits
See `docs/SECURITY.md` and `docs/INSTALLER.md` ("Not verified"). In short: the installer's disk writing and the first boot of an installed system need a real-VM check on each release; IPv6 and NetworkManager-specific controls report *unsupported/unknown* rather than guess; `ns-autotile` (auto-dwindle) has a pre-existing Python syntax error and does not run: replace its line 2 with `import os; os.environ.pop("DESKTOP_STARTUP_ID", None)` to enable it.

## Release 1.0 (production)
Everything below is new relative to the original live image:
- **Security Center** and the `nullos-secd` service: verified Restricted Mode, 4 profiles + custom, kill switch, drift repair, audits, `ns-sandbox`, `ns-lab`, `ns-pack`, `ns-offline`, AppArmor.
- **Graphical installer** (Calamares): offline, UEFI + BIOS, NullOS-branded; the installed system gets a clean state (no live auto-login, correct sudo rule).
- **NullOS boot menu** (live and installed) with "NullOS (Live Mode)" and "Install NullOS" entries.
- **Themes**: red (default), blue, green, black & white, each with its own wallpaper; **new login screen**; **Transparency** settings.
- Fixes found in real use: output wrapping, the monitor flagging its own files, apt-lock waits for tool packs, lab leftovers, AppArmor complain-mode profiles no longer shown as a fault.
- Earlier fixes still in place: sound (dbus-user-session + rtkit), shutdown without waiting for ENTER, no busy cursor, screen never blanks. Run `ns-diag` and share ~/nullsec-diag.txt if anything misbehaves.
- Touched existing files are listed in `docs/CHANGES-existing-files.patch`. `/etc/nftables.conf` is unchanged.
