# NullOS graphical installer

Boot the live ISO, open the start menu (logo button / Super+Space) and choose **Install NullOS**
(or run `ns-installer`; the right-click menu has it too). A reminder appears a few seconds after the live desktop starts.
The entry exists **only in the live session**; `ns-installer` refuses to run on an installed system.

It is [Calamares](https://calamares.io), the standard installer for Ubuntu-based distributions, configured for NullOS
in `/etc/calamares` and branded to match the desktop.

## What it does
1. **Welcome** (checks: 12 GB disk, 1.5 GB RAM, root. *No internet check: the install is fully offline.*)
2. **Location / Keyboard**
3. **Partitions**: erase disk (default), or manual. ext4 only, optional swap file. GPT on UEFI, MBR on BIOS.
4. **Users**: your name, computer name, password, optional "log in automatically". The account joins `adm cdrom dip plugdev audio video sudo`.
   `root` and the live user `ns` cannot be chosen. No separate root password (use sudo).
5. **Summary**, then it asks before touching any disk.
6. Copies the system from the live image (`/cdrom/casper/filesystem.squashfs`), writes fstab/machine-id/locale/keyboard,
   creates your user, configures the login screen, copies saved Wi-Fi/network connections, builds the initramfs and installs
   **GRUB (UEFI with a fallback entry, or BIOS)**. The bootloader packages are baked into the image, so nothing is downloaded.

Everything you have in the live system comes across: the Security Center and `nullos-secd`, profiles, tools, theme, keybindings.
Your new account starts from `/etc/skel`, exactly like the live user did.

## NullOS-specific steps (`shellprocess_prepare.conf`)
| Step | Why |
|---|---|
| remove `autologin-user=ns` from the lightdm config | the installed system has no user `ns`; your own auto-login choice is applied by the installer |
| grant `ns-session` passwordless sudo to group `sudo` instead of user `ns` | the desktop-mode switcher (`ns-mode`) runs `sudo ns-session` from the GUI; it would otherwise hit an unanswerable password prompt for any other user name |
| make sure `/boot/vmlinuz-<version>` exists | GRUB looks for that name |
| delete `/var/lib/nullos`, `/var/log/nullos` | the new system starts with a clean security state and log, not the live session's history |

Each step is written so it cannot fail the installation over a cosmetic detail.

## Boot menu and firmware messages
Both the live ISO and the installed system show the NullOS GRUB menu (logo, red-bordered menu, countdown). The live menu has
**NullOS (Live Mode)**, **Install NullOS** (boots the live system and starts the installer), safe graphics and RAM mode.

After installing and removing the ISO, a VM's firmware may print `BdsDxe: failed to load Boot0001 "UEFI ... USB HARDDRIVE" ... Not Found`
before the boot menu. That is only the firmware reporting that the *removed ISO* (a stale boot entry) is gone, and then it
continues with the next entry: `Boot0005 "NullOS" ... \EFI\NullOS\shimaa64.efi` (shimx64 on amd64), which is the installed system.
It is harmless. If it bothers you: `sudo efibootmgr` to list entries and `sudo efibootmgr -b 0001 -B` to delete the stale one.

## Size
Calamares and its Qt/KDE libraries add roughly **100 MB installed** (about 35-50 MB on the compressed ISO); the signed
bootloader packages add a little more. The build measures it: `nullos-<arch>.release.json` has the exact ISO size and
`"graphical_installer": true/false`. If any installer component is missing the build prints `WARN: installer component missing`
and records `false`, but still produces a bootable live ISO.

## What has been verified, and what has not
**Verified here (automated: `tests/installer_test.py`, `tests/calamares_smoke.sh`):**
* all config files are valid YAML; every module in the sequence exists in the real Calamares 3.3.5 package;
* the module configs that have a schema (bootloader, displaymanager, fstab, grubcfg, mount, unpackfs) pass **Calamares' own JSON schemas**;
* the **real Calamares program starts** headless on this configuration with 0 errors, loads the NullOS branding and all pages,
  and uses no deprecated keys (I also looked at a screenshot of the rendered window);
* step ordering is sound; only groups that exist are requested; packages exist in the Ubuntu archive;
* the pre-bootloader shell steps were executed against a fake target (autologin removed and everything else kept, kernel copy,
  state removal, sudoers rewrite validated with `visudo -c`);
* `ns-installer` refuses outside the live session.

**NOT verified: needs one real install in a VM or on a spare disk before you publish:**
* Calamares loads its *Python* modules (unpackfs, mount, fstab, bootloader, displaymanager, grubcfg, ...) only when an install runs,
  so a full install is the first real test of those (their configs do pass the schemas);
* writing partitions, `grub-install` on UEFI **and** on BIOS, **Secure Boot**, and the first boot of the installed system;
* the installed system booting to the login screen, auto-login choice, the Security Center turning on, network;
* the arm64 image (package availability is assumed, the build will say if not).

### Test checklist (15 minutes, in a VM with a blank disk)
1. Boot the ISO, wait for the "To install to disk" notification, start menu > Install NullOS.
2. Walk through, erase disk, create a user that is **not** called `ns`, install, restart (remove the ISO).
3. Installed system: the login screen appears, you can log in; `Super+S` opens the Security Center; enable *Restricted Network*.
4. `sudo ns-mode` / the desktop-mode switch works without a password prompt.
5. `cat /etc/lightdm/lightdm.conf.d/99-nullsec.conf` has no `autologin-user=ns`; `ns-installer` says it only runs from the live session.
6. Repeat once with UEFI and once with legacy BIOS if you can (UTM/QEMU: with and without OVMF).
Send me the Calamares log (`~/.cache/calamares/session.log` or `/root/.cache/calamares/session.log`) if anything fails.

## Not included (on purpose, for a first version)
Disk encryption (LUKS), btrfs/xfs, LVM, dual-boot detection (`os-prober` is installed but GRUB's default keeps it off),
and the advanced "OEM" mode. They can be added once the basic install is proven.
