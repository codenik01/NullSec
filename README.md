# NULLSEC OS
Minimal, black, terminal-first security distro on **Kali's official live-build config and kernel**. No custom kernel.

- Desktop: Xorg + i3 (1px borders, no icons, text bar)
- Terminal: alacritty + zsh + tmux; prompt = `[ip] [target] user@host path`
- ~60 curated tools instead of hundreds
- Hardened: nftables default-deny inbound, sysctl hardening, random MAC, bluetooth/cups/avahi off
- Colors: bg `#0a0a0a`, fg `#c8c8c8`, accent `#e5484d`

## Build (Kali/Debian/Ubuntu, 30GB free)
    ./check-packages.sh   # on Kali: reports package names missing from the repo
    ./build.sh            # ISO lands in ./out
Test in QEMU/VirtualBox first, then write with dd or Ventoy.

## Keys (Mod = Super)
Enter terminal | d run | t tool menu | b browser | Shift+x lock | Shift+e power | 1-6 workspaces (recon/web/exploit/post/notes)

## Terminal
`ns` fuzzy tool browser. `target 10.10.10.5` makes ~/ops/<target>/{recon,loot,notes} and shows it in the prompt.

## Customize
Tools: package list + `usr/share/nullsec/tools.tsv`. Colors: replace the 3 hex values across configs.
Live login is kali/kali. Change it for any installed system.

## v2 additions
- **Two sessions:** i3 (default, keyboard) and Openbox + tint2 (BlackArch-style right-click category menu, generated from tools.tsv by `ns-genmenu`). Pick at the login screen.
- **Lean by design:** ~60 tools on the ISO, no recommended packages, docs/man/locales stripped. Need more? `ns-pack list` then `ns-pack add web` (pulls the Kali pack on demand). `ns-pack rm <pkg>` removes.
- **VM ready:** open-vm-tools, spice-vdagent, qemu-guest-agent, VirtualBox guest additions.
- **Cloud build, no Kali needed:** push this folder to a GitHub repo, open Actions > build-iso > Run workflow, download the ISO artifact (~1 hour).
