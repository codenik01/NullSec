# NULLSEC OS v2
Kali kernel and repos, black/red minimal UI, ~40 tools on the ISO, the rest one command away (`ns-pack`).
Architectures: **amd64 (x86_64)** and **arm64**, built natively by CI.

## Fastest way to test (minutes, no ISO)
On any running Kali VM:  `./apply.sh` (add `--ui-only` for just the desktop, `--harden` for the firewall), then reboot.

## Build ISOs (CI, both arches)
Push to GitHub > Actions > build-iso > Run workflow. Tag `vX` to publish a Release (resumable downloads).
Local: `./build.sh amd64` or `./build.sh arm64` (native only).
Package names are auto-validated first, so a bad name is dropped instead of killing the build.

## Using it
Session: **Openbox** (default). Left/right-click the desktop = tool menu. Top panel: `[tools] [term] [power]`.
Keys: Alt+Enter terminal, Alt+d run, Alt+t tools, Alt+b browser, Alt+1..5 desktops, Alt+F4 close, Super works too.
Alt+drag moves windows, Alt+right-drag resizes. i3 is optional: `sudo ns-session i3`.
Terminal: `ns` tool browser | `ns-pack list/add/rm` | `target <ip>` | `ns-kbd <layout>` | `ns-diag` (writes ~/nullsec-diag.txt)

## If the keyboard is dead in the VM (hypervisor side)
VirtualBox: Settings > System > Pointing Device = USB Tablet; Ports > USB = USB 2.0 (EHCI); try toggling EFI.
VMware: USB compatibility 2.0/3.1. UTM/QEMU arm64: add a USB keyboard and USB mouse device. Boot menu keys need the VM window focused.
