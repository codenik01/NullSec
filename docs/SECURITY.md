# NullOS Security Center (NullOS 2.0)

One switch (**Restricted Mode**) that asks a small privileged service to apply a documented, versioned profile,
then **inspects the system to see whether it really worked**. It never reports a protection because a button was
clicked or a command returned 0.

Open it with **Super+S** (or Alt+S), the start menu, the right-click menu, or the `[ sec ]` item in the panel.
CLI: `ns-secure help`.

## Standard vs Restricted
* **Standard** is not "unprotected". It is the normal NullOS baseline: default-deny inbound firewall (`/etc/nftables.conf`,
  untouched), Wi-Fi MAC randomization, kernel hardening sysctls.
* **Restricted** *adds* controls on top. It never replaces or edits the baseline: it lives in its own nftables table
  (`inet nullos`), so turning it off is a clean `nft delete table inet nullos` and the baseline is byte-for-byte unchanged.

## Status words (always these, always meaning the same)
| Status | Meaning |
|---|---|
| VERIFIED | expected configuration was checked against the real system and confirmed |
| ACTIVE | operating, but its effect could not be independently verified |
| INACTIVE | not enabled |
| UNSUPPORTED | this hardware / kernel / environment cannot do it |
| FAILED | the operation failed or the configuration could not be confirmed |
| UNKNOWN | the actual state could not be established |
| DEGRADED | working, but an important protection or dependency is missing |

Each control records **requested → applied → verified** separately.

## How verification works (the part that makes it honest)
1. **Reference comparison**: the intended ruleset is loaded into a throw-away network namespace; the fingerprint of what
   the real nft parser/kernel produced there is compared with what the live kernel is enforcing (handles and counters ignored).
2. **Invariants** on the effective rules (default-deny policy, no unconditional accept, no accept on an unlisted interface,
   DNS accepted only to configured resolvers and *before* any general accept, IPv6 rules present when required).
3. **Behavioural probe** where possible: one UDP byte to an RFC 5737 / RFC 3849 documentation address. A policy that forbids
   it makes the kernel refuse with `EPERM`; if the packet leaves, the control is reported FAILED.
4. The Standard baseline firewall is verified the same way against `/etc/nftables.conf`.

A continuous monitor (default every 30 s) repeats this, logs drift, and re-applies the policy (max 3 times / 5 min)
if something such as `systemctl reload nftables` silently reverted it.

## Mode transition (spec §7.2)
preflight → apply → verify → report → failure policy → continuous verification → deactivation.
* The firewall is applied first and **atomically** (single nft transaction): if it is rejected, nothing has changed.
* If a required control fails verification the mode is reported **DEGRADED/FAILED, never "on"**.
* Profile `on_failure`: `report` (default) or `fallback-deny` (Isolated Lab): deny all traffic until the policy verifies.
* Disabling removes only what Restricted Mode added. A user's own **Emergency Disconnect** is never undone by a mode change.

## Profiles (`/usr/share/nullos/profiles/*.json`, validated, versioned)
| Profile | What it does |
|---|---|
| Standard | baseline only |
| **Restricted Network** (recommended) | outbound default-deny: web 80/443, NTP, DNS only to the resolvers you use, everything inside a VPN tunnel; new inbound blocked (also on VPN); DNS/DoT leaks dropped; IPv4+IPv6 same policy |
| Privacy-Focused | the above + DNS pinned to Quad9 (edit `servers`), random MAC on Wi-Fi/Ethernet, no ICMP out, desktop USB-storage mounting off |
| Isolated Lab | no internet (only lab net `10.77.0.0/16`), IPv6 blocked, guest clipboard agent stopped, USB mounting off, random MAC, `fallback-deny` |
| Custom | pick controls individually in the UI / `ns-secure custom ...` (validated, dependencies enforced) |

Add your own: drop a JSON file (same schema) in `/etc/nullos/profiles.d/`. Invalid files are skipped and logged.

## What each control really does
| Control | Implementation | Limits you should know |
|---|---|---|
| Outbound / inbound / IPv4+IPv6 | nftables table `inet nullos` | DoH inside port 443 looks like web traffic. Inbound is verified by rule inspection, not probed from outside. |
| DNS policy | nft resolver allow-list + NetworkManager `global-dns` when pinned | application-specific resolvers and DoH cannot be told apart from web traffic |
| MAC randomization | NetworkManager drop-in + reconnect; verified by comparing the address in use with the hardware address | hides the hardware address from the local network only; a connection profile with its own MAC setting overrides it (reported DEGRADED) |
| Kill switch / Emergency Disconnect | separate deny table + `nmcli` disconnect; re-applied if wiped | release with `ns-secure release`, then reconnect |
| IP & route protection | shows addresses/routes/VPN state, flags VPN-bypassing default routes (incl. IPv6 leak) | NullOS cannot choose your public IP. There is deliberately **no** "randomize IP" switch. |
| Connection / listening-service visibility | `ss` + effective firewall rules | derived from rules, not a port scan |
| Credential audit | metadata only (path, mode, owner); never opens files; `ns-secure creds fix` removes group/other bits | cannot stop a program the *same user* runs from reading that user's files: use `ns-sandbox` |
| Secrets in environment | reports variable **names** only | values are never stored or logged |
| Privilege audit / services / users / packages / updates / sudo log | `/proc`, systemd, passwd/shadow, `dpkg -V`, apt index, journal | `dpkg -V` checks against checksums on the same disk; sudo log keeps command names, never arguments |
| Critical-config monitor | sha256 of security-relevant files vs. an accepted baseline | a change is "changed", never "malicious"; accept with `ns-secure baseline accept` |
| USB storage policy | udev rule: desktop (udisks) ignores USB mass storage | root can still mount by hand; not a port lock |
| Clipboard / drag-drop | stops guest agents (spice-vdagent, vmware-user, VBoxClient) and keeps them off | stops guest-side auto-resize too; host-side sharing must be disabled in the hypervisor, and is reported ACTIVE (never VERIFIED) |
| AppArmor | honest status only (the `apparmor` package is intentionally **not** in the image: it enables userns restrictions that can break Firefox/Electron) | reports "no profiles loaded" until you install it |

## Confinement and labs
* `ns-sandbox [--net] [--ro P] [--rw P] -- cmd`: bubblewrap sandbox. Read-only system, **empty private home**, private /tmp,
  no network unless `--net`, clean environment (no inherited tokens). If it cannot be created it **refuses (exit 125)** and never runs unconfined.
* `ns-lab workspace | analyze FILE [--out DIR] | net create|list|run|destroy | vm IMAGE | doctor`
  * workspace / analyze / net = **namespaces (shared kernel)**: labelled as such. Use a VM for hostile code.
  * `net`: a private bridge + namespaces, no uplink, no default route, verified from inside. If `br_netfilter` is loaded
    (Docker/libvirt) it can filter bridged traffic through the host forward chain: the lab is reported DEGRADED with the fix.
  * `vm`: disposable QEMU (`-snapshot`, no NIC by default); needs `ns-pack add apt:qemu-system-x86`.

## Tool packs
`ns-pack list | profiles | search | info | install network|web|forensics|re|cloud|all | remove | update`.
Ubuntu-compatible sources only (no Kali/Parrot repositories; the package audit flags them if added).

## Service, authorisation, files
* `nullos-secd` (Python 3, stdlib only) runs as root; Unix socket `/run/nullos/secd.sock`, mode 0660 group `sudo`,
  caller identified with `SO_PEERCRED`. Fixed verbs only. **There is no verb that runs a command**; arguments are schema-validated;
  profile ids, lab ids and interface names are matched against strict patterns.
* The Security Center and `ns-secure` run as your user. If the GUI crashes nothing is removed (rules live in the kernel).
  If the service dies the panel shows `[ sec ? ]`, `ns-secure status` says protections **cannot be verified**, and systemd restarts it.
* State `/var/lib/nullos/state.json`, log `/var/log/nullos/security.log` (JSON lines, rotated, secrets redacted),
  panel summary `/run/nullos/status.json`.

## Offline readiness and size
`ns-offline` reports the three cases separately (live environment / offline installation / offline operation).
Each build writes `nullos-<arch>.release.json` (exact ISO bytes, sha256, squashfs and installed size, package count,
whether it is within the ~1.4 GB design target), `.iso.sha256` and a package manifest.

## Tests
`sudo bash tests/run-all.sh` (needs nftables, iproute2, bubblewrap, jq, iputils-ping). Unit tests, a real-kernel firewall test
(tamper, injected accept, wiped table, DNS drift, kill switch, atomicity), failure-policy and drift-repair tests, an end-to-end
test of daemon + client, and sandbox isolation tests with positive controls.

## Known limits (read this)
* Not an anonymity tool and not an intrusion-detection engine. Restricted Mode does not promise activity cannot be traced.
* Container-grade labs share the host kernel.
* Not verifiable inside the build environment used for development: real IPv6 behaviour, NetworkManager MAC/DNS changes,
  udev USB rule, hypervisor clipboard agents, systemd unit start-up, interactive rofi UI, QEMU lab, ISO boot.
  These are written defensively (each reports UNSUPPORTED/UNKNOWN rather than guessing) but **need one boot test on your side**.
