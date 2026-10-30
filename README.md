# NULLSEC OS (v3)
Black, minimal, mouse+keyboard security live OS. Ubuntu 24.04 base + Ubuntu's own kernel (no custom kernel).
Openbox + flat panel + right-click category menu, zsh, tmux, ~30 tools, rest on demand (`ns-pack`).

## Boot / use
Live user: `ns` (no password, passwordless sudo). Hybrid ISO: BIOS + UEFI.
Alt+Enter terminal | Alt+d run | Alt+t tool menu | Alt+b browser | Alt+1..5 desktops | Alt+F4 close | Super works for the first three
Mouse: click desktop = tool menu; panel [tools] [term] [power]; Alt+drag move, Alt+right-drag resize.
Terminal: `ns` tool browser | `target <ip>` | `ns-pack list|add <name>` | `ns-kbd <layout>` | `ns-diag`
Not installed on the ISO (install on demand, needs internet): nuclei subfinder httpx amass nikto responder exploitdb netexec impacket bloodhound volatility3 evil-winrm seclists firefox metasploit ghidra.

## Rebuild (natively, root, ~12GB free)
`sudo ./build-iso.sh amd64`  or  `sudo ./build-iso.sh arm64` (on an arm64 machine). Or push to GitHub: Actions > build-iso builds both.
arm64 is untested: the amd64 ISO was built and boot-tested; the arm64 path uses the same script on a native arm64 runner.
