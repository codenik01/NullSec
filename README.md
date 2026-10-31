# NULLSEC OS v3
Black, minimal, mouse + keyboard security live OS. Ubuntu 24.04 base + Ubuntu's own kernel (no custom kernel). amd64 + arm64.

## Use
Live user `ns` (no password, passwordless sudo). BIOS + UEFI hybrid ISO.
**Mouse:** click desktop = tool menu. Panel: [tools] [term] [net] [power]. Drag title bar to move; edges to resize; buttons: minimise / maximise (right-click = fullscreen) / close.
**Keys (Alt, or Super for the first few):** Alt+Enter terminal | Alt+d run | Alt+t tools | Alt+n network | Alt+b browser | F12 dropdown terminal | Alt+F4 close
Alt+1..5 desktops, Ctrl+Alt+1..5 send window | Alt+Shift+Left/Right = snap half, Alt+Shift+Up = maximise, Alt+Shift+Down = restore centred | F11 fullscreen | Alt+drag move, Alt+right-drag resize.
New windows open centred at 70% size on their own.

## Themes (red / blue / green)
`ns-theme blue` (or Alt+Shift+t, or right-click menu > theme). Recolours panel, borders, menus, terminal, prompt and wallpaper. Custom: `ns-theme ff8800`.

## Network
Alt+n or [ net ]: pick Wi-Fi, type password. Ethernet connects automatically. `nmtui` for advanced.

## Other
`ns-fx off` turn off fade/dim effects | `ns-dpi 144` bigger text on Retina | `ns-kbd <layout>` | `ns-diag` (saves ~/nullsec-diag.txt) | `ns-pack list/add` install extra tools | `target <ip>` | `ns` tool browser

## Build
`sudo bash build-iso.sh amd64|arm64` (native arch) or GitHub Actions > build-iso (builds both).
