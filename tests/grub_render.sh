#!/bin/bash
# Boots the REAL live-ISO grub.cfg + NullOS theme in QEMU (BIOS and, if OVMF is present, UEFI) and checks the screen pixels:
# logo, red accent, highlighted menu entry. Skips (never fails) when qemu/grub tools are missing.
HERE=$(cd "$(dirname "$0")/.." && pwd); f=0; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
ok(){ if [ "$2" = 0 ]; then echo "PASS  $1"; else echo "FAIL  $1"; f=$((f+1)); fi; }
for b in qemu-system-x86_64 grub-mkrescue xorriso python3; do command -v $b >/dev/null || { echo "SKIP  $b not installed"; echo "GRUBRENDER: SKIPPED"; exit 0; }; done
python3 -c "import PIL" 2>/dev/null || { echo "SKIP  Pillow missing"; echo "GRUBRENDER: SKIPPED"; exit 0; }
mkdir -p "$T/iso/boot/grub/themes"; cp -r "$HERE/overlay/usr/share/nullos/grub-theme" "$T/iso/boot/grub/themes/nullos"; cp "$HERE/grub-bg.jpg" "$T/iso/boot/grub/bg.jpg"
python3 - "$HERE/build-iso.sh" "$T/iso/boot/grub/grub.cfg" <<'PY'
import sys
s=open(sys.argv[1]).read(); a=s.index("cat > \"$ISO/boot/grub/grub.cfg\" <<'EOF'\n")+len("cat > \"$ISO/boot/grub/grub.cfg\" <<'EOF'\n"); b=s.index("\nEOF\n",a)
open(sys.argv[2],"w").write(s[a:b].replace("set timeout=5","set timeout=120")+"\n")
PY
grub-mkrescue -o "$T/t.iso" "$T/iso" >/dev/null 2>&1; ok "ISO with the live grub.cfg and theme builds" $?
shot(){ n=$1; wait=$2; shift 2; qemu-system-x86_64 -m 512 -cdrom "$T/t.iso" -vga std -display none -monitor unix:$T/m-$n,server,nowait -no-reboot "$@" >/dev/null 2>&1 & Q=$!
  sleep "$wait"; python3 - "$T/m-$n" "$T/$n.ppm" <<'PY'
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); time.sleep(.5); s.send(("screendump %s\n"%sys.argv[2]).encode()); time.sleep(2); s.send(b"quit\n")
PY
  sleep 1; kill $Q 2>/dev/null; }
check(){ python3 - "$T/$1.ppm" "$1" <<'PY'
import sys; from PIL import Image
im=Image.open(sys.argv[1]).convert("RGB"); W,H=im.size; px=im.load(); name=sys.argv[2]
red=sum(1 for x in range(0,W,2) for y in range(0,H,2) if abs(px[x,y][0]-229)<40 and abs(px[x,y][1]-72)<40 and abs(px[x,y][2]-77)<40)
logo=sum(1 for x in range(int(W*.40),int(W*.60)) for y in range(int(H*.07),int(H*.27)) if sum(px[x,y])>600)
hl=sum(1 for x in range(int(W*.30),int(W*.70)) for y in range(int(H*.50),int(H*.64)) if px[x,y][0]>px[x,y][2]+25 and px[x,y][0]>50)
dark=sum(1 for x in range(0,W,8) for y in range(0,H,8) if sum(px[x,y])<60)/((W//8)*(H//8))
res=[("themed screen (not blank, dark background)", dark>0.6), ("white NullOS logo at top centre (%d px)"%logo, logo>150),
     ("red accent present: wordmark/border/countdown (%d px)"%red, red>150), ("highlighted menu entry (red tint, %d px)"%hl, hl>400)]
for t,c in res: print(("PASS  " if c else "FAIL  ")+name+": "+t)
sys.exit(0 if all(c for _,c in res) else 1)
PY
}
shot bios 22; check bios; [ $? = 0 ] || f=$((f+1))
if [ -f /usr/share/OVMF/OVMF_CODE_4M.fd ] && [ -f /usr/share/OVMF/OVMF_VARS_4M.fd ]; then
  cp /usr/share/OVMF/OVMF_VARS_4M.fd "$T/vars.fd"; shot uefi 20 -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd -drive if=pflash,format=raw,file="$T/vars.fd"; check uefi; [ $? = 0 ] || f=$((f+1))
else echo "SKIP  OVMF not installed: UEFI render check skipped"; fi
# installed-system style: the header grub-mkconfig always writes + the exact output of /etc/grub.d/06_nullos_theme
mkdir -p "$T/inst/boot/grub/themes"; cp -r "$HERE/overlay/usr/share/nullos/grub-theme" "$T/inst/boot/grub/themes/nullos"
{ echo 'set timeout=120'; echo 'insmod all_video'; echo 'set gfxmode=auto'; echo 'insmod gfxterm'; echo 'terminal_output gfxterm'; sh "$HERE/overlay/etc/grub.d/06_nullos_theme"
  echo 'menuentry "NullOS" { echo hi }'; echo 'menuentry "Advanced options for NullOS" { echo hi }'; echo 'menuentry "UEFI Firmware Settings" { echo hi }'; } > "$T/inst/boot/grub/grub.cfg"
grub-mkrescue -o "$T/t.iso" "$T/inst" >/dev/null 2>&1; ok "ISO with an installed-system style grub.cfg builds" $?
shot inst 22; check inst; [ $? = 0 ] || f=$((f+1))
[ $f -eq 0 ] && echo "GRUBRENDER: ALL PASSED" || echo "GRUBRENDER: $f FAILED"; exit $f
