#!/usr/bin/env python3
"""Generates NullOS artwork from tools/assets-src: wallpapers (red = the source image, blue/green by hue rotation,
black-and-white), the GRUB theme (background + 9-slice menu images) and the installer welcome image.
Run:  python3 tools/make-assets.py     (needs Pillow; fonts-jetbrains-mono for text)"""
import colorsys, os
from PIL import Image, ImageChops, ImageDraw, ImageEnhance, ImageFilter, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.join(HERE, "..")
BG = os.path.join(ROOT, "overlay/usr/share/backgrounds/nullos"); GT = os.path.join(ROOT, "overlay/usr/share/nullos/grub-theme")
ICON = os.path.join(ROOT, "overlay/usr/share/icons/hicolor/256x256/apps/nullos.png")
RED = (229, 72, 77)
FONT = next((p for p in ("/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf") if os.path.exists(p)), None)
FONTB = next((p for p in ("/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf") if os.path.exists(p)), FONT)


def hue_variant(img, accent_hex):
    """Rotate every saturated pixel's hue from red to the accent's hue (greys, whites and blacks are untouched)."""
    r, g, b = (int(accent_hex[i:i + 2], 16) / 255 for i in (0, 2, 4))
    target = colorsys.rgb_to_hsv(r, g, b)[0]
    h, s, v = img.convert("HSV").split()
    shift = int(round(target * 255))
    h = h.point(lambda x: (x + shift) % 256)
    return Image.merge("HSV", (h, s, v)).convert("RGB")


def wallpapers():
    src = Image.open(os.path.join(HERE, "assets-src/crimson-eclipse.png")).convert("RGB")
    os.makedirs(BG, exist_ok=True)
    out = {"red": src, "blue": hue_variant(src, "4c8dff"), "green": hue_variant(src, "3ecf8e"),
           "mono": ImageEnhance.Contrast(src.convert("L")).enhance(1.12).convert("RGB")}
    for k, im in out.items():
        im.save(os.path.join(BG, k + ".jpg"), quality=90, optimize=True, progressive=True)


def glow_background(w, h, with_logo=True):
    """Dark panel with red diagonal light streaks, the NullOS mark and name (mock-up: boot screen)."""
    base = Image.new("RGB", (w, h), (5, 5, 6))
    glow = Image.new("RGB", (w, h), (0, 0, 0)); d = ImageDraw.Draw(glow)
    d.polygon([(0, int(h * .62)), (int(w * .30), 0), (int(w * .335), 0), (0, int(h * .70))], fill=(150, 20, 28))
    d.polygon([(int(w * .70), h), (w, int(h * .30)), (w, int(h * .37)), (int(w * .74), h)], fill=(120, 14, 22))
    d.polygon([(int(w * .86), h), (w, int(h * .62)), (w, int(h * .66)), (int(w * .88), h)], fill=(80, 10, 16))
    glow = glow.filter(ImageFilter.GaussianBlur(w // 90))
    base = ImageChops.add(base, glow)
    if with_logo:
        icon = Image.open(ICON).convert("RGBA"); s = int(h * .17); icon = icon.resize((s, s), Image.LANCZOS)
        base.paste(icon, ((w - s) // 2, int(h * .075)), icon)
        d = ImageDraw.Draw(base)
        f1 = ImageFont.truetype(FONTB, int(h * .075)); f2 = ImageFont.truetype(FONT, int(h * .026))
        t1, t2 = "Null", "OS"; wd = d.textlength(t1 + t2, font=f1); x = (w - wd) / 2; y = int(h * .075) + s + int(h * .012)
        d.text((x, y), t1, font=f1, fill=(235, 235, 235)); d.text((x + d.textlength(t1, font=f1), y), t2, font=f1, fill=RED)
        tag = "Secure   \u2022   Minimal   \u2022   Private"; d.text(((w - d.textlength(tag, font=f2)) / 2, y + int(h * .09)), tag, font=f2, fill=(190, 190, 190))
    return base


def nine_slice(prefix, fill, border, size=6):
    """GRUB boot-menu pixmap style: nw n ne w c e sw s se (1px border, translucent fill)."""
    s = size
    def px(w, h, edges):
        im = Image.new("RGBA", (w, h), fill); p = im.load()
        for x in range(w):
            for y in range(h):
                if ("t" in edges and y == 0) or ("b" in edges and y == h - 1) or ("l" in edges and x == 0) or ("r" in edges and x == w - 1):
                    p[x, y] = border
        return im
    parts = {"nw": (s, s, "tl"), "n": (1, s, "t"), "ne": (s, s, "tr"), "w": (s, 1, "l"), "c": (1, 1, ""), "e": (s, 1, "r"),
             "sw": (s, s, "bl"), "s": (1, s, "b"), "se": (s, s, "br")}
    for k, (w, h, e) in parts.items():
        px(w, h, e).save(os.path.join(GT, "%s_%s.png" % (prefix, k)))


def grub_theme():
    os.makedirs(GT, exist_ok=True)
    glow_background(1920, 1080).save(os.path.join(GT, "background.png"), optimize=True)
    nine_slice("select", (229, 72, 77, 70), (229, 72, 77, 255))
    nine_slice("menu", (10, 10, 12, 205), (120, 40, 44, 255))


def welcome():
    glow_background(640, 360).save(os.path.join(ROOT, "overlay/etc/calamares/branding/nullos/welcome.png"), optimize=True)


if __name__ == "__main__":
    wallpapers(); grub_theme(); welcome(); print("assets written")
