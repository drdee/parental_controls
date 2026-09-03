#!/usr/bin/env python3
"""Draws the Family Safety shield icon at one size, as a PNG.

Pure stdlib: writes a zlib-compressed RGBA PNG by hand so the build needs no
image libraries. Supersampled 4x then box-filtered, which is what keeps the
shield's curved edge from looking ragged at 32pt.
"""
import math, os, shutil, struct, subprocess, sys, zlib

def lerp(a, b, t): return a + (b - a) * t

def shield(px, py):
    """Signed containment test for a shield outline in unit space (0..1)."""
    x = (px - 0.5) * 2.0          # -1..1
    y = (py - 0.5) * 2.0
    if y < -0.72 or y > 0.86:
        return False
    # Top edge is flat-ish with rounded shoulders; sides taper to a point.
    half = 0.62 if y < 0.10 else lerp(0.62, 0.0, (y - 0.10) / 0.76) ** 0.92
    if y < -0.52:                  # round the top corners
        k = (-0.52 - y) / 0.20
        half *= math.sqrt(max(0.0, 1.0 - k * k))
    return abs(x) <= half

def checkmark(px, py):
    """Thick check stroke, unit space."""
    x = (px - 0.5) * 2.0
    y = (py - 0.5) * 2.0
    # y grows downward, so the middle vertex needs the LARGEST y to be the
    # bottom of the check. Getting this backwards draws a caret.
    pts = [(-0.32, -0.02), (-0.09, 0.26), (0.34, -0.30)]
    w = 0.115
    for (x1, y1), (x2, y2) in zip(pts, pts[1:]):
        dx, dy = x2 - x1, y2 - y1
        L2 = dx * dx + dy * dy
        t = max(0.0, min(1.0, ((x - x1) * dx + (y - y1) * dy) / L2))
        cx, cy = x1 + t * dx, y1 + t * dy
        if (x - cx) ** 2 + (y - cy) ** 2 <= w * w:
            return True
    return False

def render(size):
    SS = 4
    n = size * SS
    acc = [[0.0] * 4 for _ in range(size * size)]
    for j in range(n):
        v = (j + 0.5) / n
        for i in range(n):
            u = (i + 0.5) / n
            if not shield(u, v):
                continue
            # Vertical gradient: deep blue -> teal. Reads on light and dark.
            t = min(1.0, max(0.0, (v - 0.12) / 0.80))
            r, g, b = lerp(28, 16, t), lerp(86, 148, t), lerp(214, 168, t)
            if checkmark(u, v):
                r = g = b = 255.0
            o = (j // SS) * size + (i // SS)
            c = acc[o]
            c[0] += r; c[1] += g; c[2] += b; c[3] += 255.0
    k = SS * SS
    rows = []
    for j in range(size):
        row = bytearray([0])
        for i in range(size):
            c = acc[j * size + i]
            a = c[3] / k
            if a <= 0.5:
                row += bytes((0, 0, 0, 0))
            else:
                # Un-premultiply so edge pixels keep full colour.
                s = c[3] / 255.0
                row += bytes((min(255, int(c[0] / s + 0.5)),
                              min(255, int(c[1] / s + 0.5)),
                              min(255, int(c[2] / s + 0.5)),
                              min(255, int(a + 0.5))))
        rows.append(bytes(row))
    return b"".join(rows)

def png(size, path):
    raw = render(size)
    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    out = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw, 9))
           + chunk(b"IEND", b""))
    open(path, "wb").write(out)

# The seven bitmaps `iconutil` expects, and the iconset names for each.
# 16..512 all appear twice because @2x is a separate entry at double the
# pixels: icon_16x16@2x.png and icon_32x32.png are both 32 pixels.
ICONSET = [
    (16, "icon_16x16.png"),
    (32, "icon_16x16@2x.png"),
    (32, "icon_32x32.png"),
    (64, "icon_32x32@2x.png"),
    (128, "icon_128x128.png"),
    (256, "icon_128x128@2x.png"),
    (256, "icon_256x256.png"),
    (512, "icon_256x256@2x.png"),
    (512, "icon_512x512.png"),
    (1024, "icon_512x512@2x.png"),
]


def iconset(directory):
    """Writes a complete .iconset directory ready for `iconutil -c icns`.

    Renders one 1024px master here, then lets `sips -z` produce every smaller
    size, because sips' downscaling filter is better than the box filter above
    at 16 and 32 pixels.

    Note if iconutil ever reports "Failed to generate ICNS": it says that when
    the *output* directory does not exist, naming neither the file nor the
    real problem. Check the -o path before suspecting the PNGs.
    """
    if os.path.isdir(directory):
        shutil.rmtree(directory)
    os.makedirs(directory)

    master = os.path.join(directory, "master-1024.png")
    png(1024, master)
    for size, name in ICONSET:
        subprocess.run(
            ["sips", "-z", str(size), str(size), master,
             "--out", os.path.join(directory, name)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    os.remove(master)


if __name__ == "__main__":
    if sys.argv[1] == "--iconset":
        iconset(sys.argv[2])
    else:
        png(int(sys.argv[1]), sys.argv[2])
