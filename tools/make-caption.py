#!/usr/bin/env python3
"""Renders one caption card as a transparent PNG, for compositing onto video.

Exists because Homebrew's ffmpeg is built without libfreetype, so the
`drawtext` filter is unavailable -- the obvious way to burn in captions fails
with "No such filter: 'drawtext'". `overlay` is present, so captions are
rendered here and composited instead.

Usage: make-caption.py <width> <output.png> <line1> [line2 ...]
"""
import sys

from PIL import Image, ImageDraw, ImageFont

# Ordered by preference; the first that loads wins. Supplemental fonts are not
# present on every macOS install, so a plain Helvetica fallback matters.
FONT_CANDIDATES = [
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "/System/Library/Fonts/HelveticaNeue.ttc",
    "/System/Library/Fonts/Helvetica.ttc",
]

PAD_X, PAD_Y, LINE_GAP, RADIUS = 34, 22, 12, 16


def load_font(size):
    for path in FONT_CANDIDATES:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


def render(width, lines, out_path):
    # Scale with the video so captions stay legible on a Retina capture
    # without being read as huge on a downscaled one.
    title_size = max(20, width // 62)
    body_size = max(17, width // 78)

    title_font = load_font(title_size)
    body_font = load_font(body_size)
    fonts = [title_font] + [body_font] * (len(lines) - 1)

    measure = ImageDraw.Draw(Image.new("RGBA", (1, 1)))
    sizes = []
    for line, font in zip(lines, fonts):
        box = measure.textbbox((0, 0), line, font=font)
        sizes.append((box[2] - box[0], box[3] - box[1]))

    text_w = max(w for w, _ in sizes)
    text_h = sum(h for _, h in sizes) + LINE_GAP * (len(lines) - 1)
    card_w = text_w + PAD_X * 2
    card_h = text_h + PAD_Y * 2

    image = Image.new("RGBA", (card_w, card_h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    # Not fully opaque: the UI stays faintly visible behind the caption, which
    # keeps the viewer oriented in the screen being described.
    draw.rounded_rectangle([(0, 0), (card_w - 1, card_h - 1)],
                           radius=RADIUS, fill=(0, 0, 0, 214))

    y = PAD_Y
    for index, (line, font) in enumerate(zip(lines, fonts)):
        w, h = sizes[index]
        # First line is the heading; the rest are explanatory and dimmer.
        colour = (255, 255, 255, 255) if index == 0 else (219, 226, 233, 255)
        draw.text(((card_w - w) / 2, y), line, font=font, fill=colour)
        y += h + LINE_GAP

    image.save(out_path)
    print(f"{card_w}x{card_h}")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    render(int(sys.argv[1]), sys.argv[3:], sys.argv[2])
