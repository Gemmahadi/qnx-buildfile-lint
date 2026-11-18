#!/usr/bin/env python3
"""Build the demo video for qnx-buildfile-lint.

There is no GUI terminal emulator in this build VM (no xterm, no
xfce4-terminal; apt has no packages for them), so the demo is produced
honestly a different way: the real tool is run in a real terminal
(tmux, 100x40), each screen is captured with `tmux capture-pane -p`,
and the captured text is rasterised to 1920x1080 frames with PIL and
assembled with ffmpeg. Nothing on screen is faked: every terminal
frame is the verbatim output of the command shown in it.

Usage: python3 demo/make_video.py   (run from the repo root)
Output: demo/qnx-buildfile-lint-demo.mp4  (< 3 min, 30 fps, silent)
"""

import os
import subprocess
import sys
import time

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "demo")
FRAMES = os.path.join(DEMO, "frames")
SESSION = "qnxdemo"
FPS = 30
W, H = 1920, 1080

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

BG = (13, 17, 23)        # dark terminal
FG = (230, 237, 243)     # light text
DIM = (139, 148, 158)    # muted text
ACCENT = (255, 107, 107)  # QNX-ish red accent
GREEN = (63, 185, 80)

# (tmux command, hold seconds on screen)
SCENES = [
    ("./qnx-buildfile-lint examples/x86_64-bios.build", 8),
    ("./qnx-buildfile-lint examples/bad/bad-duplicate.build", 10),
    ("./qnx-buildfile-lint examples/bad/bad-script.build", 11),
    ("./qnx-buildfile-lint explain QNX305", 10),
    ("./qnx-buildfile-lint ifs demo/demo.ifs", 14),
    ("./run_tests.sh 2>&1 | tail -6", 9),
]


def tmux(*args):
    subprocess.run(["tmux", *args], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def capture_scenes():
    """Run the real tool in tmux and capture each screen."""
    tmux("kill-session", "-t", SESSION)
    tmux("new-session", "-d", "-s", SESSION, "-x", "100", "-y", "40")
    time.sleep(0.5)
    tmux("send-keys", "-t", SESSION, "PS1='$ '", "Enter")
    tmux("send-keys", "-t", SESSION, "cd " + ROOT + " && clear", "Enter")
    time.sleep(0.5)
    screens = []
    for cmd, hold in SCENES:
        tmux("send-keys", "-t", SESSION, cmd, "Enter")
        time.sleep(1.0)
        out = subprocess.run(["tmux", "capture-pane", "-p", "-t", SESSION],
                             capture_output=True, text=True).stdout
        lines = [ln.rstrip() for ln in out.splitlines()]
        while lines and lines[-1] == "":
            lines.pop()
        screens.append((lines, hold))
        print(f"captured: {cmd!r} -> {len(lines)} lines")
    tmux("kill-session", "-t", SESSION)
    return screens


def render_terminal(lines):
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    font = ImageFont.truetype(MONO, 20)
    adv = font.getlength("M")
    lh = 26
    x0 = int((W - 100 * adv) / 2)
    y0 = 20
    for i, line in enumerate(lines[:40]):
        y = y0 + i * lh
        if y + lh > H:
            break
        draw.text((x0, y), line, font=font, fill=FG)
    return img


def render_card(title, subtitle, footer, title_size=96):
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    tf = ImageFont.truetype(SANS_B, title_size)
    sf = ImageFont.truetype(SANS, 40)
    ff = ImageFont.truetype(MONO, 30)
    tw = draw.textlength(title, font=tf)
    draw.text(((W - tw) / 2, 380), title, font=tf, fill=FG)
    sw = draw.textlength(subtitle, font=sf)
    draw.text(((W - sw) / 2, 520), subtitle, font=sf, fill=DIM)
    draw.rectangle([W / 2 - 120, 620, W / 2 + 120, 626], fill=ACCENT)
    fw = draw.textlength(footer, font=ff)
    draw.text(((W - fw) / 2, 680), footer, font=ff, fill=GREEN)
    return img


def main():
    os.makedirs(FRAMES, exist_ok=True)
    for old in os.listdir(FRAMES):
        os.remove(os.path.join(FRAMES, old))

    screens = capture_scenes()
    frames = []  # (image, hold_seconds)
    frames.append((render_card(
        "qnx-buildfile-lint",
        "a host linter for QNX 8.0 mkifs buildfiles — and an IFS image inspector",
        "QNX Global Hackathon 2026  ·  Developer Tooling & Host Tools"), 4))
    for lines, hold in screens:
        frames.append((render_terminal(lines), hold))
    frames.append((render_card(
        "qnx-buildfile-lint",
        "79 rules  ·  Python 3, stdlib only  ·  MIT licensed",
        "github.com/gemmaworks/qnx-buildfile-lint", 72), 6))

    n = 0
    for img, hold in frames:
        for _ in range(int(hold * FPS)):
            n += 1
            img.save(os.path.join(FRAMES, f"{n:05d}.png"))
    print(f"wrote {n} frames ({n / FPS:.1f}s)")

    out = os.path.join(DEMO, "qnx-buildfile-lint-demo.mp4")
    subprocess.run([
        "ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
        "-framerate", str(FPS), "-i", os.path.join(FRAMES, "%05d.png"),
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "20",
        "-movflags", "+faststart", out,
    ], check=True)
    print("wrote", out)
    probe = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries",
         "format=duration,size", "-of", "csv=p=0", out],
        capture_output=True, text=True).stdout.strip()
    print("duration,size:", probe)


if __name__ == "__main__":
    main()
