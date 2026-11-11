"""
Re-measure the live-run timeline from the unedited recording segment.

Usage (needs ffmpeg on PATH and Pillow):
    python measure_events.py recording-unedited-38-57s.mp4

Method: decode every frame (30 fps, so +/- 0.033 s), compare each frame with
the previous one inside a fixed screen region, and report the first frame where
that region changes after a reference time. One clock is used for everything:
the screen recording. Wall-clock timestamps from DC01, the Wazuh manager and
Telegram are NOT combined, because the hosts' clocks are not synchronized.

Frames are decoded at half size (959x538) to keep it fast; regions are given
in full-size pixels of the 1918x1076 recording and scaled (layout: Telegram
left, DC01 console top right, triage feed bottom right). Each event was also checked
by eye on the saved frames in this folder.
"""
import subprocess
import sys

from PIL import Image, ImageChops, ImageStat

FPS = 30
EVENTS = [
    # name, region (x0, y0, x1, y1), threshold, search from (s, clip time)
    ("T0 Enter on DC01 (cursor drops to the next line)", (964, 200, 1120, 250), 0.3, 2.0),
    ("T1 alert 100212 appears in the triage feed",       (964, 880, 1916, 1040), 4.0, 3.0),
    ("T2 Telegram client receives the message",          (0, 190, 680, 260), 6.0, 5.0),
    ("T3 feed prints the model verdict and metrics",     (964, 880, 1916, 1040), 4.0, 5.0),
]


def frames(path):
    """Yield (time_s, grayscale frame) for every frame, decoded by ffmpeg."""
    w, h = 959, 538
    cmd = ["ffmpeg", "-v", "error", "-i", path, "-vf", f"scale={w}:{h},format=gray",
           "-f", "rawvideo", "-"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    i, size = 0, w * h
    while True:
        raw = proc.stdout.read(size)
        if len(raw) < size:
            break
        yield i / FPS, Image.frombytes("L", (w, h), raw)
        i += 1
    proc.wait()


def main(path):
    found = {}
    prev = None
    for t, img in frames(path):
        if prev is not None:
            for name, box, thr, start in EVENTS:
                if name in found or t < start:
                    continue
                if name.startswith("T3") and "T1 alert 100212 appears in the triage feed" not in found:
                    continue
                half = tuple(v // 2 for v in box)
                d = ImageStat.Stat(ImageChops.difference(img.crop(half), prev.crop(half))).mean[0]
                if d > thr and (not name.startswith("T3") or t > found["T1 alert 100212 appears in the triage feed"] + 1):
                    found[name] = round(t, 3)
        prev = img
    t0 = found.get(EVENTS[0][0])
    for name, *_ in EVENTS:
        t = found.get(name)
        if t is None:
            print(f"{name:52s}  not found")
        else:
            print(f"{name:52s}  clip {t:6.3f} s   +{t - t0:5.2f} s from T0")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "recording-unedited-38-57s.mp4")
