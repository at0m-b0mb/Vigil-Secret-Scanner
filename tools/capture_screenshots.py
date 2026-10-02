#!/usr/bin/env python3
"""
Render the window off-screen and save PNGs — proof the interface works, and the
source of the README's contact sheet.

Runs headless (``QT_QPA_PLATFORM=offscreen``), so it needs no display. It loads
each sample in both themes, writing ``images/shot-<sample>-<mode>.png``.
"""

from __future__ import annotations

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from PyQt6.QtWidgets import QApplication  # noqa: E402

from vigil.ui import theme  # noqa: E402
from vigil.ui.main_window import MainWindow  # noqa: E402

SIZE = (1180, 860)

# Every sample in both themes, so each grade on the scale — A+, B, C and F —
# is shown in light *and* dark. Two of them used to be light-only, which left
# the connection-string and test-key rules unseen in the dark palette.
SAMPLES = [
    "leaky.env",
    "tidy-config.yml",
    "webhook_service.py",
    "docker-compose.yml",
    "release-notes.md",
]
SHOTS = [(name, mode) for name in SAMPLES
         for mode in (theme.LIGHT, theme.DARK)]


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    out_dir = os.path.join(ROOT, "images")
    os.makedirs(out_dir, exist_ok=True)
    samples = os.path.join(ROOT, "samples")

    for name, mode in SHOTS:
        win = MainWindow(mode=mode)
        win.resize(*SIZE)
        with open(os.path.join(samples, name), encoding="utf-8") as fh:
            win.source.setPlainText(fh.read())
        win._on_scan()
        win.show()
        app.processEvents()
        app.processEvents()
        base = os.path.splitext(name)[0]
        path = os.path.join(out_dir, f"shot-{base}-{mode}.png")
        win.grab().save(path)
        print(f"wrote {os.path.relpath(path, ROOT)}  ({mode})")
        win.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
