"""
The exposure map — Vigil's signature.

A finding list tells you *what*; it is bad at telling you *where*. One leaked
key on line 14 of a 900-line file is a different problem from nine of them
packed into one block someone pasted in at the bottom, and the list reads almost
identically in both cases. The map is the picture that separates them: the whole
document reduced to a vertical strip, one thin band per slice of lines, tinted by
the worst thing found in that slice and left faint where nothing matched.

Everything in it is measured, never decorative:

* the strip spans the real document, line 1 at the top and the last line at the
  bottom, with a gutter scale so a band can be read back to a line number;
* a band's colour is the worst severity actually found in the lines it covers,
  and a block match — a PEM key spanning six lines — paints all six;
* if the caller asks for more bands than the document has lines, it gets one
  band per line rather than invented resolution;
* the callouts on the right are the real line numbers of the worst bands, so the
  picture hands you somewhere to look.

It is painted rather than assembled from labels because the *distribution* is
the information, and no stack of widgets shows a distribution.
"""

from __future__ import annotations

from PyQt6.QtCore import QRectF, QSize, Qt
from PyQt6.QtGui import QBrush, QColor, QFont, QFontMetrics, QPainter, QPen
from PyQt6.QtWidgets import QWidget

from . import theme
from ..core.model import ScanResult, Severity
from ..core.scan import exposure_bands

_PAD = 10
_HEADER = 26           # the count badge sits here
_GUTTER = 42           # left column: the scale's line numbers
_CALLOUT = 46          # right column: line numbers of the worst bands
_BAND_PX = 4           # target pixels per band; fewer bands if the widget is short
_MIN_STRIP = 90
_MAX_CALLOUTS = 6

_SEV_TOKEN = {
    Severity.GOOD: "sev_good",
    Severity.INFO: "sev_info",
    Severity.NOTICE: "sev_notice",
    Severity.WARNING: "sev_warning",
    Severity.ALERT: "sev_alert",
}


class ExposureMap(QWidget):
    """A vertical minimap of one scanned document."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._result: ScanResult | None = None
        self._mode = theme.LIGHT
        self.setMinimumHeight(_MIN_STRIP + _HEADER + _PAD * 2)

    # --- data ---------------------------------------------------------------
    def set_data(self, result: ScanResult | None, mode: str) -> None:
        self._result = result
        self._mode = mode
        lines = result.line_count if result else 0
        wanted = _HEADER + _PAD * 2 + max(_MIN_STRIP, min(300, lines * 4))
        self.setMinimumHeight(wanted)
        self.updateGeometry()
        self.update()

    def sizeHint(self) -> QSize:  # noqa: N802  (Qt override)
        lines = self._result.line_count if self._result else 0
        return QSize(360, _HEADER + _PAD * 2 + max(_MIN_STRIP, min(300, lines * 4)))

    def bucket_count(self, strip_height: float | None = None) -> int:
        """How many bands fit, never more than the document has lines."""
        if strip_height is None:
            strip_height = max(1.0, self.height() - _HEADER - _PAD * 2)
        lines = max(1, self._result.line_count if self._result else 1)
        return max(1, min(int(strip_height // _BAND_PX) or 1, lines))

    # --- painting -----------------------------------------------------------
    def paintEvent(self, event):  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        c = lambda n: QColor(theme.color(n, self._mode))  # noqa: E731

        result = self._result
        if result is None or not result.examined:
            p.setPen(c("ink_faint"))
            p.setFont(self._font("subtitle"))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                       "Nothing scanned yet.")
            p.end()
            return

        self._draw_badge(p, c, result)

        strip_x = _PAD + _GUTTER
        strip_w = max(24.0, self.width() - strip_x - _CALLOUT - _PAD)
        strip_y = float(_PAD + _HEADER)
        strip_h = max(10.0, self.height() - strip_y - _PAD)

        lines = max(1, result.line_count)
        buckets = self.bucket_count(strip_h)
        bands = exposure_bands(result, buckets)
        band_h = strip_h / len(bands)

        # The document, band by band. Once a band is tall enough to show it,
        # a hairline is left between them: the strip then reads as a document
        # with lines in it rather than as a bar chart.
        p.setPen(Qt.PenStyle.NoPen)
        quiet = c("rule")
        gap = 1.0 if band_h >= 4 else 0.0
        for band in bands:
            y = strip_y + band.index * band_h
            fill = quiet if band.is_quiet else c(_SEV_TOKEN[band.severity])
            p.setBrush(QBrush(fill))
            p.drawRect(QRectF(strip_x, y, strip_w,
                              max(1.0, band_h - gap) + (0.6 if not gap else 0.0)))

        # its edge, so the strip reads as one object even when it is all quiet
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(c("rule_strong"), 1))
        p.drawRect(QRectF(strip_x - 0.5, strip_y - 0.5, strip_w + 1, strip_h + 1))

        self._draw_scale(p, c, strip_x, strip_y, strip_w, strip_h, lines)
        self._draw_callouts(p, c, bands, strip_x, strip_y, strip_w, strip_h, band_h)
        p.end()

    # --- pieces -------------------------------------------------------------
    def _draw_badge(self, p: QPainter, c, result: ScanResult) -> None:
        """A pill counting the findings, and how much of the file they touch."""
        n = len(result.findings)
        exposed = len(result.exposed_lines)
        lines = max(1, result.line_count)
        if n:
            text = (f"{n} FINDING{'S' if n != 1 else ''}  ·  "
                    f"{exposed} OF {lines} LINE{'S' if lines != 1 else ''}")
        else:
            text = f"NOTHING MATCHED  ·  {lines} LINE{'S' if lines != 1 else ''} READ"

        font = self._font("label")
        p.setFont(font)
        width = QFontMetrics(font).horizontalAdvance(text) + 18
        box = QRectF(_PAD, _PAD, min(width, self.width() - _PAD * 2), 18)

        token = "brass" if n else "sev_good"
        wash = "brass_wash" if n else "sev_good_wash"
        p.setBrush(QBrush(c(wash)))
        p.setPen(QPen(c("brass_edge" if n else "rule"), 1))
        p.drawRoundedRect(box, 3, 3)
        p.setPen(c(token))
        p.drawText(box, Qt.AlignmentFlag.AlignCenter, text)

    def _draw_scale(self, p: QPainter, c, x: float, y: float, w: float,
                    h: float, lines: int) -> None:
        """Line numbers down the gutter, with hairlines into the strip."""
        p.setFont(self._font("mono_small"))
        fractions = [0.0, 1.0] if h < 140 else [0.0, 0.25, 0.5, 0.75, 1.0]
        for frac in fractions:
            ty = y + h * frac
            line_no = 1 if frac == 0.0 else max(1, int(round(lines * frac)))
            p.setPen(c("hop_internal"))
            p.drawText(QRectF(_PAD, ty - 7, _GUTTER - 8, 14),
                       Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                       str(line_no))
            if 0.0 < frac < 1.0:
                pen = QPen(c("rule_strong"), 1, Qt.PenStyle.DotLine)
                p.setPen(pen)
                p.drawLine(int(x), int(ty), int(x + w), int(ty))

    def _draw_callouts(self, p: QPainter, c, bands, x: float, y: float,
                       w: float, h: float, band_h: float) -> None:
        """Name the lines of the worst bands, so the picture points somewhere."""
        hit = [b for b in bands if not b.is_quiet]
        if not hit:
            return
        hit.sort(key=lambda b: (-b.severity.rank, -b.hits, b.index))
        chosen = sorted(hit[:_MAX_CALLOUTS], key=lambda b: b.index)

        p.setFont(self._font("mono_small"))
        last_y = -99.0
        for band in chosen:
            cy = y + (band.index + 0.5) * band_h
            if cy - last_y < 13:        # never stack two labels on top of each other
                continue
            last_y = cy
            token = _SEV_TOKEN[band.severity]
            p.setPen(QPen(c(token), 1))
            p.drawLine(int(x + w), int(cy), int(x + w + 6), int(cy))
            p.setPen(c("hop_external"))
            p.drawText(QRectF(x + w + 9, cy - 7, _CALLOUT - 10, 14),
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                       str(band.first_line))

    # --- helpers ------------------------------------------------------------
    def _font(self, role: str) -> QFont:
        family, size, weight = theme.TYPE[role]
        f = QFont()
        f.setFamilies([family.split(",")[0].strip().strip('"')])
        f.setPixelSize(size)
        f.setWeight(QFont.Weight.DemiBold if weight >= 600 else QFont.Weight.Normal)
        return f
