"""
The window.

Left: the text under inspection — pasted, opened from a file, or loaded from a
sample. Right: the reading — a grade, what was scanned, the exposure map, and
every finding with the one thing it is for, which is what to do next. The window
holds the current text and re-renders the whole right side on a theme change, so
the chips and the painted map always match the active palette.

The one button that does something to the world rather than reporting on it is
**Redact and copy**: it puts a share-safe version of the text on the clipboard
with every detected value replaced by a named placeholder. That is the common
case this tool exists for — someone needs to show you a config — and it is why
the scanner never needs to display a secret in the first place.
"""

from __future__ import annotations

import os

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QGuiApplication
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from ..core.grade import analyze
from ..core.model import ScanResult, Severity
from ..core.rules import RULES, categories
from ..core.scan import redact_text
from . import theme
from .exposuremap import ExposureMap
from .widgets import Card, Chip, hrule, key_value, label, mini_label

_SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "samples")
_SAMPLE_SUFFIXES = (".env", ".yml", ".yaml", ".py", ".md", ".txt", ".json",
                    ".conf", ".cfg", ".ini", ".toml", ".http", ".sh", ".tf")

_SEV_TOKEN = {
    Severity.GOOD: "sev_good",
    Severity.INFO: "sev_info",
    Severity.NOTICE: "sev_notice",
    Severity.WARNING: "sev_warning",
    Severity.ALERT: "sev_alert",
}


class MainWindow(QWidget):
    def __init__(self, mode: str = theme.AUTO):
        super().__init__()
        self._mode_choice = mode
        self._mode = theme.resolve(mode)
        self._result: ScanResult | None = None

        self.setWindowTitle("Vigil")
        self.resize(1160, 780)
        self._build()
        self._apply_theme()

    # --- construction -------------------------------------------------------
    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_header())

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._build_source_pane())
        split.addWidget(self._build_report_pane())
        split.setStretchFactor(0, 4)
        split.setStretchFactor(1, 6)
        split.setSizes([470, 690])
        host = QWidget()
        host.setObjectName("PageHost")
        host_lay = QVBoxLayout(host)
        host_lay.setContentsMargins(16, 12, 16, 16)
        host_lay.addWidget(split)
        root.addWidget(host, 1)

    def _build_header(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("Rail")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(20, 12, 20, 12)

        mark = QLabel("VIGIL")
        mark.setObjectName("Wordmark")
        sub = QLabel("find it before they do")
        sub.setObjectName("WordmarkSub")
        wm = QVBoxLayout()
        wm.setSpacing(0)
        wm.addWidget(mark)
        wm.addWidget(sub)
        lay.addLayout(wm)
        lay.addStretch(1)

        lay.addWidget(mini_label("THEME"))
        self.theme_box = QComboBox()
        self.theme_box.addItems(["Auto", "Light", "Dark"])
        self.theme_box.setCurrentText(self._mode_choice.capitalize())
        self.theme_box.setFixedWidth(110)
        self.theme_box.currentTextChanged.connect(self._on_theme_changed)
        lay.addWidget(self.theme_box)
        return bar

    def _build_source_pane(self) -> QWidget:
        pane = QWidget()
        lay = QVBoxLayout(pane)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(theme.SPACE["base"])

        lay.addWidget(label("Paste anything that might hold a secret",
                            "PageTitle"))
        lay.addWidget(label(
            "A config file, a source file, a .env, a log, a CI job — whatever "
            "you are about to commit, paste into a ticket, or send to someone "
            "else. Nothing leaves this machine.", "PageIntro"))

        self.source = QPlainTextEdit()
        self.source.setObjectName("Mono")
        self.source.setPlaceholderText(
            "DATABASE_URL=postgres://app:...@db:5432/app\n"
            "AWS_ACCESS_KEY_ID=...\n"
            "-----BEGIN RSA PRIVATE KEY-----\n...")
        lay.addWidget(self.source, 1)

        row = QHBoxLayout()
        scan_btn = QPushButton("Scan")
        scan_btn.setObjectName("Primary")
        scan_btn.clicked.connect(self._on_scan)
        row.addWidget(scan_btn)

        open_btn = QPushButton("Open file…")
        open_btn.clicked.connect(self._on_open)
        row.addWidget(open_btn)

        self.sample_btn = QPushButton("Load sample")
        self._build_sample_menu()
        row.addWidget(self.sample_btn)

        self.redact_btn = QPushButton("Redact and copy")
        self.redact_btn.clicked.connect(self._on_redact)
        self.redact_btn.setToolTip(
            "Copy this text to the clipboard with every detected value replaced "
            "by a named placeholder.")
        row.addWidget(self.redact_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("Quiet")
        clear_btn.clicked.connect(self._on_clear)
        row.addWidget(clear_btn)
        row.addStretch(1)
        lay.addLayout(row)

        self.status = label("", "Note")
        lay.addWidget(self.status)
        return pane

    def _build_sample_menu(self) -> None:
        menu = QMenu(self)
        try:
            names = sorted(
                f for f in os.listdir(_SAMPLES_DIR)
                if not f.startswith(".") and f.endswith(_SAMPLE_SUFFIXES)
            )
        except OSError:
            names = []
        if not names:
            act = QAction("(no samples found)", self)
            act.setEnabled(False)
            menu.addAction(act)
        for name in names:
            act = QAction(name, self)
            act.triggered.connect(lambda _=False, n=name: self._load_sample(n))
            menu.addAction(act)
        self.sample_btn.setMenu(menu)

    def _build_report_pane(self) -> QWidget:
        self.report_scroll = QScrollArea()
        self.report_scroll.setWidgetResizable(True)
        self._set_placeholder()
        return self.report_scroll

    # --- behaviour ----------------------------------------------------------
    def _on_theme_changed(self, text: str) -> None:
        self._mode_choice = text.lower()
        self._mode = theme.resolve(self._mode_choice)
        self._apply_theme()
        if self._result is not None:
            self._render_report(self._result)
        else:
            self._set_placeholder()

    def _apply_theme(self) -> None:
        self.setStyleSheet(theme.stylesheet(self._mode))

    def _on_scan(self) -> None:
        text = self.source.toPlainText()
        if not text.strip():
            self._result = None
            self.status.setText("")
            self._set_placeholder("Paste something, or load a sample, to begin.")
            return
        self._result = analyze(text)
        self.status.setText("")
        self._render_report(self._result)

    def _on_open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open a file to scan", "",
            "Text and config (*.env *.yml *.yaml *.json *.toml *.ini *.conf "
            "*.cfg *.py *.js *.ts *.go *.rb *.sh *.tf *.md *.txt *.log);;"
            "All files (*)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                self.source.setPlainText(fh.read())
        except OSError as exc:
            self._set_placeholder(f"Could not open the file: {exc}")
            return
        self._on_scan()

    def _load_sample(self, name: str) -> None:
        path = os.path.join(_SAMPLES_DIR, name)
        try:
            with open(path, encoding="utf-8") as fh:
                self.source.setPlainText(fh.read())
        except OSError as exc:
            self._set_placeholder(f"Could not load the sample: {exc}")
            return
        self._on_scan()

    def _on_redact(self) -> None:
        """Put a share-safe copy of the text on the clipboard."""
        text = self.source.toPlainText()
        if not text.strip():
            self.status.setText("Nothing to redact yet.")
            return
        result = self._result if self._result is not None else analyze(text)
        self._result = result
        redacted, replaced = redact_text(text, result)
        clipboard = QGuiApplication.clipboard()
        if clipboard is None:          # no display: say so rather than lie
            self.status.setText("No clipboard is available in this session.")
            return
        clipboard.setText(redacted)
        if replaced:
            self.status.setText(
                f"Copied to the clipboard with {replaced} value"
                f"{'s' if replaced != 1 else ''} replaced. Read it before you "
                f"send it — Vigil only replaces what it found.")
        else:
            self.status.setText(
                "Copied to the clipboard unchanged — there was nothing Vigil "
                "recognised to replace. That is not a promise it is clean.")
        self._render_report(result)

    def _on_clear(self) -> None:
        self.source.clear()
        self._result = None
        self.status.setText("")
        self._set_placeholder()

    # --- report rendering ---------------------------------------------------
    def _set_placeholder(self, text: str = "") -> None:
        host = QWidget()
        lay = QVBoxLayout(host)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.addStretch(1)
        lay.addWidget(label("Nothing scanned yet", "Figure"))
        lay.addWidget(label(
            text or
            f"Vigil reads text you already have and reports the values in it "
            f"that are shaped like credentials — {len(RULES)} named patterns "
            f"across {len(categories())} families, plus an entropy test for the "
            f"ones nobody prefixed. It shows you a redacted preview, never the "
            f"value. A clean result means nothing matched; it is never a promise "
            f"there is nothing there.", "PageIntro"))
        lay.addStretch(2)
        self.report_scroll.setWidget(host)

    def _render_report(self, result: ScanResult) -> None:
        host = QWidget()
        lay = QVBoxLayout(host)
        lay.setContentsMargins(8, 4, 8, 16)
        lay.setSpacing(theme.SPACE["base"])

        lay.addWidget(self._grade_card(result))
        lay.addWidget(self._scanned_card(result))
        lay.addWidget(self._map_card(result))
        lay.addWidget(self._findings_card(result))
        if result.notes:
            notes = Card("Notes", flat=True)
            for note in result.notes:
                notes.add(label(note, muted=True))
            lay.addWidget(notes)
        lay.addStretch(1)
        self.report_scroll.setWidget(host)

    def _grade_card(self, result: ScanResult) -> QWidget:
        g = result.grade
        card = Card()
        top = QHBoxLayout()

        letter = QLabel(g.letter)
        letter.setStyleSheet(
            f"{theme.font_css('grade')} "
            f"color: {theme.color(theme.grade_token(g.letter), self._mode)};")
        top.addWidget(letter)

        col = QVBoxLayout()
        col.setSpacing(2)
        col.addWidget(mini_label(
            f"EXPOSURE GRADE  ·  SCORE {g.score}/100" if g.graded
            else "NO GRADE  ·  NOTHING WAS EXAMINED"))
        col.addWidget(label(g.headline, "PageTitle"))
        col.addStretch(1)
        top.addLayout(col, 1)
        card.add_layout(top)
        card.add(hrule())
        card.add(label(g.ceiling_note, "Note"))
        return card

    def _scanned_card(self, result: ScanResult) -> QWidget:
        card = Card("What was scanned")
        counts = result.by_severity()
        card.add(key_value(
            "Text", f"{result.line_count} lines, {result.char_count} characters",
            self._mode))
        card.add(key_value(
            "Rules", f"{result.rules_applied} patterns across "
                     f"{len(categories())} families", self._mode))
        card.add(key_value(
            "Found", f"{len(result.secrets)} distinct value"
                     f"{'s' if len(result.secrets) != 1 else ''} "
                     f"in {result.total_occurrences} place"
                     f"{'s' if result.total_occurrences != 1 else ''}",
            self._mode))
        if result.suppressed:
            card.add(key_value(
                "Set aside", f"{result.suppressed} placeholder or low-entropy "
                             f"candidate"
                             f"{'s' if result.suppressed != 1 else ''}",
                self._mode))

        if counts:
            row = QHBoxLayout()
            row.setSpacing(theme.SPACE["snug"])
            for sev in (Severity.ALERT, Severity.WARNING, Severity.NOTICE,
                        Severity.INFO):
                if counts.get(sev):
                    row.addWidget(Chip(f"{counts[sev]} {sev.value}",
                                       _SEV_TOKEN[sev], self._mode))
            row.addStretch(1)
            card.add_layout(row)
        return card

    def _map_card(self, result: ScanResult) -> QWidget:
        card = Card("Where it sits")
        exposed = len(result.exposed_lines)
        if exposed:
            card.add(label(
                f"The whole document, top to bottom. {exposed} of "
                f"{max(1, result.line_count)} lines carry something; a band is "
                f"tinted by the worst severity found in the lines it covers.",
                "Note"))
        else:
            card.add(label(
                "The whole document, top to bottom. No band is tinted, because "
                "nothing matched anywhere in it.", "Note"))
        self.map_widget = ExposureMap()
        self.map_widget.set_data(result, self._mode)
        card.add(self.map_widget)
        return card

    def _findings_card(self, result: ScanResult) -> QWidget:
        card = Card(f"Findings ({len(result.findings)})")
        if not result.findings:
            card.add(label(
                "Nothing matched. That is the most this tool can ever tell you: "
                "it means no rule in the table and no entropy test fired on this "
                "text — not that the text holds no secrets.", muted=True))
            return card

        for i, f in enumerate(result.findings):
            if i:
                card.add(hrule())
            row = QHBoxLayout()
            row.setSpacing(theme.SPACE["base"])
            chip = Chip(f.severity.value, _SEV_TOKEN[f.severity], self._mode)
            chip.setFixedWidth(84)
            row.addWidget(chip, 0, Qt.AlignmentFlag.AlignTop)

            col = QVBoxLayout()
            col.setSpacing(3)

            head = QHBoxLayout()
            head.addWidget(label(f.title, "body"))
            head.addStretch(1)
            if f.points:
                head.addWidget(label(f"−{f.points}", "Faint"))
            col.addLayout(head)

            where = QLabel(f"{f.where}, column {f.column}  ·  {f.preview}")
            where.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse)
            where.setStyleSheet(
                f"{theme.font_css('mono_small')} "
                f"color: {theme.color('ink_muted', self._mode)};")
            where.setWordWrap(True)
            col.addWidget(where)

            col.addWidget(label(f.detail, muted=True))
            col.addWidget(label(f"What to do: {f.remediation}", "Note"))
            row.addLayout(col, 1)
            card.add_layout(row)
        return card
