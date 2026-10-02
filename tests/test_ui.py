"""
The window, driven off-screen.

The promise "never in the UI" is only worth as much as a test of the real
widget tree, so this module builds the window, loads every sample into it, and
walks every label it rendered looking for a value that was in the input. It also
paints the exposure map in both themes, because a painted widget is the one kind
that fails silently.

One QApplication for the module, one window per test, each closed before the
next — Qt is unforgiving about both.
"""

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication, QLabel  # noqa: E402

from vigil.core.grade import analyze  # noqa: E402
from vigil.core.scan import exposure_bands, scan  # noqa: E402
from vigil.ui import theme  # noqa: E402
from vigil.ui.exposuremap import ExposureMap  # noqa: E402
from vigil.ui.main_window import MainWindow  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")
SAMPLE_NAMES = ["leaky.env", "tidy-config.yml", "webhook_service.py",
                "docker-compose.yml", "release-notes.md"]


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance() or QApplication([])
    yield instance


@pytest.fixture
def window(app):
    win = MainWindow(mode=theme.LIGHT)
    win.resize(1180, 840)
    yield win
    win.close()


def _sample(name: str) -> str:
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return fh.read()


def _rendered_text(widget) -> str:
    """Every word the window actually put on screen."""
    return "\n".join(
        lab.text() for lab in widget.findChildren(QLabel) if lab.text()
    )


def _secret_values(name: str) -> list[str]:
    text = _sample(name)
    values = []
    for f in scan(text).findings:
        if not f.opaque:
            continue
        for occ in f.occurrences:
            value = text[occ.start:occ.end]
            if len(value) >= 12:
                values.append(value)
    return values


# --- construction -----------------------------------------------------------

def test_the_window_opens_with_a_placeholder(window):
    assert window.windowTitle() == "Vigil"
    assert "Nothing scanned yet" in _rendered_text(window)


@pytest.mark.parametrize("mode", [theme.LIGHT, theme.DARK, theme.AUTO])
def test_the_window_builds_in_every_mode(app, mode):
    win = MainWindow(mode=mode)
    try:
        assert win.theme_box.currentText().lower() == mode
        assert theme.resolve(win._mode) in (theme.LIGHT, theme.DARK)
    finally:
        win.close()


def test_the_wordmark_and_tagline_are_present(window):
    rendered = _rendered_text(window)
    assert "VIGIL" in rendered
    assert "find it before they do" in rendered


# Typography the house style allows: dashes, the middot, ellipsis, curly
# quotes, a true minus, the preview bullet, and the arrow used for a
# breadcrumb through a vendor console. Everything else above U+2100 would be
# decoration, and there is none of that in this interface.
ALLOWED_MARKS = "—–·…‘’“”−•→"


@pytest.mark.parametrize("name", [None] + SAMPLE_NAMES)
def test_there_is_no_emoji_anywhere_in_the_interface(window, name):
    if name is not None:
        window.source.setPlainText(_sample(name))
        window._on_scan()
    for ch in _rendered_text(window):
        assert ord(ch) < 0x2100 or ch in ALLOWED_MARKS, repr(ch)


# --- scanning ---------------------------------------------------------------

@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_loading_a_sample_renders_its_grade(window, name):
    window.source.setPlainText(_sample(name))
    window._on_scan()
    rendered = _rendered_text(window)
    expected = analyze(_sample(name)).grade
    assert expected.letter in rendered
    assert expected.headline in rendered
    assert expected.ceiling_note in rendered


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_the_window_never_renders_a_secret(window, name):
    window.source.setPlainText(_sample(name))
    window._on_scan()
    rendered = _rendered_text(window)
    for value in _secret_values(name):
        assert value not in rendered, f"{name}: a matched value reached a label"


def test_a_finding_is_rendered_with_its_remediation(window):
    window.source.setPlainText(_sample("leaky.env"))
    window._on_scan()
    rendered = _rendered_text(window)
    assert "AWS access key ID" in rendered
    assert "What to do:" in rendered
    assert "line 13" in rendered


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_the_word_safe_reaches_no_label_in_the_window(window, name):
    window.source.setPlainText(_sample(name))
    window._on_scan()
    assert "safe" not in _rendered_text(window).lower(), name


# --- legibility of the copy that matters most -------------------------------
# The honesty ceiling and every remediation are the most load-bearing words in
# the product, and they render at 11px — normal text, which WCAG AA holds to
# 4.5:1. They sat on the faint ink at 3.06-4.09:1. These pin the role they
# carry and then measure the colour that role resolves to, so neither the role
# nor the token can quietly slip back.

GROUNDS = ["canvas", "surface", "surface_alt", "sunken", "rail"]
PROSE_ROLES = {"Note", "Muted"}


def _labels(window, predicate) -> list:
    return [lab for lab in window.findChildren(QLabel) if predicate(lab.text())]


def _assert_role_clears_aa(role: str) -> None:
    token = {"Note": "ink_muted", "Muted": "ink_muted",
             "Faint": "ink_faint"}[role]
    for mode in (theme.LIGHT, theme.DARK):
        for ground in GROUNDS:
            ratio = theme.contrast(theme.color(token, mode),
                                   theme.color(ground, mode))
            assert ratio >= 4.5, f"{role}/{token} on {ground} in {mode}: {ratio:.2f}"


def test_the_ceiling_note_is_rendered_legibly(window):
    window.source.setPlainText(_sample("leaky.env"))
    window._on_scan()
    note = analyze(_sample("leaky.env")).grade.ceiling_note
    found = _labels(window, lambda t: t == note)
    assert found, "the ceiling note never reached the window"
    for lab in found:
        assert lab.objectName() in PROSE_ROLES, lab.objectName()
        _assert_role_clears_aa(lab.objectName())


def test_every_remediation_is_rendered_legibly(window):
    window.source.setPlainText(_sample("leaky.env"))
    window._on_scan()
    found = _labels(window, lambda t: t.startswith("What to do:"))
    assert len(found) >= 10, len(found)
    for lab in found:
        assert lab.objectName() in PROSE_ROLES, lab.objectName()
        _assert_role_clears_aa(lab.objectName())


def test_the_exposure_map_explainer_is_rendered_legibly(window):
    for name in ("leaky.env", "tidy-config.yml"):
        window.source.setPlainText(_sample(name))
        window._on_scan()
        found = _labels(window, lambda t: t.startswith("The whole document"))
        assert found, name
        for lab in found:
            assert lab.objectName() in PROSE_ROLES, lab.objectName()
            _assert_role_clears_aa(lab.objectName())


def test_the_redaction_warning_is_rendered_legibly(window):
    window.source.setPlainText(_sample("leaky.env"))
    window._on_scan()
    window._on_redact()
    assert window.status.objectName() in PROSE_ROLES, window.status.objectName()
    _assert_role_clears_aa(window.status.objectName())


def test_a_clean_scan_says_what_nothing_matched_means(window):
    window.source.setPlainText(_sample("tidy-config.yml"))
    window._on_scan()
    rendered = _rendered_text(window)
    assert "A+" in rendered
    assert "not that the text holds no secrets" in rendered


def test_scanning_nothing_asks_for_something(window):
    window.source.setPlainText("   ")
    window._on_scan()
    assert "load a sample" in _rendered_text(window)
    assert window._result is None


def test_clearing_returns_to_the_placeholder(window):
    window.source.setPlainText(_sample("leaky.env"))
    window._on_scan()
    window._on_clear()
    assert window._result is None
    assert "Nothing scanned yet" in _rendered_text(window)


def test_the_sample_menu_lists_every_sample(window):
    labels = {a.text() for a in window.sample_btn.menu().actions()}
    for name in SAMPLE_NAMES:
        assert name in labels


# --- the theme --------------------------------------------------------------

def test_switching_the_theme_rerenders_the_report(window):
    window.source.setPlainText(_sample("leaky.env"))
    window._on_scan()
    window._on_theme_changed("Dark")
    assert window._mode == theme.DARK
    assert "AWS access key ID" in _rendered_text(window)


def test_switching_the_theme_with_no_report_keeps_the_placeholder(window):
    window._on_theme_changed("Dark")
    assert "Nothing scanned yet" in _rendered_text(window)


@pytest.mark.parametrize("mode", [theme.LIGHT, theme.DARK])
def test_the_stylesheet_is_applied(window, mode):
    window._on_theme_changed(mode.capitalize())
    assert "QPushButton" in window.styleSheet()


# --- redaction through the window ------------------------------------------

def test_redacting_without_text_says_so(window):
    window._on_redact()
    assert window.status.text() == "Nothing to redact yet."


def test_redacting_reports_what_it_replaced(window):
    window.source.setPlainText(_sample("leaky.env"))
    window._on_scan()
    window._on_redact()
    status = window.status.text()
    assert "Copied to the clipboard" in status
    assert "Read it before you send it" in status


def test_redacting_a_clean_file_refuses_to_imply_it_is_clean(window):
    window.source.setPlainText(_sample("tidy-config.yml"))
    window._on_scan()
    window._on_redact()
    assert "not a promise it is clean" in window.status.text()


def test_redacting_puts_no_secret_on_the_clipboard(window):
    from PyQt6.QtGui import QGuiApplication
    window.source.setPlainText(_sample("leaky.env"))
    window._on_scan()
    window._on_redact()
    clipboard = QGuiApplication.clipboard()
    if clipboard is None:            # pragma: no cover - platform dependent
        pytest.skip("no clipboard in this session")
    text = clipboard.text()
    for value in _secret_values("leaky.env"):
        assert value not in text


def test_redacting_scans_first_if_it_has_to(window):
    window.source.setPlainText(_sample("leaky.env"))
    window._on_redact()              # no explicit scan
    assert window._result is not None
    assert "Copied to the clipboard" in window.status.text()


# --- the exposure map -------------------------------------------------------

def test_an_empty_map_says_nothing_scanned(app):
    widget = ExposureMap()
    widget.resize(360, 240)
    widget.set_data(None, theme.LIGHT)
    assert widget.grab().size().width() == 360


@pytest.mark.parametrize("mode", [theme.LIGHT, theme.DARK])
@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_the_map_paints_every_sample_in_both_themes(app, name, mode):
    widget = ExposureMap()
    widget.resize(360, 260)
    widget.set_data(analyze(_sample(name)), mode)
    image = widget.grab().toImage()
    assert not image.isNull()
    assert image.width() == 360


def test_the_map_never_asks_for_more_bands_than_lines(app):
    widget = ExposureMap()
    widget.resize(360, 600)
    result = analyze("A=1\nB=2\nC=3\n")
    widget.set_data(result, theme.LIGHT)
    assert widget.bucket_count() <= result.line_count
    assert len(exposure_bands(result, widget.bucket_count())) <= 3


def test_the_map_grows_with_the_document(app):
    short = ExposureMap()
    short.set_data(analyze("A=1\n"), theme.LIGHT)
    tall = ExposureMap()
    tall.set_data(analyze("\n".join(f"L{i}=1" for i in range(200))),
                  theme.LIGHT)
    assert tall.sizeHint().height() > short.sizeHint().height()


def test_the_map_height_is_bounded(app):
    widget = ExposureMap()
    widget.set_data(analyze("\n".join(f"L{i}=1" for i in range(5000))),
                    theme.LIGHT)
    assert widget.sizeHint().height() <= 400


def test_the_map_is_rebuilt_on_a_theme_change(window):
    window.source.setPlainText(_sample("leaky.env"))
    window._on_scan()
    light = window.map_widget.grab().toImage()
    window._on_theme_changed("Dark")
    dark = window.map_widget.grab().toImage()
    assert light != dark
