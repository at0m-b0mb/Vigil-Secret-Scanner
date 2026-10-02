"""
Contrast.

Not ceremony — reading these by eye passes pairings that fail WCAG. Every text
colour must clear AA on every ground it can land on, and every severity badge
must clear AA on its own wash.
"""

import re

import pytest

from vigil.core.model import NO_GRADE
from vigil.ui import theme

TEXT_TOKENS = ["ink", "ink_muted", "ink_faint", "brass",
               "sev_good", "sev_info", "sev_notice", "sev_warning", "sev_alert",
               "hop_external", "hop_internal"]
GROUNDS = ["canvas", "surface", "surface_alt", "sunken", "rail"]
WASHES = {
    "sev_good": "sev_good_wash",
    "sev_notice": "sev_notice_wash",
    "sev_warning": "sev_warning_wash",
    "sev_alert": "sev_alert_wash",
}

# AA, for every one of them. There is no large-text exemption in this file:
# the smallest role in the stylesheet is 11px and it carries the honesty
# ceiling and every remediation, so a token exempted "because it is only used
# decoratively" is a token nobody is checking.
AA = 4.5


@pytest.mark.parametrize("mode", [theme.LIGHT, theme.DARK])
@pytest.mark.parametrize("token", TEXT_TOKENS)
@pytest.mark.parametrize("ground", GROUNDS)
def test_text_is_legible_on_every_ground(mode, token, ground):
    ratio = theme.contrast(theme.color(token, mode), theme.color(ground, mode))
    assert ratio >= AA, f"{token} on {ground} in {mode}: {ratio:.2f}:1"


@pytest.mark.parametrize("mode", [theme.LIGHT, theme.DARK])
@pytest.mark.parametrize("token,wash", sorted(WASHES.items()))
def test_badge_text_is_legible_on_its_own_wash(mode, token, wash):
    ratio = theme.contrast(theme.color(token, mode), theme.color(wash, mode))
    assert ratio >= AA, f"{token} on {wash} in {mode}: {ratio:.2f}:1"


# Checking the tokens is not the same as checking what renders. These read the
# colour each text role actually declares straight out of the built stylesheet,
# so repointing a role at a quieter ink is caught even if every token still
# passes on its own.
TEXT_ROLES = ["#Muted", "#Faint", "#Note", "#Label", "#NavGroup",
              "#WordmarkSub", "#Wordmark", "#PageTitle", "#PageIntro",
              "#CardTitle", "#Display", "#Figure"]


def _role_colour(sheet: str, role: str) -> str | None:
    """The `color:` one QSS rule block declares, as a hex string."""
    block = re.search(re.escape(role) + r"[^{]*\{([^}]*)\}", sheet)
    if block is None:
        return None
    hit = re.search(r"(?<![-\w])color:\s*(#[0-9A-Fa-f]{6})", block.group(1))
    return hit.group(1) if hit else None


def test_every_text_role_is_found_in_the_stylesheet():
    # Guard the guard: a role that stopped existing would pass vacuously.
    sheet = theme.stylesheet(theme.LIGHT)
    for role in TEXT_ROLES:
        assert _role_colour(sheet, role) is not None, role


@pytest.mark.parametrize("mode", [theme.LIGHT, theme.DARK])
@pytest.mark.parametrize("role", TEXT_ROLES)
@pytest.mark.parametrize("ground", GROUNDS)
def test_every_text_role_in_the_stylesheet_clears_aa(mode, role, ground):
    declared = _role_colour(theme.stylesheet(mode), role)
    ratio = theme.contrast(declared, theme.color(ground, mode))
    assert ratio >= AA, f"{role} ({declared}) on {ground} in {mode}: {ratio:.2f}:1"


def test_the_prose_roles_are_the_quietest_ink_that_still_clears_aa():
    # #Note is what the ceiling note and the remediations wear. It must not be
    # the faint ink that was failing AA, and it must be a declared token.
    for mode in (theme.LIGHT, theme.DARK):
        sheet = theme.stylesheet(mode)
        assert _role_colour(sheet, "#Note") == theme.color("ink_muted", mode)


def test_dark_mode_is_true_black_and_never_blue():
    assert theme.color("canvas", theme.DARK) == "#000000"
    for name, pair in theme.PALETTE.items():
        h = pair.dark.lstrip("#")
        r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
        assert b <= max(r, g) + 12, f"{name} reads as blue in the dark theme"


def test_every_colour_declares_both_themes():
    for name, pair in theme.PALETTE.items():
        assert pair.light.startswith("#") and len(pair.light) == 7, name
        assert pair.dark.startswith("#") and len(pair.dark) == 7, name


def test_there_are_two_golds_and_they_differ():
    for mode in (theme.LIGHT, theme.DARK):
        assert theme.color("brass", mode) != theme.color("shine", mode)


def test_stylesheet_builds_for_both_modes():
    for mode in (theme.LIGHT, theme.DARK):
        sheet = theme.stylesheet(mode)
        assert "QPushButton" in sheet
        assert "{{" not in sheet, "an unescaped brace leaked into the QSS"


def test_grade_tokens_cover_every_letter():
    for letter in ["A+", "A", "A-", "B+", "B", "C", "C-", "D", "F"]:
        assert theme.grade_token(letter) in theme.PALETTE


def test_the_ungraded_sentinel_is_not_coloured_as_a_failure():
    # "nothing was examined" is not a bad result; it is no result. Painting the
    # sentinel in the alert colour would be a verdict the headline retracts.
    assert theme.grade_token(NO_GRADE) == "sev_info"
    assert theme.grade_token(NO_GRADE) != theme.grade_token("F")
