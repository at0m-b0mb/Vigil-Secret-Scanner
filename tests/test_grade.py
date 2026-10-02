"""The letter, the ceilings that hold it down, and the honesty it carries."""

import os

import pytest

from vigil.core.grade import CEILING_NOTE, _LETTERS, analyze
from vigil.core.model import NO_GRADE, Severity
from vigil.core.rules import RULES

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")
SAMPLE_NAMES = ["leaky.env", "tidy-config.yml", "webhook_service.py",
                "docker-compose.yml", "release-notes.md"]

AKIA = "AKIAEXAMPLEKEY123456"
PEM = "-----BEGIN RSA PRIVATE KEY-----\nbm90LWEtcmVhbC1rZXk=\n"
CERT = "-----BEGIN CERTIFICATE-----\nbm90\n-----END CERTIFICATE-----\n"


def _sample(name: str) -> str:
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return fh.read()


def _worse_or_equal(letter: str, ceiling: str) -> bool:
    return _LETTERS.index(letter) >= _LETTERS.index(ceiling)


def _spoken(result) -> str:
    """Every word a result puts in front of a reader, lower-cased."""
    g = result.grade
    return " ".join(
        [g.letter, g.headline, g.ceiling_note]
        + [f.title for f in result.findings]
        + [f.detail for f in result.findings]
        + [f.remediation for f in result.findings]
        + [f.preview for f in result.findings]
        + [f.label for f in result.findings]
        + result.notes
    ).lower()


# --- the top of the scale ---------------------------------------------------

def test_a_plus_only_when_nothing_matched():
    result = analyze("PORT=8080\nLOG_LEVEL=info\n")
    assert result.grade.letter == "A+"
    assert result.grade.score == 100
    assert result.grade.headline == "Nothing matched"


def test_a_plus_still_carries_the_ceiling_note():
    result = analyze("PORT=8080\n")
    assert "never that there are no secrets" in result.grade.ceiling_note


def test_one_structural_marker_costs_the_top_grade_but_nothing_else():
    result = analyze("-----BEGIN CERTIFICATE-----\nbm90\n-----END CERTIFICATE-----\n")
    assert result.grade.letter == "A"
    assert result.grade.score == 100       # an INFO finding costs no points
    assert result.findings[0].severity is Severity.INFO


def test_a_notice_cannot_reach_an_a():
    result = analyze("STRIPE=sk_test_EXAMPLEnotarealkey00\n")
    assert _worse_or_equal(result.grade.letter, "B")


def test_a_warning_cannot_reach_a_b():
    result = analyze("DB=postgres://app:not-a-real-db-password@db:5432/x\n")
    assert _worse_or_equal(result.grade.letter, "C")


# --- the bottom -------------------------------------------------------------

@pytest.mark.parametrize("text", [
    f"AWS_ACCESS_KEY_ID={AKIA}",
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIbPxRfiCYEXAMPLEKEYnotreal00",
    "ghp_EXAMPLEnotarealtokenEXAMPLE000000000",
    "sk_live_EXAMPLEnotarealkey00",
    PEM,
])
def test_an_issued_looking_credential_forces_f(text):
    assert analyze(text).grade.letter == "F"


def test_forcing_beats_an_otherwise_high_score():
    # One certificate and one AWS key: the score stays high, the letter does not.
    text = f"-----BEGIN CERTIFICATE-----\nbm90\n\nKEY={AKIA}\n"
    result = analyze(text)
    assert result.grade.score >= 60
    assert result.grade.letter == "F"


def test_many_warnings_can_reach_f_on_points_alone():
    lines = [f"DB{i}=postgres://app:not-a-real-pass-{i}@db:5432/x" for i in range(9)]
    result = analyze("\n".join(lines))
    assert result.grade.letter == "F"
    assert not any(f.forces_f for f in result.findings)


# --- the honest unknowns ----------------------------------------------------

def test_nothing_examined_borrows_no_letter_from_the_scale():
    # A letter is a verdict. Nothing was examined, so there is no verdict to
    # render: the sentinel keeps the big letterform from contradicting the
    # headline printed beside it.
    for text in ("", "   ", "\n\n"):
        result = analyze(text)
        assert result.grade.letter == NO_GRADE
        assert result.grade.letter not in _LETTERS
        assert not result.grade.graded
        assert "nothing" in result.grade.headline.lower()


def test_a_real_grade_still_says_it_is_one():
    assert analyze("PORT=8080\n").grade.graded
    assert analyze(f"KEY={AKIA}\n").grade.graded


def test_binary_input_is_capped_rather_than_passed():
    result = analyze("\x00\x01\x02\x03binary" * 40)
    assert _worse_or_equal(result.grade.letter, "C")
    assert "does not read as text" in result.grade.headline


def test_a_secret_inside_binary_still_forces_f():
    result = analyze("\x00\x01\x02\x03" * 40 + f"\n{AKIA}\n")
    assert result.grade.letter == "F"


# --- points -----------------------------------------------------------------

def test_every_finding_records_what_it_cost():
    result = analyze(f"KEY={AKIA}\nSTRIPE=sk_test_EXAMPLEnotarealkey00\n")
    for f in result.findings:
        if f.severity in (Severity.ALERT, Severity.WARNING, Severity.NOTICE):
            assert f.points > 0
        else:
            assert f.points == 0


def test_repeats_add_a_little_but_not_a_lot():
    once = analyze(f"KEY={AKIA}\n")
    twice = analyze(f"KEY={AKIA}\nAGAIN={AKIA}\n")
    assert twice.findings[0].points > once.findings[0].points
    assert twice.findings[0].points <= once.findings[0].points + 8


def test_the_repeat_cost_is_bounded():
    many = analyze("\n".join(f"KEY={AKIA}" for _ in range(50)))
    assert many.findings[0].points <= 48


def test_the_score_never_leaves_its_range():
    for text in ["", "PORT=1", f"KEY={AKIA}", _sample("leaky.env")]:
        assert 0 <= analyze(text).grade.score <= 100


# --- the samples ------------------------------------------------------------

EXPECTED = {
    "tidy-config.yml": "A+",
    "release-notes.md": "B",
    "docker-compose.yml": "C",
    "webhook_service.py": "F",
    "leaky.env": "F",
}


@pytest.mark.parametrize("name,letter", sorted(EXPECTED.items()))
def test_each_sample_lands_on_its_grade(name, letter):
    assert analyze(_sample(name)).grade.letter == letter


def test_the_samples_span_the_scale():
    letters = {analyze(_sample(n)).grade.letter for n in SAMPLE_NAMES}
    assert len(letters) >= 4
    assert "A+" in letters and "F" in letters


# --- the house ethos --------------------------------------------------------

@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_every_result_carries_the_ceiling_note(name):
    assert analyze(_sample(name)).grade.ceiling_note == CEILING_NOTE


@pytest.mark.parametrize("text", ["", "PORT=8080", f"KEY={AKIA}", PEM])
def test_the_ceiling_note_is_never_omitted(text):
    assert analyze(text).grade.ceiling_note == CEILING_NOTE


def test_the_ceiling_note_names_all_three_blind_spots():
    note = CEILING_NOTE.lower()
    assert "miss any secret it has no rule for" in note   # coverage
    assert "live key from one revoked" in note            # liveness
    assert "flag something harmless" in note              # false positives


# The verdict surface. A headline is what someone reads and repeats, so the
# words that would turn a scan into a clearance are banned outright here.
BANNED_IN_A_HEADLINE = ("safe", "secure", "clean", "no secrets", "all clear",
                        "nothing to worry")

# Prose may never pass a verdict on the text it was given.
BANNED_VERDICTS = (
    "file is safe", "text is safe", "config is safe", "you are safe",
    "this is safe", "is secure", "are secure", "no secrets were",
    "no secrets here", "nothing to worry", "you are clean", "all clear",
)


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_no_headline_ever_reads_as_a_clearance(name):
    headline = analyze(_sample(name)).grade.headline.lower()
    for word in BANNED_IN_A_HEADLINE:
        assert word not in headline, word


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_no_prose_passes_a_verdict_on_the_input(name):
    result = analyze(_sample(name))
    blob = " ".join(
        [result.grade.headline, result.grade.ceiling_note]
        + [f.title for f in result.findings]
        + [f.detail for f in result.findings]
        + [f.remediation for f in result.findings]
        + result.notes
    ).lower()
    for claim in BANNED_VERDICTS:
        assert claim not in blob, claim


def test_the_banned_words_would_actually_catch_a_clearance():
    # Guard the guard: a test that cannot fail protects nothing.
    pretend = "this file is safe and secure, no secrets here".lower()
    assert any(w in pretend for w in BANNED_IN_A_HEADLINE)
    assert any(c in pretend for c in BANNED_VERDICTS)


# --- the one absolute claim -------------------------------------------------
# The README, the social card and the release notes all say the same thing:
# the word *safe* appears nowhere in a result. These assert the word itself,
# over the whole table and over every result, rather than a list of phrases —
# a phrase list is exactly how the claim drifted out of true once already. The
# certificate remediation read "only one of them is safe to publish", which is
# correct English and still broke the promise printed on the box.

def test_the_word_safe_appears_nowhere_in_the_rule_table():
    for r in RULES:
        for part in ("title", "description", "remediation"):
            assert "safe" not in getattr(r, part).lower(), f"{r.name}.{part}"


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_the_word_safe_appears_nowhere_in_a_sample_result(name):
    assert "safe" not in _spoken(analyze(_sample(name))), name


@pytest.mark.parametrize("text", [
    "", "   ", "PORT=8080\n", f"KEY={AKIA}\n", PEM, CERT,
    "STRIPE=sk_test_EXAMPLEnotarealkey00\n",
    "DB=postgres://app:not-a-real-db-password@db:5432/x\n",
    "Authorization: Bearer Hq8synthetic2Vb9XzQm4Vzt7Mn\n",
    "\x00\x01\x02\x03binary" * 40,
])
def test_the_word_safe_appears_nowhere_in_any_other_result(text):
    assert "safe" not in _spoken(analyze(text))


def test_the_safe_sweep_would_actually_catch_the_word():
    # Guard the guard, again: the sweep has to see a planted occurrence.
    result = analyze(f"KEY={AKIA}\n")
    result.findings[0].remediation += " and only one of them is safe to publish."
    assert "safe" in _spoken(result)


def test_the_clean_headline_does_not_overclaim():
    headline = analyze("PORT=8080\n").grade.headline.lower()
    assert "clean" not in headline
    assert "no secret" not in headline


def test_a_grade_letter_is_always_on_the_scale():
    for text in ["PORT=1", f"KEY={AKIA}", PEM, "\x00" * 50]:
        grade = analyze(text).grade
        assert grade.graded
        assert grade.letter in _LETTERS
    for text in ["", "   "]:                 # never examined: no letter at all
        assert analyze(text).grade.letter == NO_GRADE


def test_findings_are_sorted_most_severe_first_after_grading():
    result = analyze(_sample("webhook_service.py"))
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_grading_is_idempotent():
    from vigil.core.grade import grade_scan
    first = analyze(_sample("leaky.env"))
    letter, score = first.grade.letter, first.grade.score
    again = grade_scan(first)
    assert (again.grade.letter, again.grade.score) == (letter, score)
