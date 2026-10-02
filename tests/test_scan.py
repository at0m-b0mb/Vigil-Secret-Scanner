"""The scan: positions, collapsing, precedence, redaction, and the limits."""

import os

import pytest

from vigil.core.model import Severity
from vigil.core.rules import RULES, rule
from vigil.core.scan import (
    LineIndex,
    REDACTION,
    passes_gate,
    preview_for,
    redact_text,
    scan,
)

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")

AKIA = "AKIAEXAMPLEKEY123456"
GHP = "ghp_EXAMPLEnotarealtokenEXAMPLE000000000"
PEM = ("-----BEGIN RSA PRIVATE KEY-----\n"
       "bm90LWEtcmVhbC1rZXk=\n"
       "bm90LWEtcmVhbC1rZXk=\n"
       "-----END RSA PRIVATE KEY-----")


def _sample(name: str) -> str:
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return fh.read()


# --- the line index ---------------------------------------------------------

def test_line_index_counts_lines_without_a_trailing_newline():
    assert LineIndex("a\nb\nc").line_count == 3


def test_a_trailing_newline_does_not_open_a_line():
    assert LineIndex("a\nb\nc\n").line_count == 3


def test_line_and_column_are_one_based():
    index = LineIndex("abc\ndefgh\n")
    assert index.line_of(0) == 1
    assert index.column_of(0) == 1
    assert index.line_of(4) == 2
    assert index.column_of(4) == 1
    assert index.column_of(6) == 3


def test_windows_line_endings_keep_their_own_line():
    index = LineIndex("one\r\ntwo\r\nthree")
    assert index.line_count == 3
    assert index.line_of(index.text.index("two")) == 2


def test_an_occurrence_records_the_span_it_covers():
    text = "x\n" + PEM + "\n"
    occ = LineIndex(text).locate(text.index("-----BEGIN"),
                                text.index("-----END") + len("-----END RSA PRIVATE KEY-----"))
    assert occ.line == 2
    assert occ.end_line == 5
    assert occ.spans_lines == 4


def test_the_empty_text_has_no_lines_to_index():
    assert LineIndex("").line_count == 1   # position 0 exists; scan reports 0


# --- the basics -------------------------------------------------------------

def test_an_empty_scan_says_it_examined_nothing():
    result = scan("")
    assert not result.examined
    assert result.findings == []
    assert result.line_count == 0
    assert "nothing was examined" in " ".join(result.notes)


def test_whitespace_only_is_also_nothing_examined():
    assert not scan("   \n\t\n").examined


def test_a_clean_scan_is_examined_and_empty():
    result = scan("PORT=8080\nLOG_LEVEL=info\n")
    assert result.examined
    assert result.findings == []
    assert result.worst is None


def test_every_rule_is_applied_every_time():
    assert scan("hello").rules_applied == len(RULES)


def test_character_and_line_counts_are_the_real_ones():
    text = "a\nb\nc\n"
    result = scan(text)
    assert result.char_count == len(text)
    assert result.line_count == 3


# --- findings ---------------------------------------------------------------

def test_a_finding_knows_where_it_is():
    text = f"PORT=8080\nAWS_ACCESS_KEY_ID={AKIA}\n"
    f = scan(text).findings[0]
    assert f.line == 2
    assert f.column == len("AWS_ACCESS_KEY_ID=") + 1
    assert text[f.occurrences[0].start:f.occurrences[0].end] == AKIA


def test_a_finding_carries_a_preview_and_never_the_value():
    result = scan(f"AWS_ACCESS_KEY_ID={AKIA}")
    f = result.findings[0]
    assert f.preview != AKIA
    assert AKIA not in f.preview
    assert f.length == len(AKIA)


def test_a_finding_carries_the_words_from_its_rule():
    result = scan(f"AWS_ACCESS_KEY_ID={AKIA}")
    f = result.findings[0]
    assert f.remediation == rule("aws_access_key_id").remediation
    assert rule("aws_access_key_id").description in f.detail


def test_a_label_is_quoted_into_the_detail():
    result = scan("API_KEY = Hq8-synthetic-2Vb-9Xz")
    f = result.findings[0]
    assert f.label == "API_KEY"
    assert "Assigned to API_KEY." in f.detail


def test_findings_are_sorted_most_severe_first():
    text = (
        "STRIPE_TEST=sk_test_EXAMPLEnotarealkey00\n"
        "DB=postgres://app:not-a-real-db-password@db:5432/x\n"
        f"AWS_ACCESS_KEY_ID={AKIA}\n"
    )
    ranks = [f.severity.rank for f in scan(text).findings]
    assert ranks == sorted(ranks, reverse=True)
    assert scan(text).findings[0].severity is Severity.ALERT


def test_equal_severities_are_ordered_by_line():
    text = f"GH={GHP}\nX=1\nAWS={AKIA}\n"
    alerts = [f for f in scan(text).findings if f.severity is Severity.ALERT]
    assert [f.line for f in alerts] == sorted(f.line for f in alerts)


# --- collapsing -------------------------------------------------------------

def test_the_same_value_many_times_is_one_finding_with_a_count():
    text = "\n".join(f"line {i}: {AKIA}" for i in range(6))
    result = scan(text)
    assert len(result.findings) == 1
    assert result.findings[0].count == 6
    assert result.total_occurrences == 6


def test_collapsing_keeps_every_position():
    text = "\n".join(f"{AKIA}" for _ in range(4))
    lines = [o.line for o in scan(text).findings[0].occurrences]
    assert lines == [1, 2, 3, 4]


def test_collapsing_is_mentioned_in_the_notes():
    text = "\n".join(f"{AKIA}" for _ in range(3))
    assert any("collapsed" in n for n in scan(text).notes)


def test_two_different_values_from_one_rule_stay_separate():
    other = "AKIAEXAMPLEKEY123457"
    result = scan(f"{AKIA}\n{other}\n")
    assert len(result.findings) == 2


def test_where_reads_as_a_sentence():
    one = scan(f"{AKIA}").findings[0]
    assert one.where == "line 1"
    many = scan(f"{AKIA}\n{AKIA}\n{AKIA}").findings[0]
    assert many.where == "line 1 (+2 more)"


# --- the gates --------------------------------------------------------------

def test_an_ungated_rule_accepts_an_obviously_fake_value():
    # It must: a scanner cannot tell a revoked key from a live one, and the
    # sample set depends on this being honest rather than clever.
    assert passes_gate(rule("aws_access_key_id"), AKIA)


def test_the_template_gate_drops_substitutions_only():
    r = rule("db_connection_password")
    assert not passes_gate(r, "${DB_PASSWORD}")
    assert passes_gate(r, "not-a-real-db-password")


def test_the_full_gate_drops_the_placeholder_vocabulary():
    r = rule("generic_secret_assignment")
    assert not passes_gate(r, "changeme")
    assert not passes_gate(r, "not-a-real-key")
    assert passes_gate(r, "Hq8-synthetic-2Vb-9Xz")


def test_the_full_gate_enforces_a_minimum_length():
    assert not passes_gate(rule("generic_secret_assignment"), "Hq8-2Vb")


def test_suppressed_candidates_are_counted_and_noted():
    result = scan("password = changeme\napi_key = ${API_KEY}\n")
    assert result.suppressed == 2
    assert result.findings == []
    assert any("dropped" in n for n in result.notes)


# --- previews ---------------------------------------------------------------

def test_a_block_preview_is_its_own_first_line():
    assert preview_for(rule("private_key_block"), PEM) == \
        "-----BEGIN RSA PRIVATE KEY-----"


def test_a_block_preview_discloses_no_key_material():
    preview = preview_for(rule("private_key_block"), PEM)
    assert "bm90" not in preview


def test_a_value_preview_is_bulleted():
    assert "•" in preview_for(rule("aws_access_key_id"), AKIA)


# --- binary input -----------------------------------------------------------

def test_binary_input_is_flagged_and_explained():
    result = scan("\x00\x01\x02binary\x00blob" * 20)
    assert result.looks_binary
    assert any("does not read as text" in n for n in result.notes)


def test_a_single_long_line_says_line_numbers_cannot_help():
    result = scan("x" * 500)
    assert any("one line" in n for n in result.notes)


# --- redaction --------------------------------------------------------------

def test_redaction_removes_the_value_and_counts_it():
    text = f"AWS_ACCESS_KEY_ID={AKIA}\n"
    result = scan(text)
    out, n = redact_text(text, result)
    assert AKIA not in out
    assert n == 1
    assert REDACTION.format(name="aws_access_key_id") in out


def test_redaction_keeps_everything_that_was_not_a_secret():
    text = f"# a comment\nPORT=8080\nAWS_ACCESS_KEY_ID={AKIA}\nLOG=info\n"
    out, _ = redact_text(text, scan(text))
    assert "# a comment" in out
    assert "PORT=8080" in out
    assert "LOG=info" in out


def test_redaction_handles_several_values_on_one_line():
    text = f"{AKIA} and {GHP}\n"
    out, n = redact_text(text, scan(text))
    assert n == 2
    assert AKIA not in out and GHP not in out


def test_redaction_replaces_every_copy_of_a_collapsed_value():
    text = "\n".join(AKIA for _ in range(5))
    out, n = redact_text(text, scan(text))
    assert n == 5
    assert AKIA not in out


def test_redaction_keeps_a_pem_block_recognisable():
    text = f"KEY = '''{PEM}'''\n"
    out, _ = redact_text(text, scan(text))
    assert "-----BEGIN RSA PRIVATE KEY-----" in out
    assert "-----END RSA PRIVATE KEY-----" in out
    assert "bm90LWEtcmVhbC1rZXk=" not in out


def test_redaction_leaves_a_certificate_alone():
    text = "-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydA==\n-----END CERTIFICATE-----\n"
    out, n = redact_text(text, scan(text))
    assert n == 0
    assert out == text


def test_redaction_of_clean_text_changes_nothing():
    text = "PORT=8080\n"
    out, n = redact_text(text, scan(text))
    assert out == text and n == 0


def test_redaction_only_removes_the_password_from_a_url():
    text = "DATABASE_URL=postgres://orders_app:not-a-real-db-password@db:5432/orders\n"
    out, _ = redact_text(text, scan(text))
    assert "not-a-real-db-password" not in out
    assert "orders_app" in out and "db:5432/orders" in out


def test_redaction_accepts_a_custom_placeholder():
    text = f"KEY={AKIA}\n"
    out, _ = redact_text(text, scan(text), template="<<gone:{name}>>")
    assert "<<gone:aws_access_key_id>>" in out


# --- the samples ------------------------------------------------------------

SAMPLE_NAMES = ["leaky.env", "tidy-config.yml", "webhook_service.py",
                "docker-compose.yml", "release-notes.md"]


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_every_sample_scans_without_error(name):
    result = scan(_sample(name))
    assert result.examined
    assert not result.looks_binary


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_no_sample_secret_survives_redaction_into_a_preview(name):
    text = _sample(name)
    result = scan(text)
    for f in result.findings:
        for occ in f.occurrences:
            value = text[occ.start:occ.end]
            if f.opaque:
                assert value not in f.preview, f"{name}: {f.rule}"


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_redacting_a_sample_removes_every_opaque_value(name):
    text = _sample(name)
    result = scan(text)
    out, _ = redact_text(text, result)
    for f in result.findings:
        if not f.opaque:
            continue
        for occ in f.occurrences:
            assert text[occ.start:occ.end] not in out, f"{name}: {f.rule}"


def test_the_leaky_sample_finds_every_vendor_family():
    fired = {f.rule for f in scan(_sample("leaky.env")).findings}
    for name in ("aws_access_key_id", "aws_secret_access_key", "github_token",
                 "google_api_key", "stripe_live_key", "sendgrid_key",
                 "slack_token", "openai_style_key", "npm_token", "pypi_token"):
        assert name in fired, name


def test_the_tidy_sample_finds_nothing_and_sets_plenty_aside():
    result = scan(_sample("tidy-config.yml"))
    assert result.findings == []
    assert result.suppressed >= 4


def test_the_python_sample_reports_the_block_not_its_contents():
    fired = {f.rule for f in scan(_sample("webhook_service.py")).findings}
    assert "private_key_block" in fired
    assert "certificate_block" in fired
    assert "jwt" in fired


def test_the_compose_sample_finds_the_connection_strings():
    result = scan(_sample("docker-compose.yml"))
    assert {f.rule for f in result.findings} == {"db_connection_password"}
    assert len(result.findings) == 2
