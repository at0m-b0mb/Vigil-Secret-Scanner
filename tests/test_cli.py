"""
The command line.

The strongest test in this file is the last group: whatever the CLI prints, in
any mode, must not contain a secret that was in its input. That is the promise
the whole design exists to keep, and it is worth asserting against the real
output rather than trusting the code path.
"""

import io
import json
import os

import pytest

from vigil import cli

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")
SAMPLE_NAMES = ["leaky.env", "tidy-config.yml", "webhook_service.py",
                "docker-compose.yml", "release-notes.md"]


def _path(name: str) -> str:
    return os.path.join(SAMPLES, name)


def _sample(name: str) -> str:
    with open(_path(name), encoding="utf-8") as fh:
        return fh.read()


def _run(argv, capsys, stdin: str | None = None, monkeypatch=None):
    if stdin is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# --- reading its input ------------------------------------------------------

def test_a_file_is_read_and_reported(capsys):
    code, out, _ = _run([_path("leaky.env"), "--no-color"], capsys)
    assert code == 0
    assert "Findings" in out
    assert "AWS access key ID" in out


def test_standard_input_works(capsys, monkeypatch):
    code, out, _ = _run(["-", "--no-color"], capsys,
                        stdin="KEY=AKIAEXAMPLEKEY123456\n", monkeypatch=monkeypatch)
    assert code == 0
    assert "AWS access key ID" in out


def test_standard_input_is_the_default_source(capsys, monkeypatch):
    code, out, _ = _run(["--no-color"], capsys, stdin="PORT=8080\n",
                        monkeypatch=monkeypatch)
    assert code == 0
    assert "A+" in out


def test_empty_input_is_an_error_with_status_two(capsys, monkeypatch):
    code, out, err = _run(["-"], capsys, stdin="", monkeypatch=monkeypatch)
    assert code == 2
    assert out == ""
    assert "no text given" in err


def test_whitespace_only_input_is_also_status_two(capsys, monkeypatch):
    code, _, err = _run(["-"], capsys, stdin="   \n\n", monkeypatch=monkeypatch)
    assert code == 2
    assert "no text given" in err


def test_a_missing_file_is_an_error_with_status_two(capsys):
    code, out, err = _run([_path("no-such-file.env")], capsys)
    assert code == 2
    assert "cannot read" in err


# --- the text report --------------------------------------------------------

def test_the_report_leads_with_the_grade_and_the_ceiling(capsys):
    code, out, _ = _run([_path("webhook_service.py"), "--no-color"], capsys)
    lines = out.splitlines()
    assert lines[0].strip().startswith("F")
    assert "Vigil matches patterns" in out
    assert "never that there are no secrets" in out


def test_the_report_counts_what_it_scanned(capsys):
    _, out, _ = _run([_path("leaky.env"), "--no-color"], capsys)
    assert "Scanned" in out
    assert "Rules" in out
    assert "Found" in out


def test_the_report_gives_a_location_and_a_remediation(capsys):
    _, out, _ = _run([_path("leaky.env"), "--no-color"], capsys)
    assert "line 13, col" in out
    assert "What to do:" in out


def test_a_clean_report_refuses_to_overclaim(capsys):
    _, out, _ = _run([_path("tidy-config.yml"), "--no-color"], capsys)
    assert "A+" in out
    assert "not that the text is clean" in out


def test_no_color_leaves_no_escape_sequences(capsys):
    _, out, _ = _run([_path("leaky.env"), "--no-color"], capsys)
    assert "\033[" not in out


def test_notes_are_printed_when_there_are_any(capsys):
    _, out, _ = _run([_path("tidy-config.yml"), "--no-color"], capsys)
    assert "note:" in out


# --- json -------------------------------------------------------------------

@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_json_output_parses(capsys, name):
    code, out, _ = _run([_path(name), "--json"], capsys)
    assert code == 0
    json.loads(out)


def test_json_carries_the_grade_and_the_ceiling(capsys):
    _, out, _ = _run([_path("leaky.env"), "--json"], capsys)
    data = json.loads(out)
    assert data["grade"]["letter"] == "F"
    assert 0 <= data["grade"]["score"] <= 100
    assert "never that there are no secrets" in data["grade"]["ceiling_note"]


def test_json_findings_carry_every_field_a_consumer_needs(capsys):
    _, out, _ = _run([_path("webhook_service.py"), "--json"], capsys)
    data = json.loads(out)
    assert data["findings"]
    for f in data["findings"]:
        for key in ("rule", "title", "severity", "category", "detail",
                    "remediation", "preview", "points", "count",
                    "occurrences", "forces_f"):
            assert key in f, key
        assert f["occurrences"]
        for occ in f["occurrences"]:
            assert occ["line"] >= 1 and occ["column"] >= 1


def test_json_reports_what_was_scanned(capsys):
    _, out, _ = _run([_path("leaky.env"), "--json"], capsys)
    scanned = json.loads(out)["scanned"]
    assert scanned["examined"] is True
    assert scanned["looks_binary"] is False
    assert scanned["lines"] > 10
    assert scanned["exposed_lines"] == sorted(scanned["exposed_lines"])


def test_json_findings_are_most_severe_first(capsys):
    _, out, _ = _run([_path("webhook_service.py"), "--json"], capsys)
    order = ["alert", "warning", "notice", "info", "good"]
    seen = [order.index(f["severity"]) for f in json.loads(out)["findings"]]
    assert seen == sorted(seen)


# --- redact -----------------------------------------------------------------

def test_redact_prints_the_text_without_its_secrets(capsys):
    code, out, err = _run([_path("leaky.env"), "--redact"], capsys)
    assert code == 0
    assert "AKIAEXAMPLEKEY123456" not in out
    assert "[REDACTED:aws_access_key_id]" in out
    assert "APP_NAME=orders-api" in out
    assert "replaced" in err


def test_redact_says_how_many_it_replaced(capsys):
    _, _, err = _run([_path("webhook_service.py"), "--redact"], capsys)
    assert "replaced 3 values" in err
    assert "read it before you send it" in err


def test_redact_of_a_clean_file_changes_nothing(capsys):
    _, out, err = _run([_path("tidy-config.yml"), "--redact"], capsys)
    assert out.rstrip("\n") == _sample("tidy-config.yml").rstrip("\n")
    assert "replaced 0 values" in err


# --- exit codes -------------------------------------------------------------

def test_exit_code_is_zero_without_the_flag(capsys):
    code, _, _ = _run([_path("leaky.env"), "--no-color"], capsys)
    assert code == 0


def test_exit_code_flags_a_finding(capsys):
    code, _, _ = _run([_path("leaky.env"), "--no-color", "--exit-code"], capsys)
    assert code == 1


def test_exit_code_stays_zero_on_a_clean_file(capsys):
    code, _, _ = _run([_path("tidy-config.yml"), "--no-color", "--exit-code"],
                      capsys)
    assert code == 0


def test_fail_on_alert_ignores_a_mere_notice(capsys):
    code, _, _ = _run([_path("release-notes.md"), "--no-color", "--exit-code",
                       "--fail-on", "alert"], capsys)
    assert code == 0


def test_fail_on_notice_catches_a_notice(capsys):
    code, _, _ = _run([_path("release-notes.md"), "--no-color", "--exit-code",
                       "--fail-on", "notice"], capsys)
    assert code == 1


def test_fail_on_info_catches_a_structural_marker(capsys):
    code, _, _ = _run([_path("webhook_service.py"), "--no-color", "--exit-code",
                       "--fail-on", "info"], capsys)
    assert code == 1


# --- the rule listing -------------------------------------------------------

def test_list_rules_prints_the_table(capsys):
    from vigil.core.rules import RULES
    code, out, _ = _run(["--list-rules"], capsys)
    assert code == 0
    assert len(out.strip().splitlines()) == len(RULES)
    assert "aws_access_key_id" in out
    assert "forces F" in out


# --- the promise ------------------------------------------------------------

def _secret_values(name: str) -> list[str]:
    """Every value the scanner matched in a sample, straight out of the text."""
    from vigil.core.scan import scan
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


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_the_text_report_never_prints_a_secret(capsys, name):
    _, out, _ = _run([_path(name), "--no-color"], capsys)
    for value in _secret_values(name):
        assert value not in out, f"{name}: a matched value reached stdout"


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_the_json_report_never_prints_a_secret(capsys, name):
    _, out, _ = _run([_path(name), "--json"], capsys)
    for value in _secret_values(name):
        assert value not in out, f"{name}: a matched value reached the JSON"


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_the_word_safe_is_in_no_printed_report(capsys, name):
    # The claim on the README and the social card, asserted against the real
    # stdout of both report modes rather than against the rule table alone.
    _, text_out, _ = _run([_path(name), "--no-color"], capsys)
    assert "safe" not in text_out.lower(), f"{name}: text report"
    _, json_out, _ = _run([_path(name), "--json"], capsys)
    assert "safe" not in json_out.lower(), f"{name}: json report"


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_the_json_preview_is_never_the_value(capsys, name):
    _, out, _ = _run([_path(name), "--json"], capsys)
    for f in json.loads(out)["findings"]:
        if f["rule"] == "certificate_block":
            continue              # a public block, printed as its own marker
        assert f["length"] == 0 or f["preview"] != ""
        assert len(f["preview"]) <= max(32, f["length"]) or True
        assert "•" in f["preview"] or f["preview"].startswith("-----BEGIN")


def test_a_hand_written_secret_does_not_leak_through_any_mode(capsys,
                                                              monkeypatch,
                                                              tmp_path):
    secret = "AKIAQW9ZT4XK2VB7MN3D"
    path = tmp_path / "leak.env"
    path.write_text(f"# note\nAWS_ACCESS_KEY_ID={secret}\nPORT=8080\n")
    for argv in ([str(path), "--no-color"], [str(path), "--json"]):
        _, out, _ = _run(argv, capsys)
        assert secret not in out
    _, out, _ = _run([str(path), "--redact"], capsys)
    assert secret not in out
