"""Telling a secret from a stand-in: entropy, shape, and the redactor."""

import pytest

from vigil.core import entropy


# --- Shannon entropy --------------------------------------------------------

def test_empty_string_has_no_entropy():
    assert entropy.shannon("") == 0.0


def test_one_repeated_character_has_no_entropy():
    assert entropy.shannon("aaaaaaaaaaaa") == 0.0


def test_eight_distinct_characters_score_exactly_three_bits():
    # The generic rule's floor is pinned to this value, so it is worth asserting.
    assert entropy.shannon("abcdefgh") == pytest.approx(3.0)


def test_entropy_is_per_character_not_total():
    # Doubling a string keeps the distribution, so the density is unchanged.
    assert entropy.shannon("abcdefgh") == pytest.approx(
        entropy.shannon("abcdefghabcdefgh"))


def test_total_bits_grows_with_length():
    assert entropy.total_bits("abcdefghabcdefgh") > entropy.total_bits("abcdefgh")


def test_a_generated_looking_key_beats_a_typed_word():
    assert entropy.shannon("Hq8-synthetic-2Vb-9Xz") > entropy.shannon("changeme")


def test_entropy_never_exceeds_log2_of_the_alphabet():
    value = "abcd"
    assert entropy.shannon(value) == pytest.approx(2.0)


# --- character classes ------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("abcdef", 1),
    ("abcDEF", 2),
    ("abcDEF123", 3),
    ("abcDEF123!", 4),
    ("", 0),
])
def test_charset_classes_counts_the_kinds_present(value, expected):
    assert entropy.charset_classes(value) == expected


# --- repetition -------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "aaaaaaaa", "abababab", "abcabcabcabc", "xxxxxxxxxxxx", "ab", "0000000000",
])
def test_repetitive_values_are_recognised(value):
    assert entropy.is_repetitive(value)


@pytest.mark.parametrize("value", [
    "Hq8-synthetic-2Vb-9Xz", "wJalrXUtnFEMIbPxRfiCYEXAMPLEKEYnotreal00",
])
def test_varied_values_are_not_repetitive(value):
    assert not entropy.is_repetitive(value)


# --- templates --------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "${AWS_SECRET_ACCESS_KEY}",
    "${AWS_SECRET_ACCESS_KEY",          # clipped by a value capture
    "$AWS_SECRET",
    "{{ vault_api_key }}",
    "{{ vault_api_key",
    "{% raw %}",
    "{api_key}",
    "<your-key-here>",
    "<your-key-here",
    "%APPDATA%",
    "$(pass show api/key)",
    "`cat /run/secrets/key`",
    "#{ENV['API_KEY']}",
])
def test_substitutions_are_recognised_however_clipped(value):
    assert entropy.is_templated(value), value


def test_a_real_looking_value_is_not_templated():
    assert not entropy.is_templated("Hq8-synthetic-2Vb-9Xz")


# --- the placeholder judgement ---------------------------------------------

@pytest.mark.parametrize("value", [
    "", "   ", "changeme", "changeme-on-first-boot", "CHANGE_ME",
    "your-api-key-here", "placeholder", "REDACTED", "dummy-value",
    "example-secret-value", "not-a-real-key", "replace-me-before-deploy",
    "xxxxxxxxxxxx", "************", "true", "false", "null", "none",
    "12345678", "1.4.2", "v2.0.1", "/run/secrets/db_password",
    "./secrets/key.pem", "~/.aws/credentials", "${TOKEN}", "todo",
    "secret", "token", "password",
])
def test_stand_ins_are_recognised(value):
    assert entropy.is_placeholder(value), value


@pytest.mark.parametrize("value", [
    "Hq8-synthetic-2Vb-9Xz",
    "pw-7Xq2-synthetic-9Kz4-Vb",
    "sy9Qv-synthetic-4Xk2Rb-7Mz",
    "wJalrXUtnFEMIbPxRfiCYQm4VztKEYsynth7Mn",
])
def test_credential_shaped_values_are_not_stand_ins(value):
    assert not entropy.is_placeholder(value), value


def test_the_placeholder_vocabulary_is_about_form_not_vendors():
    # Every entry must read as "a value goes here", not as somebody's name.
    for word in entropy.PLACEHOLDER_WORDS:
        assert word.islower() or ":" in word or "/" in word, word


# --- the combined generic test ---------------------------------------------

def test_looks_generated_requires_both_shape_and_density():
    assert entropy.looks_generated("Hq8-synthetic-2Vb-9Xz")
    assert not entropy.looks_generated("changeme")        # vocabulary
    assert not entropy.looks_generated("aaaaaaaaaaaaaaa")  # repetition
    assert not entropy.looks_generated("${TOKEN}")        # substitution


def test_clears_entropy_respects_a_custom_floor():
    assert entropy.clears_entropy("abcdefgh", 3.0)
    assert not entropy.clears_entropy("abcdefgh", 3.1)


# --- binary input -----------------------------------------------------------

def test_a_nul_byte_means_this_is_not_text():
    assert entropy.looks_binary("some text\x00more text")


def test_dense_control_bytes_mean_this_is_not_text():
    assert entropy.looks_binary("\x01\x02\x03\x04\x05abcdefgh")


def test_ordinary_text_is_not_binary():
    assert not entropy.looks_binary("API_KEY=value\nPORT=8080\n")


def test_empty_text_is_not_called_binary():
    assert not entropy.looks_binary("")


def test_tabs_and_newlines_do_not_make_text_binary():
    assert not entropy.looks_binary("a\tb\r\nc\nd" * 50)


# --- redaction --------------------------------------------------------------

def test_redaction_never_returns_the_value():
    for value in ["AKIAEXAMPLEKEY123456", "short", "abcdefghij", "a" * 200]:
        assert entropy.redact(value) != value


def test_redaction_reveals_four_each_end_for_a_long_value():
    out = entropy.redact("AKIAEXAMPLEKEY123456")
    assert out.startswith("AKIA")
    assert out.endswith("3456")
    assert "EXAMPLEKEY12" not in out


def test_redaction_reveals_less_as_the_value_shortens():
    assert entropy.redact("abcdefghijklmnopq").startswith("abcd")
    assert entropy.redact("abcdefghijklmnop").startswith("ab")
    assert set(entropy.redact("abcdefgh")) == {"•"}
    assert set(entropy.redact("abcd")) == {"•"}


def test_redaction_bullets_track_the_hidden_length():
    assert entropy.redact("abcdefgh").count("•") == 8
    assert entropy.redact("abcd").count("•") == 4


def test_redaction_of_a_short_value_reveals_nothing():
    out = entropy.redact("abcdefgh")
    assert not any(ch.isalnum() for ch in out)


def test_redaction_bullet_count_is_bounded():
    out = entropy.redact("x" * 500)
    assert out.count("•") <= 16


def test_redaction_of_an_empty_value_is_empty():
    assert entropy.redact("") == ""


def test_redaction_leaks_at_most_eight_characters():
    value = "Hq8-synthetic-2Vb-9Xz"
    out = entropy.redact(value)
    revealed = sum(1 for ch in out if ch != "•")
    assert revealed <= 8
