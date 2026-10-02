"""
Telling a secret from a stand-in.

The hard part of a secret scanner is not finding `password =` — it is deciding
whether what follows is a credential or the word ``changeme``. A vendor-prefixed
key proves itself (nothing but an AWS key starts ``AKIA`` and runs sixteen more
characters), but the generic rule — *a secret-ish name assigned something* —
needs judgement, and this module is all of it.

Two measures, applied in order:

* **Shape.** A value that is templated (``${VAR}``, ``{{ vault_key }}``,
  ``<your-key-here>``), spelled out of a placeholder vocabulary, repetitive, or
  simply not a credential at all (a number, a boolean, a path) is a stand-in.
  This is a judgement about *form*, not a list of forbidden words.

* **Shannon entropy**, in bits per character. A real credential is drawn from a
  wide alphabet with little structure and lands near the top of its range; a
  word a person typed does not. The threshold is deliberately low
  (:data:`GENERIC_MIN_ENTROPY`) because the cost of a false negative in a secret
  scanner is someone's production key, and the cost of a false positive is one
  line a reader can dismiss.

Both gates apply only to rules that ask for them. A rule that recognises an
issued credential by its prefix never consults this module — which is why Vigil
still reports an obviously fake ``AKIAEXAMPLE…`` key. It cannot tell a revoked
key from a live one, and pretending otherwise would be the dishonest choice.
"""

from __future__ import annotations

import math
import re
from collections import Counter

# The generic rule's floor, in bits per character. An eight-character value of
# wholly distinct characters scores exactly 3.0, so this admits the weakest
# thing that could plausibly be a generated secret and rejects English.
GENERIC_MIN_ENTROPY = 3.0

# Substrings that announce a stand-in. Each one is a phrase a person writes when
# they mean "a value goes here" — not a judgement about any product or vendor.
PLACEHOLDER_WORDS = (
    "changeme", "change-me", "change_me", "change_this", "changethis",
    "placeholder", "redacted", "removed", "elided", "omitted",
    "yourkey", "your-key", "your_key", "your-token", "your_token",
    "your-secret", "your_secret", "your-password", "your_password",
    "yourapikey", "your-api-key", "your_api_key",
    "notareal", "not-a-real", "not_a_real", "notreal", "fakekey", "fake-key",
    "dummy", "example", "exemple", "sample-value", "samplevalue",
    "insertvalue", "insert-value", "insert_here", "inserthere",
    "replaceme", "replace-me", "replace_me", "goes-here", "goes_here",
    "goeshere", "todo", "tbd", "xxxxxx", "secret-here", "secret_here",
    "s3cr3t-here", "set-in-vault", "set_in_vault", "from-vault", "from_vault",
    "vault:", "sops:", "op://", "aws-secretsmanager", "secretref",
)

# Values that are a bare literal rather than a credential.
NON_SECRETS = frozenset({
    "true", "false", "null", "none", "nil", "undefined", "empty", "nothing",
    "optional", "required", "disabled", "enabled", "default", "unset",
    "password", "secret", "token", "apikey", "api_key", "credential",
})

# A substitution, written whole or clipped. The closing brace matters less than
# it looks: a scanner's value capture usually stops at the delimiter, so
# ``${AWS_SECRET_ACCESS_KEY`` arrives here without its ``}`` and must still be
# recognised as the reference it plainly is.
_TEMPLATE = re.compile(
    r"""(
        \$\{[^{}]*\}?           # ${VAR}            (close optional)
      | \$[A-Za-z_][A-Za-z0-9_]*  # $VAR
      | \{\{[^{}]*(?:\}\}?)?    # {{ jinja }}       (close optional)
      | \{%[^%]*(?:%\}?)?        # {% jinja %}
      | \{[A-Za-z_][A-Za-z0-9_]*\}?  # {python_format}
      | <[^<>]*>?                # <your-key-here>   (close optional)
      | %[A-Za-z_][A-Za-z0-9_]*%?  # %WINDOWS%
      | \$\([^()]*\)?           # $(shell)
      | `[^`]*`?                 # `backticks`
      | \#\{[^{}]*\}?           # #{ruby}
    )""",
    re.VERBOSE,
)

# The openers above, anchored: a value that *starts* with one is a reference
# however badly it was clipped.
_TEMPLATE_OPENER = re.compile(r"^(?:\$\{|\$\(|\{\{|\{%|<|%[A-Za-z_]|`|\#\{|\$[A-Za-z_])")

_ALL_DIGITS = re.compile(r"^[\d._,+-]+$")
_PATHLIKE = re.compile(r"^(?:[./~]|[A-Za-z]:[\\/])")
_VERSIONISH = re.compile(r"^v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.]+)?$")


def shannon(value: str) -> float:
    """Entropy of *value* in bits per character (0.0 for an empty string).

    This is the per-character figure, not the total, so it compares values of
    different lengths honestly: a long repetitive string scores low and a short
    varied one scores high, which is the distinction that matters here.
    """
    if not value:
        return 0.0
    n = len(value)
    total = 0.0
    for count in Counter(value).values():
        p = count / n
        total -= p * math.log2(p)
    return total


def total_bits(value: str) -> float:
    """Entropy of *value* in bits overall — its length times its density."""
    return shannon(value) * len(value)


def charset_classes(value: str) -> int:
    """How many of lower / upper / digit / symbol the value draws on."""
    classes = 0
    if any(c.islower() for c in value):
        classes += 1
    if any(c.isupper() for c in value):
        classes += 1
    if any(c.isdigit() for c in value):
        classes += 1
    if any(not c.isalnum() for c in value):
        classes += 1
    return classes


def is_repetitive(value: str) -> bool:
    """True when one character, or a tiny alphabet, dominates the value."""
    if len(value) < 4:
        return True
    counts = Counter(value)
    if len(counts) <= 2:
        return True
    if counts.most_common(1)[0][1] / len(value) >= 0.6:
        return True
    # a short unit repeated to length: "abcabcabcabc"
    for unit in range(1, min(4, len(value) // 3) + 1):
        if value == value[:unit] * (len(value) // unit) and len(value) % unit == 0:
            return True
    return False


def is_templated(value: str) -> bool:
    """True when the value is, or contains, a substitution placeholder."""
    v = value.strip()
    return bool(_TEMPLATE_OPENER.match(v) or _TEMPLATE.search(v))


def is_placeholder(value: str) -> bool:
    """True when the value is plainly a stand-in rather than a credential.

    Checked in cheapening order — shape first, vocabulary second — so the common
    cases cost almost nothing.
    """
    v = value.strip().strip("\"'")
    if not v:
        return True
    low = v.lower()

    if low in NON_SECRETS:
        return True
    if is_templated(v):
        return True
    if _ALL_DIGITS.match(v) or _VERSIONISH.match(v):
        return True
    if _PATHLIKE.match(v):
        return True
    if is_repetitive(v):
        return True
    if set(low) <= set("x*.-_"):
        return True
    for word in PLACEHOLDER_WORDS:
        if word in low:
            return True
    return False


def clears_entropy(value: str, minimum: float = GENERIC_MIN_ENTROPY) -> bool:
    """Does the value's per-character entropy reach *minimum*?"""
    return shannon(value) >= minimum


def looks_generated(value: str, minimum: float = GENERIC_MIN_ENTROPY) -> bool:
    """The full generic test: not a stand-in, and dense enough to be a secret."""
    if is_placeholder(value):
        return False
    return clears_entropy(value, minimum)


def looks_binary(text: str, sample: int = 8192) -> bool:
    """True when the text does not read as text, so patterns cannot be found.

    A scanner has nothing to say about a compiled binary or an encrypted blob —
    and saying "nothing matched" about one would be a lie of omission. Detecting
    the case lets the grader cap itself instead.
    """
    if not text:
        return False
    head = text[:sample]
    if "\x00" in head:
        return True
    odd = sum(
        1 for ch in head
        if ord(ch) < 9 or 13 < ord(ch) < 32 or ord(ch) == 127
    )
    return odd / len(head) > 0.08


def redact(value: str, keep: int | None = None, bullet: str = "•") -> str:
    """Return a preview of *value* that cannot be read back.

    The house rule is the first four and last four characters with the middle
    bulleted — but a short value would give itself away under that rule, so the
    reveal shrinks with the length and disappears entirely below nine
    characters. The number of bullets tracks the hidden length (capped, so a PEM
    line does not become a wall of dots), which is enough to recognise a value
    you already know without disclosing one you do not.
    """
    if not value:
        return ""
    n = len(value)
    if keep is None:
        keep = 0 if n <= 8 else (2 if n <= 16 else 4)
    keep = max(0, min(keep, max(0, (n - 4) // 2)))
    hidden = n - 2 * keep
    dots = bullet * max(4, min(16, hidden))
    if keep == 0:
        return dots
    return f"{value[:keep]}{dots}{value[-keep:]}"
