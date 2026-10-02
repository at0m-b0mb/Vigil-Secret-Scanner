"""
The judgement — findings first, then a letter.

The grader reads what :mod:`vigil.core.scan` found and turns it into a single
A+..F letter. Two principles shape it, both carried over from the rest of this
catalogue:

* **Honesty ceiling.** Vigil matches patterns and measures entropy in the text
  it was given. It will miss any secret it has no rule for, it cannot tell a
  live key from one revoked years ago, and it will sometimes flag something
  harmless. So **A+ means only "nothing matched"** — never "there are no
  secrets here" — and the note saying as much is attached to every result,
  including the clean one.

* **Unknown beats a guess.** Text that cannot be read as text — a binary, an
  archive, an encrypted blob — produces no matches for reasons that have nothing
  to do with its contents. That case is capped at C and labelled, rather than
  being waved through on an empty finding list. An input that was never
  examined at all goes one further and gets no letter: :data:`NO_GRADE`, the
  em dash, because a letter is a verdict and there is nothing here to pass one
  on.

The scale below the top is driven by the worst severity present and then by the
count, because one leaked key is a different kind of problem from thirty — but
the first one already costs you the pass mark:

====================================  =========
what the scan found                   best possible
====================================  =========
nothing                               A+
a structural marker only              A
a soft exposure (a test credential)   B
a real exposure (a bearer token…)     C
anything shaped like an issued key    F
====================================  =========
"""

from __future__ import annotations

from .model import NO_GRADE, Grade, ScanResult, Severity
from .scan import scan

# Letters, best to worst, so ceilings can be compared as positions.
_LETTERS = [
    "A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F",
]

CEILING_NOTE = (
    "Vigil matches patterns and entropy in the text you gave it. It will miss "
    "any secret it has no rule for, it cannot tell a live key from one revoked "
    "years ago, and it will sometimes flag something harmless. A clean result "
    "means nothing matched — never that there are no secrets."
)

# What one distinct finding costs. Severity, not rule, sets the price: two
# different bearer tokens are the same size of problem.
_POINTS = {
    Severity.GOOD: 0,
    Severity.INFO: 0,
    Severity.NOTICE: 6,
    Severity.WARNING: 12,
    Severity.ALERT: 40,
}

# How far up the scale each severity still allows. A single finding of any kind
# costs A+, which is what reserves the top grade for a genuinely quiet result.
_CEILINGS = {
    Severity.GOOD: "A",
    Severity.INFO: "A",
    Severity.NOTICE: "B",
    Severity.WARNING: "C",
    Severity.ALERT: "D",
}


def _letter_for_score(score: int) -> str:
    bands = [
        (97, "A+"), (93, "A"), (90, "A-"),
        (87, "B+"), (83, "B"), (80, "B-"),
        (77, "C+"), (73, "C"), (70, "C-"),
        (67, "D+"), (63, "D"), (60, "D-"),
    ]
    for floor, letter in bands:
        if score >= floor:
            return letter
    return "F"


def _cap(letter: str, ceiling: str) -> str:
    """Return the worse (lower) of two letters."""
    return letter if _LETTERS.index(letter) >= _LETTERS.index(ceiling) else ceiling


def _repeat_cost(count: int) -> int:
    """What the copies beyond the first add.

    Deliberately shallow: thirty copies of one key is worse than one copy, but
    it is still one key, and a finding list dominated by repetition would hide
    the second, different secret further down.
    """
    return min(8, max(0, count - 1) * 2)


def grade_scan(result: ScanResult) -> ScanResult:
    """Populate ``result.grade`` in place, and return the result."""
    score = 100
    for finding in result.findings:
        cost = _POINTS[finding.severity]
        if cost:
            cost += _repeat_cost(finding.count)
        finding.points = cost
        score -= cost
    score = max(0, min(100, score))

    letter = _letter_for_score(score)
    worst = result.worst

    # the honest unknowns, which no finding list can speak for
    if not result.examined:
        # No letter, not a middling one. A borrowed "C" would put a verdict in
        # the largest type on the page beside a headline that retracts it.
        return _finish(result, NO_GRADE, 100,
                       "No text was examined — this grade describes nothing")
    if result.looks_binary:
        if worst is not None:
            letter = _cap(letter, _CEILINGS[worst])
        if any(f.forces_f for f in result.findings):
            letter = "F"
        return _finish(result, _cap(letter, "C"), score,
                       "This does not read as text — a scanner cannot see inside it")

    if worst is None:
        return _finish(result, "A+", 100, "Nothing matched")

    letter = _cap(letter, _CEILINGS[worst])
    if any(f.forces_f for f in result.findings):
        letter = "F"

    return _finish(result, letter, score, _headline(result, worst, letter))


def _headline(result: ScanResult, worst: Severity, letter: str) -> str:
    """One line a person can read before anything else."""
    secrets = result.secrets
    n = len(secrets)
    issued = sum(1 for f in result.findings if f.forces_f)

    if issued:
        if issued == 1:
            return "One value is shaped exactly like an issued credential"
        return f"{issued} values are shaped like issued credentials"
    if worst is Severity.WARNING:
        if n == 1:
            return "One exposed value — a bearer credential, not a key pattern"
        return f"{n} exposed values, none matching an issued-key shape"
    if worst is Severity.NOTICE:
        return "A credential is present, but not one that acts in production"
    return "Nothing credential-shaped; one structural block noted"


def _finish(result: ScanResult, letter: str, score: int, headline: str) -> ScanResult:
    result.grade = Grade(letter=letter, score=score, headline=headline,
                         ceiling_note=CEILING_NOTE)
    return result


def analyze(text: str) -> ScanResult:
    """Convenience: scan then grade, the whole pipeline in one call."""
    return grade_scan(scan(text))
