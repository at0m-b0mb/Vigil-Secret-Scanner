"""
The shapes the scan produces.

Everything Vigil learns about a piece of text is poured into these dataclasses,
and everything the interface draws reads from them. Nothing here matches or
scores anything — these are the nouns, defined once, so the engine and the
window never disagree about what a "rule", an "occurrence" or a "finding" is.

One invariant lives here rather than in prose: a :class:`Finding` carries a
*preview*, never a value. The secret itself is held only as spans into the text
the caller already has, so there is no field anywhere in this module that a
report could accidentally print in full.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """How much a single finding should worry the reader."""

    GOOD = "good"        # a reassuring signal, not a problem
    INFO = "info"        # worth knowing, not alarming
    NOTICE = "notice"    # a soft exposure
    WARNING = "warning"  # a real exposure
    ALERT = "alert"      # a credential that looks issued and usable

    @property
    def rank(self) -> int:
        return {
            Severity.GOOD: 0,
            Severity.INFO: 1,
            Severity.NOTICE: 2,
            Severity.WARNING: 3,
            Severity.ALERT: 4,
        }[self]


class Preview(Enum):
    """How a match may be shown to a human.

    ``REDACT`` is the default and the safe one: the first and last few
    characters with the middle replaced by bullets. ``MARKER`` is for matches
    that are structural rather than secret — the ``-----BEGIN ... KEY-----``
    line of a PEM block carries no key material, so printing it whole is both
    safe and far more informative than bullets.
    """

    REDACT = "redact"
    MARKER = "marker"


# How hard a rule filters stand-in values. A rule that recognises an issued
# credential by its prefix needs no filter at all — the prefix *is* the
# evidence, and a scanner cannot tell a revoked key from a live one. A password
# lifted out of a URL is filtered only for substitution syntax, because a URL
# in a checked-in file is usually copied from something that worked. Only the
# generic "a secret-ish name was assigned something" rule gets the full
# placeholder vocabulary and the entropy floor, because only there is the shape
# of the value the whole of the evidence.
GATE_NONE = "none"
GATE_TEMPLATE = "template"
GATE_FULL = "full"


@dataclass(frozen=True)
class Rule:
    """One named detector.

    A rule is a compiled pattern plus the words a person needs when it fires:
    what the thing is, and what to do about it. ``value_group`` points at the
    part of the match that is the secret — everything outside it (a variable
    name, a URL scheme, a PEM label) is safe to echo and is captured by
    ``label_group`` so a finding can say *where* without saying *what*.
    """

    name: str                       # stable machine id, e.g. "aws_access_key_id"
    title: str                      # "AWS access key ID"
    severity: Severity
    pattern: re.Pattern[str]
    description: str                # what the match is
    remediation: str                # what to do about it, concretely
    value_group: int = 0            # the span that is the secret (0 = whole match)
    label_group: int | None = None  # a safe name/scheme/label to quote
    label_phrase: str = ""          # "Assigned to {label}." — uses the label
    preview: Preview = Preview.REDACT
    opaque: bool = True             # does the value span need redacting?
    forces_f: bool = False          # an issued-looking credential: no pass mark
    min_entropy: float = 0.0        # value must clear this to count
    min_length: int = 0             # value must be at least this long
    gate: str = GATE_NONE           # which stand-in filter the value must pass
    category: str = "credential"

    @property
    def is_secret(self) -> bool:
        """Does a match mean something was exposed, rather than merely noted?"""
        return self.severity.rank >= Severity.NOTICE.rank


@dataclass(frozen=True)
class Occurrence:
    """Where one copy of a value sits in the text.

    ``start``/``end`` are character offsets into the scanned string, which is
    what redaction needs; ``line``/``column`` are 1-based and are what a person
    needs. ``end_line`` differs from ``line`` only for a block match such as a
    PEM key, and it is what lets the exposure map paint the whole block.
    """

    line: int
    column: int
    start: int
    end: int
    end_line: int

    @property
    def spans_lines(self) -> int:
        return max(1, self.end_line - self.line + 1)


@dataclass
class Finding:
    """One exposure, in words a person can act on.

    Identical values matched by the same rule collapse into a single finding
    with every :class:`Occurrence` recorded, so a key pasted into forty lines
    of a log reads as one problem with a count rather than forty problems.
    """

    rule: str
    title: str
    severity: Severity
    detail: str
    remediation: str
    occurrences: list[Occurrence] = field(default_factory=list)
    preview: str = ""
    label: str = ""
    length: int = 0
    entropy: float = 0.0
    points: int = 0
    category: str = "credential"
    forces_f: bool = False
    opaque: bool = True

    @property
    def count(self) -> int:
        return len(self.occurrences)

    @property
    def line(self) -> int:
        return self.occurrences[0].line if self.occurrences else 0

    @property
    def column(self) -> int:
        return self.occurrences[0].column if self.occurrences else 0

    @property
    def where(self) -> str:
        """A human location: ``line 12``, or ``line 12 (+3 more)``."""
        if not self.occurrences:
            return "no location"
        head = f"line {self.line}"
        if self.count > 1:
            head += f" (+{self.count - 1} more)"
        return head


# The letter for a result that has no letter. Text that was never examined
# produced no findings for reasons that have nothing to do with its contents,
# so there is nothing to grade — and borrowing a real letter for it would put a
# verdict next to a headline that retracts it. An em dash is a mark, not a
# grade, which is exactly what it has to read as.
NO_GRADE = "—"


@dataclass
class Grade:
    """The final letter, the number behind it, and why."""

    letter: str
    score: int
    headline: str
    ceiling_note: str               # the honesty caveat — always present

    @property
    def graded(self) -> bool:
        """Is there a letter at all? ``False`` when nothing was examined."""
        return self.letter != NO_GRADE


@dataclass(frozen=True)
class Band:
    """One row of the exposure map: a slice of the document, and its worst hit.

    ``severity`` is ``None`` when nothing matched in the slice, which is what
    the map draws faint. A band always knows the real line numbers it covers,
    so the picture can never drift from the document it claims to summarise.
    """

    index: int
    first_line: int
    last_line: int
    severity: Severity | None = None
    hits: int = 0

    @property
    def is_quiet(self) -> bool:
        return self.severity is None


@dataclass
class ScanResult:
    """Everything Vigil learned about one piece of text."""

    findings: list[Finding] = field(default_factory=list)
    line_count: int = 0
    char_count: int = 0
    rules_applied: int = 0
    suppressed: int = 0             # matches dropped as placeholders / low entropy
    looks_binary: bool = False
    examined: bool = False          # was there any text to look at at all?
    grade: Grade | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def secrets(self) -> list[Finding]:
        """Findings that mean something was exposed (notice and above)."""
        return [f for f in self.findings if f.severity.rank >= Severity.NOTICE.rank]

    @property
    def total_occurrences(self) -> int:
        return sum(f.count for f in self.findings)

    @property
    def worst(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    @property
    def exposed_lines(self) -> set[int]:
        """Every line number touched by any finding."""
        lines: set[int] = set()
        for f in self.findings:
            for occ in f.occurrences:
                lines.update(range(occ.line, occ.end_line + 1))
        return lines

    def by_severity(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
