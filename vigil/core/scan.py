"""
The scan.

Walk the rule table over a piece of text, keep the matches that survive their
rule's stand-in filter, collapse identical values, and hand back a
:class:`~vigil.core.model.ScanResult`. Three decisions in here do most of the
work:

* **Precedence by specificity.** The table is ordered specific-first and a match
  is refused if its value overlaps one already accepted. So
  ``GITHUB_TOKEN=ghp_…`` is one GitHub token rather than a GitHub token plus a
  nameless "secret-named value", and nothing inside a private-key block is
  reported separately from the block.

* **One value, one finding.** A key pasted into forty lines of a log is one
  problem with a count of forty, not forty problems. Every position is kept, so
  the exposure map and the redactor still see all of them.

* **The value never leaves.** A finding carries a redacted preview and a pair of
  offsets. The secret itself stays in the caller's own string, which means no
  report, no JSON document and no screenshot can print it by accident — the
  shortest path to disclosure does not exist.
"""

from __future__ import annotations

import re
from bisect import bisect_left, bisect_right, insort

from .entropy import (
    is_placeholder,
    is_repetitive,
    is_templated,
    looks_binary,
    redact,
    shannon,
)
from .entropy import NON_SECRETS
from .model import (
    GATE_FULL,
    GATE_TEMPLATE,
    Band,
    Finding,
    Occurrence,
    Preview,
    Rule,
    ScanResult,
    Severity,
)
from .rules import RULES

REDACTION = "[REDACTED:{name}]"

_MARKER_LINE = re.compile(r"^-----BEGIN [A-Z ]*-----", re.MULTILINE)


# --- positions ---------------------------------------------------------------

class LineIndex:
    """Character offsets to 1-based line and column numbers.

    Built once per scan from the text as given, so the numbers a finding
    reports are the numbers an editor shows — including for a file with
    Windows line endings, where the ``\\r`` belongs to the line it ends.
    """

    def __init__(self, text: str):
        self.text = text
        starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                starts.append(i + 1)
        if len(starts) > 1 and starts[-1] == len(text):
            starts.pop()           # a trailing newline does not open a line
        self.starts = starts

    @property
    def line_count(self) -> int:
        return len(self.starts)

    def line_of(self, pos: int) -> int:
        """1-based line number containing *pos*."""
        pos = max(0, min(pos, max(0, len(self.text) - 1)))
        return bisect_right(self.starts, pos)

    def column_of(self, pos: int) -> int:
        """1-based column of *pos* within its line."""
        line = self.line_of(pos)
        return pos - self.starts[line - 1] + 1

    def locate(self, start: int, end: int) -> Occurrence:
        return Occurrence(
            line=self.line_of(start),
            column=self.column_of(start),
            start=start,
            end=end,
            end_line=self.line_of(max(start, end - 1)),
        )


class _Spans:
    """The value spans accepted so far, kept sorted for overlap tests."""

    def __init__(self) -> None:
        self._by_start: list[tuple[int, int]] = []

    def overlaps(self, start: int, end: int) -> bool:
        i = bisect_right(self._by_start, (start, end))
        # the span starting at or before this one
        if i and self._by_start[i - 1][1] > start:
            return True
        # the next span starting inside this one
        return i < len(self._by_start) and self._by_start[i][0] < end

    def add(self, start: int, end: int) -> None:
        insort(self._by_start, (start, end))

    def __len__(self) -> int:
        return len(self._by_start)


# --- the gates ---------------------------------------------------------------

def passes_gate(rule: Rule, value: str) -> bool:
    """Does *value* survive the stand-in filter its rule asks for?

    ``GATE_NONE`` lets everything through: the rule recognised an issued
    credential by its prefix, and Vigil has no way to know whether that
    credential is live. ``GATE_TEMPLATE`` drops only substitution syntax and
    plainly non-values. ``GATE_FULL`` additionally applies the placeholder
    vocabulary and the entropy floor.
    """
    v = value.strip().strip("\"'")
    if rule.min_length and len(v) < rule.min_length:
        return False
    if rule.gate == GATE_TEMPLATE:
        if is_templated(v) or v.lower() in NON_SECRETS or is_repetitive(v):
            return False
        return True
    if rule.gate == GATE_FULL:
        if is_placeholder(v):
            return False
        if rule.min_entropy and shannon(v) < rule.min_entropy:
            return False
        return True
    return True


# --- previews ----------------------------------------------------------------

def preview_for(rule: Rule, value: str) -> str:
    """The only representation of a match that is allowed out of this module.

    For most rules that is bullets around a few characters. For a block rule it
    is the block's own first line — ``-----BEGIN RSA PRIVATE KEY-----`` names
    what was found far better than bullets would and carries no key material,
    which stays behind in the caller's text.
    """
    if rule.preview is Preview.MARKER:
        return value.split("\n", 1)[0].strip()
    return redact(value)


# --- the scan ----------------------------------------------------------------

def scan(text: str, rules: tuple[Rule, ...] = RULES) -> ScanResult:
    """Run every rule over *text* and return what survived.

    The result is always complete and always honest about its own limits: an
    empty or binary input produces no findings *and* says so in
    :attr:`~vigil.core.model.ScanResult.notes`, so a caller can never mistake
    "nothing was examined" for "nothing was found".
    """
    text = text or ""
    index = LineIndex(text)
    result = ScanResult(
        line_count=index.line_count if text else 0,
        char_count=len(text),
        rules_applied=len(rules),
        looks_binary=looks_binary(text),
        examined=bool(text.strip()),
    )
    if not result.examined:
        result.notes.append("No text was given, so nothing was examined.")
        return result

    taken = _Spans()
    by_value: dict[tuple[str, str], Finding] = {}
    findings: list[Finding] = []
    suppressed = 0
    collapsed = 0

    for rule in rules:
        for match in rule.pattern.finditer(text):
            raw = match.group(rule.value_group)
            if raw is None:
                continue
            start, end = match.span(rule.value_group)
            if start < 0:
                continue
            if not passes_gate(rule, raw):
                suppressed += 1
                continue
            if taken.overlaps(start, end):
                continue
            taken.add(start, end)

            value = raw.strip().strip("\"'")
            key = (rule.name, raw)
            occurrence = index.locate(start, end)
            existing = by_value.get(key)
            if existing is not None:
                existing.occurrences.append(occurrence)
                collapsed += 1
                continue

            label = ""
            if rule.label_group is not None:
                label = (match.group(rule.label_group) or "").strip().strip("\"'")
            detail = rule.description
            if label and rule.label_phrase:
                detail = f"{detail} {rule.label_phrase.format(label=label)}"

            finding = Finding(
                rule=rule.name,
                title=rule.title,
                severity=rule.severity,
                detail=detail,
                remediation=rule.remediation,
                occurrences=[occurrence],
                preview=preview_for(rule, raw),
                label=label,
                length=len(value),
                entropy=round(shannon(value), 3),
                category=rule.category,
                forces_f=rule.forces_f,
                opaque=rule.opaque,
            )
            by_value[key] = finding
            findings.append(finding)

    result.findings = sorted(findings, key=lambda f: (-f.severity.rank, f.line))
    result.suppressed = suppressed

    if result.looks_binary:
        result.notes.append(
            "This text does not read as text — it holds control bytes a document "
            "would not. Patterns cannot be matched inside a binary or an "
            "encrypted blob, so a quiet result here means nothing at all.")
    if suppressed:
        result.notes.append(
            f"{suppressed} candidate value"
            f"{'s were' if suppressed != 1 else ' was'} dropped as a "
            f"placeholder, a substitution, or too uniform to be a generated "
            f"secret.")
    if collapsed:
        result.notes.append(
            f"{collapsed} further cop{'ies' if collapsed != 1 else 'y'} of "
            f"values already listed {'were' if collapsed != 1 else 'was'} "
            f"collapsed into the findings above, with the count kept.")
    if index.line_count == 1 and len(text) > 400:
        result.notes.append(
            "The whole text is one line, so a line number cannot narrow down "
            "where a value sits. Column numbers are still exact.")
    return result


# --- redaction ---------------------------------------------------------------

def redact_text(text: str, result: ScanResult,
                template: str = REDACTION) -> tuple[str, int]:
    """Return *text* with every detected secret replaced, and how many went.

    This is the share-safe copy of a config: every value Vigil judged opaque is
    replaced by a named placeholder, so the shape of the file, its comments and
    its structure survive while the credentials do not. A PEM block keeps its
    ``BEGIN``/``END`` lines, because those carry no key material and losing them
    would make the file unreadable for no gain.

    Replacements are applied from the end of the text backwards, so every offset
    stays valid as it goes.
    """
    spans: list[tuple[int, int, str]] = []
    for finding in result.findings:
        if not finding.opaque:
            continue
        token = template.format(name=finding.rule)
        for occ in finding.occurrences:
            spans.append((occ.start, occ.end, token))
    spans.sort(key=lambda s: s[0], reverse=True)

    out = text
    for start, end, token in spans:
        body = text[start:end]
        replacement = token
        if _MARKER_LINE.match(body):
            lines = body.splitlines()
            head = lines[0]
            tail = lines[-1] if len(lines) > 1 and lines[-1].startswith("-----END") else ""
            replacement = f"{head}\n{token}\n{tail}" if tail else f"{head}\n{token}"
        out = out[:start] + replacement + out[end:]
    return out, len(spans)


# --- the exposure map's data -------------------------------------------------

def exposure_bands(result: ScanResult, buckets: int) -> list[Band]:
    """Slice the document into *buckets* bands and give each one its worst hit.

    The bands always cover the real document: every line belongs to exactly one
    band, the first band starts at line 1 and the last ends at the last line. If
    the caller asks for more bands than there are lines it gets one band per
    line instead of inventing resolution the document does not have.
    """
    lines = max(1, result.line_count)
    buckets = max(1, min(int(buckets), lines))

    # Band *i* covers the lines in ``(edges[i], edges[i + 1]]``. Both the layout
    # and the line-to-band lookup are derived from this one list, which is what
    # keeps a tinted band over the line that actually carried the hit.
    edges = [(i * lines) // buckets for i in range(buckets + 1)]
    worst: list[Severity | None] = [None] * buckets
    hits = [0] * buckets

    for finding in result.findings:
        for occ in finding.occurrences:
            first = _bucket_of(occ.line, edges, lines)
            last = _bucket_of(occ.end_line, edges, lines)
            for b in range(first, last + 1):
                hits[b] += 1
                current = worst[b]
                if current is None or finding.severity.rank > current.rank:
                    worst[b] = finding.severity

    return [
        Band(index=i, first_line=edges[i] + 1, last_line=edges[i + 1],
             severity=worst[i], hits=hits[i])
        for i in range(buckets)
    ]


def _bucket_of(line: int, edges: list[int], lines: int) -> int:
    """Which band holds *line*, read straight off the band edges."""
    line = max(1, min(line, lines))
    return max(0, min(len(edges) - 2, bisect_left(edges, line) - 1))
