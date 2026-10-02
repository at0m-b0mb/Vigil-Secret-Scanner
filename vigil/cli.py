"""
Vigil on the command line.

The same engine the window uses, with no Qt in sight — so it runs on a server,
in a pipe, or as a pre-commit hook. Point it at a file or pipe text into
standard input; add ``--json`` for machine-readable output, ``--redact`` to get
the share-safe copy of the text instead of a report, and ``--exit-code`` when
you want a non-zero status to fail a build.

    vigil .env
    cat config.yml | vigil -
    vigil service.py --json
    vigil .env --redact > .env.share
    vigil .env --exit-code --no-color

Exit status: ``2`` when there was nothing to read, ``1`` with ``--exit-code``
when something was found at or above the chosen severity, ``0`` otherwise. The
report itself never prints a secret — only the redacted preview a finding
carries.
"""

from __future__ import annotations

import argparse
import json
import sys

from .core.grade import analyze
from .core.model import ScanResult, Severity
from .core.rules import RULES, categories
from .core.scan import redact_text

_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "good": "\033[32m", "notice": "\033[33m", "warning": "\033[33m",
    "alert": "\033[31m", "info": "\033[90m", "brass": "\033[33m",
}

_SEVERITY_ORDER = ["info", "notice", "warning", "alert"]


def _paint(text: str, key: str, color: bool) -> str:
    if not color:
        return text
    return f"{_C.get(key, '')}{text}{_C['reset']}"


def _wrap(text: str, width: int, indent: str) -> list[str]:
    """Soft-wrap a sentence to *width*, so a remediation reads in a terminal."""
    words = text.split()
    lines: list[str] = []
    current = indent
    for word in words:
        if len(current) + len(word) + 1 > width and current.strip():
            lines.append(current)
            current = indent + word
        else:
            current = f"{current}{'' if current == indent else ' '}{word}"
    if current.strip():
        lines.append(current)
    return lines


def _report_text(result: ScanResult, color: bool, width: int = 78) -> str:
    g = result.grade
    out: list[str] = []
    head = _paint(f"  {g.letter}  ", "bold", color) + f" {g.headline}"
    if g.graded:                    # no score beside a result that is no result
        head += "  " + _paint(f"({g.score}/100)", "dim", color)
    out.append(head)
    for line in _wrap(g.ceiling_note, width, ""):
        out.append(_paint(line, "dim", color))
    out.append("")

    out.append(
        f"Scanned      {result.line_count} lines, {result.char_count} "
        f"characters")
    out.append(
        f"Rules        {result.rules_applied} patterns across "
        f"{len(categories())} families")
    out.append(
        f"Found        {len(result.secrets)} distinct value"
        f"{'s' if len(result.secrets) != 1 else ''} in "
        f"{result.total_occurrences} place"
        f"{'s' if result.total_occurrences != 1 else ''}, touching "
        f"{len(result.exposed_lines)} line"
        f"{'s' if len(result.exposed_lines) != 1 else ''}")
    if result.suppressed:
        out.append(
            f"Set aside    {result.suppressed} placeholder or low-entropy "
            f"candidate{'s' if result.suppressed != 1 else ''}")
    out.append("")

    out.append(f"Findings ({len(result.findings)})")
    if not result.findings:
        out.append(_paint(
            "  nothing matched — which means no rule fired, not that the text "
            "is clean", "dim", color))
    for f in result.findings:
        key = f.severity.value
        tag = _paint(f"[{key:^7}]", key, color)
        pts = _paint(f" -{f.points}", "dim", color) if f.points else ""
        out.append(f"  {tag} {f.title}{pts}")
        loc = f"line {f.line}, col {f.column}"
        if f.count > 1:
            loc += f" (+{f.count - 1} more)"
        out.append(_paint(f"          {loc}  ·  {f.preview}", "brass", color))
        for line in _wrap(f.detail, width, "          "):
            out.append(_paint(line, "dim", color))
        for line in _wrap(f"What to do: {f.remediation}", width, "          "):
            out.append(_paint(line, "dim", color))
    if result.notes:
        out.append("")
        for note in result.notes:
            for line in _wrap(f"note: {note}", width, "  "):
                out.append(_paint(line, "dim", color))
    return "\n".join(out)


def _report_json(result: ScanResult) -> str:
    g = result.grade
    data = {
        "grade": {
            "letter": g.letter, "score": g.score, "headline": g.headline,
            "ceiling_note": g.ceiling_note, "graded": g.graded,
        },
        "scanned": {
            "lines": result.line_count,
            "characters": result.char_count,
            "rules_applied": result.rules_applied,
            "examined": result.examined,
            "looks_binary": result.looks_binary,
            "suppressed": result.suppressed,
            "exposed_lines": sorted(result.exposed_lines),
        },
        "findings": [
            {
                "rule": f.rule,
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category,
                "detail": f.detail,
                "remediation": f.remediation,
                "preview": f.preview,       # redacted; never the value
                "label": f.label,
                "length": f.length,
                "entropy": f.entropy,
                "points": f.points,
                "forces_f": f.forces_f,
                "count": f.count,
                "occurrences": [
                    {"line": o.line, "column": o.column,
                     "end_line": o.end_line, "start": o.start, "end": o.end}
                    for o in f.occurrences
                ],
            }
            for f in result.findings
        ],
        "notes": result.notes,
    }
    return json.dumps(data, indent=2)


def _worst_rank(result: ScanResult) -> int:
    worst = result.worst
    return worst.rank if worst else -1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vigil",
        description="Scan text for values shaped like credentials, and grade "
                    "the exposure. Never prints a secret it finds.")
    parser.add_argument("source", nargs="?", default="-",
                        help="path to a file to scan, or - for standard input")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    parser.add_argument("--redact", action="store_true",
                        help="print the text with every detected value "
                             "replaced, instead of a report")
    parser.add_argument("--no-color", action="store_true",
                        help="plain text, no ANSI")
    parser.add_argument("--exit-code", action="store_true",
                        help="return 1 if anything was found at or above "
                             "--fail-on")
    parser.add_argument("--fail-on", choices=_SEVERITY_ORDER, default="notice",
                        help="the severity --exit-code reacts to "
                             "(default: notice)")
    parser.add_argument("--list-rules", action="store_true",
                        help="print the rule table and exit")
    args = parser.parse_args(argv)

    if args.list_rules:
        for r in RULES:
            print(f"{r.name:28} {r.severity.value:8} {r.category:13} "
                  f"{'forces F' if r.forces_f else ''}")
        return 0

    if args.source == "-":
        raw = sys.stdin.read()
    else:
        try:
            with open(args.source, encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError as exc:
            print(f"vigil: cannot read {args.source}: {exc}", file=sys.stderr)
            return 2

    if not raw.strip():
        print("vigil: no text given", file=sys.stderr)
        return 2

    result = analyze(raw)

    if args.redact:
        redacted, replaced = redact_text(raw, result)
        sys.stdout.write(redacted)
        if not redacted.endswith("\n"):
            sys.stdout.write("\n")
        print(f"vigil: replaced {replaced} value"
              f"{'s' if replaced != 1 else ''}; read it before you send it",
              file=sys.stderr)
    elif args.json:
        print(_report_json(result))
    else:
        color = sys.stdout.isatty() and not args.no_color
        print(_report_text(result, color))

    if args.exit_code:
        threshold = Severity(args.fail_on).rank
        if _worst_rank(result) >= threshold:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
