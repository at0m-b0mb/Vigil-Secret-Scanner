# Changelog

All notable changes to Vigil are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[semantic versioning](https://semver.org/).

## [1.0.0] — 2026-10-02

First release.

### The scanner
- **21 named detectors across 10 families** — AWS access key IDs and secret
  keys, GitHub and GitLab tokens, Slack tokens and incoming webhooks, Google API
  keys, Stripe live keys (and test keys, graded separately), SendGrid, Twilio,
  npm, PyPI and `sk-` model keys, PEM private key blocks, JWTs, passwords inside
  database connection strings and URLs, hard-coded `Authorization` headers, and
  a generic rule for secret-named values that clear an entropy floor. Its name
  vocabulary includes `private_key` and `ssh_key`, so a key injected by CI or
  lifted out of a service-account document as a single line of base64 is caught
  as well as the armoured PEM form. Bare `key` is deliberately excluded, so
  `cache_key` and `partition_key` stay quiet.
- **Stand-in filtering** — substitutions (`${VAR}`, `{{ jinja }}`,
  `<your-key-here>`, `%VAR%`, `$(shell)`), a placeholder vocabulary, repetitive
  and non-credential values, and anything below 3.0 bits of Shannon entropy per
  character are set aside and counted, so the judgement is visible rather than
  silent. Rules that recognise an *issued* credential by its prefix take no
  filter at all, because shape is the only evidence a scanner has.
- **Precedence by specificity** — PEM blocks claim their own span first, so
  nothing is mined out of a key's base64 body; the generic rule runs last. One
  value is reported once, by the most specific rule that saw it.
- **Collapsing** — identical values are one finding with every position kept, so
  a key pasted through a log is one problem with a count.
- **Redacted previews** — a finding carries at most four characters from each
  end (fewer as the value shortens, none below nine characters) and a pair of
  offsets. The value itself is never copied into a result, so no report, JSON
  document or screenshot can print it by accident.
- **Redact and copy** — the share-safe version of the text, with every detected
  value replaced by a named placeholder and PEM blocks left recognisable.

### The picture
- **The exposure map** — the whole document drawn as a vertical strip, one band
  per slice of lines, tinted by the worst severity found in it and left faint
  where nothing matched. Block matches paint every line they span, the gutter
  carries a real scale, and callouts name the lines of the worst bands.

### The grade
- A+ to F, with an honesty ceiling attached to **every** result: Vigil will miss
  any secret it has no rule for, cannot tell a live key from a revoked one, and
  will sometimes flag something harmless. **A+ means nothing matched, never that
  there are no secrets**, and the word *safe* appears nowhere in a result — the
  word itself, swept across all 21 rules and every rendered report, not a list
  of phrases.
- Ceilings by severity: a structural marker caps at A, a soft exposure at B, a
  real exposure at C, and anything shaped like an issued credential is F.
- **Unknown beats a guess** — text that does not read as text is capped at C and
  labelled rather than passed. Input that was never examined is not capped but
  ungraded: it reads `—`, because a letter is a verdict and there is nothing
  there to pass one on.

### Interfaces
- A PyQt6 window in the house style — warm paper and gold, true-black dark mode,
  and an Auto theme that follows the OS.
- A dependency-free command line sharing the same engine: text, `--json` and
  `--redact` output, standard-input support, `--list-rules`, and `--exit-code`
  with `--fail-on` for a pre-commit hook or a CI job.

### Engineering
- The engine (`vigil.core`) is pure standard library — no third-party
  dependencies, no network, no sockets — and a test reads that out of the import
  graph rather than asserting it in prose.
- 783 test cases across nine modules: the entropy judgements, every rule's
  positives and the near-misses it must refuse, precedence and collapsing, the
  redactor, the grader's ceilings, the command line in all three modes, the
  window driven off-screen, and a WCAG-AA contrast suite covering every
  text/background pairing in both themes at 4.5:1, with no large-text exemption
  for any ink and a check on the built stylesheet as well as the tokens.
- Four invariants are asserted against real output: nothing Vigil prints may
  contain a secret from its input, no headline may read as a clearance, the word
  *safe* appears in no result at all, and a tinted band on the exposure map must
  cover the line that caused it. The last one found an off-by-one during
  development.
- Off-screen screenshot capture, and a repository-art generator whose social
  card is held inside GitHub's safe border by a registered-rectangle check and
  then measured in the rendered pixels. The art imports the engine and scans a
  real sample, so the picture on the repository page is the one the application
  draws.
