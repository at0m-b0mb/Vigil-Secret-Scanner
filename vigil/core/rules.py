"""
The rule table.

Twenty-one named detectors, each a compiled pattern plus the sentence a person
needs when it fires. The table is ordered **widest claim first, then most
specific**, and that order is load-bearing: :mod:`vigil.core.scan` walks it in
sequence and refuses a match whose value overlaps one already accepted. So a PEM
block claims its own span before anything can be found inside it, and
``GITHUB_TOKEN=ghp_…`` is reported once, as a GitHub token, rather than twice —
once properly and once as "a secret-ish name was assigned something". The
generic rule is deliberately last, because it is the only one that guesses.

Four kinds of rule live here, and the difference is the whole design:

* **Blocks** — a PEM private key or certificate, matched from ``BEGIN`` to
  ``END``. They go first so their base64 interior is never mined for
  coincidences; an unterminated block claims only its own first line.

* **Issued credentials** — a vendor prefix and a fixed shape (``AKIA`` plus
  sixteen, ``ghp_`` plus thirty-six, ``AIza`` plus thirty-five). The prefix is
  the evidence, so these take no stand-in filter and no entropy floor, and they
  set ``forces_f``: there is no arrangement of other facts under which a thing
  shaped exactly like an issued key earns a pass mark. Vigil cannot tell such a
  key from one revoked years ago, and will say so rather than guess.

* **Bearer tokens and credentials in transit** — a JWT, a password lifted out
  of a connection string, an ``Authorization`` header. Real exposures, but ones
  where the match alone does not establish that a credential was issued, so
  they cost points without forcing the bottom of the scale.

* **Structure** — a certificate block is a public document; it is reported so a
  reader knows Vigil saw it and chose not to count it.

Every description is a property of the text. No rule asks who a brand is, and
no rule would behave differently if the vendor renamed itself tomorrow.
"""

from __future__ import annotations

import re

from .model import GATE_FULL, GATE_NONE, GATE_TEMPLATE, Preview, Rule, Severity
from .entropy import GENERIC_MIN_ENTROPY

# Names that mean "the thing after the equals sign is a credential".
#
# Every entry has to be a name that *only* ever holds a secret. Bare ``key`` is
# deliberately absent: it would flag ``cache_key``, ``sort_key`` and
# ``partition_key``, which are ordinary data. ``private_key`` and ``ssh_key``
# are here because the PEM rule above only sees the armoured form, and a key
# injected by CI or lifted out of a service-account JSON arrives as a single
# line of base64 assigned to exactly those names. ``public_key`` is the
# near-miss that must not fire, and does not, because ``key`` alone is out.
_SECRETISH = (
    r"(?:pass(?:word|wd|phrase)?|pwd"
    r"|secret(?:_?key)?|client_?secret"
    r"|api_?key|apikey|access_?key|secret_?access_?key"
    r"|auth_?token|access_?token|refresh_?token|bearer_?token|session_?token"
    r"|private_?token|personal_?access_?token|token"
    r"|credentials?|auth"
    r"|encryption_?key|signing_?key|master_?key|secret_?token"
    r"|private_?key|ssh_?key)"
)

# A value in a config or a source file: everything up to whitespace or a
# delimiter. Quotes are handled either side, so both `k = "v"` and `k: v` work.
_VALUE = r"""([^\s"'`,;)\]}]{6,512})"""

# Database and message-broker schemes that carry credentials in the authority.
_DB_SCHEMES = r"(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqps?|mssql|sqlserver|clickhouse|cockroachdb|cassandra|couchbase|neo4j|influxdb)"

# Other schemes where user:pass@host is a plain credential leak.
_URL_SCHEMES = r"(?:https?|ftps?|sftp|ssh|smtps?|imaps?|pop3s?|ldaps?|rsync|git|svn|telnet)"


def _c(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# --- the table, most specific first -----------------------------------------

RULES: tuple[Rule, ...] = (

    # -- PEM blocks, matched first ------------------------------------------
    # Order is load-bearing here. A block's whole span is claimed up front, so
    # anything that happens to look like a key inside the base64 body is never
    # reported separately from the block that contains it. An unterminated
    # block claims only its BEGIN line, which leaves the rest readable.

    Rule(
        name="private_key_block",
        title="Private key block",
        severity=Severity.ALERT,
        pattern=_c(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
            r"(?:[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?"
            r"PRIVATE KEY-----)?"
        ),
        description=(
            "A PEM private key block. This is the key itself, not a reference to "
            "one: whatever it signs or decrypts — TLS, SSH, commits, tokens — can "
            "be signed or decrypted by anyone holding this text."
        ),
        remediation=(
            "Generate a replacement key pair, publish the new public key "
            "everywhere the old one was trusted, and revoke the old one "
            "(certificate revocation, `authorized_keys`, the forge's SSH key "
            "list). An encrypted block buys you only the strength of its "
            "passphrase."
        ),
        preview=Preview.MARKER,
        opaque=True,
        forces_f=True,
        category="key-material",
    ),

    Rule(
        name="certificate_block",
        title="Certificate block",
        severity=Severity.INFO,
        pattern=_c(
            r"-----BEGIN CERTIFICATE-----"
            r"(?:[\s\S]*?-----END CERTIFICATE-----)?"
        ),
        description=(
            "A PEM certificate block. A certificate is the public half of a key "
            "pair and is meant to be handed out, so this is not an exposure — it "
            "is noted so you know Vigil read it and chose not to count it."
        ),
        remediation=(
            "Nothing to do. Worth one glance for company: a certificate and its "
            "private key are often written next to each other, and only one of "
            "them is meant to be published."
        ),
        preview=Preview.MARKER,
        opaque=False,
        gate=GATE_NONE,
        category="structure",
    ),

    # -- issued credentials, recognised by prefix and shape -----------------

    Rule(
        name="aws_access_key_id",
        title="AWS access key ID",
        severity=Severity.ALERT,
        pattern=_c(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        description=(
            "A twenty-character identifier in the exact shape AWS issues for an "
            "access key. Paired with its secret it is a full set of console-less "
            "credentials; on its own it still names the account and the key."
        ),
        remediation=(
            "Deactivate and delete this key in the AWS console under IAM → "
            "Users → Security credentials, issue a replacement, and read "
            "CloudTrail for use you did not make. Rotating the secret alone "
            "leaves this ID valid."
        ),
        forces_f=True,
        category="cloud",
    ),

    Rule(
        name="aws_secret_access_key",
        title="AWS secret access key",
        severity=Severity.ALERT,
        pattern=_c(
            r"\b((?:aws|amazon)[A-Za-z0-9_.\-]{0,32})\s*[:=]\s*[\"']?"
            r"([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
            re.IGNORECASE,
        ),
        description=(
            "A forty-character base64-ish value assigned to an AWS-named "
            "setting — the length and alphabet of a secret access key, in the "
            "position one is written."
        ),
        remediation=(
            "Treat the whole key pair as burnt: delete it in IAM, issue a new "
            "one, and move the replacement into an environment variable or a "
            "secrets manager rather than this file."
        ),
        value_group=2,
        label_group=1,
        label_phrase="Assigned to {label}.",
        forces_f=True,
        category="cloud",
    ),

    Rule(
        name="github_token",
        title="GitHub token",
        severity=Severity.ALERT,
        pattern=_c(
            r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}"
            r"|github_pat_[A-Za-z0-9_]{22,255})\b"
        ),
        description=(
            "A GitHub token in its issued form. The prefix says which kind — "
            "`ghp_` a classic personal token, `github_pat_` a fine-grained one, "
            "`ghs_` a server-to-server app token — and any of them can read, and "
            "usually write, whatever the issuing account can reach."
        ),
        remediation=(
            "Revoke it now at github.com/settings/tokens (or in the app's "
            "installation settings for a `ghs_` token), then check the account's "
            "security log. Rewriting the commit that carried it does not revoke "
            "it — GitHub keeps unreachable objects."
        ),
        forces_f=True,
        category="forge",
    ),

    Rule(
        name="gitlab_token",
        title="GitLab personal access token",
        severity=Severity.ALERT,
        pattern=_c(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"),
        description=(
            "A value in the shape GitLab issues for a personal access token. "
            "Its scopes are whatever was ticked when it was made, which in "
            "practice is usually `api`."
        ),
        remediation=(
            "Revoke it under GitLab → Preferences → Access tokens, issue a "
            "scoped replacement, and audit the project's audit events."
        ),
        forces_f=True,
        category="forge",
    ),

    Rule(
        name="slack_token",
        title="Slack token",
        severity=Severity.ALERT,
        pattern=_c(r"\b(xox[baprse]-[A-Za-z0-9\-]{10,})"),
        description=(
            "A Slack token in its issued form. The letter after `xox` says what "
            "it is — a bot, user, app or refresh token — and each can read the "
            "conversations its scopes allow."
        ),
        remediation=(
            "Revoke it in the Slack app's OAuth settings and reinstall the app "
            "to mint a new one. Review the workspace's access logs for reads you "
            "did not make."
        ),
        forces_f=True,
        category="saas",
    ),

    Rule(
        name="google_api_key",
        title="Google API key",
        severity=Severity.ALERT,
        pattern=_c(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
        description=(
            "A thirty-nine character value beginning `AIza` — the shape Google "
            "issues for an API key. Unless it was restricted by referrer or IP, "
            "anyone holding it can bill the project it belongs to."
        ),
        remediation=(
            "Delete the key in the Google Cloud console under APIs & Services → "
            "Credentials, create a replacement, and restrict the replacement by "
            "API and by referrer or IP. Check the project's billing for the "
            "period the key was exposed."
        ),
        forces_f=True,
        category="cloud",
    ),

    Rule(
        name="stripe_live_key",
        title="Stripe live secret key",
        severity=Severity.ALERT,
        pattern=_c(r"\b((?:sk|rk)_live_[0-9A-Za-z]{10,})\b"),
        description=(
            "A Stripe key whose `live` segment says it acts on real money, not "
            "the test ledger. A secret or restricted key can read customers and "
            "move funds to the extent its permissions allow."
        ),
        remediation=(
            "Roll it immediately in the Stripe dashboard under Developers → API "
            "keys, which invalidates the old one, then review the account's "
            "events and logs for the exposure window."
        ),
        forces_f=True,
        category="payments",
    ),

    Rule(
        name="stripe_test_key",
        title="Stripe test key",
        severity=Severity.NOTICE,
        pattern=_c(r"\b((?:sk|rk|pk)_test_[0-9A-Za-z]{10,})\b"),
        description=(
            "A Stripe key whose `test` segment says it only ever touches the "
            "test ledger. Not a live credential — but it is still a credential, "
            "and a file that holds test keys is usually a file that will one day "
            "hold live ones."
        ),
        remediation=(
            "No emergency. Move it out of the file anyway, so the habit holds "
            "when the key is a live one, and confirm nothing in the repository "
            "switches it for a live key at deploy time."
        ),
        category="payments",
    ),

    Rule(
        name="sendgrid_key",
        title="SendGrid API key",
        severity=Severity.ALERT,
        pattern=_c(r"\b(SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})\b"),
        description=(
            "A two-part value prefixed `SG.` — the shape SendGrid issues for an "
            "API key. With mail-send permission it can send as any verified "
            "identity on the account, which makes it a phishing credential as "
            "much as a billing one."
        ),
        remediation=(
            "Delete the key in the SendGrid console under Settings → API Keys, "
            "issue a replacement with only the permissions it needs, and check "
            "the account's activity feed for mail you did not send."
        ),
        forces_f=True,
        category="saas",
    ),

    Rule(
        name="twilio_api_key",
        title="Twilio API key SID",
        severity=Severity.ALERT,
        pattern=_c(r"\b(SK[0-9a-f]{32})\b"),
        description=(
            "Thirty-four characters beginning `SK` with a thirty-two character "
            "lowercase hex body — the shape Twilio issues for an API key SID. "
            "Any long hex blob can land in this shape, so this is the one rule "
            "in the table that carries a real false-positive rate."
        ),
        remediation=(
            "If it is a Twilio key, delete it in the console under Account → API "
            "keys and issue a replacement; voice and SMS spend on a leaked key "
            "is immediate. If it is a hash or a random identifier, dismiss this "
            "finding — a scanner cannot tell the difference from the shape alone."
        ),
        forces_f=True,
        category="saas",
    ),

    Rule(
        name="openai_style_key",
        title="OpenAI-style secret key",
        severity=Severity.ALERT,
        pattern=_c(r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,})\b"),
        description=(
            "A value beginning `sk-`, the convention several model providers use "
            "for a secret key. These bill per request, so the cost of a leak "
            "accrues quietly rather than announcing itself."
        ),
        remediation=(
            "Revoke it in the provider's dashboard, issue a replacement, and set "
            "a spending limit on the project if one is available. Check usage for "
            "the exposure window."
        ),
        forces_f=True,
        category="saas",
    ),

    Rule(
        name="npm_token",
        title="npm access token",
        severity=Severity.ALERT,
        pattern=_c(r"\b(npm_[A-Za-z0-9]{36})\b"),
        description=(
            "A forty-character value beginning `npm_` — an npm access token. "
            "With publish rights it can push a new version of every package the "
            "account owns, which makes it a supply-chain credential."
        ),
        remediation=(
            "Revoke it under npmjs.com → Access Tokens, issue a granular "
            "replacement, and check the publish history of every package the "
            "account can write."
        ),
        forces_f=True,
        category="registry",
    ),

    Rule(
        name="pypi_token",
        title="PyPI API token",
        severity=Severity.ALERT,
        pattern=_c(r"\b(pypi-[A-Za-z0-9_\-]{16,})\b"),
        description=(
            "A value beginning `pypi-` — a PyPI upload token. Like an npm "
            "token, its blast radius is everyone who installs what it can "
            "publish."
        ),
        remediation=(
            "Revoke it in your PyPI account settings, issue a project-scoped "
            "replacement, and prefer trusted publishing from CI so no token "
            "needs to exist in a file at all."
        ),
        forces_f=True,
        category="registry",
    ),

    # -- bearer tokens and credentials in transit ---------------------------

    Rule(
        name="jwt",
        title="JSON Web Token",
        severity=Severity.WARNING,
        pattern=_c(
            r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}"
            r"(?:\.[A-Za-z0-9_\-]{0,512})?)\b"
        ),
        description=(
            "Three base64url segments beginning `eyJ` — a JWT. Its header and "
            "claims are not encrypted, merely encoded, so anything inside it is "
            "already readable by whoever holds it, and it authenticates as "
            "whoever it was issued to until it expires."
        ),
        remediation=(
            "Decode the claims to see whose session this is and when it expires, "
            "then invalidate it the way your issuer allows — rotating the signing "
            "key, bumping a token version, or revoking the session. A short "
            "expiry limits the damage; it does not remove it."
        ),
        category="bearer",
    ),

    Rule(
        name="db_connection_password",
        title="Password in a connection string",
        severity=Severity.WARNING,
        pattern=_c(
            r"(" + _DB_SCHEMES + r")://[^\s:/@\"']{1,128}:"
            r"([^\s/@\"'`]{1,256})@[^\s\"'`]{1,256}",
            re.IGNORECASE,
        ),
        description=(
            "A database or broker URL with the password written into the "
            "authority section. Connection strings travel: they end up in logs, "
            "in process listings, in error messages and in crash reports, and the "
            "password travels with them."
        ),
        remediation=(
            "Rotate this database user's password, then split the credential out "
            "of the URL — most drivers accept a separate user and password, and "
            "every platform offers an environment variable or a secrets manager "
            "for the password half."
        ),
        value_group=2,
        label_group=1,
        label_phrase="In a {label}:// URL.",
        gate=GATE_TEMPLATE,
        category="database",
    ),

    Rule(
        name="url_basic_auth",
        title="Credentials in a URL",
        severity=Severity.WARNING,
        pattern=_c(
            r"(" + _URL_SCHEMES + r")://[^\s:/@\"']{1,128}:"
            r"([^\s/@\"'`]{1,256})@[^\s\"'`]{1,256}",
            re.IGNORECASE,
        ),
        description=(
            "A URL carrying `user:password@` in front of the host. Whatever "
            "handles this URL — a client library, a proxy, a shell history, an "
            "access log — handles the password too."
        ),
        remediation=(
            "Rotate the password, then pass the credential as a header or a "
            "client option instead of embedding it in the URL. If the service "
            "supports a token, prefer one: tokens can be scoped and revoked "
            "without disturbing the account."
        ),
        value_group=2,
        label_group=1,
        label_phrase="In a {label}:// URL.",
        gate=GATE_TEMPLATE,
        category="bearer",
    ),

    Rule(
        name="authorization_header",
        title="Authorization header value",
        severity=Severity.WARNING,
        pattern=_c(
            r"\bauthorizations?\b[\"']?\s*[:=]\s*[\"']?"
            r"(bearer|basic|token|apikey)\s+([A-Za-z0-9._~+/=\-]{12,512})",
            re.IGNORECASE,
        ),
        description=(
            "A literal `Authorization` header value written into the text. "
            "Whatever scheme it uses, the part after the keyword is the whole "
            "credential — a `Basic` value is only base64, which is encoding, not "
            "protection."
        ),
        remediation=(
            "Rotate the credential at its source, then build the header at "
            "runtime from configuration. A hard-coded header is a credential "
            "with no owner and no expiry."
        ),
        value_group=2,
        label_group=1,
        label_phrase="Written as a {label} credential.",
        gate=GATE_TEMPLATE,
        category="bearer",
    ),

    Rule(
        name="slack_webhook",
        title="Slack incoming webhook",
        severity=Severity.WARNING,
        pattern=_c(
            r"(https://hooks\.slack\.com/services/[A-Za-z0-9_\-]{6,}"
            r"/[A-Za-z0-9_\-]{6,}/[A-Za-z0-9_\-]{6,})"
        ),
        description=(
            "A Slack incoming-webhook URL. The URL *is* the credential: anyone "
            "who has it can post into that channel as the app, with no further "
            "authentication."
        ),
        remediation=(
            "Delete the webhook in the Slack app's configuration and create a "
            "replacement, then keep the new URL in configuration rather than in "
            "the file."
        ),
        category="saas",
    ),

    Rule(
        name="generic_secret_assignment",
        title="Secret-named value",
        severity=Severity.WARNING,
        pattern=_c(
            r"\b([A-Za-z0-9_.\-]{0,40}" + _SECRETISH + r"(?:_?id)?)\b"
            r"[\"']?\s*[:=]{1,2}>?\s*[\"']?" + _VALUE,
            re.IGNORECASE,
        ),
        description=(
            "A name that says `secret` assigned a value dense enough to be one. "
            "No vendor prefix identifies this, so the judgement is the shape of "
            "the value: templated, repetitive, numeric and placeholder values are "
            "dropped, and what is left clears "
            f"{GENERIC_MIN_ENTROPY:.1f} bits of entropy per character."
        ),
        remediation=(
            "Rotate it at whatever issued it, then read it from the environment "
            "or a secrets manager. If this value really is harmless, the finding "
            "is telling you something else worth fixing: the name promises a "
            "secret, so a reader — and the next scanner — will treat it as one."
        ),
        value_group=2,
        label_group=1,
        label_phrase="Assigned to {label}.",
        min_entropy=GENERIC_MIN_ENTROPY,
        min_length=8,
        gate=GATE_FULL,
        category="assignment",
    ),

)


RULES_BY_NAME: dict[str, Rule] = {r.name: r for r in RULES}


def rule(name: str) -> Rule:
    """Look a rule up by name, for tests and for report rendering."""
    return RULES_BY_NAME[name]


def rule_count() -> int:
    return len(RULES)


def forcing_rules() -> tuple[str, ...]:
    """The names of rules that deny a pass mark outright."""
    return tuple(r.name for r in RULES if r.forces_f)


def categories() -> tuple[str, ...]:
    seen: list[str] = []
    for r in RULES:
        if r.category not in seen:
            seen.append(r.category)
    return tuple(seen)
