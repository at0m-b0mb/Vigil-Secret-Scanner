"""The rule table: what each detector catches, and what it refuses."""

import pytest

from vigil.core import rules
from vigil.core.model import Preview, Severity
from vigil.core.scan import scan


def _fired(text: str) -> set[str]:
    return {f.rule for f in scan(text).findings}


# --- the table itself -------------------------------------------------------

def test_every_rule_has_a_unique_name():
    names = [r.name for r in rules.RULES]
    assert len(names) == len(set(names))


def test_every_rule_explains_itself_and_what_to_do():
    for r in rules.RULES:
        assert len(r.description) > 40, r.name
        assert len(r.remediation) > 40, r.name
        assert r.description.strip().endswith("."), r.name
        assert r.remediation.strip().endswith("."), r.name


# Products whose own name is lowercase, so a title may begin in lower case.
LOWERCASE_NAMES = {"npm", "pypi"}


def test_every_rule_has_a_human_title():
    for r in rules.RULES:
        assert r.title and r.title != r.name, r.name
        assert "_" not in r.title, r.name
        first = r.title.split()[0]
        assert first[0].isupper() or first in LOWERCASE_NAMES, r.name


def test_value_groups_exist_in_their_patterns():
    for r in rules.RULES:
        assert r.value_group <= r.pattern.groups, r.name
        if r.label_group is not None:
            assert r.label_group <= r.pattern.groups, r.name
            assert r.label_group != r.value_group, r.name


def test_a_labelled_rule_has_a_phrase_to_put_the_label_in():
    for r in rules.RULES:
        if r.label_group is not None:
            assert "{label}" in r.label_phrase, r.name


def test_forcing_rules_are_all_alerts():
    for r in rules.RULES:
        if r.forces_f:
            assert r.severity is Severity.ALERT, r.name


def test_the_four_named_families_force_the_bottom_grade():
    forcing = rules.forcing_rules()
    for name in ("aws_access_key_id", "aws_secret_access_key", "github_token",
                 "stripe_live_key", "private_key_block"):
        assert name in forcing


def test_structural_rules_do_not_force_a_grade_and_are_not_redacted():
    cert = rules.rule("certificate_block")
    assert cert.severity is Severity.INFO
    assert not cert.forces_f
    assert not cert.opaque
    assert cert.preview is Preview.MARKER


def test_block_rules_come_first_so_their_interiors_are_masked():
    order = [r.name for r in rules.RULES]
    assert order.index("private_key_block") < order.index("aws_access_key_id")
    assert order.index("certificate_block") < order.index("generic_secret_assignment")


def test_the_generic_rule_comes_last_of_the_matchers():
    order = [r.name for r in rules.RULES]
    assert order.index("generic_secret_assignment") == len(order) - 1


def test_only_the_generic_rule_applies_the_full_stand_in_filter():
    full = [r.name for r in rules.RULES if r.gate == "full"]
    assert full == ["generic_secret_assignment"]


def test_no_rule_names_a_brand_as_the_thing_it_judges():
    # A rule may name a vendor to say whose *format* it recognises; none may
    # describe itself as judging who somebody is.
    for r in rules.RULES:
        blob = (r.description + r.remediation).lower()
        for banned in ("blocklist", "blacklist", "known bad", "untrusted vendor"):
            assert banned not in blob, r.name


def test_rule_lookup_and_counts():
    assert rules.rule_count() == len(rules.RULES)
    assert rules.rule("jwt").name == "jwt"
    with pytest.raises(KeyError):
        rules.rule("no_such_rule")


def test_categories_are_listed_once_each_in_table_order():
    cats = rules.categories()
    assert len(cats) == len(set(cats))
    assert cats[0] == "key-material"


# A Twilio key is "SK" and 32 hex digits -- exactly what this project detects,
# and exactly what GitHub's push protection blocks. A scanner's own fixtures
# are the thing it would catch, so the literal is assembled here rather than
# written out: the rule stays under test, and no credential-shaped string sits
# in the file for a scanner to find.
_TWILIO_SHAPED = "SK" + "0123456789abcdef" * 2


# --- positives --------------------------------------------------------------

POSITIVES = [
    ("aws_access_key_id", "AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY123456"),
    ("aws_access_key_id", "temporary: ASIAEXAMPLEKEY123456"),
    ("aws_secret_access_key",
     "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIbPxRfiCYEXAMPLEKEYnotreal00"),
    ("github_token", "ghp_EXAMPLEnotarealtokenEXAMPLE000000000"),
    ("github_token", "github_pat_EXAMPLEnotarealfinegrained00"),
    ("gitlab_token", "CI_TOKEN=glpat-EXAMPLEnotarealglpat00"),
    ("slack_token", "xoxb-EXAMPLEnotarealslacktoken0000000000"),
    ("slack_token", "xoxp-EXAMPLEnotarealslacktoken0000000000"),
    ("slack_webhook",
     "https://hooks.slack.com/services/T00000000/B00000000/EXAMPLEnotarealhook"),
    ("google_api_key", "AIzaEXAMPLE-not-a-real-google-key-00000"),
    ("stripe_live_key", "sk_live_EXAMPLEnotarealkey00"),
    ("stripe_live_key", "rk_live_EXAMPLEnotarealkey00"),
    ("stripe_test_key", "sk_test_EXAMPLEnotarealkey00"),
    ("stripe_test_key", "pk_test_EXAMPLEnotarealkey00"),
    ("sendgrid_key", "SG.EXAMPLEnotareal0.EXAMPLEnotarealsendgridkey00000"),
    ("twilio_api_key", _TWILIO_SHAPED),
    ("openai_style_key", "sk-EXAMPLEnotarealopenaikey000000000000"),
    ("openai_style_key", "sk-proj-EXAMPLEnotarealopenaikey000000000000"),
    ("npm_token", "npm_EXAMPLEnotarealnpmtoken0000000000000"),
    ("pypi_token", "pypi-EXAMPLEnotarealpypitoken00"),
    ("private_key_block", "-----BEGIN RSA PRIVATE KEY-----\nbm90\n-----END RSA PRIVATE KEY-----"),
    ("private_key_block", "-----BEGIN OPENSSH PRIVATE KEY-----\nbm90\n"),
    ("private_key_block", "-----BEGIN PRIVATE KEY-----\nbm90\n"),
    ("certificate_block", "-----BEGIN CERTIFICATE-----\nbm90\n-----END CERTIFICATE-----"),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c2lnbmF0dXJl"),
    ("db_connection_password",
     "DATABASE_URL=postgres://app:not-a-real-db-password@db:5432/orders"),
    ("db_connection_password",
     "mysql://root:not-a-real-db-password@127.0.0.1:3306/app"),
    ("db_connection_password",
     "mongodb+srv://svc:not-a-real-mongo-pass@cluster0.example.net/reports"),
    ("url_basic_auth", "smtp://mailer:not-a-real-smtp-pass@smtp.example.net:587"),
    ("url_basic_auth", "https://admin:not-a-real-pass@dashboard.example.net/"),
    ("authorization_header",
     '"Authorization": "Basic YWRtaW46bm90LWEtcmVhbC1wYXNzd29yZA=="'),
    ("authorization_header",
     "Authorization: Bearer Hq8synthetic2Vb9XzQm4Vzt7Mn"),
    ("generic_secret_assignment", 'API_KEY = "Hq8-synthetic-2Vb-9Xz"'),
    ("generic_secret_assignment", "client_secret: Hq8-synthetic-2Vb-9Xz"),
    ("generic_secret_assignment", "ADMIN_PASSWORD=pw-7Xq2-synthetic-9Kz4-Vb"),
    ("generic_secret_assignment", "access_key_id => Hq8-synthetic-2Vb-9Xz"),
    ("generic_secret_assignment", "PRIVATE_KEY=Hq8-synthetic-2Vb-9Xz"),
    ("generic_secret_assignment", "ssh_key: Hq8-synthetic-2Vb-9Xz"),
]


@pytest.mark.parametrize("rule_name,text", POSITIVES,
                         ids=[f"{n}:{i}" for i, (n, _) in enumerate(POSITIVES)])
def test_rule_fires_on_its_own_shape(rule_name, text):
    assert rule_name in _fired(text)


# --- negatives --------------------------------------------------------------

NEGATIVES = [
    # too short, or the wrong alphabet, for the shape they imitate
    ("aws_access_key_id", "AKIASHORT123"),
    ("aws_access_key_id", "AKIAexamplekey123456"),          # lower case
    ("aws_secret_access_key", "AWS_SECRET_ACCESS_KEY=tooshort"),
    ("github_token", "ghp_short"),
    ("gitlab_token", "glpat-short"),
    ("google_api_key", "AIzaTooShort"),
    ("twilio_api_key", "SK0123456789abcdef0123456789abcde"),  # 31 hex
    ("npm_token", "npm_tooshort"),
    ("stripe_live_key", "sk_test_EXAMPLEnotarealkey00"),      # test, not live
    ("jwt", "eyJonlyonesegment"),
    # structure that carries no credential
    ("db_connection_password", "postgres://orders_app@db.internal:5432/orders"),
    ("db_connection_password", "redis://cache:6379/0"),
    ("url_basic_auth", "https://flags.example.net/v1/orders-api"),
    ("private_key_block", "-----BEGIN CERTIFICATE-----\nbm90\n"),
    ("certificate_block", "-----BEGIN RSA PRIVATE KEY-----\nbm90\n"),
    # stand-ins the generic rule must refuse
    ("generic_secret_assignment", "password = changeme"),
    ("generic_secret_assignment", "api_key: ${API_KEY}"),
    ("generic_secret_assignment", "token: <your-token-here>"),
    ("generic_secret_assignment", 'secret: "{{ vault_secret }}"'),
    ("generic_secret_assignment", "password = 12345678"),
    ("generic_secret_assignment", "secret_key = aaaaaaaaaaaaaaaa"),
    ("generic_secret_assignment", "password_file: /run/secrets/db_password"),
    ("generic_secret_assignment", "password_env: ORDERS_DB_PASSWORD"),
    ("generic_secret_assignment", "auth = true"),
    ("generic_secret_assignment", "token = null"),
    ("generic_secret_assignment", "api_key_path: ./secrets/api_key.txt"),
    ("generic_secret_assignment", "password = short"),
    # a key name that is not a secret name: bare `key` stays out of the
    # vocabulary precisely so these keep scoring nothing
    ("generic_secret_assignment", "public_key=Hq8-synthetic-2Vb-9Xz"),
    ("generic_secret_assignment", "cache_key = Hq8-synthetic-2Vb-9Xz"),
    ("generic_secret_assignment", "partition_key: Hq8-synthetic-2Vb-9Xz"),
]


@pytest.mark.parametrize("rule_name,text", NEGATIVES,
                         ids=[f"{n}:{i}" for i, (n, _) in enumerate(NEGATIVES)])
def test_rule_refuses_what_only_resembles_it(rule_name, text):
    assert rule_name not in _fired(text)


# --- the inline private key -------------------------------------------------
# The armoured PEM form was always caught. A key written as a single-line
# value — which is how a service-account JSON field or a CI-injected secret
# actually looks — was invisible, and a file holding one scored A+ "Nothing
# matched". The name vocabulary had signing_key, encryption_key and
# master_key but not private_key.

INLINE_KEY_NAMES = ["private_key", "PRIVATE_KEY", "Private_Key", "privatekey",
                    "ssh_key", "SSH_KEY", "sshkey", "GCP_SA_PRIVATE_KEY",
                    "deploy_ssh_key", "service_account_private_key"]


@pytest.mark.parametrize("name", INLINE_KEY_NAMES)
def test_an_inline_private_key_is_not_invisible(name):
    assert "generic_secret_assignment" in _fired(f"{name}=Hq8-synthetic-2Vb-9Xz")


# A suffix *after* the secret-ish word ends the name match, because the pattern
# requires a word boundary there. That is deliberate and it predates the
# private_key entry — it is what makes `password_env: ORDERS_DB_PASSWORD` and
# `api_key_path: ./secrets/api_key.txt` refuse to fire. So `PRIVATE_KEY_PEM=`
# is missed for the same reason `API_KEY_V2=` is, and this records the limit
# rather than leaving it to be discovered.
@pytest.mark.parametrize("name", ["PRIVATE_KEY_PEM", "API_KEY_V2",
                                  "PASSWORD_ENV"])
def test_a_suffix_after_the_secret_word_ends_the_name(name):
    assert _fired(f"{name}=Hq8-synthetic-2Vb-9Xz") == set()


# The near-misses that keep the addition targeted. Bare `key` is deliberately
# absent from the vocabulary; if it were there, every one of these would fire.
NOT_SECRET_KEY_NAMES = ["public_key", "PUBLIC_KEY", "publickey", "cache_key",
                        "sort_key", "partition_key", "idempotency_key",
                        "shard_key", "key"]


@pytest.mark.parametrize("name", NOT_SECRET_KEY_NAMES)
def test_a_key_that_is_not_a_secret_does_not_fire(name):
    assert _fired(f"{name}=Hq8-synthetic-2Vb-9Xz") == set()


# --- precedence -------------------------------------------------------------

def test_a_named_token_is_reported_once_as_itself():
    fired = _fired("GITHUB_TOKEN=ghp_EXAMPLEnotarealtokenEXAMPLE000000000")
    assert fired == {"github_token"}


def test_an_aws_secret_is_not_also_a_nameless_assignment():
    fired = _fired(
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIbPxRfiCYEXAMPLEKEYnotreal00")
    assert fired == {"aws_secret_access_key"}


def test_a_password_in_a_url_wins_over_the_name_it_was_assigned_to():
    fired = _fired(
        "DB_PASSWORD_URL=postgres://app:not-a-real-db-password@db:5432/orders")
    assert fired == {"db_connection_password"}


def test_a_jwt_in_an_authorization_header_is_reported_as_a_jwt():
    fired = _fired(
        "Authorization: Bearer "
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c2lnbmF0dXJl")
    assert fired == {"jwt"}


def test_nothing_inside_a_private_key_block_is_reported_separately():
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "AKIAEXAMPLEKEY123456\n"
        "ghp_EXAMPLEnotarealtokenEXAMPLE000000000\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    assert _fired(text) == {"private_key_block"}


def test_an_unterminated_block_claims_only_its_own_line():
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY123456\n"
    )
    assert _fired(text) == {"private_key_block", "aws_access_key_id"}
