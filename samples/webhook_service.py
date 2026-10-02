"""
SYNTHETIC SAMPLE — a plausible service module with the mistakes people make.

Nothing in this file is a real credential. The PEM block is fabricated base64,
the JWT decodes to synthetic claims, and the Basic header encodes
``admin:not-a-real-password``. It is here so Vigil has something to find.
"""

import base64
import hmac
import json
from hashlib import sha256
from urllib.parse import urlencode

# Left behind after a debugging session, which is how these usually arrive.
SESSION_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJub3QtYS1yZWFsLXN1YmplY3QiLCJuYW1lIjoiU3ludGhldGljIFVzZXIifQ.c3ludGhldGljLXNpZ25hdHVyZS1ub3QtcmVhbA"  # noqa: E501

# Pasted in "temporarily" to get the integration working.
DEFAULT_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "webhook-service/1.4",
    "Authorization": "Basic YWRtaW46bm90LWEtcmVhbC1wYXNzd29yZA==",
}

# The signing key for outbound webhooks, committed instead of mounted.
SIGNING_KEY = """-----BEGIN RSA PRIVATE KEY-----
bm90LWEtcmVhbC1rZXktdGhpcy1pcy1zeW50aGV0aWMtYmFzZTY0LWZvci1hLXNh
bXBsZS1maWxlLWFuZC1kZWNvZGVzLXRvLW5vdGhpbmctdXNlZnVsLWF0LWFsbC1y
ZWFsbHktbm90LWEta2V5LW5vdC1hLWtleS1ub3QtYS1rZXktbm90LWEta2V5LXh4
eC1lbmQtb2YtdGhlLXN5bnRoZXRpYy1ibG9jay1ub3QtcmVhbC1ub3QtcmVhbA==
-----END RSA PRIVATE KEY-----"""

# The certificate is the public half. It is fine to ship; Vigil says so.
PEER_CERT = """-----BEGIN CERTIFICATE-----
bm90LWEtcmVhbC1jZXJ0aWZpY2F0ZS1qdXN0LXN5bnRoZXRpYy1iYXNlNjQtdGV4
dC1zby10aGUtc2FtcGxlLWhhcy1hLXB1YmxpYy1ibG9jay1pbi1pdC10b28teHh4
-----END CERTIFICATE-----"""

WEBHOOK_BASE = "https://hooks.example.net/v2/deliveries"


def sign(payload: bytes, key: bytes) -> str:
    """Sign an outbound payload. The key should arrive as an argument."""
    return hmac.new(key, payload, sha256).hexdigest()


def build_request(event: dict) -> tuple[str, dict, bytes]:
    """Assemble one delivery: a URL, headers, and a signed body."""
    body = json.dumps(event, separators=(",", ":"), sort_keys=True).encode()
    headers = dict(DEFAULT_HEADERS)
    headers["X-Signature"] = sign(body, SIGNING_KEY.encode())
    query = urlencode({"event": event.get("type", "unknown")})
    return f"{WEBHOOK_BASE}?{query}", headers, body


def decode_claims(token: str) -> dict:
    """A JWT's claims are encoded, not encrypted — anyone holding it can read."""
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))
