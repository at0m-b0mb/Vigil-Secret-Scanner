# Orders API — 1.4.2 release notes

> SYNTHETIC SAMPLE. Every value in this document is fabricated. It is here so
> Vigil has a middle of the scale to demonstrate: one credential that cannot
> touch production, and one block that is meant to be public.

## Fixed

- Webhook deliveries no longer retry a 4xx response forever (#1182).
- The `/healthz` probe no longer opens a database connection (#1190).
- Idempotency keys are now compared case-sensitively, matching the docs (#1193).

## Changed

- The payments sandbox is configured from the repository again, so a reviewer
  can run the test suite without asking anyone for anything:

      STRIPE_PUBLISHABLE_KEY=pk_test_EXAMPLEnotarealkey00
      STRIPE_SECRET_KEY=sk_test_EXAMPLEnotarealkey00

  These only ever reach the test ledger. They are still credentials, and a file
  that holds test keys is usually the file that will one day hold live ones.

## Operations

The staging ingress now pins the peer certificate below. A certificate is the
public half of a key pair — publishing it is the point of having it:

    -----BEGIN CERTIFICATE-----
    bm90LWEtcmVhbC1jZXJ0aWZpY2F0ZS1mb3ItdGhlLXJlbGVhc2Utbm90ZXMtc2Ft
    cGxlLWp1c3Qtc3ludGhldGljLWJhc2U2NC10ZXh0LW5vdGhpbmctdG8tc2VlLXh4
    -----END CERTIFICATE-----

Rotation is handled by the platform team; the private half has never left the
hardware module and does not appear in this repository.

## Upgrade notes

No migrations. Roll forward one instance at a time and watch the delivery
backlog; it should drain within a minute.
