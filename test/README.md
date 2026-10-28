# SUCM ACME compliance tester

Black-box RFC 8555 tests for the SUCM ACME server (`/acme/...`). Priority: **can we get a certificate
out**, not full RFC coverage.

## Purpose

SUCM's ACME layer lets internal clients (certbot etc.) obtain certificates through SUCM's Harica/Vault
pipeline. This tester answers, from the outside and with no access to SUCM internals:

- Does the server work end to end for a real client (account with EAB, order, finalize, download, revoke)?
- Does it reject what it must (domains outside the allow-list, wildcards, bad EAB, bad signatures/nonces,
  malformed or hostile input) with correct `application/problem+json` errors, never a 5xx?
- Does it follow the RFC 8555 details clients rely on (headers, error types, formats)?

Use it after each deploy to sucm-test (see `just release` in the repo root), before enabling ACME in
production, and to reproduce bugs. It is a development/feedback tool, not part of the deployed app.

Tests are grouped in levels (pytest markers):

| Level | Goal |
|-------|------|
| 1 | Happy path: directory, nonce, newAccount + EAB, newOrder, authz, finalize, download |
| 2 | Renewal, rejectedIdentifier, wildcard rejected (by design), bad EAB, badNonce, CSR mismatch |
| 3 | Security and isolation: revoke, malformed JWS/JSON, oversized body |
| 4 | Remaining RFC conformance (headers, exact error types, ...) |

Test cases, RFC references, findings and results: [../docs/ACME-TEST-PROTOCOL.md](../docs/ACME-TEST-PROTOCOL.md)
(the single copy; update it there after each run).

## First-time setup (each person, on their own machine)

You need `just`, `python3` with `venv`, and network access to the ACME server under test (e.g. run it on the
same host as sucm-test or any machine that can reach it).

```bash
cd test
just setup      # venv + dependencies
just init       # creates ~/.config/sucm-acme-tester/tester.env (chmod 600)
$EDITOR ~/.config/sucm-acme-tester/tester.env
just doctor     # checks config and that the directory is reachable
```

`tester.env` needs your **own ACME account**: request one in the SUCM portal (`/acme-accounts/request`), then have
an admin activate it and put your test domain on its allow-list (`/acme-accounts/admin`). Colleagues must not share
an account: the server binds an EAB kid to the first account key, which is kept in `account_key.pem` next to
`tester.env`. Do not delete that file; reruns need it.

A **second account** is optional but needed for the cross-account isolation tests (L3-01): request another account,
have it activated, and set `ACME_EAB_KID_2` / `ACME_EAB_HMAC_KEY_2` in `tester.env` (its key goes in `account_key_2.pem`).
Without it those tests are skipped.

State (credentials, keys, certbot's config) lives outside the repo in `~/.config/sucm-acme-tester/`
(override with `ACME_STATE_DIR`). Environment variables override `tester.env`. Nothing secret is ever committed.

## Running

```bash
just test            # everything that does not issue a certificate (safe)
just level 3         # one level, without issuance
just run "level3 or level4"
just k revoke        # tests by name
just issue           # level 1 INCLUDING real issuance (asks first)
just certbot         # same flow with real certbot (asks first, needs certbot + openssl)
```

Extra pytest arguments can be appended, e.g. `just test -x -v`.

**Real certificates:** tests marked `issuance` order a real, publicly trusted certificate from the CA (Harica
production until a staging CA is configured, finding F4). It will show up in CT logs. Only run `issue`/`certbot`
when you mean it, and revoke afterwards (the protocol's L3-02 does this).

## Layout

- `acme_tester/` - minimal ACME client (`client.py`), config loading (`config.py`), pre-flight check (`doctor.py`)
- `tests/` - one file per level; shared fixtures in `conftest.py`
- `e2e/certbot.sh` - level 1 with real certbot
- `justfile`, `pytest.ini`, `requirements.txt` - runner and dependencies (independent of the app's Poetry setup)
