# SUCM — Repository Guide for Copilot CLI

## What this is
SUCM ("SSL certificate manager with web GUI") is a Flask web application used at
Stockholm University to manage the lifecycle of SSL/TLS certificates: submitting
CSRs, requesting/renewing certificates from a Certificate Authority (Sectigo or
Harica via ACME/EAB), storing secrets in Vault, notifying groups on
expiry/errors, and tracking everything in a MySQL database.

## Layout
- `sucm_app.py` — WSGI/app entrypoint (`create_app()` from `sucm/__init__.py`).
- `sucm/` — main package
  - `sucm_routes.py` — Flask blueprint (`main`) with all certificate-management HTTP routes/views.
  - `sucm_certificate.py` — core certificate issuance/renewal/revocation logic.
  - `sucm_certificateauthority/` — CA integrations (`sectigo_eab.py`, `harica_eab.py`) using ACME.
    Sectigo is legacy/EOL (all its certs expired, no new orders possible — kept only so old
    `ActiveCertificate` rows don't break); Harica is the CA of record going forward.
    `harica_eab.py` raises `HaricaError` on any HARICA API failure (it previously called
    `sys.exit(1)`, which killed the WSGI worker / scheduler mid-request); callers catch or
    propagate it to an error response rather than letting the process die.
  - `sucm_secret/` — secrets backends (`sucm_vault.py`, `su_vault.py`) for storing keys/certs in HashiCorp Vault.
  - `sucm_automation.py` — APScheduler-based background jobs (auto-renewal, checks). Skips
    `cert_type == "Manual"` (needs a human) and `cert_type == "ACME"` (client-driven renewal, see below).
  - `sucm_db.py` — MySQL data access layer (mysql-connector-python). `get_records()`/
    `remove_record()` take a bare column name plus a value and build `WHERE <column> = %s`
    internally (the column is validated with `str.isidentifier()`, the value is always
    parameterized) — callers never supply raw SQL fragments. For anything more complex
    (joins, date arithmetic, etc.) use `execute_select_query`/`execute_modify_query`
    with real parameter binding — mandatory for attacker-reachable input (e.g. anything
    the ACME server parses). Integer primary keys for the app-managed tables
    (`Certificate`, `ActiveCertificate`, `NotifyGroup`, `AcmeAccount`, `AcmeAccountDomain`,
    `AcmeOrder`, `AcmeAuthorization`) are allocated via `claim_next_id()`, which bumps a row
    in the `IdCounter` table atomically (`INSERT ... ON DUPLICATE KEY UPDATE`) so concurrent
    web/ACME/scheduler connections can never pick the same id — do not reintroduce the racy
    `SELECT MAX(pk)+1` read (`get_next_available_id()` is kept only for legacy/low-concurrency
    callers and is allow-listed to the same tables). `IdCounter` is created by
    `scripts/migrate_acme_accounts.py`. `execute_modify_rows()` returns the affected-row
    count for atomic check-and-set writes (e.g. the ACME `bind_jwk()` `WHERE Jwk_Json IS NULL`
    guard).
  - `sucm_notifygroup.py` — email notification groups. `validate_email_csv()` enforces a
    strict per-address shape (no CR/LF) on the recipient list before it is saved, so a stored
    list can never become a mail-header injection primitive; `send_email()` additionally
    strips CR/LF from headers as defense-in-depth.
  - `sucm_roles.py` — role-based authorization: parses `X-Remote-MemberOf` into a role set
    (`ROLE_GROUPS` in `sucm_globals.py`) and provides `@require_role(...)` to enforce roles
    in-app (defense-in-depth on top of Apache's Shibboleth gating). See
    `TODO-role-based-views.md` for the full design.
  - `sucm_acme_account.py` — `SucmAcmeAccount` model: ACME-account request/activation, the
    per-account domain allow-list (`AcmeAccount`/`AcmeAccountDomain` tables), and (since phase 2)
    reversible (Fernet-encrypted) EAB HMAC-key storage + JWK binding — see `sucm_acme_crypto.py`.
  - `sucm_acme_routes.py` — `acme_accounts` Flask blueprint (`/acme-accounts/...`): public account
    request + one-time credential reveal, and an admin panel (activate accounts, manage allow-lists).
    The one-time reveal does NOT round-trip the plaintext HMAC key through the client-side session
    cookie (signed, not encrypted) - only a non-secret reveal token goes in the session, and the key
    itself stays server-side (Fernet-encrypted) in `AcmeRevealToken` until first read.
  - `sucm_acme_reveal.py` — `SucmAcmeRevealToken`: server-side one-time store for the EAB HMAC key
    reveal (`AcmeRevealToken` table). `create()` stashes the encrypted key keyed by an unguessable
    token; `consume()` deletes-on-read so the plaintext is revealed exactly once; `prune_expired()`
    is run by the scheduler so unclaimed tokens do not linger.
  - `sucm_acme_crypto.py` — Fernet encrypt/decrypt for the EAB HMAC key (key derived from
    `SUCM.secret_key`, see comment in the file for rationale).
  - `sucm_acme_jws.py` — manual JWS parsing/verification (RS256/ES256/HS256) built directly on
    `cryptography` primitives, used by the ACME server.
  - `sucm_acme_nonce.py` — DB-backed anti-replay nonce issue/consume (`AcmeNonce` table).
  - `sucm_acme_order.py` — `SucmAcmeOrder` model: order/authorization CRUD plus the `finalize`
    bridge into `SucmCertificate` (auto-provisions a `cert_type="ACME"` `Certificate` row, validates
    the CSR's identifier set against the order, then calls `submit_manual_csr()`/
    `renew_cert_with_csr()` exactly as a manually-submitted CSR would).
  - `sucm_acme_server_routes.py` — `acme_server` Flask blueprint (`/acme/...`): the actual RFC 8555
    wire protocol (directory/new-nonce/new-account/new-order/authz/challenge/finalize/certificate/
    revoke-cert) that certbot (or any ACME client) speaks directly, with no Shibboleth session.
  - `sucm_settings.py` — config loading (`conf/sucm_conf.ini`) and logging setup (app/audit/syslog).
  - `sucm_globals.py` — shared in-memory state/constants, incl. `CERT_TYPES` (user-selectable:
    `Automatic`/`Manual`) and `ACME_CERT_TYPE` (`"ACME"` — deliberately excluded from `CERT_TYPES`;
    only ever set by the ACME account admin panel or the ACME order-finalize bridge, never through
    the normal add/edit-cert GUI).
  - `templates/` — Jinja2 HTML templates for the web UI, incl. `acme_account_*.html`/`acme_admin_*.html`.
  - `harica*.py` at repo root — standalone Harica ACME experiment/test scripts (not part of the app package).
- `scripts/` — standalone maintenance scripts run outside the Flask app (own DB config parsing, minimal deps).
  - `migrate_acme_accounts.py` — idempotent DB migration for all ACME tables (`AcmeAccount`,
    `AcmeAccountDomain`, `AcmeNonce`, `AcmeOrder`, `AcmeAuthorization`) plus the `IdCounter`
    table used by `sucm_db.claim_next_id()` and the `AcmeRevealToken` table used by
    `sucm_acme_reveal.py`; reads DB creds straight from
    `sucm_conf.ini`, supports `--dry-run`/`--no-ssl`/`--config`. Also renames the old phase-1
    `Kid`/`Hmac_Key_Hash`/`Jwk_Thumbprint` columns in place if an earlier version of this script was
    already run.
- `conf/sucm_conf.ini_example` — example config; real config goes to `<venv>/conf/sucm_conf.ini`.
- `ci-scripts/` — `Dockerfile` (Jenkins agent) and Jenkins pipeline.
- `docs/` — reference RFCs for ACME (8555, 8738, 9773) — used to design the ACME MITM layer.
- `pyproject.toml` — Poetry project definition, dependencies, and pylint config.

## The ACME MITM layer
Goal: let internal clients (e.g. certbot) get certs issued through SUCM's existing Harica/Vault
pipeline via the standard ACME protocol, gated by admin-managed per-account domain allow-lists
rather than real domain-control validation (acceptable here since it's an internal-only tool and
Harica, unlike the now-EOL Sectigo, has no objection to this model).

**Phase 1 — account portal** (`/acme-accounts/...`): self-service account request, instant creation,
EAB `kid`/HMAC credential shown once; an admin panel to activate accounts and manage domain
allow-lists.

**Phase 2 — ACME server** (`/acme/...`, `sucm_acme_server_routes.py`): the actual RFC 8555 protocol
endpoint. Key design points:
  - The EAB HMAC key is stored **encrypted** (Fernet, reversible), not hashed — RFC 8555
    `externalAccountBinding` is HMAC-signed, so the server must recompute the HMAC over each
    `newAccount` request using the raw shared secret; a one-way hash cannot be used for this.
  - The account's public JWK is stored (not just a thumbprint) after the first successful
    `newAccount`, so later `kid`-signed requests can be signature-verified.
  - **Trust-based issuance, not real domain-control validation**: on `newOrder`, every identifier
    is checked against the account's domain allow-list; if all pass, authorizations (and their one
    challenge) are created already `valid`, so certbot proceeds straight to `finalize` with no
    challenge round-trip.
  - `finalize` validates the CSR's identifier set against the order, then drives the existing
    `SucmCertificate.submit_manual_csr()`/`renew_cert_with_csr()` pipeline synchronously (Harica's
    fetch_cert flow is itself synchronous/multi-step but has no human in the loop).
  - **Wildcard certificates are NOT supported by design**: any order identifier starting with
    `*.` is rejected in `create_order()` (`rejectedIdentifier`). This is an explicit decision,
    not an oversight — do not "fix" the resulting inability to issue wildcards.
  - The target CA/secret-path/notify-group for ACME-issued certs are read from the `[ACME]`
    section of `sucm_conf.ini` (`ca_plugin_name`, `secret_path`, `notify_group_id`) via
    `_load_acme_config()` in `sucm_acme_order.py`. **PRE-PROD BLOCKER**: these must be set to
    real production values before the ACME server is enabled; if `ca_plugin_name`/`secret_path`
    are unset, `finalize_order()` fails closed (serverInternal) rather than issuing into a
    default/test location. `secret_path` must be one of the paths the secrets backend's
    `get_all_paths()` returns.
  - Nonces are DB-backed (`AcmeNonce` table), not in-memory, since the app can run as multiple WSGI
    processes/threads that don't share memory.
  - `revoke-cert` authorizes by the submitted certificate's actual identity — it walks the calling
    account's own orders and requires an exact **issuer + serial-number** match against a stored,
    ACME-issued active certificate. It deliberately does NOT look certs up by the (caller-controlled)
    CN string, and revokes the *matched* cert rather than the "latest" one for a CN.
  - Every ACME-facing DB query uses parameter binding (`execute_select_query`/`execute_modify_query`),
    since these endpoints are reached directly by unauthenticated-at-the-Apache-layer clients.

### Auth tiers (Apache/Shibboleth, config lives in the separate `su-salt-states-services-cert` repo)
- General app + `/acme-accounts/request`+`/created` → `it-staff` (existing default `<LocationMatch "^/">`).
- `/acme-accounts/admin*` → `it-produktion-infra-imdb`, via a more specific `<LocationMatch>` block that
  sets **`AuthMerging Off`** — required, otherwise Apache's default `Require` merging is an implicit OR
  across overlapping `<LocationMatch>` sections and `it-staff` would also satisfy the admin path.
- `/acme/...` (the ACME server itself) → unauthenticated at the Apache/Shibboleth layer (`Require all
  granted` + `AuthMerging Off`, since certbot speaks JWS/EAB, not browser headers); all
  authentication/authorization happens inside the app via JWS signature verification + EAB.
- `/automation` (renders the application log) is additionally gated **in-app** to the
  `acme_admin` role (`it-produktion-infra-imdb`) rather than the broad `it-staff` group, because it
  exposes raw operational log output the wider cert-manager population does not need. The
  corresponding Apache `<LocationMatch>` should be tightened to the same group (see
  `su-salt-states-services-cert`).

**Header trust / fail-closed**: Apache sets `X-Remote-User`/`X-Remote-Display-Name`/`X-Remote-MemberOf`
via `RequestHeader set` in `sucm-apache.conf`, which *replaces* any client-supplied value, so the
SSO-gated paths cannot be spoofed through Apache. As defense-in-depth, the `main` and `acme_accounts`
blueprints' `before_request` additionally **abort(403) if `X-Remote-User` is absent** — a request that
reaches the app without it has bypassed/misconfigured the SSO gate. (`/acme/*` is exempt: it is
header-less by design and authenticates via JWS/EAB.)

**CSRF / CSP**: All cookie/session-authenticated POST forms carry a Flask-WTF `csrf_token()`
(`CSRFProtect` is enabled in `create_app()`); the ACME server blueprint is exempt because it is
JWS-authenticated, not cookie-based. Session cookies are `HttpOnly`/`SameSite=Lax`/`Secure`, and a
restrictive `Content-Security-Policy` (+ `X-Frame-Options`/`X-Content-Type-Options`) is set in
`create_app()`'s `after_request`.

**Web-form `secret_path` validation**: `edit_cert_response()` validates the submitted `secret_path`
against the secrets backend's `get_all_paths()` (the same list the GUI dropdown is populated from)
plus a shape check, rejecting anything else. The Vault user's own ACLs remain the authoritative
control; this app-side allow-list is defense-in-depth.

## Runtime dependencies of note
Flask, flask-SSO (Shibboleth-based auth via headers, see README apache example),
Flask-WTF (CSRF), mysql-connector-python, hvac (Vault), acme/josepy/pyopenssl (ACME/cert handling),
apscheduler (background jobs), requests_toolbelt.

## Pre-production blockers
These MUST be resolved before the ACME layer (or a production release) ships:
- **`acme_requester` role group** (`sucm_globals.py`): currently the `jira-administrators`
  placeholder. Replace with the real "org but not it-staff" `memberOf` group, in lockstep with the
  matching `<LocationMatch "^/acme-accounts/(request|created)">` block in
  `su-salt-states-services-cert`'s `sucm-apache.conf`. (Decision on the real group is pending.)
- **`[ACME]` config section** (`sucm_conf.ini`): set `ca_plugin_name`, `secret_path`, and
  `notify_group_id` to real production values — see "The ACME MITM layer" above. Issuance fails
  closed until then.

Auth in production is handled by Apache + Shibboleth, which sets
`X-Remote-User` / `X-Remote-MemberOf` headers; see "Auth tiers" above for which
`memberOf` group is required per route group (`it-staff` general/portal,
`it-produktion-infra-imdb` ACME admin).

## Setup / running locally
This project uses **Poetry**.
```bash
poetry install
poetry run sucm_app        # or: poetry run python sucm_app.py
```
Config file is expected at `<virtualenv_root>/conf/sucm_conf.ini` (copy from
`conf/sucm_conf.ini_example` and fill in MySQL, Vault, and CA credentials).
App/audit logs are written to `<venv_root>/application.log` and `audit.log`;
`sucm_settings.py` truncates `application.log` on startup.

Required DB schema is documented in `README.md` (MySQL `CREATE TABLE`
statements for `CertificateAuthority`, `Certificate`, `ActiveCertificate`,
`NotifyGroup`, plus the ACME layer's `AcmeAccount`/`AcmeAccountDomain`/
`AcmeNonce`/`AcmeOrder`/`AcmeAuthorization`, plus `IdCounter` and `AcmeRevealToken` —
apply the latter seven via `scripts/migrate_acme_accounts.py` rather than by hand).

## Linting / formatting
Dev deps: `black`, `isort`, `pylint` (config lives in `pyproject.toml`).
```bash
poetry run black .
poetry run isort .
poetry run pylint sucm
```
There is no automated test suite in this repo currently.

## Conventions & gotchas
- No tests exist yet — validate changes by running the lints above and,
  where feasible, exercising affected routes/functions manually.
- Secrets/config (`sucm_conf.ini`, Vault tokens, CA credentials) must never be
  committed; only the `_example` config is tracked.
- `print()`/logger output in the issuance/revoke paths (`sucm_certificate.py`, the Harica
  plugin) is retained for troubleshooting but must stay **status/metadata only** — it must never
  emit secrets or response bodies that can contain them (the Harica plugin previously printed the
  post-login JWT and the full certificate PEM chain; those were removed). Do not add prints of
  passwords, TOTP seeds, HMAC keys, private keys, JWTs, cert PEMs, or raw API response bodies.
- `harica-*.py` and `haricatest*.py` at the repo root are exploratory/manual
  test scripts for the Harica ACME flow, separate from the Flask app.
- CI runs via Jenkins (`ci-scripts/pipeline_sucm.groovy`) inside the Docker
  image defined in `ci-scripts/Dockerfile`.
- ACME MITM layer: no formal test procedure yet — intentionally deferred
  until you're ready to design a proper end-to-end test plan (account
  request → admin activation/allow-list → certbot registration/order/
  issuance/renewal/revocation) covering both the account portal (phase 1,
  already tested informally) and the ACME server (phase 2, not yet tested
  against a real client/DB — only unit-level crypto/JWS logic and
  `py_compile` have been checked so far).
