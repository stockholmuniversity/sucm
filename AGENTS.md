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
  - `sucm_routes.py` — Flask blueprint with all HTTP routes/views.
  - `sucm_certificate.py` — core certificate issuance/renewal/revocation logic.
  - `sucm_certificateauthority/` — CA integrations (`sectigo_eab.py`, `harica_eab.py`) using ACME.
  - `sucm_secret/` — secrets backends (`sucm_vault.py`, `su_vault.py`) for storing keys/certs in HashiCorp Vault.
  - `sucm_automation.py` — APScheduler-based background jobs (auto-renewal, checks).
  - `sucm_db.py` — MySQL data access layer (mysql-connector-python).
  - `sucm_notifygroup.py` — email notification groups.
  - `sucm_settings.py` — config loading (`conf/sucm_conf.ini`) and logging setup (app/audit/syslog).
  - `sucm_globals.py` — shared in-memory state/constants.
  - `templates/` — Jinja2 HTML templates for the web UI.
  - `harica*.py` at repo root — standalone Harica ACME experiment/test scripts (not part of the app package).
- `conf/sucm_conf.ini_example` — example config; real config goes to `<venv>/conf/sucm_conf.ini`.
- `ci-scripts/` — `Dockerfile` (Jenkins agent) and Jenkins pipeline.
- `docs/` — reference RFCs for ACME (8555, 8738, 9773).
- `pyproject.toml` — Poetry project definition, dependencies, and pylint config.

## Runtime dependencies of note
Flask, flask-SSO (Shibboleth-based auth via headers, see README apache example),
mysql-connector-python, hvac (Vault), acme/josepy/pyopenssl (ACME/cert handling),
apscheduler (background jobs), requests_toolbelt.

Auth in production is handled by Apache + Shibboleth, which sets
`X-Remote-User` / `X-Remote-MemberOf` headers; the app expects `it-staff`
group membership.

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
`NotifyGroup`).

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
- `harica-*.py` and `haricatest*.py` at the repo root are exploratory/manual
  test scripts for the Harica ACME flow, separate from the Flask app.
- CI runs via Jenkins (`ci-scripts/pipeline_sucm.groovy`) inside the Docker
  image defined in `ci-scripts/Dockerfile`.
