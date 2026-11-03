**example wsgi script**

	import sys
	
	sys.path.insert(0, "/local/cert-app")
	
	from sucm_app import app as application
**example apache conf**

*(Note: production Apache config is Salt-managed in the `su-salt-states-services-cert`
repo, templated from `salt/services/cert/app/files/etc/apache2/sites-enabled/sucm-apache.conf`.
The snippet below is a static, illustrative copy - keep both in sync manually.)*

    <VirtualHost *:80>
      ServerName sucm-test.it.su.se
      RewriteEngine On
      #redirect port 80 requests
      RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R,L]
    </VirtualHost>
    
    <VirtualHost *:443>
      ServerName sucm-test.it.su.se
    
      SSLEngine on
      SSLCertificateFile	/local/secret/ssl/cert-test-app01.it.su.se.pem
      SSLCertificateKeyFile /local/secret/ssl/cert-test-app01.it.su.se.key
      SSLCertificateChainFile /local/secret/ssl/cert-test-app01.it.su.se-cachain.crt
    
      SSLProxyProtocol all -SSLv2 -SSLv3 -TLSv1
    
      SSLProxyEngine on
    
      DocumentRoot /local/cert-app
      ErrorDocument 401 "You are missing entitlement required to use this service."
    
      # this can probably be reduced after commit 89fc5e3, that removed cert_pem from active_cert dictionary.
      LimitRequestLine 90000
      LimitRequestFieldSize 90000
    
      WSGIDaemonProcess sucm python-home=/local/cert-app
      WSGIProcessGroup sucm
    
      WSGIScriptAlias / /local/cert-app/sucm.wsgi
    
    
      <LocationMatch "^/acme-accounts/admin">
          AuthMerging Off
          AuthType shibboleth
          ShibRequireSessionWith idp-test.it.su.se
          Require shib-attr memberOf it-produktion-infra-imdb
          RequestHeader set X-Remote-User %{REMOTE_USER}s
          RequestHeader set X-Remote-Display-Name %{displayName}s
          RequestHeader set X-Remote-MemberOf %{memberOf}s
      </LocationMatch>
    
      # The ACME wire-protocol server: reached directly by automated clients
      # (e.g. certbot), which never send Shibboleth session headers. Auth is
      # entirely inside the app (EAB-bound account + JWS signature
      # verification) - see sucm_acme_server_routes.py.
      <LocationMatch "^/acme/">
          AuthMerging Off
          Require all granted
      </LocationMatch>
    
      <LocationMatch "^/">
          AuthType shibboleth
          ShibRequireSessionWith idp-test.it.su.se
          Require shib-attr memberOf it-staff
          RequestHeader set X-Remote-User %{REMOTE_USER}s
          RequestHeader set X-Remote-Display-Name %{displayName}s
          RequestHeader set X-Remote-MemberOf %{memberOf}s
      </LocationMatch>
    
    
      <Directory /opt/SUCM>
          Require all granted
      </Directory>

</VirtualHost>

**Database schema**

The canonical schema is [`sql/schema.sql`](sql/schema.sql). It is the
production baseline (dumped 2026-11-03, kept for reference in
`docs/sucm-prod-ddl-2026-11-03.sql`). There is no ORM: the application never
creates or alters tables itself, so a new system must be set up with this file.

The file is **idempotent and additive only** (`CREATE TABLE IF NOT EXISTS`,
`INSERT IGNORE`). It never alters, drops or overwrites anything, so it is safe to
run against a database that already holds data - it only adds what is missing.

Tables:

| Group | Tables |
|-------|--------|
| Certificates | `CertificateAuthority`, `Certificate`, `ActiveCertificate`, `NotifyGroup` |
| Id allocation | `IdCounter` - the app assigns integer primary keys itself (no `AUTO_INCREMENT`); `sucm_db.claim_next_id()` creates a row per table on first use, seeded from `MAX(pk)`, so leave it empty |
| ACME layer | `AcmeAccount`, `AcmeAccountDomain`, `AcmeNonce`, `AcmeOrder`, `AcmeAuthorization`, `AcmeRevealToken` |

`CertificateAuthority` is seeded with `Sectigo` (1, legacy), `Dummy CA` (2) and
`Harica` (3); the `[ACME]` `ca_plugin_name` setting must match one of these names.

Set up a **new system**:

    CREATE DATABASE cert_app CHARACTER SET utf8 COLLATE utf8_swedish_ci;
    -- then, as a user allowed to CREATE tables:
    mysql cert_app < sql/schema.sql

Use the same character set/collation as production (`utf8` / `utf8_swedish_ci`);
the tables inherit it from the database. Table names are used in CamelCase by the
code, so a server with `lower_case_table_names=1` (as on test) is fine.

**Upgrade an existing system** that predates the ACME layer: run
`sql/schema.sql` (adds the missing tables only). If it has an *old phase-1 ACME
schema*, use `scripts/migrate_acme_accounts.py` instead (`--dry-run` first): it
renames the old `Kid`/`Hmac_Key_Hash`/`Jwk_Thumbprint` columns, adds
`Name`/`Topdesk_Ticket`, drops the unused `Owner_Contact` and creates the ACME
tables.

Safe workflow against production: take a backup, review the plan, then apply.

    mysqldump --single-transaction --no-tablespaces cert_app > pre-change.sql   # contains data: chmod 600, never commit
    mysql cert_app < sql/schema.sql

To capture a schema baseline (no data) for comparison:

    mysqldump --no-data --skip-comments --skip-add-drop-table \
      --single-transaction --no-tablespaces cert_app > ddl-$(date +%F).sql


The ACME tables (`AcmeAccount` etc.) are part of `sql/schema.sql`.

**Atomic id-allocation table**

The app assigns integer primary keys itself (no AUTO_INCREMENT) for
`Certificate`, `ActiveCertificate`, `NotifyGroup`, and the ACME tables. To make
that race-free across the app's separate DB connections (web UI, ACME
finalize, and the scheduler), `sucm_db.claim_next_id()` bumps a per-table row
in `IdCounter` atomically (`INSERT ... ON DUPLICATE KEY UPDATE`), seeded from the
live table's `MAX(pk)` on first use.

**One-time ACME credential-reveal table**

When an ACME account is requested, its plaintext EAB HMAC key is shown to the
requester exactly once. To avoid round-tripping that secret through the
client-side session cookie, it is kept server-side (Fernet-encrypted) in
`AcmeRevealToken`, keyed by an unguessable one-time token that is deleted on first
read (`sucm_acme_reveal.py`); expired unconsumed tokens are pruned by the scheduler.

**ACME server (phase 2)**

The actual RFC 8555 ACME protocol endpoint lives at `/acme/...`
(`sucm/sucm_acme_server_routes.py`), separate from the human-facing account
portal at `/acme-accounts/...` (`sucm_acme_routes.py`). Key points:

  - Apache/Shibboleth does not gate `/acme/` at all (see the `<LocationMatch
    "^/acme/">` block above) - clients like certbot never send a Shibboleth
    session. All authentication/authorization is inside the app: every
    account-scoped request must be a valid JWS signed by the account's
    registered key, and `newAccount` requires a valid `externalAccountBinding`
    (HMAC-signed with the account's EAB secret, see `sucm_acme_crypto.py`).
  - Issuance is **trust-based, not real domain-control validation**: on
    `newOrder`, every requested identifier is checked against the account's
    admin-managed domain allow-list (`sucm_acme_account.py`,
    `is_domain_allowed`), and if all pass, authorizations (and their single
    challenge) are created already `valid` - no HTTP-01/DNS-01 challenge is
    ever actually fetched from the client. This was an explicit design
    decision for this internal-only tool; do not reuse this approach for
    anything facing untrusted clients.
  - `finalize` validates the CSR's identifier set against the order, then
    drives the same `SucmCertificate.submit_manual_csr()` /
    `renew_cert_with_csr()` pipeline a manually-submitted CSR would, using the
    CA/secret-path/notify-group read from the `[ACME]` section of
    `sucm_conf.ini` (`ca_plugin_name`/`secret_path`/`notify_group_id`, loaded by
    `_load_acme_config()` in `sucm_acme_order.py`). These are **required before
    production** - if `ca_plugin_name`/`secret_path` are unset, `finalize_order()`
    fails closed (serverInternal) rather than issuing into a default/test location.
  - Nonces are DB-backed (`AcmeNonce`), not in-memory, since the app can run
    as multiple WSGI processes/threads. `SucmAcmeNonce.consume()` is a single
    atomic conditional `DELETE` (checked by affected-row count), so a nonce is
    strictly single-use even under concurrent requests; `prune_expired()` runs
    from the scheduler so the table does not grow unboundedly.
  - The account's client JWK is bound on first `newAccount` via an atomic
    check-and-set (`UPDATE ... WHERE Jwk_Json IS NULL`), so two concurrent
    first registrations for the same EAB kid cannot overwrite each other's key.

