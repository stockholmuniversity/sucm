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

**Create db tables**

    CREATE TABLE CertificateAuthority (
    CA_Id INT UNSIGNED NOT NULL,
    CA_Name TEXT NOT NULL,
    Auth_Method TEXT NOT NULL,
    PRIMARY KEY (CA_Id));
    
    INSERT INTO CertificateAuthority (CA_Id, CA_Name, Auth_Method)
    VALUES
    ('1', 'Sectigo', 'EAB'),
    ('2', 'Dummy CA', 'Returns Snakeoil');
    
    CREATE TABLE Certificate(
    Cert_Id INT UNSIGNED NOT NULL,
    CA_Id INT NOT NULL,
    Common_Name TEXT NOT NULL,
    Subject_Alt TEXT NOT NULL,
    Country TEXT NOT NULL,
    State TEXT NOT NULL,
    City TEXT NOT NULL,
    Org TEXT NOT NULL,
    Status TEXT NOT NULL,
    Type TEXT NOT NULL,
    Secret_Path TEXT NOT NULL,
    Notify_Group_Id INT NULL,
    Create_Date DATE NULL,
    Expiry_Date DATE NULL,
    PRIMARY KEY (Cert_Id));
    
    CREATE TABLE ActiveCertificate(
    ActiveCertificate_Id INT UNSIGNED NOT NULL,
    Cert_Id INT NOT NULL,
    Common_Name TEXT NOT NULL,
    Cert_PEM TEXT NOT NULL,
    Create_Date DATE NULL,
    Expiry_Date DATE NULL,
    PRIMARY KEY (ActiveCertificate_Id));
    
    CREATE TABLE NotifyGroup(
    Group_Id INT UNSIGNED NOT NULL,
    Group_Name TEXT NOT NULL,
    Email_CSV TEXT NOT NULL,
    PRIMARY KEY (Group_Id));

**ACME MITM layer - account/domain tables (phase 1) + ACME server tables (phase 2)**

*(Apply with `scripts/migrate_acme_accounts.py` instead of running this SQL by
hand - see the script's `--help`/`--dry-run` for details. Statements below are
kept here as the canonical schema reference. If you already ran an earlier
version of this script, re-run it - it renames the old
Kid/Hmac_Key_Hash/Jwk_Thumbprint columns, adds Name/Topdesk_Ticket, and drops
the unused Owner_Contact column in place.)*

    CREATE TABLE AcmeAccount(
    Account_Id INT UNSIGNED NOT NULL,
    Eab_Kid VARCHAR(64) NOT NULL,
    Hmac_Key_Encrypted TEXT NOT NULL,
    Name VARCHAR(255) NOT NULL,
    Topdesk_Ticket VARCHAR(64) NOT NULL,
    Status TEXT NOT NULL,
    Jwk_Json TEXT NULL,
    Requested_By VARCHAR(255) NULL,
    Create_Date DATETIME NULL,
    Activated_By VARCHAR(255) NULL,
    Activated_Date DATETIME NULL,
    PRIMARY KEY (Account_Id),
    UNIQUE KEY uq_acmeaccount_eab_kid (Eab_Kid));

    CREATE TABLE AcmeAccountDomain(
    Domain_Id INT UNSIGNED NOT NULL,
    Account_Id INT UNSIGNED NOT NULL,
    Domain_Pattern VARCHAR(255) NOT NULL,
    PRIMARY KEY (Domain_Id),
    FOREIGN KEY (Account_Id) REFERENCES AcmeAccount(Account_Id) ON DELETE CASCADE);

    CREATE TABLE AcmeNonce(
    Nonce VARCHAR(64) NOT NULL,
    Create_Date DATETIME NOT NULL,
    PRIMARY KEY (Nonce));

    CREATE TABLE AcmeOrder(
    Order_Id INT UNSIGNED NOT NULL,
    Account_Id INT UNSIGNED NOT NULL,
    Status TEXT NOT NULL,
    Identifiers TEXT NOT NULL,
    Cert_Id INT UNSIGNED NULL,
    Expires DATETIME NOT NULL,
    Create_Date DATETIME NOT NULL,
    Error TEXT NULL,
    PRIMARY KEY (Order_Id),
    FOREIGN KEY (Account_Id) REFERENCES AcmeAccount(Account_Id) ON DELETE CASCADE);

    CREATE TABLE AcmeAuthorization(
    Authz_Id INT UNSIGNED NOT NULL,
    Order_Id INT UNSIGNED NOT NULL,
    Identifier_Type VARCHAR(16) NOT NULL,
    Identifier_Value VARCHAR(255) NOT NULL,
    Status TEXT NOT NULL,
    Challenge_Token VARCHAR(64) NOT NULL,
    Challenge_Status TEXT NOT NULL,
    Expires DATETIME NOT NULL,
    PRIMARY KEY (Authz_Id),
    FOREIGN KEY (Order_Id) REFERENCES AcmeOrder(Order_Id) ON DELETE CASCADE);

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
    `renew_cert_with_csr()` pipeline a manually-submitted CSR would, using a
    fixed CA/secret-path/notify-group (`sucm_acme_order.py`'s
    `ACME_CA_PLUGIN_NAME`/`ACME_SECRET_PATH`/`ACME_NOTIFY_GROUP_ID` - update
    these directly in that file if the target CA or Vault path changes).
  - Nonces are DB-backed (`AcmeNonce`), not in-memory, since the app can run
    as multiple WSGI processes/threads.

