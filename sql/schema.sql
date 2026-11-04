-- SUCM database schema (baseline = production as dumped 2026-11-03, see
-- docs/sucm-prod-ddl-2026-11-03.sql).
--
-- Idempotent and additive only: every statement is CREATE TABLE IF NOT EXISTS /
-- INSERT IGNORE, so it never alters or deletes anything that already exists.
-- Running it against a populated database only adds missing tables.
--
-- Usage (empty database created with the right character set, see README):
--   mysql cert_app < sql/schema.sql
--
-- Upgrading an older database that already has the ACME tables from an earlier
-- version? Use scripts/migrate_acme_accounts.py, which also renames/adds columns.
-- Primary keys are allocated by the application (no AUTO_INCREMENT); see
-- sucm_db.claim_next_id() and the IdCounter table below.

-- ---------------------------------------------------------------------------
-- Core certificate tables
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS CertificateAuthority (
    CA_Id INT UNSIGNED NOT NULL,
    CA_Name TEXT NOT NULL,
    Auth_Method TEXT NOT NULL,
    PRIMARY KEY (CA_Id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS Certificate (
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
    Secret_Path TEXT NULL,
    Notify_Group_Id INT NULL,
    Create_Date DATE NULL,
    Expiry_Date DATE NULL,
    Cert_Id_Harica TEXT NULL,
    PRIMARY KEY (Cert_Id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ActiveCertificate (
    ActiveCertificate_Id INT UNSIGNED NOT NULL,
    Cert_Id INT NOT NULL,
    Common_Name TEXT NOT NULL,
    Cert_PEM TEXT NOT NULL,
    Create_Date DATE NULL,
    Expiry_Date DATE NULL,
    Cert_Id_Harica TEXT NULL,
    PRIMARY KEY (ActiveCertificate_Id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS NotifyGroup (
    Group_Id INT UNSIGNED NOT NULL,
    Group_Name TEXT NOT NULL,
    Email_CSV TEXT NOT NULL,
    PRIMARY KEY (Group_Id)
) ENGINE=InnoDB;

-- Atomic primary-key allocation (sucm_db.claim_next_id()). Rows are created
-- on first use, seeded from the live table's MAX(pk), so this table is left empty.
CREATE TABLE IF NOT EXISTS IdCounter (
    name VARCHAR(64) NOT NULL,
    value INT UNSIGNED NOT NULL,
    PRIMARY KEY (name)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- ACME MITM layer
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS AcmeAccount (
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
    UNIQUE KEY uq_acmeaccount_eab_kid (Eab_Kid)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS AcmeAccountDomain (
    Domain_Id INT UNSIGNED NOT NULL,
    Account_Id INT UNSIGNED NOT NULL,
    Domain_Pattern VARCHAR(255) NOT NULL,
    PRIMARY KEY (Domain_Id),
    FOREIGN KEY (Account_Id) REFERENCES AcmeAccount(Account_Id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS AcmeNonce (
    Nonce VARCHAR(64) NOT NULL,
    Create_Date DATETIME NOT NULL,
    PRIMARY KEY (Nonce)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS AcmeOrder (
    Order_Id INT UNSIGNED NOT NULL,
    Account_Id INT UNSIGNED NOT NULL,
    Status TEXT NOT NULL,
    Identifiers TEXT NOT NULL,
    Cert_Id INT UNSIGNED NULL,
    Expires DATETIME NOT NULL,
    Create_Date DATETIME NOT NULL,
    Error TEXT NULL,
    PRIMARY KEY (Order_Id),
    FOREIGN KEY (Account_Id) REFERENCES AcmeAccount(Account_Id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS AcmeAuthorization (
    Authz_Id INT UNSIGNED NOT NULL,
    Order_Id INT UNSIGNED NOT NULL,
    Identifier_Type VARCHAR(16) NOT NULL,
    Identifier_Value VARCHAR(255) NOT NULL,
    Status TEXT NOT NULL,
    Challenge_Token VARCHAR(64) NOT NULL,
    Challenge_Status TEXT NOT NULL,
    Expires DATETIME NOT NULL,
    PRIMARY KEY (Authz_Id),
    FOREIGN KEY (Order_Id) REFERENCES AcmeOrder(Order_Id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- One-time server-side store for the EAB HMAC key reveal (sucm_acme_reveal.py).
CREATE TABLE IF NOT EXISTS AcmeRevealToken (
    Token VARCHAR(64) NOT NULL,
    Account_Id INT UNSIGNED NOT NULL,
    Hmac_Key_Encrypted TEXT NOT NULL,
    Create_Date DATETIME NOT NULL,
    PRIMARY KEY (Token),
    FOREIGN KEY (Account_Id) REFERENCES AcmeAccount(Account_Id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Reference data (matches the test database; INSERT IGNORE never overwrites)
-- ---------------------------------------------------------------------------

INSERT IGNORE INTO CertificateAuthority (CA_Id, CA_Name, Auth_Method) VALUES
    (1, 'Sectigo', 'EAB'),
    (2, 'Dummy CA', 'Returns Snakeoil'),
    (3, 'Harica', 'EAB');
