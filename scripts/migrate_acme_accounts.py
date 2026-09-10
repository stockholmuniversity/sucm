#!/usr/bin/env python3
"""
One-off DB migration for the ACME MITM layer.

Creates/updates all ACME-related tables (see README.md for the canonical
schema):
  - AcmeAccount / AcmeAccountDomain (account portal, phase 1)
  - AcmeNonce / AcmeOrder / AcmeAuthorization (ACME wire protocol server,
    phase 2)

Safe to re-run - uses CREATE TABLE IF NOT EXISTS, and column
renames/widenings are guarded by an information_schema check so they only
run once.

If AcmeAccount already exists from an earlier phase-1-only deployment (with
the old Kid/Hmac_Key_Hash/Jwk_Thumbprint columns), this script renames
those columns in place to Eab_Kid/Hmac_Key_Encrypted/Jwk_Json and widens
them to TEXT, since the EAB hmac key must now be recoverable (encrypted),
not just a one-way hash - see sucm_acme_crypto.py. NOTE: any pending
accounts created under the old schema will have their Hmac_Key_Encrypted
column contain a leftover SHA-256 hash, not a usable encrypted secret;
those accounts cannot be used and must be re-requested via the portal.

It also adds the Name/Topdesk_Ticket columns (friendly account label and a
TOPDESK ticket reference an admin uses to manually validate the request)
if missing, and drops the old Owner_Contact column (contact email is no
longer collected) if present.

Reads DB credentials from the same sucm_conf.ini used by the app itself
(the [mysql_connector] section) rather than the Python package, so it can
be run standalone before the app is (re)started - no Flask/hvac/acme
dependencies required, just mysql-connector-python.

Usage:
    python3 scripts/migrate_acme_accounts.py [--config PATH] [--dry-run]

By default, PATH is resolved the same way sucm_settings.py does it:
<current Python venv prefix>/conf/sucm_conf.ini - i.e. run this with the
same interpreter/venv the app uses (e.g. /local/cert-app's venv), or pass
--config explicitly.
"""

import argparse
import configparser
import os
import sys

TABLES = [
    (
        "AcmeAccount",
        """
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
        )
        """,
    ),
    (
        "AcmeAccountDomain",
        """
        CREATE TABLE IF NOT EXISTS AcmeAccountDomain (
            Domain_Id INT UNSIGNED NOT NULL,
            Account_Id INT UNSIGNED NOT NULL,
            Domain_Pattern VARCHAR(255) NOT NULL,
            PRIMARY KEY (Domain_Id),
            FOREIGN KEY (Account_Id) REFERENCES AcmeAccount(Account_Id)
                ON DELETE CASCADE
        )
        """,
    ),
    (
        "AcmeNonce",
        """
        CREATE TABLE IF NOT EXISTS AcmeNonce (
            Nonce VARCHAR(64) NOT NULL,
            Create_Date DATETIME NOT NULL,
            PRIMARY KEY (Nonce)
        )
        """,
    ),
    (
        "AcmeOrder",
        """
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
            FOREIGN KEY (Account_Id) REFERENCES AcmeAccount(Account_Id)
                ON DELETE CASCADE
        )
        """,
    ),
    (
        "AcmeAuthorization",
        """
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
            FOREIGN KEY (Order_Id) REFERENCES AcmeOrder(Order_Id)
                ON DELETE CASCADE
        )
        """,
    ),
]

# (table, old_column, new_column, new_column_definition) - only applied if
# the old column still exists (i.e. an earlier phase-1-only deployment).
COLUMN_RENAMES = [
    ("AcmeAccount", "Kid", "Eab_Kid", "VARCHAR(64) NOT NULL"),
    ("AcmeAccount", "Hmac_Key_Hash", "Hmac_Key_Encrypted", "TEXT NOT NULL"),
    ("AcmeAccount", "Jwk_Thumbprint", "Jwk_Json", "TEXT NULL"),
]

# (table, column, column_definition) - only added if the column is missing
# (i.e. an earlier deployment predating the Name/Topdesk_Ticket fields).
# Backfilled with empty string for any pre-existing rows.
COLUMN_ADDITIONS = [
    ("AcmeAccount", "Name", "VARCHAR(255) NOT NULL DEFAULT ''"),
    ("AcmeAccount", "Topdesk_Ticket", "VARCHAR(64) NOT NULL DEFAULT ''"),
]

# (table, column) - dropped if present. Owner_Contact/contact-email was
# replaced by Name + Topdesk_Ticket; no longer collected or used.
COLUMN_DROPS = [
    ("AcmeAccount", "Owner_Contact"),
]


def default_config_path():
    return os.path.join(sys.prefix, "conf", "sucm_conf.ini")


def load_db_config(config_path):
    if not os.path.isfile(config_path):
        print(f"Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    cfg = configparser.ConfigParser()
    cfg.read(config_path)

    if not cfg.has_section("mysql_connector"):
        print(
            f"[mysql_connector] section missing from {config_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    return {
        "host": cfg.get("mysql_connector", "host"),
        "database": cfg.get("mysql_connector", "database"),
        "user": cfg.get("mysql_connector", "user"),
        "password": cfg.get("mysql_connector", "password"),
    }


def table_exists(cursor, database, table):
    cursor.execute(
        "SELECT COUNT(*) FROM information_schema.TABLES "
        "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s",
        (database, table),
    )
    (count,) = cursor.fetchone()
    return count > 0


def column_exists(cursor, database, table, column):
    cursor.execute(
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s",
        (database, table, column),
    )
    (count,) = cursor.fetchone()
    return count > 0


def apply_column_renames(cursor, database):
    for table, old_column, new_column, new_definition in COLUMN_RENAMES:
        if not table_exists(cursor, database, table):
            continue
        if not column_exists(cursor, database, table, old_column):
            continue
        if column_exists(cursor, database, table, new_column):
            print(
                f"  (skip) {table}.{old_column} -> {new_column}: "
                f"both columns already exist, resolve manually"
            )
            continue
        ddl = f"ALTER TABLE {table} CHANGE COLUMN {old_column} {new_column} {new_definition}"
        print(f"  Renaming {table}.{old_column} -> {new_column} ...")
        cursor.execute(ddl)


def apply_column_additions(cursor, database):
    for table, column, definition in COLUMN_ADDITIONS:
        if not table_exists(cursor, database, table):
            continue
        if column_exists(cursor, database, table, column):
            continue
        ddl = f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        print(f"  Adding {table}.{column} ...")
        cursor.execute(ddl)


def apply_column_drops(cursor, database):
    for table, column in COLUMN_DROPS:
        if not table_exists(cursor, database, table):
            continue
        if not column_exists(cursor, database, table, column):
            continue
        ddl = f"ALTER TABLE {table} DROP COLUMN {column}"
        print(f"  Dropping {table}.{column} (no longer used) ...")
        cursor.execute(ddl)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        default=None,
        help="Path to sucm_conf.ini (default: <venv prefix>/conf/sucm_conf.ini)",
    )
    parser.add_argument(
        "--no-ssl",
        action="store_true",
        help="Disable TLS for the DB connection (matches SucmMysql defaults "
        "otherwise: SSL required, verified against system CA bundle).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the SQL that would run, without connecting to the DB.",
    )
    args = parser.parse_args()

    config_path = args.config or default_config_path()

    if args.dry_run:
        print(f"# Would read DB credentials from: {config_path}")
        for name, ddl in TABLES:
            print(f"-- {name}")
            print(ddl.strip() + ";\n")
        print("-- Column renames (applied only if the old column is present):")
        for table, old_column, new_column, new_definition in COLUMN_RENAMES:
            print(
                f"ALTER TABLE {table} CHANGE COLUMN {old_column} {new_column} "
                f"{new_definition};"
            )
        print("-- Column additions (applied only if the column is missing):")
        for table, column, definition in COLUMN_ADDITIONS:
            print(f"ALTER TABLE {table} ADD COLUMN {column} {definition};")
        print("-- Column drops (applied only if the column is present):")
        for table, column in COLUMN_DROPS:
            print(f"ALTER TABLE {table} DROP COLUMN {column};")
        return

    try:
        import mysql.connector
    except ImportError:
        print(
            "mysql-connector-python is required to run this script "
            "(it is already a project dependency; run inside the app's "
            "venv, e.g. 'poetry run python3 scripts/migrate_acme_accounts.py').",
            file=sys.stderr,
        )
        sys.exit(1)

    db_config = load_db_config(config_path)
    print(f"Using config: {config_path}")
    print(f"Connecting to {db_config['host']}/{db_config['database']} ...")

    connect_kwargs = {
        "host": db_config["host"],
        "database": db_config["database"],
        "user": db_config["user"],
        "password": db_config["password"],
        "port": 3306,
    }
    if not args.no_ssl:
        connect_kwargs["ssl_ca"] = "/etc/ssl/certs/ca-certificates.crt"
        connect_kwargs["ssl_verify_cert"] = True

    connection = mysql.connector.connect(**connect_kwargs)
    try:
        cursor = connection.cursor()

        print("Checking for old-schema columns to rename ...")
        apply_column_renames(cursor, db_config["database"])

        print("Checking for new columns to add ...")
        apply_column_additions(cursor, db_config["database"])

        print("Checking for obsolete columns to drop ...")
        apply_column_drops(cursor, db_config["database"])

        for name, ddl in TABLES:
            print(f"Creating table {name} (if not exists) ...")
            cursor.execute(ddl)

        connection.commit()
        print("Migration complete.")
    finally:
        connection.close()


if __name__ == "__main__":
    main()

