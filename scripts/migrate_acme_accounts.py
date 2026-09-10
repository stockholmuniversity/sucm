#!/usr/bin/env python3
"""
One-off DB migration for the ACME MITM layer, phase 1 (account portal).

Creates the AcmeAccount and AcmeAccountDomain tables (see README.md for the
canonical schema). Safe to re-run - uses CREATE TABLE IF NOT EXISTS.

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
            Kid VARCHAR(64) NOT NULL,
            Hmac_Key_Hash CHAR(64) NOT NULL,
            Owner_Contact VARCHAR(255) NOT NULL,
            Status TEXT NOT NULL,
            Jwk_Thumbprint VARCHAR(255) NULL,
            Requested_By VARCHAR(255) NULL,
            Create_Date DATETIME NULL,
            Activated_By VARCHAR(255) NULL,
            Activated_Date DATETIME NULL,
            PRIMARY KEY (Account_Id),
            UNIQUE KEY uq_acmeaccount_kid (Kid)
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
        for name, ddl in TABLES:
            print(f"Creating table {name} (if not exists) ...")
            cursor.execute(ddl)
        connection.commit()
        print("Migration complete.")
    finally:
        connection.close()


if __name__ == "__main__":
    main()
