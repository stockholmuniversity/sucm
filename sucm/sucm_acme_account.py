import secrets
from datetime import datetime

from .sucm_acme_crypto import decrypt_secret, encrypt_secret
from .sucm_common import sucm_db

ACME_ACCOUNT_STATUSES = ["pending", "active", "disabled"]


class SucmAcmeAccount:
    """
    Manages ACME account requests and the (future) ACME server's account
    lookups.

    Accounts are created instantly in "pending" status by anyone who can
    reach the request form. The plaintext EAB hmac key is generated once,
    shown to the requester exactly once, and stored only in encrypted form
    (see sucm_acme_crypto) - it must still be recoverable (not merely
    verifiable) because RFC 8555 externalAccountBinding is HMAC-based: the
    server needs the raw shared secret to verify each newAccount signature,
    a hash alone would not work. An administrator must explicitly activate
    an account and assign its allowed domains before it can be used.

    An account's ACME client key (JWK) is bound on its first successful
    newAccount call and stored so subsequent "kid"-signed requests
    (identifying the account by its ACME account URL) can be verified.
    """

    def __init__(self, account_id=None):
        self.account_id = account_id

    @staticmethod
    def _generate_eab_kid():
        return "acct_" + secrets.token_urlsafe(24)

    @staticmethod
    def _generate_hmac_key():
        # base64url string, usable directly as ACME externalAccountBinding
        # HMAC key material (RFC 8555 section 7.3.4).
        return secrets.token_urlsafe(32)

    # Explicit column list (rather than SELECT *) so the row -> dict mapping
    # never depends on the table's physical column order. ALTER TABLE ADD
    # COLUMN (used by scripts/migrate_acme_accounts.py to add Name and
    # Topdesk_Ticket on already-deployed tables) appends new columns at the
    # end of the table, not wherever they were declared in the model -
    # relying on SELECT * silently scrambled these fields.
    _COLUMNS = (
        "Account_Id, Eab_Kid, Hmac_Key_Encrypted, Name, Topdesk_Ticket, "
        "Status, Jwk_Json, Requested_By, Create_Date, Activated_By, "
        "Activated_Date"
    )

    @staticmethod
    def _account_row_to_dict(row):
        return {
            "account_id": row[0],
            "eab_kid": row[1],
            "hmac_key_encrypted": row[2],
            "name": row[3],
            "topdesk_ticket": row[4],
            "status": row[5],
            "jwk_json": row[6],
            "requested_by": row[7],
            "create_date": row[8],
            "activated_by": row[9],
            "activated_date": row[10],
        }

    @staticmethod
    def _domain_row_to_dict(row):
        return {
            "domain_id": row[0],
            "account_id": row[1],
            "domain_pattern": row[2],
        }

    def get_next_account_id(self):
        return sucm_db.get_next_available_id("AcmeAccount")

    def create_account(self, name, topdesk_ticket, requested_by=None):
        """
        Creates a new pending AcmeAccount.

        `name` is a free-text friendly label for the account (shown in the
        admin panel). `topdesk_ticket` is a free-text TOPDESK ticket
        reference the admin uses to manually validate the request before
        activating it - it is not otherwise interpreted or enforced by
        the app.

        Returns (account_id, eab_kid, hmac_key) - the caller MUST show
        hmac_key to the requester immediately; it cannot be shown again
        (only the ACME server, with access to the app's config, can ever
        recover it afterwards).
        """
        account_id = self.get_next_account_id()
        eab_kid = self._generate_eab_kid()
        hmac_key = self._generate_hmac_key()

        account_data = {
            "Account_Id": account_id,
            "Eab_Kid": eab_kid,
            "Hmac_Key_Encrypted": encrypt_secret(hmac_key),
            "Name": name,
            "Topdesk_Ticket": topdesk_ticket,
            "Status": "pending",
            "Requested_By": requested_by,
            "Create_Date": datetime.now(),
        }
        sucm_db.add_update_record("AcmeAccount", account_data)
        self.account_id = account_id
        return account_id, eab_kid, hmac_key

    def get_all_accounts(self):
        rows = sucm_db.execute_select_query(f"SELECT {self._COLUMNS} FROM AcmeAccount")
        if not rows:
            return []
        return [self._account_row_to_dict(row) for row in rows]

    def get_account_detail(self, account_id=None):
        if account_id is None:
            account_id = self.account_id
        rows = sucm_db.execute_select_query(
            f"SELECT {self._COLUMNS} FROM AcmeAccount WHERE Account_Id = %s",
            (account_id,),
        )
        if not rows:
            return {}
        return self._account_row_to_dict(rows[0])

    def get_account_by_eab_kid(self, eab_kid):
        rows = sucm_db.execute_select_query(
            f"SELECT {self._COLUMNS} FROM AcmeAccount WHERE Eab_Kid = %s", (eab_kid,)
        )
        if not rows:
            return {}
        return self._account_row_to_dict(rows[0])

    def get_decrypted_hmac_key(self, account):
        """
        account: the dict returned by get_account_detail/get_account_by_eab_kid.
        """
        return decrypt_secret(account["hmac_key_encrypted"])

    def bind_jwk(self, account_id, jwk_json):
        sucm_db.execute_modify_query(
            "UPDATE AcmeAccount SET Jwk_Json = %s WHERE Account_Id = %s",
            (jwk_json, account_id),
        )

    def activate_account(self, account_id, activated_by):
        sucm_db.execute_modify_query(
            "UPDATE AcmeAccount SET Status = %s, Activated_By = %s, "
            "Activated_Date = %s WHERE Account_Id = %s",
            ("active", activated_by, datetime.now(), account_id),
        )

    def disable_account(self, account_id):
        sucm_db.execute_modify_query(
            "UPDATE AcmeAccount SET Status = %s WHERE Account_Id = %s",
            ("disabled", account_id),
        )

    def delete_account(self, account_id):
        sucm_db.remove_record("AcmeAccount", f"Account_Id = {int(account_id)}")

    # --- Domain allow-list ---

    def get_next_domain_id(self):
        return sucm_db.get_next_available_id("AcmeAccountDomain")

    def get_domains(self, account_id=None):
        if account_id is None:
            account_id = self.account_id
        rows = sucm_db.execute_select_query(
            "SELECT * FROM AcmeAccountDomain WHERE Account_Id = %s", (account_id,)
        )
        if not rows:
            return []
        return [self._domain_row_to_dict(row) for row in rows]

    def add_domain(self, account_id, domain_pattern):
        domain_id = self.get_next_domain_id()
        domain_data = {
            "Domain_Id": domain_id,
            "Account_Id": account_id,
            "Domain_Pattern": domain_pattern.strip().lower(),
        }
        sucm_db.add_update_record("AcmeAccountDomain", domain_data)
        return domain_id

    def remove_domain(self, domain_id):
        sucm_db.remove_record("AcmeAccountDomain", f"Domain_Id = {int(domain_id)}")

    @staticmethod
    def _pattern_matches(pattern, identifier_value):
        pattern = pattern.strip().lower()
        identifier_value = identifier_value.strip().lower()

        if pattern == identifier_value:
            return True

        if pattern.startswith("*."):
            suffix = pattern[2:]
            if identifier_value.endswith("." + suffix):
                label = identifier_value[: -(len(suffix) + 1)]
                # Wildcards only ever cover exactly one label, matching
                # normal CA/browser wildcard-cert semantics.
                return bool(label) and "." not in label

        return False

    def is_domain_allowed(self, account_id, identifier_value):
        domains = self.get_domains(account_id)
        return any(
            self._pattern_matches(d["domain_pattern"], identifier_value)
            for d in domains
        )
