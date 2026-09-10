import hashlib
import secrets
from datetime import datetime

from .sucm_common import sucm_db

ACME_ACCOUNT_STATUSES = ["pending", "active", "disabled"]


class SucmAcmeAccount:
    """
    Manages ACME account requests used for the (future) ACME front-end.

    Accounts are created instantly in "pending" status by anyone who can
    reach the request form. The plaintext EAB hmac key is generated once,
    returned to the caller, and never stored - only its SHA-256 hash is
    persisted so it can be verified (but not recovered) later by the ACME
    server. An administrator must explicitly activate an account and assign
    its allowed domains before it can be used to request certificates.
    """

    def __init__(self, account_id=None):
        self.account_id = account_id

    @staticmethod
    def _hash_hmac_key(hmac_key):
        return hashlib.sha256(hmac_key.encode("utf-8")).hexdigest()

    @staticmethod
    def _generate_kid():
        return "acct_" + secrets.token_urlsafe(24)

    @staticmethod
    def _generate_hmac_key():
        # base64url string, usable directly as ACME externalAccountBinding
        # HMAC key material (RFC 8555 section 7.3.4).
        return secrets.token_urlsafe(32)

    @staticmethod
    def _account_row_to_dict(row):
        return {
            "account_id": row[0],
            "kid": row[1],
            "hmac_key_hash": row[2],
            "owner_contact": row[3],
            "status": row[4],
            "jwk_thumbprint": row[5],
            "requested_by": row[6],
            "create_date": row[7],
            "activated_by": row[8],
            "activated_date": row[9],
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

    def create_account(self, owner_contact, requested_by=None):
        """
        Creates a new pending AcmeAccount.

        Returns (account_id, kid, hmac_key) - the caller MUST show hmac_key
        to the requester immediately; it cannot be retrieved again.
        """
        account_id = self.get_next_account_id()
        kid = self._generate_kid()
        hmac_key = self._generate_hmac_key()

        account_data = {
            "Account_Id": account_id,
            "Kid": kid,
            "Hmac_Key_Hash": self._hash_hmac_key(hmac_key),
            "Owner_Contact": owner_contact,
            "Status": "pending",
            "Requested_By": requested_by,
            "Create_Date": datetime.now(),
        }
        sucm_db.add_update_record("AcmeAccount", account_data)
        self.account_id = account_id
        return account_id, kid, hmac_key

    def get_all_accounts(self):
        rows = sucm_db.get_records("AcmeAccount")
        if not rows:
            return []
        return [self._account_row_to_dict(row) for row in rows]

    def get_account_detail(self, account_id=None):
        if account_id is None:
            account_id = self.account_id
        rows = sucm_db.execute_select_query(
            "SELECT * FROM AcmeAccount WHERE Account_Id = %s", (account_id,)
        )
        if not rows:
            return {}
        return self._account_row_to_dict(rows[0])

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
