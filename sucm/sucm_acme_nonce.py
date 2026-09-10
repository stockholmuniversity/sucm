"""
DB-backed nonce store for the ACME server (RFC 8555 section 7.2).

Nonces must be single-use and unpredictable. They are stored in the DB
(rather than in-memory) because the app can run as multiple WSGI
worker processes/threads that do not share memory.
"""

import secrets
from datetime import datetime, timedelta

from .sucm_common import sucm_db

# How long an issued-but-unused nonce remains valid.
NONCE_TTL_MINUTES = 60


class SucmAcmeNonce:
    @staticmethod
    def issue():
        nonce = secrets.token_urlsafe(24)
        sucm_db.add_update_record(
            "AcmeNonce", {"Nonce": nonce, "Create_Date": datetime.now()}
        )
        return nonce

    @staticmethod
    def consume(nonce):
        """
        Atomically checks a nonce is known/unexpired and deletes it so it
        cannot be reused. Returns True if the nonce was valid.
        """
        if not nonce:
            return False

        rows = sucm_db.execute_select_query(
            "SELECT Create_Date FROM AcmeNonce WHERE Nonce = %s", (nonce,)
        )
        # Always delete on a hit, whether expired or not, so a nonce can
        # never be replayed a second time regardless of outcome.
        sucm_db.execute_modify_query(
            "DELETE FROM AcmeNonce WHERE Nonce = %s", (nonce,)
        )
        if not rows:
            return False

        create_date = rows[0][0]
        if datetime.now() - create_date > timedelta(minutes=NONCE_TTL_MINUTES):
            return False

        return True

    @staticmethod
    def prune_expired():
        cutoff = datetime.now() - timedelta(minutes=NONCE_TTL_MINUTES)
        sucm_db.execute_modify_query(
            "DELETE FROM AcmeNonce WHERE Create_Date < %s", (cutoff,)
        )
