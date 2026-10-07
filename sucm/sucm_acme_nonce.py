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
        Atomically consumes a nonce, returning True iff it was valid.

        Implemented as a single conditional DELETE: the row is removed only if
        it exists AND is still within its TTL, and the affected-row count tells
        us which. Because the delete is one statement, two concurrent requests
        presenting the same nonce cannot both succeed - whoever's DELETE commits
        first wins and the other sees 0 rows (the previous SELECT-then-DELETE
        left a replay window between the two queries). A nonce is single-use
        whether it was valid or already expired.
        """
        if not nonce:
            return False

        cutoff = datetime.now() - timedelta(minutes=NONCE_TTL_MINUTES)
        deleted = sucm_db.execute_modify_rows(
            "DELETE FROM AcmeNonce WHERE Nonce = %s AND Create_Date >= %s",
            (nonce, cutoff),
        )
        if deleted == 1:
            return True

        # 0 rows: either the nonce never existed, or it existed but was expired.
        # Clean up a possibly-expired leftover so the table doesn't accumulate
        # dead nonces (a no-op if it never existed).
        sucm_db.execute_modify_query("DELETE FROM AcmeNonce WHERE Nonce = %s", (nonce,))
        return False

    @staticmethod
    def prune_expired():
        cutoff = datetime.now() - timedelta(minutes=NONCE_TTL_MINUTES)
        sucm_db.execute_modify_query(
            "DELETE FROM AcmeNonce WHERE Create_Date < %s", (cutoff,)
        )
