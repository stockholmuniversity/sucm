"""
Server-side one-time reveal store for newly created ACME account credentials.

When a user requests an ACME account, the plaintext EAB HMAC key must be shown
to them exactly once (it is otherwise stored only Fernet-encrypted, since the
ACME server needs the raw secret to verify externalAccountBinding - see
sucm_acme_account.py). Previously that plaintext round-tripped through the
client-side session cookie (Flask's default cookie is signed, not encrypted),
which left the secret base64-readable in the browser (and any cookie store /
proxy log) until the /created page was visited - indefinitely if it never was.

Instead we stash the encrypted key server-side in the AcmeRevealToken table,
keyed by an unguessable one-time token, and put only that (non-secret) token
in the session. /created consumes the token (deletes the row) on first read,
so the plaintext is revealed exactly once. Expired, unconsumed tokens are
pruned by the scheduler via prune_expired().
"""

import secrets
from datetime import datetime, timedelta

from .sucm_acme_crypto import decrypt_secret, encrypt_secret
from .sucm_common import sucm_db

# How long an unclaimed reveal token stays valid before it is treated as
# expired (and pruned). Long enough for a user to click through the redirect,
# short enough that a forgotten token does not linger.
REVEAL_TTL_MINUTES = 15


class SucmAcmeRevealToken:
    @staticmethod
    def create(account_id, hmac_key):
        """
        Store the plaintext EAB HMAC key (Fernet-encrypted) keyed by a fresh
        one-time token. Returns the token to stash in the session.
        """
        token = secrets.token_urlsafe(32)
        sucm_db.add_update_record(
            "AcmeRevealToken",
            {
                "Token": token,
                "Account_Id": account_id,
                "Hmac_Key_Encrypted": encrypt_secret(hmac_key),
                "Create_Date": datetime.now(),
            },
        )
        return token

    @staticmethod
    def consume(token):
        """
        Atomically consume a reveal token: returns (account_id, hmac_key) on
        first valid use, None otherwise (unknown, expired, or already used).
        The row is always deleted on a hit - even if expired - so a token is
        strictly single-use.
        """
        if not token:
            return None

        rows = sucm_db.execute_select_query(
            "SELECT Account_Id, Hmac_Key_Encrypted, Create_Date "
            "FROM AcmeRevealToken WHERE Token = %s",
            (token,),
        )
        # Delete on any hit so the token can never be replayed, regardless of
        # whether it turns out to be expired.
        sucm_db.execute_modify_query(
            "DELETE FROM AcmeRevealToken WHERE Token = %s", (token,)
        )
        if not rows:
            return None

        account_id, hmac_key_encrypted, create_date = rows[0]
        if datetime.now() - create_date > timedelta(minutes=REVEAL_TTL_MINUTES):
            return None

        return account_id, decrypt_secret(hmac_key_encrypted)

    @staticmethod
    def prune_expired():
        cutoff = datetime.now() - timedelta(minutes=REVEAL_TTL_MINUTES)
        sucm_db.execute_modify_query(
            "DELETE FROM AcmeRevealToken WHERE Create_Date < %s", (cutoff,)
        )
