import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from .sucm_settings import cfg


def _fernet():
    """
    Derives a stable 32-byte Fernet key from the app's existing SUCM
    secret_key config value, so no new secret needs to be provisioned/
    rotated separately just for this. Anyone with sucm_conf.ini already
    has enough to impersonate sessions, so this doesn't lower the bar.
    """
    secret = cfg.get("SUCM", "secret_key").encode("utf-8")
    derived = hashlib.sha256(secret).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_secret(plaintext):
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext):
    try:
        return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Could not decrypt stored secret") from exc
