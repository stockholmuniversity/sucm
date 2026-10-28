import os
from dataclasses import dataclass

STATE_DIR = os.path.expanduser(
    os.environ.get("ACME_STATE_DIR", "~/.config/sucm-acme-tester")
)


def load_state_env():
    """Load KEY=VALUE lines from <state dir>/tester.env without overriding the environment.

    Credentials and account keys live outside the repo, in the state dir.
    """
    path = os.path.join(STATE_DIR, "tester.env")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


LAST_ORDER_FILE = os.path.join(STATE_DIR, "last_order_url")


def read_last_order_url():
    """URL of the most recent order that reached 'valid' (written by the
    issuance flow). Fallback for ACME_ISSUED_ORDER_URL so the cross-account
    and re-finalize tests work without a manual step after `just issue`."""
    try:
        with open(LAST_ORDER_FILE, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def write_last_order_url(url):
    fd = os.open(LAST_ORDER_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(url + "\n")


@dataclass
class Config:
    directory_url: str
    eab_kid: str
    eab_hmac_key: str
    test_domain: str
    verify: object  # True / False / CA bundle path
    account_key_file: str
    eab_kid2: str = ""
    eab_hmac_key2: str = ""
    account_key_file2: str = ""
    issued_order_url: str = ""
    disabled_kid: str = ""
    disabled_hmac_key: str = ""
    disabled_account_key_file: str = ""

    @classmethod
    def from_env(cls):
        load_state_env()
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        verify = os.environ.get("ACME_TLS_VERIFY", "true")
        if verify.lower() == "true":
            verify = True
        elif verify.lower() == "false":
            verify = False
        return cls(
            directory_url=os.environ.get("ACME_DIRECTORY", ""),
            eab_kid=os.environ.get("ACME_EAB_KID", ""),
            eab_hmac_key=os.environ.get("ACME_EAB_HMAC_KEY", ""),
            test_domain=os.environ.get("ACME_TEST_DOMAIN", ""),
            verify=verify,
            account_key_file=os.environ.get(
                "ACME_ACCOUNT_KEY", os.path.join(STATE_DIR, "account_key.pem")
            ),
            eab_kid2=os.environ.get("ACME_EAB_KID_2", ""),
            eab_hmac_key2=os.environ.get("ACME_EAB_HMAC_KEY_2", ""),
            account_key_file2=os.environ.get(
                "ACME_ACCOUNT_KEY_2", os.path.join(STATE_DIR, "account_key_2.pem")
            ),
            issued_order_url=os.environ.get(
                "ACME_ISSUED_ORDER_URL", read_last_order_url()
            ),
            disabled_kid=os.environ.get("ACME_DISABLED_KID", ""),
            disabled_hmac_key=os.environ.get("ACME_DISABLED_HMAC_KEY", ""),
            disabled_account_key_file=os.environ.get(
                "ACME_DISABLED_ACCOUNT_KEY",
                os.path.join(STATE_DIR, "disabled_account_key.pem"),
            ),
        )
