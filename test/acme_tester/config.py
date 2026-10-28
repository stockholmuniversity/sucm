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


@dataclass
class Config:
    directory_url: str
    eab_kid: str
    eab_hmac_key: str
    test_domain: str
    verify: object  # True / False / CA bundle path
    account_key_file: str

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
        )
