import pytest

from acme_tester.client import AcmeClient
from acme_tester.config import Config


@pytest.fixture(scope="session")
def cfg():
    c = Config.from_env()
    if not c.directory_url:
        pytest.skip("ACME_DIRECTORY not set (see tester.env.example)")
    return c


@pytest.fixture
def client(cfg):
    return AcmeClient(cfg.directory_url, verify=cfg.verify)


@pytest.fixture
def need_eab(cfg):
    if not (cfg.eab_kid and cfg.eab_hmac_key and cfg.test_domain):
        pytest.skip("ACME_EAB_KID / ACME_EAB_HMAC_KEY / ACME_TEST_DOMAIN not set")
    return cfg


@pytest.fixture
def acct(need_eab, cfg):
    """Client registered with the persisted account key (existing account is reused)."""
    c = AcmeClient(cfg.directory_url, verify=cfg.verify, key_file=cfg.account_key_file)
    c.new_account(cfg.eab_kid, cfg.eab_hmac_key)
    return c


@pytest.fixture
def acct2(cfg):
    """Client for a second, independent account (isolation tests); skipped if not configured."""
    if not (cfg.eab_kid2 and cfg.eab_hmac_key2):
        pytest.skip("ACME_EAB_KID_2 / ACME_EAB_HMAC_KEY_2 not set (second account needed)")
    c = AcmeClient(cfg.directory_url, verify=cfg.verify, key_file=cfg.account_key_file2)
    c.new_account(cfg.eab_kid2, cfg.eab_hmac_key2)
    return c


def assert_problem(resp, *types, status=None):
    """Assert an ACME problem document; `types` are short names like 'badNonce'."""
    assert 400 <= resp.status_code < 500, f"{resp.status_code}: {resp.text[:300]}"
    if status:
        assert resp.status_code == status
    body = resp.json()
    if types:
        want = ["urn:ietf:params:acme:error:" + t for t in types]
        assert body.get("type") in want, body
    return body
