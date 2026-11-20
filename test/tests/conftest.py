import pytest

from acme_tester.client import AcmeClient, AcmeProblem
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


@pytest.fixture(scope="session")
def _eab_verified(cfg):
    """Register once per run; a rejected EAB stops the run with one clear message instead of dozens of errors."""
    if not (cfg.eab_kid and cfg.eab_hmac_key and cfg.test_domain):
        return False
    try:
        AcmeClient(cfg.directory_url, verify=cfg.verify, key_file=cfg.account_key_file).new_account(
            cfg.eab_kid, cfg.eab_hmac_key
        )
    except AcmeProblem as exc:
        pytest.exit(
            f"ACME_EAB_KID/ACME_EAB_HMAC_KEY rejected by the server ({exc}). Request a new account in the portal, "
            "have it activated, update tester.env and delete account_key.pem in the state dir. See test/README.md.",
            returncode=2,
        )
    return True


@pytest.fixture
def need_eab(cfg, _eab_verified):
    if not _eab_verified:
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


@pytest.fixture
def issued_order(acct, cfg):
    """A valid, already-finalized order owned by the tester account (see README)."""
    if not cfg.issued_order_url:
        pytest.skip("no issued order known (run `just issue` once, or set ACME_ISSUED_ORDER_URL)")
    try:
        order = acct.get_order(cfg.issued_order_url)
    except AcmeProblem as exc:
        if exc.status == 404:
            pytest.skip("saved order does not belong to this account (run `just issue` once)")
        raise
    if order["status"] != "valid" or not order.get("certificate"):
        pytest.skip(f"issued order is not valid: {order.get('status')}")
    return order


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
