"""Level 2: basic negative cases. None of these issue a certificate."""

import base64
import hashlib
import hmac
import json
import secrets

import pytest

from acme_tester.client import AcmeClient, AcmeProblem, b64, make_csr, unb64
from tests.conftest import assert_problem

pytestmark = pytest.mark.level2


def _order(client, identifiers):
    return client.post_raw(
        client.directory["newOrder"],
        client.sign(client.directory["newOrder"], {"identifiers": identifiers}),
    )


def _dns(*values):
    return [{"type": "dns", "value": v} for v in values]


def test_l2_02_domain_outside_allow_list(acct):
    resp = _order(acct, _dns(f"notallowed-{secrets.token_hex(4)}.example.org"))
    assert_problem(resp, "rejectedIdentifier")


def test_l2_03_wildcard_rejected_by_design(acct, cfg):
    resp = _order(acct, _dns("*." + cfg.test_domain))
    assert_problem(resp, "rejectedIdentifier")


def test_l2_04_unknown_eab_kid(cfg, client):
    with pytest.raises(AcmeProblem) as exc:
        client.new_account("acct_doesnotexist" + secrets.token_hex(4), cfg.eab_hmac_key)
    assert 400 <= exc.value.status < 500


def test_l2_05_eab_with_wrong_hmac(need_eab, cfg, client):
    # Fresh random account key: must never be able to bind the real kid.
    wrong_hmac = b64(secrets.token_bytes(32))
    with pytest.raises(AcmeProblem) as exc:
        client.new_account(cfg.eab_kid, wrong_hmac)
    assert 400 <= exc.value.status < 500


def test_l2_06_reused_nonce_is_bad_nonce(acct):
    url = acct.directory["newOrder"]
    nonce = acct.new_nonce()
    body = acct.sign(url, {"identifiers": _dns("x.example.org")}, nonce=nonce)
    first = acct.post_raw(url, body)  # rejected by allow-list, but nonce is consumed
    assert first.status_code != 500
    second = acct.post_raw(url, body)
    assert_problem(second, "badNonce")


def test_l2_07_invalid_nonce_is_bad_nonce(acct):
    url = acct.directory["newOrder"]
    body = acct.sign(url, {"identifiers": _dns("x.example.org")}, nonce="not-a-real-nonce")
    assert_problem(acct.post_raw(url, body), "badNonce")


def test_l2_08_finalize_with_mismatching_csr(acct, cfg):
    order_url, order = acct.new_order([cfg.test_domain])
    other = f"other-{secrets.token_hex(4)}.example.org"
    csr_der, _ = make_csr([other])
    resp = acct.post_raw(
        order["finalize"], acct.sign(order["finalize"], {"csr": b64(csr_der)})
    )
    assert_problem(resp, "badCSR")


def test_l2_10_empty_identifier_list(acct):
    resp = _order(acct, [])
    assert_problem(resp, "malformed")


def test_l2_10b_unsupported_identifier_type(acct):
    resp = _order(acct, [{"type": "ip", "value": "192.0.2.1"}])
    assert_problem(resp, "unsupportedIdentifier", "rejectedIdentifier", "malformed")


def test_l2_09_failed_finalize_is_retryable(acct, cfg):
    """A finalize that fails CSR validation leaves the order 'ready', so a
    client may retry with a corrected CSR (certbot does this). Re-finalize
    must not give orderNotReady here; only a *successful* finalize makes the
    order non-ready (see L2-09b)."""
    order_url, order = acct.new_order([cfg.test_domain])
    other = f"other-{secrets.token_hex(4)}.example.org"
    csr_der, _ = make_csr([other])
    resp = acct.post_raw(
        order["finalize"], acct.sign(order["finalize"], {"csr": b64(csr_der)})
    )
    assert_problem(resp, "badCSR")
    # Retry with the same (still wrong) CSR: order is still 'ready', so the
    # failure is again badCSR, not orderNotReady.
    resp = acct.post_raw(
        order["finalize"], acct.sign(order["finalize"], {"csr": b64(csr_der)})
    )
    assert_problem(resp, "badCSR")


def test_l2_09b_finalize_valid_order_again_is_order_not_ready(acct, cfg):
    """Re-finalizing an already-valid order must give orderNotReady (audit C2;
    this is what certbot does when it retries). Needs a previously issued order,
    see the 'order-url' option in tester.env / README."""
    order_url = cfg.issued_order_url
    if not order_url:
        pytest.skip("no issued order known (run `just issue` once, or set ACME_ISSUED_ORDER_URL)")
    order = acct.get_order(order_url)
    assert order["status"] == "valid", order
    csr_der, _ = make_csr([cfg.test_domain])
    resp = acct.post_raw(
        order["finalize"], acct.sign(order["finalize"], {"csr": b64(csr_der)})
    )
    assert_problem(resp, "orderNotReady")


# --- L2-12…15: EAB negative cases (audit B1-B4) --------------------------------
#
# These exercise the inner externalAccountBinding JWS of newAccount. Each test
# uses a fresh random account key, so any rejection must come from the EAB
# itself (an activated account binds its kid to the first key it sees, so the
# real kid must NOT be paired with a fresh key in a way that could succeed -
# all of these are expected to fail).


def _new_account_raw(client, payload):
    """POST a newAccount payload signed with the client's (fresh) key."""
    url = client.directory["newAccount"]
    return client.post_raw(url, client.sign(url, payload, use_jwk=True))


def _eab(client, cfg, kid=None, hmac_key=None, url=None, alg="HS256"):
    """Build an externalAccountBinding JWS with tweakable parts."""
    protected = {
        "alg": alg,
        "kid": kid if kid is not None else cfg.eab_kid,
        "url": url if url is not None else client.directory["newAccount"],
    }
    p64 = b64(json.dumps(protected).encode())
    payload64 = b64(json.dumps(client.jwk).encode())
    key = unb64(hmac_key if hmac_key is not None else cfg.eab_hmac_key)
    sig = hmac.new(
        key, f"{p64}.{payload64}".encode(), getattr(hashlib, f"sha{alg[2:]}")
    ).digest()
    return {"protected": p64, "payload": payload64, "signature": b64(sig)}


def test_l2_12_missing_eab_is_external_account_required(need_eab, cfg, client):
    """newAccount without externalAccountBinding -> externalAccountRequired (B1).
    The directory advertises externalAccountRequired: true, so the specific
    error type is part of the contract."""
    resp = _new_account_raw(client, {"termsOfServiceAgreed": True})
    assert_problem(resp, "externalAccountRequired")


def test_l2_13_eab_with_wrong_url(need_eab, cfg, client):
    """EAB whose inner 'url' is not the newAccount URL -> rejected (B2)."""
    eab = _eab(client, cfg, url=client.directory["newOrder"])
    resp = _new_account_raw(
        client, {"termsOfServiceAgreed": True, "externalAccountBinding": eab}
    )
    assert_problem(resp, "unauthorized", "malformed")


@pytest.mark.parametrize("alg", ["HS384", "HS512"])
def test_l2_14_eab_with_wrong_alg(need_eab, cfg, client, alg):
    """EAB signed with HS384/HS512 -> rejected (B3). verify_signature()
    supports them, but SUPPORTED_EAB_ALGS only allows HS256."""
    eab = _eab(client, cfg, alg=alg)
    resp = _new_account_raw(
        client, {"termsOfServiceAgreed": True, "externalAccountBinding": eab}
    )
    assert_problem(resp, "unauthorized", "malformed")


def test_l2_15_eab_wrong_hmac_isolated(need_eab, cfg, client):
    """Wrong HMAC with everything else correct -> rejected because of the
    signature, not key binding (B4). The account key is fresh, but the EAB
    itself is invalid, so the failure must be the HMAC."""
    eab = _eab(client, cfg, hmac_key=b64(secrets.token_bytes(32)))
    resp = _new_account_raw(
        client, {"termsOfServiceAgreed": True, "externalAccountBinding": eab}
    )
    assert_problem(resp, "unauthorized", "malformed")


# --- C4 / C5: multi-identifier orders and identifier normalization ----------


def test_c4_multi_identifier_order(acct, cfg):
    """An order with two allowed identifiers creates two authorizations (C4).
    This is the normal certbot flow for a SAN certificate."""
    second = f"second-{secrets.token_hex(4)}.{cfg.test_domain}"
    # Both names must be on the allow-list; if the second one is not, the
    # whole order is rejected with rejectedIdentifier (which is also a pass).
    resp = _order(acct, _dns(cfg.test_domain, second))
    if resp.status_code == 201:
        order = resp.json()
        assert len(order["authorizations"]) == 2, order
    else:
        assert_problem(resp, "rejectedIdentifier")


def test_c5_uppercase_identifier(acct, cfg):
    """An uppercase identifier is normalized for the allow-list check (C5).
    The stored authz keeps the original case; the finalize CSR check compares
    lowercased names."""
    upper = cfg.test_domain.upper()
    resp = _order(acct, _dns(upper))
    assert resp.status_code == 201, resp.text
    order = resp.json()
    assert order["identifiers"][0]["value"] == upper  # stored as sent
    authz_url = order["authorizations"][0]
    authz = acct.post(authz_url, None).json()
    assert authz["identifier"]["value"] == upper  # authz keeps case too


def test_c5_trailing_dot_rejected(acct, cfg):
    """An FQDN with a trailing dot is not the same identifier and must be
    rejected (C5)."""
    resp = _order(acct, _dns(cfg.test_domain + "."))
    assert_problem(resp, "rejectedIdentifier")


@pytest.mark.xfail(reason="F17: duplicate identifiers create duplicate authzs", strict=True)
def test_l2_16_duplicate_identifiers_rejected(acct, cfg):
    """The same identifier twice in one order must be deduplicated or
    rejected (F17) - today it creates two duplicate authorizations."""
    resp = _order(acct, _dns(cfg.test_domain, cfg.test_domain))
    if resp.status_code == 201:
        order = resp.json()
        assert len(order["authorizations"]) == 1, order
    else:
        assert_problem(resp, "malformed", "rejectedIdentifier")
