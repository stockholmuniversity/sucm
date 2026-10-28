"""Level 2: basic negative cases. None of these issue a certificate."""

import secrets

import pytest

from acme_tester.client import AcmeClient, AcmeProblem, b64, make_csr
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
