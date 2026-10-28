"""Level 3 (no-issuance subset): malformed/hostile requests must give a 4xx problem, never a 500."""

import json
import secrets

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acme_tester.client import b64
from tests.conftest import assert_problem

pytestmark = pytest.mark.level3

NEW_ORDER_PAYLOAD = {"identifiers": [{"type": "dns", "value": "x.example.org"}]}


def _url(acct):
    return acct.directory["newOrder"]


def test_l3_05_tampered_signature(acct):
    body = acct.sign(_url(acct), NEW_ORDER_PAYLOAD)
    sig = bytearray(__import__("base64").urlsafe_b64decode(body["signature"] + "=="))
    sig[0] ^= 0xFF
    body["signature"] = __import__("base64").urlsafe_b64encode(bytes(sig)).rstrip(b"=").decode()
    assert_problem(acct.post_raw(_url(acct), body))


def test_l3_06_url_header_mismatch(acct):
    other = acct.directory["newAccount"]
    body = acct.sign(other, NEW_ORDER_PAYLOAD)  # signed for another URL
    assert_problem(acct.post_raw(_url(acct), body), "malformed", "unauthorized")


def test_l3_07_both_jwk_and_kid(acct):
    body = acct.sign(_url(acct), NEW_ORDER_PAYLOAD, extra_protected={"jwk": acct.jwk})
    assert_problem(acct.post_raw(_url(acct), body), "malformed")


@pytest.mark.parametrize("alg", ["none", "HS256", "RS256"])
def test_l3_08_unsupported_or_wrong_alg(acct, alg):
    body = acct.sign(_url(acct), NEW_ORDER_PAYLOAD, extra_protected={"alg": alg})
    assert_problem(acct.post_raw(_url(acct), body))


def test_l3_08b_missing_alg_nonce_url(acct):
    import base64

    protected = base64.urlsafe_b64encode(json.dumps({"kid": acct.kid}).encode()).rstrip(b"=")
    body = {"protected": protected.decode(), "payload": "", "signature": "AAAA"}
    assert_problem(acct.post_raw(_url(acct), body))


@pytest.mark.parametrize(
    "data",
    ["not json", "", "[]", "{}", '{"protected": 1}'],
    ids=["text", "empty", "list", "emptyobj", "badfields"],
)
def test_l3_09_garbage_body(acct, data):
    resp = acct.http.post(
        _url(acct),
        data=data,
        headers={"Content-Type": "application/jose+json"},
        verify=acct.verify,
        timeout=30,
    )
    assert 400 <= resp.status_code < 500, f"{resp.status_code}: {resp.text[:200]}"


def test_l3_09b_wrong_content_type(acct):
    body = acct.sign(_url(acct), NEW_ORDER_PAYLOAD)
    resp = acct.http.post(
        _url(acct),
        data=json.dumps(body),
        headers={"Content-Type": "text/plain"},
        verify=acct.verify,
        timeout=30,
    )
    assert 400 <= resp.status_code < 500, f"{resp.status_code}: {resp.text[:200]}"


def test_l3_10_oversized_body(acct):
    resp = acct.http.post(
        _url(acct),
        data="A" * (5 * 1024 * 1024),
        headers={"Content-Type": "application/jose+json"},
        verify=acct.verify,
        timeout=60,
    )
    assert 400 <= resp.status_code < 500, resp.status_code


@pytest.mark.parametrize(
    "value",
    ["x' OR '1'='1", "a.example.org'; DROP TABLE AcmeOrder;--", "a" * 5000 + ".example.org", "x\r\nBcc: a@b.c"],
    ids=["sqli-or", "sqli-drop", "very-long", "crlf"],
)
def test_l3_11_hostile_identifier(acct, value):
    resp = acct.post_raw(
        _url(acct),
        acct.sign(_url(acct), {"identifiers": [{"type": "dns", "value": value}]}),
    )
    assert 400 <= resp.status_code < 500, f"{resp.status_code}: {resp.text[:200]}"


def test_l3_12_eab_already_bound_to_other_key(need_eab, cfg, client):
    from acme_tester.client import AcmeProblem

    with pytest.raises(AcmeProblem) as exc:
        client.new_account(cfg.eab_kid, cfg.eab_hmac_key)  # fresh random key
    assert exc.value.status in (400, 403)
    assert "unauthorized" in exc.value.type or "malformed" in exc.value.type


# --- L3-01: cross-account isolation (needs a second account, see tester.env.example) ---


@pytest.fixture
def foreign_order(acct, cfg):
    """An order owned by account A (never finalized, nothing is issued)."""
    url, order = acct.new_order([cfg.test_domain])
    return url, order


def test_l3_01a_other_account_cannot_read_order(acct2, foreign_order):
    url, _ = foreign_order
    assert_problem(acct2.post_raw(url, acct2.sign(url, None)), "unauthorized", "malformed")


def test_l3_01b_other_account_cannot_read_authz(acct2, foreign_order):
    _, order = foreign_order
    url = order["authorizations"][0]
    assert_problem(acct2.post_raw(url, acct2.sign(url, None)), "unauthorized", "malformed")


def test_l3_01c_other_account_cannot_finalize(acct2, foreign_order, cfg):
    from acme_tester.client import make_csr

    _, order = foreign_order
    url = order["finalize"]
    body = acct2.sign(url, {"csr": b64(make_csr([cfg.test_domain])[0])})
    assert_problem(acct2.post_raw(url, body), "unauthorized", "malformed")


# --- L3-01d / L3-03: certificate download and revocation across accounts ----
#
# These need a previously issued, valid order (saved by `just issue`, or
# ACME_ISSUED_ORDER_URL) so they can verify that the certificate download and
# revocation endpoints apply the same account-ownership checks as the order
# endpoints. They do not issue a new certificate themselves.


@pytest.fixture
def issued_order(acct, cfg):
    """A valid, already-finalized order owned by account A (see README)."""
    if not cfg.issued_order_url:
        pytest.skip("no issued order known (run `just issue` once, or set ACME_ISSUED_ORDER_URL)")
    order = acct.get_order(cfg.issued_order_url)
    if order["status"] != "valid" or not order.get("certificate"):
        pytest.skip(f"issued order is not valid: {order.get('status')}")
    return order


def test_l3_01d_other_account_cannot_download_cert(acct2, issued_order):
    """Account B must not be able to download account A's certificate (L3-01)."""
    url = issued_order["certificate"]
    assert_problem(acct2.post_raw(url, acct2.sign(url, None)), "unauthorized", "malformed")


def test_l3_03_other_account_cannot_revoke_cert(acct, acct2, cfg, issued_order):
    """Account B must not be able to revoke a certificate in account A's
    namespace (L3-03). A self-signed cert carrying A's test domain is used:
    B has no order with a matching issuer+serial, so the answer must be
    unauthorized - even though the CN collides with A's (revoked) cert,
    which must NOT leak an alreadyRevoked to B (F9/G3 edge case). Using a
    self-signed cert keeps this test independent of whether A's real cert
    has since been revoked (`just issue` revokes it, after which even A
    gets 404 on download)."""
    der = _self_signed_cert_der(cfg.test_domain)
    resp = acct2.post_raw(
        acct2.directory["revokeCert"],
        acct2.sign(acct2.directory["revokeCert"], {"certificate": b64(der)}),
    )
    assert_problem(resp, "unauthorized")


def test_l3_04_revoke_with_wrong_issuer_or_serial(acct):
    """Revocation of a certificate the account never received must be denied
    (L3-04). A self-signed cert with an unrelated CN matches no issuer+serial
    of any stored cert and no CN either, so the F9 _cert_matches_leaf()
    heuristic cannot turn the answer into alreadyRevoked: expect unauthorized."""
    der = _self_signed_cert_der(f"l304-{secrets.token_hex(4)}.example.org")
    resp = acct.post_raw(
        acct.directory["revokeCert"],
        acct.sign(acct.directory["revokeCert"], {"certificate": b64(der)}),
    )
    assert_problem(resp, "unauthorized")


def _self_signed_cert_der(cn):
    """A throwaway self-signed cert, parseable but never issued by any CA."""
    import datetime

    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)
