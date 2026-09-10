"""
The actual ACME (RFC 8555) server: the wire protocol certbot (or any other
ACME client) speaks. Unlike sucm_acme_routes.py (the human-facing account
request/admin portal, gated by Shibboleth), every endpoint here is reached
directly by automated clients with no SSO session, so:

 - all DB access here MUST use parameterised queries (never
   sucm_db.get_records()/remove_record()'s string-interpolated
   conditions - see AGENTS.md).
 - every response that is part of a JWS exchange gets a fresh
   Replay-Nonce header (RFC 8555 section 6.5).
 - errors are returned as application/problem+json (RFC 8555 section 6.7),
   never as an HTML/redirect page.
"""

import json

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from flask import Blueprint, Response, jsonify, request, url_for

from .sucm_acme_account import SucmAcmeAccount
from .sucm_acme_crypto import decrypt_secret
from .sucm_acme_jws import (
    JwsBadNonceError,
    JwsError,
    SUPPORTED_ACCOUNT_ALGS,
    SUPPORTED_EAB_ALGS,
    b64url_decode,
    jwk_to_public_key,
    parse_flattened_jws,
    verify_signature,
)
from .sucm_acme_nonce import SucmAcmeNonce
from .sucm_acme_order import SucmAcmeOrder, SucmAcmeOrderError
from .sucm_certificate import SucmCertificate
from .sucm_globals import ACME_CERT_TYPE
from .sucm_settings import audit_logger

bp = Blueprint("acme_server", __name__, url_prefix="/acme")

PROBLEM_NS = "urn:ietf:params:acme:error:"


def _problem(acme_type, detail, status_code=400):
    body = {"type": PROBLEM_NS + acme_type, "detail": detail}
    resp = jsonify(body)
    resp.status_code = status_code
    resp.headers["Content-Type"] = "application/problem+json"
    resp.headers["Replay-Nonce"] = SucmAcmeNonce.issue()
    return resp


def _jws_problem(exc):
    if isinstance(exc, JwsBadNonceError):
        return _problem("badNonce", str(exc))
    return _problem("malformed", str(exc))


def _account_url(account_id):
    return url_for("acme_server.account", account_id=account_id, _external=True)


def _order_url(order_id):
    return url_for("acme_server.get_order", order_id=order_id, _external=True)


def _authz_url(authz_id):
    return url_for("acme_server.get_authz", authz_id=authz_id, _external=True)


def _chall_url(authz_id):
    return url_for("acme_server.challenge", authz_id=authz_id, _external=True)


def _finalize_url(order_id):
    return url_for("acme_server.finalize", order_id=order_id, _external=True)


def _cert_url(order_id):
    return url_for("acme_server.download_cert", order_id=order_id, _external=True)


def _order_to_json(order):
    authzs = SucmAcmeOrder().get_authorizations_for_order(order["order_id"])
    body = {
        "status": order["status"],
        "expires": order["expires"].isoformat() + "Z",
        "identifiers": order["identifiers"],
        "authorizations": [_authz_url(a["authz_id"]) for a in authzs],
        "finalize": _finalize_url(order["order_id"]),
    }
    if order["status"] == "valid" and order["cert_id"] is not None:
        body["certificate"] = _cert_url(order["order_id"])
    if order.get("error"):
        body["error"] = {"type": PROBLEM_NS + "serverInternal", "detail": order["error"]}
    return body


def _authz_to_json(authz):
    return {
        "status": authz["status"],
        "expires": authz["expires"].isoformat() + "Z",
        "identifier": {
            "type": authz["identifier_type"],
            "value": authz["identifier_value"],
        },
        "challenges": [
            {
                "type": "http-01",
                "url": _chall_url(authz["authz_id"]),
                "status": authz["challenge_status"],
                "token": authz["challenge_token"],
            }
        ],
    }


@bp.after_request
def _add_nonce_header(response):
    # RFC 8555 6.5.1: every response from an ACME server MUST include a
    # Replay-Nonce header, not just successful ones.
    if "Replay-Nonce" not in response.headers:
        response.headers["Replay-Nonce"] = SucmAcmeNonce.issue()
    return response


@bp.route("/directory", methods=["GET"])
def directory():
    body = {
        "newNonce": url_for("acme_server.new_nonce", _external=True),
        "newAccount": url_for("acme_server.new_account", _external=True),
        "newOrder": url_for("acme_server.new_order", _external=True),
        "revokeCert": url_for("acme_server.revoke_cert", _external=True),
        "meta": {
            "externalAccountRequired": True,
        },
    }
    return jsonify(body)


@bp.route("/new-nonce", methods=["GET", "HEAD"])
def new_nonce():
    nonce = SucmAcmeNonce.issue()
    status_code = 204 if request.method == "GET" else 200
    response = Response("", status=status_code)
    response.headers["Replay-Nonce"] = nonce
    response.headers["Cache-Control"] = "no-store"
    return response


def _verify_outer_jws(body_json, expected_url):
    """
    Parses+verifies a JWS's outer signature (against either an embedded
    "jwk" or a "kid" referring to an already-registered account).

    Returns (protected, payload_dict, account_dict_or_None).
    Raises JwsError/SucmAcmeOrderError on any failure - callers should
    catch these and turn them into problem+json responses.
    """
    protected, payload_bytes, signature, protected_b64, payload_b64 = parse_flattened_jws(
        body_json
    )

    alg = protected.get("alg")
    if alg not in SUPPORTED_ACCOUNT_ALGS:
        raise JwsError(f"Unsupported or missing JWS alg: {alg}")

    if protected.get("url") != expected_url:
        raise JwsError("JWS protected header 'url' does not match the request URL")

    if not SucmAcmeNonce.consume(protected.get("nonce")):
        raise JwsBadNonceError("Invalid, reused, or expired anti-replay nonce")

    account = None
    if "jwk" in protected:
        jwk = protected["jwk"]
    elif "kid" in protected:
        account_id = protected["kid"].rstrip("/").rsplit("/", 1)[-1]
        account = SucmAcmeAccount().get_account_detail(account_id)
        if not account or not account.get("jwk_json"):
            raise JwsError("Unknown ACME account kid")
        if account["status"] != "active":
            raise JwsError(f"Account is not active (status: {account['status']})")
        jwk = json.loads(account["jwk_json"])
    else:
        raise JwsError("JWS protected header must contain either 'jwk' or 'kid'")

    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    public_key = jwk_to_public_key(jwk)
    verify_signature(alg, signing_input, signature, public_key=public_key)

    payload = json.loads(payload_bytes) if payload_bytes else {}
    return protected, payload, account, jwk


def _verify_eab(eab_jws, account_jwk, outer_url):
    """
    Verifies the externalAccountBinding inner JWS (RFC 8555 section 7.3.4):
    HS256-signed with the account's pre-shared EAB hmac key, "kid" is the
    Eab_Kid, payload is the outer account JWK.
    """
    protected, payload_bytes, signature, protected_b64, payload_b64 = parse_flattened_jws(
        eab_jws
    )

    alg = protected.get("alg")
    if alg not in SUPPORTED_EAB_ALGS:
        raise JwsError(f"Unsupported externalAccountBinding alg: {alg}")
    if protected.get("url") != outer_url:
        raise JwsError("externalAccountBinding 'url' does not match the outer JWS url")

    eab_kid = protected.get("kid")
    account = SucmAcmeAccount().get_account_by_eab_kid(eab_kid)
    if not account:
        raise JwsError("Unknown externalAccountBinding kid")

    hmac_key = decrypt_secret(account["hmac_key_encrypted"])
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    verify_signature(alg, signing_input, signature, hmac_key=hmac_key.encode("utf-8"))

    bound_jwk = json.loads(payload_bytes)
    if bound_jwk != account_jwk:
        raise JwsError("externalAccountBinding payload JWK does not match the account JWK")

    return account


@bp.route("/new-account", methods=["POST"])
def new_account():
    outer_url = url_for("acme_server.new_account", _external=True)
    try:
        protected, payload, _account, jwk = _verify_outer_jws(request.get_json(force=True), outer_url)
    except JwsError as exc:
        return _jws_problem(exc)

    if "jwk" not in protected:
        return _problem("malformed", "newAccount requires an embedded 'jwk', not 'kid'")

    eab = payload.get("externalAccountBinding")
    if not eab:
        return _problem(
            "externalAccountRequired",
            "This server requires externalAccountBinding for every new account",
        )

    try:
        eab_account = _verify_eab(eab, jwk, outer_url)
    except JwsError as exc:
        return _problem("unauthorized", str(exc))

    if eab_account["status"] == "pending":
        return _problem(
            "unauthorized",
            "This account has been requested but not yet activated by an administrator",
        )
    if eab_account["status"] == "disabled":
        return _problem("unauthorized", "This account has been disabled by an administrator")

    account_model = SucmAcmeAccount()
    jwk_json = json.dumps(jwk, sort_keys=True)
    if eab_account.get("jwk_json"):
        if json.loads(eab_account["jwk_json"]) != jwk:
            return _problem(
                "unauthorized",
                "This EAB credential is already bound to a different account key; "
                "request a new account via the portal if you need a new key",
            )
    else:
        account_model.bind_jwk(eab_account["account_id"], jwk_json)
        audit_logger.info(
            "ACME account %s bound to a client JWK via newAccount", eab_account["account_id"]
        )

    account_url = _account_url(eab_account["account_id"])
    resp = jsonify(
        {
            "status": "valid",
            "orders": url_for(
                "acme_server.account_orders",
                account_id=eab_account["account_id"],
                _external=True,
            ),
        }
    )
    resp.status_code = 201
    resp.headers["Location"] = account_url
    return resp


@bp.route("/account/<int:account_id>", methods=["POST"])
def account(account_id):
    outer_url = _account_url(account_id)
    try:
        _protected, _payload, acct, _jwk = _verify_outer_jws(request.get_json(force=True), outer_url)
    except JwsError as exc:
        return _jws_problem(exc)

    if not acct or int(acct["account_id"]) != account_id:
        return _problem("unauthorized", "kid does not match the requested account")

    return jsonify(
        {
            "status": "valid" if acct["status"] == "active" else acct["status"],
            "orders": url_for("acme_server.account_orders", account_id=account_id, _external=True),
        }
    )


@bp.route("/account/<int:account_id>/orders", methods=["POST"])
def account_orders(account_id):
    outer_url = url_for("acme_server.account_orders", account_id=account_id, _external=True)
    try:
        _protected, _payload, acct, _jwk = _verify_outer_jws(request.get_json(force=True), outer_url)
    except JwsError as exc:
        return _jws_problem(exc)
    if not acct or int(acct["account_id"]) != account_id:
        return _problem("unauthorized", "kid does not match the requested account")
    return jsonify({"orders": []})


@bp.route("/new-order", methods=["POST"])
def new_order():
    outer_url = url_for("acme_server.new_order", _external=True)
    try:
        _protected, payload, acct, _jwk = _verify_outer_jws(request.get_json(force=True), outer_url)
    except JwsError as exc:
        return _jws_problem(exc)

    if not acct:
        return _problem("malformed", "new-order must be signed with an account 'kid', not an embedded 'jwk'")

    identifiers = payload.get("identifiers", [])
    try:
        order = SucmAcmeOrder().create_order(acct["account_id"], identifiers)
    except SucmAcmeOrderError as exc:
        return _problem(exc.acme_type, str(exc), exc.status_code)

    resp = jsonify(_order_to_json(order))
    resp.status_code = 201
    resp.headers["Location"] = _order_url(order["order_id"])
    return resp


@bp.route("/order/<int:order_id>", methods=["POST"])
def get_order(order_id):
    outer_url = _order_url(order_id)
    try:
        _protected, _payload, acct, _jwk = _verify_outer_jws(request.get_json(force=True), outer_url)
    except JwsError as exc:
        return _jws_problem(exc)

    order = SucmAcmeOrder().get_order(order_id)
    if not order or not acct or order["account_id"] != acct["account_id"]:
        return _problem("malformed", "No such order", 404)

    return jsonify(_order_to_json(order))


@bp.route("/authz/<int:authz_id>", methods=["POST"])
def get_authz(authz_id):
    outer_url = _authz_url(authz_id)
    try:
        _protected, _payload, acct, _jwk = _verify_outer_jws(request.get_json(force=True), outer_url)
    except JwsError as exc:
        return _jws_problem(exc)

    authz = SucmAcmeOrder().get_authorization(authz_id)
    if not authz:
        return _problem("malformed", "No such authorization", 404)
    order = SucmAcmeOrder().get_order(authz["order_id"])
    if not acct or not order or order["account_id"] != acct["account_id"]:
        return _problem("unauthorized", "This authorization does not belong to your account")

    return jsonify(_authz_to_json(authz))


@bp.route("/chall/<int:authz_id>", methods=["POST"])
def challenge(authz_id):
    outer_url = _chall_url(authz_id)
    try:
        _protected, _payload, acct, _jwk = _verify_outer_jws(request.get_json(force=True), outer_url)
    except JwsError as exc:
        return _jws_problem(exc)

    authz = SucmAcmeOrder().get_authorization(authz_id)
    if not authz:
        return _problem("malformed", "No such authorization", 404)
    order = SucmAcmeOrder().get_order(authz["order_id"])
    if not acct or not order or order["account_id"] != acct["account_id"]:
        return _problem("unauthorized", "This authorization does not belong to your account")

    # Authorizations are pre-validated (see sucm_acme_order.py docstring),
    # so there is nothing to actually do here - just report "valid".
    resp = jsonify(
        {
            "type": "http-01",
            "url": outer_url,
            "status": authz["challenge_status"],
            "token": authz["challenge_token"],
        }
    )
    resp.headers["Link"] = f'<{_authz_url(authz_id)}>;rel="up"'
    return resp


@bp.route("/finalize/<int:order_id>", methods=["POST"])
def finalize(order_id):
    outer_url = _finalize_url(order_id)
    try:
        _protected, payload, acct, _jwk = _verify_outer_jws(request.get_json(force=True), outer_url)
    except JwsError as exc:
        return _jws_problem(exc)

    order = SucmAcmeOrder().get_order(order_id)
    if not order or not acct or order["account_id"] != acct["account_id"]:
        return _problem("malformed", "No such order", 404)

    csr_b64 = payload.get("csr")
    if not csr_b64:
        return _problem("malformed", "finalize payload must contain a 'csr'")

    try:
        csr_der = b64url_decode(csr_b64)
        order = SucmAcmeOrder().finalize_order(order_id, csr_der)
    except SucmAcmeOrderError as exc:
        return _problem(exc.acme_type, str(exc), exc.status_code)

    return jsonify(_order_to_json(order))


@bp.route("/cert/<int:order_id>", methods=["POST"])
def download_cert(order_id):
    outer_url = _cert_url(order_id)
    try:
        _protected, _payload, acct, _jwk = _verify_outer_jws(
            request.get_json(force=True), outer_url
        )
    except JwsError as exc:
        return _jws_problem(exc)

    order = SucmAcmeOrder().get_order(order_id)
    if not order or order["status"] != "valid" or order["cert_id"] is None:
        return _problem("malformed", "No certificate available for this order", 404)
    if not acct or order["account_id"] != acct["account_id"]:
        return _problem("unauthorized", "This order does not belong to your account")

    active_certs = SucmCertificate().get_all_active_certs(order["cert_id"])
    if not active_certs:
        return _problem("malformed", "No certificate available for this order", 404)
    latest = max(active_certs, key=lambda c: c["active_cert_id"])
    pem = SucmCertificate().get_active_cert_pem(latest["active_cert_id"])

    response = Response(pem, status=200)
    response.headers["Content-Type"] = "application/pem-certificate-chain"
    return response


@bp.route("/revoke-cert", methods=["POST"])
def revoke_cert():
    outer_url = url_for("acme_server.revoke_cert", _external=True)
    try:
        _protected, payload, acct, _jwk = _verify_outer_jws(request.get_json(force=True), outer_url)
    except JwsError as exc:
        return _jws_problem(exc)
    if not acct:
        return _problem("malformed", "revoke-cert must be signed with an account 'kid'")

    cert_b64 = payload.get("certificate")
    if not cert_b64:
        return _problem("malformed", "revoke-cert payload must contain a 'certificate'")

    try:
        cert_der = b64url_decode(cert_b64)
        leaf = x509.load_der_x509_certificate(cert_der, default_backend())
    except ValueError as exc:
        return _problem("malformed", f"Could not parse certificate: {exc}")

    common_name = None
    try:
        cn_attrs = leaf.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn_attrs:
            common_name = cn_attrs[0].value
    except Exception:
        pass
    if not common_name:
        return _problem("malformed", "Could not determine the certificate's common name")

    cert_detail = SucmCertificate().get_common_name(common_name)

    if not cert_detail or cert_detail.get("cert_type") != ACME_CERT_TYPE:
        return _problem("unauthorized", "No matching ACME-issued certificate found")

    orders = SucmAcmeOrder().get_orders_for_cert(cert_detail["cert_id"])
    if not any(o["account_id"] == acct["account_id"] for o in orders):
        return _problem("unauthorized", "This certificate was not issued to your account")

    active_certs = SucmCertificate().get_all_active_certs(cert_detail["cert_id"])
    if not active_certs:
        return _problem("malformed", "No active certificate to revoke", 404)
    latest = max(active_certs, key=lambda c: c["active_cert_id"])

    try:
        SucmCertificate(cert_id=cert_detail["cert_id"]).revoke_cert(latest["active_cert_id"])
    except Exception as exc:
        return _problem("serverInternal", f"Revocation failed: {exc}", 500)

    audit_logger.info(
        "ACME account %s revoked certificate %s (%s)",
        acct["account_id"],
        cert_detail["cert_id"],
        common_name,
    )
    return ("", 200)
