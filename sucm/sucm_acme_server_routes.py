"""
The actual ACME (RFC 8555) server: the wire protocol certbot (or any other
ACME client) speaks. Unlike sucm_acme_routes.py (the human-facing account
request/admin portal, gated by Shibboleth), every endpoint here is reached
directly by automated clients with no SSO session, so:

 - all DB access here MUST use parameterised queries. get_records()/
   remove_record() now build `WHERE <col> = %s` internally from a validated
   column identifier, so they are safe - but for anything beyond
   single-column equality use execute_select_query()/execute_modify_query()
   with real parameter binding, never an f-string SQL fragment (see AGENTS.md).
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
        body["error"] = {
            "type": PROBLEM_NS + "serverInternal",
            "detail": order["error"],
        }
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
    # RFC 8555 7.1: every response except the directory itself SHOULD carry
    # a Link header pointing at the directory (rel="index"), so clients can
    # always discover the directory URL from any ACME response.
    if request.endpoint and request.endpoint != "acme_server.directory":
        index_link = f'<{url_for("acme_server.directory", _external=True)}>;rel="index"'
        if "Link" in response.headers:
            response.headers.add("Link", index_link)
        else:
            response.headers["Link"] = index_link
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
    protected, payload_bytes, signature, protected_b64, payload_b64 = (
        parse_flattened_jws(body_json)
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
    protected, payload_bytes, signature, protected_b64, payload_b64 = (
        parse_flattened_jws(eab_jws)
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
    # The EAB hmac key we hand out (and that certbot/acme clients receive)
    # is a base64url string per RFC 8555 section 7.3.4 - clients decode it
    # before using it as raw HMAC key material, so we must do the same
    # rather than using the string's own ASCII bytes as the key.
    verify_signature(alg, signing_input, signature, hmac_key=b64url_decode(hmac_key))

    bound_jwk = json.loads(payload_bytes)
    if bound_jwk != account_jwk:
        raise JwsError(
            "externalAccountBinding payload JWK does not match the account JWK"
        )

    return account


@bp.route("/new-account", methods=["POST"])
def new_account():
    outer_url = url_for("acme_server.new_account", _external=True)
    try:
        protected, payload, _account, jwk = _verify_outer_jws(
            request.get_json(force=True), outer_url
        )
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
        return _problem(
            "unauthorized", "This account has been disabled by an administrator"
        )

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
        # Atomic check-and-set: only binds if no JWK was bound yet. If we lost
        # a race with a concurrent first newAccount for the same EAB kid, the
        # winner's JWK is now authoritative - re-read and require it to match
        # the key this request was actually signed with, rather than letting
        # our (losing) key overwrite it.
        if account_model.bind_jwk(eab_account["account_id"], jwk_json):
            audit_logger.info(
                "ACME account %s bound to a client JWK via newAccount",
                eab_account["account_id"],
            )
        else:
            winner = account_model.get_account_detail(eab_account["account_id"])
            if not winner.get("jwk_json") or json.loads(winner["jwk_json"]) != jwk:
                return _problem(
                    "unauthorized",
                    "This EAB credential is already bound to a different account key; "
                    "request a new account via the portal if you need a new key",
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
        _protected, _payload, acct, _jwk = _verify_outer_jws(
            request.get_json(force=True), outer_url
        )
    except JwsError as exc:
        return _jws_problem(exc)

    if not acct or int(acct["account_id"]) != account_id:
        return _problem("unauthorized", "kid does not match the requested account")

    return jsonify(
        {
            "status": "valid" if acct["status"] == "active" else acct["status"],
            "orders": url_for(
                "acme_server.account_orders", account_id=account_id, _external=True
            ),
        }
    )


@bp.route("/account/<int:account_id>/orders", methods=["POST"])
def account_orders(account_id):
    outer_url = url_for(
        "acme_server.account_orders", account_id=account_id, _external=True
    )
    try:
        _protected, _payload, acct, _jwk = _verify_outer_jws(
            request.get_json(force=True), outer_url
        )
    except JwsError as exc:
        return _jws_problem(exc)
    if not acct or int(acct["account_id"]) != account_id:
        return _problem("unauthorized", "kid does not match the requested account")
    return jsonify({"orders": []})


@bp.route("/new-order", methods=["POST"])
def new_order():
    outer_url = url_for("acme_server.new_order", _external=True)
    try:
        _protected, payload, acct, _jwk = _verify_outer_jws(
            request.get_json(force=True), outer_url
        )
    except JwsError as exc:
        return _jws_problem(exc)

    if not acct:
        return _problem(
            "malformed",
            "new-order must be signed with an account 'kid', not an embedded 'jwk'",
        )

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
        _protected, _payload, acct, _jwk = _verify_outer_jws(
            request.get_json(force=True), outer_url
        )
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
        _protected, _payload, acct, _jwk = _verify_outer_jws(
            request.get_json(force=True), outer_url
        )
    except JwsError as exc:
        return _jws_problem(exc)

    authz = SucmAcmeOrder().get_authorization(authz_id)
    if not authz:
        return _problem("malformed", "No such authorization", 404)
    order = SucmAcmeOrder().get_order(authz["order_id"])
    if not acct or not order or order["account_id"] != acct["account_id"]:
        return _problem(
            "unauthorized", "This authorization does not belong to your account"
        )

    return jsonify(_authz_to_json(authz))


@bp.route("/chall/<int:authz_id>", methods=["POST"])
def challenge(authz_id):
    outer_url = _chall_url(authz_id)
    try:
        _protected, _payload, acct, _jwk = _verify_outer_jws(
            request.get_json(force=True), outer_url
        )
    except JwsError as exc:
        return _jws_problem(exc)

    authz = SucmAcmeOrder().get_authorization(authz_id)
    if not authz:
        return _problem("malformed", "No such authorization", 404)
    order = SucmAcmeOrder().get_order(authz["order_id"])
    if not acct or not order or order["account_id"] != acct["account_id"]:
        return _problem(
            "unauthorized", "This authorization does not belong to your account"
        )

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
        _protected, payload, acct, _jwk = _verify_outer_jws(
            request.get_json(force=True), outer_url
        )
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


def _cert_matches_leaf(cert_detail, leaf):
    """
    Heuristic: does a Certificate row plausibly describe the same identity as
    the submitted leaf cert? Used ONLY to decide between an "alreadyRevoked"
    and a generic "unauthorized" response after the authoritative
    issuer+serial match against ActiveCertificate rows has failed - never to
    select a revocation target. Matches on common name (or any dNSName SAN).
    """
    try:
        leaf_cn_attrs = leaf.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )
        leaf_names = {a.value for a in leaf_cn_attrs}
        try:
            san = leaf.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            leaf_names.update(san.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            pass
    except Exception:
        return False

    row_names = {cert_detail.get("common_name") or ""}
    subject_alt = cert_detail.get("subject_alt") or ""
    # subject_alt is stored as a comma-separated list of DNS names
    row_names.update(n.strip() for n in subject_alt.split(",") if n.strip())
    row_names.discard("")

    return bool(leaf_names & row_names)


@bp.route("/revoke-cert", methods=["POST"])
def revoke_cert():
    outer_url = url_for("acme_server.revoke_cert", _external=True)
    try:
        _protected, payload, acct, _jwk = _verify_outer_jws(
            request.get_json(force=True), outer_url
        )
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

    # Identify the certificate being revoked by its actual identity -
    # (issuer, serial number) - NOT by the attacker-controllable CN string in
    # its subject. The previous implementation looked up a Certificate row by
    # CN and revoked whatever the *latest* active cert for that CN was, which
    # both trusted a string the caller controls and could revoke a cert other
    # than the one submitted. We instead walk only the calling account's own
    # ACME orders and require an exact issuer+serial match against a stored,
    # ACME-issued active certificate.
    submitted_serial = leaf.serial_number
    submitted_issuer = leaf.issuer.rfc4514_string()

    sc = SucmCertificate()
    order_model = SucmAcmeOrder()
    matched = None  # (cert_detail, active_cert_dict)
    cn_matched_but_inactive = False

    for order in order_model.get_orders_for_account(acct["account_id"]):
        if order["cert_id"] is None:
            continue
        cert_detail = sc.get_certificate_detail(order["cert_id"])
        if not cert_detail or cert_detail.get("cert_type") != ACME_CERT_TYPE:
            continue
        active_certs = sc.get_all_active_certs(cert_detail["cert_id"])
        # Remember if this order's certificate has no active rows left: a
        # cert that was issued to this account but has since been revoked
        # looks exactly like this. Used below to report alreadyRevoked
        # instead of the generic unauthorized (RFC 8555 7.6).
        if not active_certs and _cert_matches_leaf(cert_detail, leaf):
            cn_matched_but_inactive = True
        for active in active_certs:
            try:
                stored_pem = sc.get_active_cert_pem(active["active_cert_id"])
                stored_leaf = x509.load_pem_x509_certificate(
                    stored_pem.encode(), default_backend()
                )
            except Exception:
                # Unparseable stored row - skip it rather than fail the whole
                # revocation request.
                continue
            if (
                stored_leaf.serial_number == submitted_serial
                and stored_leaf.issuer.rfc4514_string() == submitted_issuer
            ):
                matched = (cert_detail, active)
                break
        if matched:
            break

    if not matched:
        if cn_matched_but_inactive:
            return _problem(
                "alreadyRevoked",
                "The certificate has already been revoked",
            )
        # Deliberately generic: do not reveal whether the cert exists but is
        # owned by another account vs. not known at all.
        return _problem(
            "unauthorized",
            "No certificate issued to your account matches the submitted "
            "certificate (by issuer and serial number)",
        )

    cert_detail, active = matched
    common_name = cert_detail.get("common_name")

    try:
        SucmCertificate(cert_id=cert_detail["cert_id"]).revoke_cert(
            active["active_cert_id"]
        )
    except Exception as exc:
        return _problem("serverInternal", f"Revocation failed: {exc}", 500)

    audit_logger.info(
        "ACME account %s revoked certificate %s (%s, serial %s)",
        acct["account_id"],
        cert_detail["cert_id"],
        common_name,
        submitted_serial,
    )
    return ("", 200)
