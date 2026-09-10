"""
Minimal JWS (RFC 7515) verification for the ACME server, limited to what
RFC 8555 actually requires: Flattened JSON Serialization, RS256/ES256 for
account keys, HS256 for externalAccountBinding. Built directly on
`cryptography` primitives rather than a third-party JOSE library, so the
exact wire behaviour is easy to reason about/test.
"""

import base64
import hashlib
import hmac
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

SUPPORTED_ACCOUNT_ALGS = ("RS256", "ES256")
SUPPORTED_EAB_ALGS = ("HS256",)

_EC_CURVES = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}


class JwsError(Exception):
    """Raised for any malformed or unverifiable JWS - callers should map
    this to an ACME "malformed" problem document."""


class JwsBadNonceError(JwsError):
    """Raised specifically for a missing/invalid/expired nonce, so callers
    can map it to the ACME "badNonce" problem type instead of the generic
    "malformed" - RFC 8555 section 6.5.1 requires this distinct type so
    clients know to retry automatically with the fresh nonce that comes
    back on the error response."""


def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data):
    if isinstance(data, str):
        data = data.encode("ascii")
    padding_needed = (-len(data)) % 4
    data += b"=" * padding_needed
    return base64.urlsafe_b64decode(data)


def parse_flattened_jws(body):
    """
    body: parsed JSON dict of the ACME request body.
    Returns (protected: dict, payload_bytes: bytes, signature_bytes: bytes,
             protected_b64: str, payload_b64: str).
    """
    try:
        protected_b64 = body["protected"]
        payload_b64 = body.get("payload", "")
        signature_b64 = body["signature"]
    except (KeyError, TypeError) as exc:
        raise JwsError("Request body is not a valid JWS") from exc

    try:
        protected = json.loads(b64url_decode(protected_b64))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JwsError("Could not decode JWS protected header") from exc

    payload_bytes = b64url_decode(payload_b64) if payload_b64 else b""
    signature_bytes = b64url_decode(signature_b64)

    return protected, payload_bytes, signature_bytes, protected_b64, payload_b64


def jwk_to_public_key(jwk):
    """Builds a `cryptography` public key object from a JSON Web Key dict."""
    kty = jwk.get("kty")
    if kty == "RSA":
        n = int.from_bytes(b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(b64url_decode(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    if kty == "EC":
        curve = _EC_CURVES.get(jwk.get("crv"))
        if curve is None:
            raise JwsError(f"Unsupported EC curve: {jwk.get('crv')}")
        x = int.from_bytes(b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(b64url_decode(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    raise JwsError(f"Unsupported JWK key type: {kty}")


def verify_signature(alg, signing_input, signature, *, public_key=None, hmac_key=None):
    """
    signing_input: b"<protected_b64>.<payload_b64>" (ASCII bytes).
    Raises JwsError if the signature does not verify.
    """
    try:
        if alg == "RS256":
            public_key.verify(
                signature, signing_input, padding.PKCS1v15(), hashes.SHA256()
            )
        elif alg == "ES256":
            half = len(signature) // 2
            r = int.from_bytes(signature[:half], "big")
            s = int.from_bytes(signature[half:], "big")
            der_sig = utils.encode_dss_signature(r, s)
            public_key.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))
        elif alg in ("HS256", "HS384", "HS512"):
            digestmod = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
            expected = hmac.new(hmac_key, signing_input, digestmod).digest()
            if not hmac.compare_digest(expected, signature):
                raise JwsError("HMAC signature verification failed")
        else:
            raise JwsError(f"Unsupported JWS alg: {alg}")
    except InvalidSignature as exc:
        raise JwsError("Signature verification failed") from exc
