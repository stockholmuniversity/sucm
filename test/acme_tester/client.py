"""Minimal RFC 8555 client (ES256 account key) that can also send deliberately bad requests."""

import base64
import hashlib
import hmac
import json
import os

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class AcmeProblem(Exception):
    def __init__(self, resp):
        self.resp = resp
        self.status = resp.status_code
        try:
            self.body = resp.json()
        except ValueError:
            self.body = {"raw": resp.text[:500]}
        self.type = self.body.get("type", "")
        super().__init__(f"HTTP {self.status}: {self.body}")


class AcmeClient:
    def __init__(self, directory_url, verify=True, key_file=None):
        self.directory_url = directory_url
        self.verify = verify
        self.http = requests.Session()
        self.key = load_or_create_key(key_file)
        self.kid = None
        self.nonce = None
        self.directory = self._get(directory_url).json()

    # --- plumbing -----------------------------------------------------
    def _get(self, url):
        return self.http.get(url, verify=self.verify, timeout=30)

    @property
    def jwk(self):
        nums = self.key.public_key().public_numbers()
        return {
            "crv": "P-256",
            "kty": "EC",
            "x": b64(nums.x.to_bytes(32, "big")),
            "y": b64(nums.y.to_bytes(32, "big")),
        }

    def new_nonce(self):
        url = self.directory["newNonce"]
        resp = self.http.head(url, verify=self.verify, timeout=30)
        return resp.headers["Replay-Nonce"]

    def sign(self, url, payload, use_jwk=False, nonce=None, extra_protected=None):
        """Build a flattened JWS. payload=None means POST-as-GET (empty payload)."""
        protected = {"alg": "ES256", "nonce": nonce or self._take_nonce(), "url": url}
        if use_jwk or not self.kid:
            protected["jwk"] = self.jwk
        else:
            protected["kid"] = self.kid
        protected.update(extra_protected or {})
        p64 = b64(json.dumps(protected).encode())
        pl64 = "" if payload is None else b64(json.dumps(payload).encode())
        der = self.key.sign(f"{p64}.{pl64}".encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return {"protected": p64, "payload": pl64, "signature": b64(sig)}

    def _take_nonce(self):
        nonce, self.nonce = self.nonce, None
        return nonce or self.new_nonce()

    def post_raw(self, url, body):
        resp = self.http.post(
            url,
            data=json.dumps(body),
            headers={"Content-Type": "application/jose+json"},
            verify=self.verify,
            timeout=60,
        )
        self.nonce = resp.headers.get("Replay-Nonce")
        return resp

    def post(self, url, payload, use_jwk=False):
        resp = self.post_raw(url, self.sign(url, payload, use_jwk=use_jwk))
        if resp.status_code >= 400:
            raise AcmeProblem(resp)
        return resp

    # --- protocol steps -------------------------------------------------
    def eab_jws(self, eab_kid, eab_hmac_key_b64, url=None):
        url = url or self.directory["newAccount"]
        protected = b64(
            json.dumps({"alg": "HS256", "kid": eab_kid, "url": url}).encode()
        )
        payload = b64(json.dumps(self.jwk).encode())
        sig = hmac.new(
            unb64(eab_hmac_key_b64), f"{protected}.{payload}".encode(), hashlib.sha256
        ).digest()
        return {"protected": protected, "payload": payload, "signature": b64(sig)}

    def new_account(self, eab_kid, eab_hmac_key_b64, contact=None):
        payload = {
            "termsOfServiceAgreed": True,
            "externalAccountBinding": self.eab_jws(eab_kid, eab_hmac_key_b64),
        }
        if contact:
            payload["contact"] = contact
        resp = self.post(self.directory["newAccount"], payload, use_jwk=True)
        self.kid = resp.headers["Location"]
        return resp

    def new_order(self, domains):
        payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
        resp = self.post(self.directory["newOrder"], payload)
        return resp.headers["Location"], resp.json()

    def get_order(self, order_url):
        return self.post(order_url, None).json()

    def finalize(self, finalize_url, domains):
        csr_der = make_csr(domains)[0]
        return self.post(finalize_url, {"csr": b64(csr_der)}).json()

    def download(self, cert_url):
        return self.post(cert_url, None)

    def revoke(self, cert_pem, reason=0):
        """RFC 8555 7.6, signed with the account key (kid)."""
        leaf = x509.load_pem_x509_certificates(cert_pem)[0]
        der = leaf.public_bytes(serialization.Encoding.DER)
        return self.post(
            self.directory["revokeCert"], {"certificate": b64(der), "reason": reason}
        )


def load_or_create_key(path):
    """An EAB credential binds to the first account key, so reruns must reuse it."""
    if path and os.path.exists(path):
        with open(path, "rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    if path:
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
    return key


def make_csr(domains):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER), key
