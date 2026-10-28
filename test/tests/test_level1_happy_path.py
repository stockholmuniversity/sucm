"""Level 1: can we get a certificate out? Steps are separate tests sharing state,
so the report shows exactly which step breaks (later steps skip once one fails)."""

import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.x509.oid import NameOID

from acme_tester.client import AcmeClient, AcmeProblem, b64, make_csr
from acme_tester.config import write_last_order_url

pytestmark = pytest.mark.level1


def test_directory_has_required_resources(client):
    for key in ("newNonce", "newAccount", "newOrder"):
        assert key in client.directory, f"directory missing {key}"


def test_new_nonce_returns_replay_nonce(client):
    resp = client.http.head(
        client.directory["newNonce"], verify=client.verify, timeout=30
    )
    assert resp.status_code in (200, 204)
    assert resp.headers.get("Replay-Nonce")


def test_nonces_are_unique(client):
    assert client.new_nonce() != client.new_nonce()


class TestFlow:
    """Ordered: account -> order -> finalize -> download."""

    state = {}

    def _need(self, *keys):
        for k in keys:
            if k not in self.state:
                pytest.skip(f"previous step did not produce '{k}'")

    def test_1_new_account_with_eab(self, need_eab, cfg):
        c = AcmeClient(
            cfg.directory_url, verify=cfg.verify, key_file=cfg.account_key_file
        )
        resp = c.new_account(cfg.eab_kid, cfg.eab_hmac_key)
        assert resp.status_code in (200, 201)
        assert resp.headers["Location"].startswith("http")
        self.state["client"] = c

    def test_2_new_order(self, cfg):
        self._need("client")
        c = self.state["client"]
        order_url, order = c.new_order([cfg.test_domain])
        assert order["status"] in ("pending", "ready")
        assert order["finalize"]
        self.state.update(order_url=order_url, order=order)

    def test_3_authorizations_are_valid(self):
        self._need("client", "order")
        c = self.state["client"]
        for authz_url in self.state["order"]["authorizations"]:
            authz = c.post(authz_url, None).json()
            assert authz["status"] == "valid", authz

    @pytest.mark.issuance
    def test_4_finalize(self, cfg):
        self._need("client", "order")
        c = self.state["client"]
        csr_der, csr_key = make_csr([cfg.test_domain])
        order = c.post(
            self.state["order"]["finalize"], {"csr": b64(csr_der)}
        ).json()
        deadline = time.time() + 120
        while order["status"] in ("processing", "ready") and time.time() < deadline:
            time.sleep(3)
            order = c.get_order(self.state["order_url"])
        assert order["status"] == "valid", order
        assert order.get("certificate")
        self.state.update(
            certificate=order["certificate"],
            csr=x509.load_der_x509_csr(csr_der),
            csr_key=csr_key,
        )
        # Remember the valid order's URL so later runs (cross-account and
        # re-finalize tests) can find an issued order without re-issuing.
        write_last_order_url(self.state["order_url"])
        print(f"\nissued order: {self.state['order_url']} (saved to state dir)")

    @pytest.mark.issuance
    def test_5_download_certificate(self, cfg):
        self._need("client", "certificate")
        resp = self.state["client"].download(self.state["certificate"])
        assert "pem-certificate-chain" in resp.headers.get("Content-Type", "")
        chain = x509.load_pem_x509_certificates(resp.content)
        assert chain, "empty certificate chain"
        leaf = chain[0]
        names = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        assert cfg.test_domain in names
        self.state["chain"] = chain

    # --- L1-10: the delivered certificate must actually be usable (audit §6) ---

    @pytest.mark.xfail(
        reason="NEW finding (run 5): the served chain is the CA API's raw "
        "'fullchain' field - leaf appears 3 times (positions 0, 1, 5), the "
        "intermediate 3 times (2, 4, 6) and the issuer link breaks after "
        "position 1. SUCM stores/serves it verbatim (sucm_certificate.py "
        "renew_cert_with_csr / get_active_cert_pem).",
        strict=True,
    )
    @pytest.mark.issuance
    def test_5b_chain_is_leaf_first_and_links(self):
        self._need("chain")
        chain = self.state["chain"]
        assert len(chain) >= 2, "expected at least leaf + intermediate"
        # No certificate may appear twice (a chain is a path, not a bag).
        serials = [c.serial_number for c in chain]
        assert len(set(serials)) == len(serials), "duplicate certificate in chain"
        for i, cert in enumerate(chain):
            if i + 1 < len(chain):
                assert cert.issuer == chain[i + 1].subject, (
                    f"chain misordered at position {i}: "
                    f"{cert.issuer.rfc4514_string()} != "
                    f"{chain[i + 1].subject.rfc4514_string()}"
                )
            _verify_signed_by(cert, chain[i + 1] if i + 1 < len(chain) else cert)

    @pytest.mark.issuance
    def test_5c_cert_public_key_matches_csr(self):
        self._need("chain", "csr_key")
        leaf_pub = self.state["chain"][0].public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        csr_pub = self.state["csr_key"].public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert leaf_pub == csr_pub, "certified public key is not the CSR's key"

    @pytest.mark.issuance
    def test_5d_validity_period_is_sane(self):
        self._need("chain")
        leaf = self.state["chain"][0]
        now = datetime.now(timezone.utc)
        assert leaf.not_valid_before_utc <= now + timedelta(minutes=5)
        assert leaf.not_valid_after_utc > now
        assert leaf.not_valid_after_utc <= now + timedelta(days=399)

    @pytest.mark.issuance
    def test_5e_leaf_eku_is_server_auth(self):
        self._need("chain")
        eku = self.state["chain"][0].extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in eku


def _verify_signed_by(cert, issuer):
    """Raise unless cert's signature verifies against issuer's public key."""
    pub = issuer.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
    else:  # RSA
        pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )


class TestRevoke:
    """L3-02 / L3-02b: revoke the cert issued by TestFlow through ACME (needs TestFlow to pass)."""

    @pytest.mark.issuance
    def test_6_revoke_own_certificate(self):
        if "certificate" not in TestFlow.state:
            pytest.skip("no certificate issued in TestFlow")
        c = TestFlow.state["client"]
        pem = c.download(TestFlow.state["certificate"]).content
        resp = c.revoke(pem)
        assert resp.status_code == 200, resp.text
        TestFlow.state["revoked_pem"] = pem

    @pytest.mark.issuance
    def test_7_revoke_again_is_rejected(self):
        if "revoked_pem" not in TestFlow.state:
            pytest.skip("certificate was not revoked")
        c = TestFlow.state["client"]
        with pytest.raises(AcmeProblem) as exc:
            c.revoke(TestFlow.state["revoked_pem"])
        # RFC 8555 7.6 requires alreadyRevoked for an already revoked certificate
        assert exc.value.type.endswith(":alreadyRevoked"), exc.value.body


class TestRenewal:
    """L2-01: a second order for the same domain (renewal) must issue a new,
    different certificate (audit G2). The server-side part (same Certificate
    row reused, old ActiveCertificate replaced rather than orphaned) needs DB
    access and is verified separately."""

    state = {}

    def _need(self, *keys):
        for k in keys:
            if k not in self.state:
                pytest.skip(f"previous step did not produce '{k}'")

    @pytest.mark.issuance
    def test_1_renewal_order_and_finalize(self, acct, cfg):
        order_url, order = acct.new_order([cfg.test_domain])
        csr_der, csr_key = make_csr([cfg.test_domain])
        order = acct.post(order["finalize"], {"csr": b64(csr_der)}).json()
        deadline = time.time() + 120
        while order["status"] in ("processing", "ready") and time.time() < deadline:
            time.sleep(3)
            order = acct.get_order(order_url)
        assert order["status"] == "valid", order
        assert order.get("certificate")
        self.state.update(
            order_url=order_url, cert_url=order["certificate"], csr_key=csr_key
        )
        write_last_order_url(order_url)
        print(f"\nrenewal order: {order_url} (saved to state dir)")

    @pytest.mark.issuance
    def test_2_renewal_cert_is_new(self, acct):
        self._need("cert_url")
        pem = acct.download(self.state["cert_url"]).content
        leaf = x509.load_pem_x509_certificates(pem)[0]
        assert (
            leaf.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            == self.state["csr_key"].public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ), "renewal cert does not carry the renewal CSR's key"
        self.state["pem"] = pem

    @pytest.mark.issuance
    def test_3_revoke_renewed_cert(self, acct):
        """Leave no unrevoked test certs behind (see F4)."""
        self._need("pem")
        resp = acct.revoke(self.state["pem"])
        assert resp.status_code == 200, resp.text
