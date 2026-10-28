"""Level 1: can we get a certificate out? Steps are separate tests sharing state,
so the report shows exactly which step breaks (later steps skip once one fails)."""

import time

import pytest
from cryptography import x509

from acme_tester.client import AcmeClient, AcmeProblem
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
        order = c.finalize(self.state["order"]["finalize"], [cfg.test_domain])
        deadline = time.time() + 120
        while order["status"] in ("processing", "ready") and time.time() < deadline:
            time.sleep(3)
            order = c.get_order(self.state["order_url"])
        assert order["status"] == "valid", order
        assert order.get("certificate")
        self.state["certificate"] = order["certificate"]
        # Remember the valid order's URL so later runs (cross-account and
        # re-finalize tests) can find an issued order without re-issuing.
        write_last_order_url(self.state["order_url"])
        print(f"\nissued order: {self.state['order_url']} (saved to state dir)")

    @pytest.mark.issuance
    def test_5_download_certificate(self, cfg):
        self._need("client", "certificate")
        resp = self.state["client"].download(self.state["certificate"])
        assert "pem-certificate-chain" in resp.headers.get("Content-Type", "")
        leaf = x509.load_pem_x509_certificate(resp.content)
        names = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        assert cfg.test_domain in names


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
