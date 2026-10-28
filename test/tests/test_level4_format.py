"""Level 4 (cheap header/format checks)."""

import pytest

from tests.conftest import assert_problem

pytestmark = pytest.mark.level4


def test_l4_01_error_is_problem_json(acct):
    url = acct.directory["newOrder"]
    resp = acct.post_raw(url, acct.sign(url, {"identifiers": []}))
    assert_problem(resp)
    assert resp.headers["Content-Type"].startswith("application/problem+json")
    assert resp.json()["type"].startswith("urn:ietf:params:acme:error:")


def test_l4_02_replay_nonce_on_errors(acct):
    url = acct.directory["newOrder"]
    resp = acct.post_raw(url, acct.sign(url, {"identifiers": []}))
    assert resp.status_code >= 400
    assert resp.headers.get("Replay-Nonce")


def test_l4_03_directory_link_header_on_post(acct):
    url = acct.directory["newOrder"]
    resp = acct.post_raw(url, acct.sign(url, {"identifiers": [{"type": "dns", "value": "x.example.org"}]}))
    assert 'rel="index"' in resp.headers.get("Link", ""), dict(resp.headers)


def test_l4_04_new_nonce_cache_control(client):
    resp = client.http.head(client.directory["newNonce"], verify=client.verify, timeout=30)
    assert "no-store" in resp.headers.get("Cache-Control", "")


def test_l4_extra_directory_content_type(client):
    resp = client._get(client.directory_url)
    assert resp.headers["Content-Type"].startswith("application/json")


# --- Tests for confirmed audit findings (F10, F11, F14, F15, F18) -----------
# These pin the current (buggy) behaviour as expected-fail until the server is
# fixed. Remove the xfail markers when the fix lands.


@pytest.mark.xfail(reason="F18: malformed payload shapes give HTTP 500 HTML", strict=True)
@pytest.mark.parametrize(
    "payload",
    [
        {"identifiers": "abc"},
        {"identifiers": [{"type": "dns", "value": 5}]},
    ],
    ids=["identifiers-not-list", "value-not-string"],
)
def test_l4_13_malformed_payload_shapes_never_5xx(acct, payload):
    """Malformed newOrder payload shapes must return a 4xx problem, never
    a 500 (F18)."""
    url = acct.directory["newOrder"]
    resp = acct.post_raw(url, acct.sign(url, payload))
    assert 400 <= resp.status_code < 500, f"{resp.status_code}: {resp.text[:200]}"


def test_l4_13b_bad_base64_csr_never_5xx(acct, cfg):
    """A 'csr' that is not valid base64url must give a 4xx problem at
    finalize, never a 500 (F18)."""
    _, order = acct.new_order([cfg.test_domain])
    url = order["finalize"]
    resp = acct.post_raw(url, acct.sign(url, {"csr": "not-valid-base64url!!!"}))
    assert 400 <= resp.status_code < 500, f"{resp.status_code}: {resp.text[:200]}"


@pytest.mark.xfail(reason="F14: GET on POST-only endpoints returns HTML 405", strict=True)
def test_l4_11_get_on_post_only_endpoint_is_problem_json(acct):
    """GET on a POST-only ACME endpoint must return problem+json, not HTML (F14)."""
    resp = acct.http.get(acct.directory["newOrder"], verify=acct.verify, timeout=30)
    assert resp.status_code == 405
    assert resp.headers["Content-Type"].startswith("application/problem+json")


@pytest.mark.xfail(reason="F15: POST-as-GET with non-empty payload is accepted", strict=True)
def test_l4_12_post_as_get_with_payload_rejected(acct, cfg):
    """POST-as-GET (payload None) with a non-empty payload must be rejected (F15)."""
    order_url, order = acct.new_order([cfg.test_domain])
    resp = acct.post_raw(order_url, acct.sign(order_url, {"x": 1}))
    assert_problem(resp, "malformed", status=400)


@pytest.mark.xfail(reason="F11: expires is local time labelled 'Z'", strict=True)
def test_l4_10_expires_is_rfc3339_utc(acct, cfg):
    """The expires field must be RFC 3339 and actually in UTC (F11)."""
    _, order = acct.new_order([cfg.test_domain])
    expires = order["expires"]
    assert expires.endswith("Z"), expires
    # Parse and compare with UTC now; the server is in Europe/Stockholm so
    # a naive local timestamp will be off by the TZ offset.
    from datetime import datetime, timezone

    dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    delta = abs((dt - now).total_seconds())
    assert delta < 120, f"expires {expires} is {delta}s from UTC now"


@pytest.mark.xfail(reason="F10/A2: account_orders is a stub returning []", strict=True)
def test_l4_08_account_orders_lists_orders(acct, cfg):
    """The account object must list its orders (RFC 8555 7.1.2.1). The server
    currently returns a hard-coded empty list (F10)."""
    acct.new_order([cfg.test_domain])
    account = acct.post(acct.kid, None).json()
    orders = acct.post(account["orders"], None).json()
    assert orders["orders"], "orders list is empty"


@pytest.mark.xfail(reason="F13/A4: re-registration returns 201, should be 200", strict=True)
def test_l4_13b_reregistration_returns_200(acct, cfg):
    """Re-sending newAccount with the same key must return 200, not 201 (F13).
    certbot does this on every run."""
    resp = acct.new_account(cfg.eab_kid, cfg.eab_hmac_key)
    assert resp.status_code == 200, resp.status_code
