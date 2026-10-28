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
