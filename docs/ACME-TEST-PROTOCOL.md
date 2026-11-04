# ACME Test Protocol – SUCM

| Field | Value |
|-------|-------|
| System under test | SUCM **v0.12.0** (first runs), **v0.14.0** (rerun 2026-10-26; includes the ACME revoke fix) |
| Environment | sucm-test (`https://sucm-test.it.su.se/acme/directory`) |
| Test tool | `test/` in the sucm repo (see `test/README.md`) |
| Run from | haak0644.it.su.se as user haak0644 |
| Test accounts | Account Id 10015 (burned, see run log), 10016 (current). Both are throwaway and must be deactivated after testing |
| Test domain | `acmetest-haak0644.it.su.se` |
| CA plugin (`[ACME]`) | `Harica_EAB` (temporary, see F1/F2/F4) |
| Date / tester | 2026-10-23 / haak0644 |

References: RFC 8555 (ACME), RFC 8738 (IP identifiers, out of scope), RFC 9773 (ARI, out of scope).

## Purpose and approach
**Purpose:** verify functionally that SUCM's ACME server (`/acme/...`) meets RFC 8555 well enough for a standard client
(certbot) to **obtain a certificate**. Full conformance is secondary, so the tests are split into levels and
level 1 decides whether the ACME feature is usable.

**Approach:**
- Black-box: the tool only speaks HTTP/JWS to the server and imports no SUCM code.
- Two clients: a minimal custom ACME client (can send deliberately malformed requests in levels 2–3) and real certbot (e2e smoke test).
- Runs from haak0644.it.su.se as user haak0644 (not root). The Python tests use the system Python; the certbot script
  uses its own config directories and ignores an existing (broken) certbot configuration on the machine.
- Accounts are created manually in the portal (`/acme-accounts/`), activated by an admin (group `it-produktion-infra-imdb`)
  and given a domain on the allow-list. EAB credentials are one-time throwaway credentials and must be deactivated after the tests.
- Keys and credentials are kept **outside the repo**, in `~/.config/sucm-acme-tester/` on the test host (chmod 700/600).
- The server binds an EAB kid to the first account key it sees. The tester therefore persists its account key, and
  certbot its config dir, so the same account can be reused across runs.
- The server is trust-based (no real domain validation): authorizations are created already `valid` and certbot goes straight to finalize.
  Wildcard certificates are not supported, by design.

## Run log 2026-10-23
| Time | Event | Outcome |
|------|-------|---------|
| 10:29 | Account 10015 requested, EAB credentials received | Account `pending` |
| 10:30 | First run, account not activated | `newAccount` → `unauthorized: not yet activated` (L2-11, OK). The EAB signature was already accepted here. |
| 10:32 | Account activated (TOPdesk 123), domain added. Run 1 | Protocol level PASS; the account was bound to the tester's first (unsaved) key. |
| 10:33 | Run 2 with a new random key | `EAB credential is already bound to a different account key` (L3-12, OK, but exposed a tester bug: the key was not persisted). Account 10015 consumed. |
| 10:36 | Tester changed: account key is persisted in the state dir | Fix |
| 10:38 | New account (10016), new EAB, activated | `newAccount`, `newOrder`, authz PASS |
| 10:39 | Finalize | **FAIL** `serverInternal`: `[ACME] ca_plugin_name / secret_path missing from config` (see F1) |
| 10:53 | `[ACME]` added **temporarily for testing** directly on cert-test-app02 in `/local/cert-app/conf/sucm_conf.ini` (`Harica_EAB`, `SUCMTEST/test/ssl/`, empty notify_group_id). Backup: `sucm_conf.ini.bak-acmetest`. App reloaded via `touch sucm.wsgi`. | Overwritten by the next salt highstate (F2). |
| 10:56 | Full level 1 (`pytest -m level1`) | **8/8 PASS**, one certificate issued for `acmetest-haak0644.it.su.se` |
| 10:58 | Revoke of own cert via ACME | **FAIL** (F6) |
| later | Levels 2–4 without issuance | 31 passed, 2 failed (F7, F8) |
| 2026-10-26 15:20 | **Rerun against SUCM v0.14.0** (fix commit `73dee23` "ACME revoke bug fix" deployed). Non-issuing tests (`-m "not issuance"`) | 37 passed, 2 failed (F7 and F8 unchanged) |
| 15:21 | Level 1 with issuance + new revoke steps | order 10024 → cert_id 181 issued (second real Harica cert, F4). **Certificate row now created** (F6 fixed), ACME revoke of own cert **succeeded** (audit.log: `account 10016 revoked certificate 181`, serial `0x300c8ab27e76d40f9e267565fffc3660`) |
| 15:22 | Revoke the same cert again | `unauthorized` instead of `alreadyRevoked` (F9, minor) |

## Run 2 – SUCM v0.14.0 (2026-10-26)
**Setup:** SUCM v0.14.0 on sucm-test (includes `73dee23` "ACME revoke bug fix"), `[ACME]` now rendered by salt, account 10016, run from haak0644.it.su.se as haak0644 with the tester code at its commit on that date.

**Commands and outcome**
| Command | Issues cert? | Result |
|---------|--------------|--------|
| `pytest -m "not issuance" tests` | no | 37 passed, 2 failed (L3-08 RS256, L4-03), 2 deselected |
| `pytest tests/test_level1_happy_path.py -v` | yes (order 10024, cert_id 181) | 9 passed, 1 failed (`TestRevoke::test_7`, L3-02b) |

**Comparison with run 1 (v0.12.0)**
| Test | Run 1 (v0.12.0) | Run 2 (v0.14.0) | Comment |
|------|-----------------|-----------------|---------|
| L1-01–L1-08 | PASS (after temporary `[ACME]`) | PASS | Cert 181, `Certificate` row created |
| L3-02 revoke own cert | FAIL (F6) | **PASS** | Fixed. Audit log: `account 10016 revoked certificate 181` |
| L3-02b revoke again | not tested | FAIL | `unauthorized` instead of `alreadyRevoked` (F9). `test_7` was corrected afterwards and **not rerun** (needs another real cert) |
| L3-08 RS256 with EC key | FAIL (F7) | FAIL | Unchanged, still HTTP 500 |
| L4-03 `Link` header | FAIL (F8) | FAIL | Unchanged |
| All other implemented L2–L4 tests | PASS | PASS | No regressions |

**Not run:** L1-09 (certbot, needs a second EAB account), L2-01 (renewal, issues a real cert), L2-09, L3-01, L3-03, L3-04, L4-05–L4-09.

**Side effects:** one more real, publicly trusted cert issued and revoked (cert 181, serial `0x300c8ab27e76d40f9e267565fffc3660`); cert 180 from run 1 is still unrevoked (see F4/F6). Issuance is deferred until a Harica test environment exists.

## Run 3 – SUCM v0.25.0 (2026-10-27)
**Setup:** SUCM v0.25.0 on sucm-test (released with `just release`), account 10016, run from haak0644.it.su.se as haak0644.

**Commands and outcome**
| Command | Issues cert? | Result |
|---------|--------------|--------|
| `pytest -m "not issuance"` | no | 39 passed, 4 deselected (issuance) |
| `pytest tests/test_level1_happy_path.py -v` | yes (order 10031, cert_id 181) | 10 passed (incl. `TestRevoke` test_6 and test_7) |

**Comparison with run 2 (v0.14.0)**
| Test | Run 2 | Run 3 | Comment |
|------|-------|-------|---------|
| L3-08 RS256 with EC key | FAIL (F7) | **PASS** | Fixed, no HTTP 500 |
| L4-03 `Link` header | FAIL (F8) | **PASS** | Fixed |
| L1-01–L1-08 (issuance) | PASS | PASS | Order 10031 finalized with cert_id=181 (existing `Certificate` row reused for the same CN) |
| L3-02 revoke own cert | PASS | PASS | Audit log: `account 10016 revoked certificate 181` |
| L3-02b revoke again | FAIL (F9) | **PASS** | Fixed: `test_7` asserts the problem type `alreadyRevoked` and passes |
| All other non-issuing tests | PASS | PASS | No regressions |

**Not run:** L1-09, L2-01 and the others listed for run 2.

**Side effects:** one more real, publicly trusted cert issued and revoked (cert 181, serial `26048677086895878156064284276644153603`) at the user's request, before the Harica staging environment (F4) exists.

## Findings
| # | Finding | Cause | Action |
|---|---------|-------|--------|
| F1 | `finalize` returns HTTP 500 `ACME issuance is not configured on this server` | Commit `9b3a26a` ("Refactoring and hardening") moved `ca_plugin_name`/`secret_path` from hardcoded values (`Harica_EAB`, `SUCMTEST/test/ssl/`) into `[ACME]` in `sucm_conf.ini`. The section is missing on sucm-test, so issuance fails closed. Expected behaviour, but blocks level 1. | Add `[ACME]` to the config **via salt** (see F2) |
| F2 | The config on sucm-test is managed by salt (`su-salt-states-services-cert`, `services/cert/app/init.sls`, `file.managed` of `/local/cert-app/conf/sucm_conf.ini`). A manual change on the server is **overwritten** on the next highstate/redeploy. | The template `files/local/cert-app/conf/sucm_conf.ini` lacks `[ACME]` | Add `[ACME]` to the template (values via `settings.sls`/pillar, different for test and prod). **FIXED 2026-10-26:** salt repo branch `test`, commit `c474734` "ACME config" (`[ACME]` in the template; `settings.sls`: prod `SUCM/prod/ssl/`, test `SUCMTEST/test/ssl/`, plugin `Harica_EAB`, empty `notify_group_id`). Verified on sucm-test: `sucm_conf.ini` rewritten 14:49 with the same `[ACME]` values. Still to do: merge `test` into `prod` before prod use |
| F3 | The server has a `[HARICA_ACME]` section that is not in the local salt template | The local salt repo may be behind the server (last commit 2026-08-19) | Verify that the template on the salt master's branch matches. **RESOLVED 2026-10-26:** `[HARICA_ACME]` (directory/kid/hmac) is in the template on branch `test` |
| F4 | `api_base_url = https://cm.harica.gr` on sucm-test (hardcoded in `settings.sls`, same for test and prod) | No separate Harica test environment configured | **Confirmed 2026-10-23: a real, publicly trusted certificate was issued.** Order 10020, `CN=acmetest-haak0644.it.su.se, O=Stockholms universitet`, issuer `CN=GEANT TLS ECC 1, O=Hellenic Academic and Research Institutions CA, C=GR`, valid until 2027-05-10, serial `0x0eecde42b50b39885829a5762fbf1910`. Will appear in CT logs. Revoke after testing (L3-02 can be used) and introduce a separate test CA for future runs |
| F5 | The tester did not persist the account key (tester bug) | Random key per run | Fixed, the key is saved in the state dir |
| F6 | **SUCM bug:** an ACME-issued cert gets no `Certificate` row, only `ActiveCertificate` (orphan). `finalize` still returns 200 and the certificate is delivered. Consequence: `revoke-cert` returns `unauthorized: No certificate issued to your account matches…` for the account's own cert (L3-02 FAIL), and renewal cannot find the existing row. | `[ACME] notify_group_id =` (empty, per `conf/sucm_conf.ini_example` "may be left empty") is read as `''` and written to the integer column `Notify_Group_Id` → MySQL 1366 *Incorrect integer value ''*. `add_update_record()` swallows the error and returns `"Failure"`, and `finalize_order()` does not check the result. Syslog 10:53:49. | (a)+(b) Code fixed in the sucm working tree (not committed/deployed): empty `notify_group_id` → `None` in `_load_acme_config()`; `submit_manual_csr()` aborts before ordering from the CA if the `Certificate` row cannot be saved. (c) Alternatively set a real `notify_group_id` in the test config. **FIXED and verified on v0.14.0 (2026-10-26):** cert 181 got its `Certificate` row and was revoked via ACME. Cert 180 (issued before the fix) still has no `Certificate` row and cannot be revoked via ACME; it must be cleaned up manually. |
| F7 | **SUCM bug:** a signature with `alg: RS256` against an EC account returns HTTP 500 with HTML instead of problem+json (L3-08) | Probably an unhandled exception in `verify_signature()` when the algorithm does not match the key type. Robustness/DoS only, no authentication bypass: the signature is not accepted | Catch all exceptions in JWS verification and respond `malformed`/`badSignatureAlgorithm`; check that `alg` fits the JWK's `kty`/`crv`. **FIXED, verified on v0.25.0 (2026-10-27)** |
| F8 | `Link: <…/directory>;rel="index"` is missing on responses (L4-03) | Not implemented | Low priority. Add in `after_request` for `/acme/*` except directory. **FIXED, verified on v0.25.0 (2026-10-27)** |
| F9 | Revoking an already revoked certificate returns `unauthorized` instead of `alreadyRevoked` (RFC 8555 7.6) | Revoked certs are no longer an active, matching certificate for the account, so lookup fails before the revoked state can be recognized | Low priority. Cosmetic for clients; certbot treats both as failure. **FIXED, verified on v0.25.0 (2026-10-27)** |
| F19 | **SUCM bug:** the served certificate chain is broken — the CA API's `fullchain` is stored/served verbatim and contains concatenated chain variants (leaf 3× at positions 0/1/5, intermediate 3×, issuer link broken after position 1) | `renew_cert_with_csr()` uses `cert_data[2]` (`fullchain`) as-is; `get_active_cert_pem()` serves it unchanged | Parse the fullchain, pick the leaf + the correct issuer chain (e.g. via `cnmatch`/issuer walk), store only that. **Found by L1-10 `test_5b` (run 5, 2026-10-28); xfail until fixed.** Limited client impact (TLS path building tolerates it) but violates RFC 8555 7.4.2 |

### Findings from the blind-spot audit (`ACME-TEST-PROTOCOL-AUDIT.md`)

The audit (code review against v0.14.0) was verified on 2026-10-28 against **sucm-test v0.28.2**: by reading the code and, where
safe, with live non-issuing probes from the shell host (no certificate was issued; the probes left a few unused `ready` orders
on the test account). Status: **CONFIRMED** (reproduced live), **CONFIRMED (code)** (seen in the code, not exercised live),
**PASS** (audit gap closed, server behaves correctly), **OUTDATED**, **UNVERIFIED** (needs more setup).

| # | Audit ref | Finding | Evidence (v0.28.2) | Status / action |
|---|-----------|---------|--------------------|-----------------|
| F10 | A2 | `account_orders` returns `{"orders": []}` even for an account with orders | Live: account with orders 10029–10031 gets `{"orders":[]}` | **CONFIRMED.** Implement (RFC 8555 7.1.2.1) or record L4-08 as known-unimplemented |
| F11 | §5 | `expires` is local time labelled `Z` | Live: order created 10:28:34 UTC returned `"expires":"2026-11-04T11:28:34Z"`; server zone is Europe/Stockholm (+1) | **CONFIRMED.** Use UTC-aware timestamps; add RFC 3339/UTC test (L4-10) |
| F12 | C1 | Order/authz expiry is stored but never enforced | Code: `expires` is only written and emitted, never compared with now; `finalize_order()` checks `status` only | **CONFIRMED (code).** Enforce expiry (RFC 8555 7.1.3/7.1.4) + test (needs time control or a DB-edited `Expires`) |
| F13 | A4 | `newAccount` for an already-registered key returns 201 | Live: re-registering the same key + EAB returned 201 (RFC 8555 7.3.1: 200) | **CONFIRMED.** Low priority; harmless for certbot |
| F14 | D2 | GET on POST-only endpoints returns Flask's HTML 405 | Live: GET `/acme/new-order`, `/new-account`, `/revoke-cert` → 405 `text/html` | **CONFIRMED.** Add problem+json `malformed`/405 handler for `/acme/*` |
| F15 | D3 | POST-as-GET with a non-empty payload is accepted | Live: order URL with payload `{"x":1}` → 200 | **CONFIRMED.** Reject non-empty payload (RFC 8555 6.3) |
| F16 | D1 | No cap on identifiers per order | Live: an order with 100 identifiers → 201 (100 authz rows). Nonce growth per response: code only | **CONFIRMED.** Record a decision / add a cap (and a rate limit on `new-nonce`) |
| F17 | C4 | Duplicate identifiers in one order create duplicate authorizations | Live: 2× same name → 201 with 2 authz URLs | **CONFIRMED.** Deduplicate or reject |
| F18 | New (found while verifying D4/C5) | Malformed payload shapes give HTTP 500 HTML: `csr` that is not valid base64url; `identifiers` not a list (`"abc"`); identifier `value` not a string (`5`) | Live: all three → 500 `text/html` (same class as F7: robustness, not an auth bypass) | **NEW, CONFIRMED.** Validate input types, return `malformed` |

Audit items that turned out fine or are outdated:

| Audit ref | Result |
|-----------|--------|
| B1 (no EAB), B2 (EAB `url` mismatch), B3 (non-HS256 EAB alg), B4 (valid kid/url/alg, wrong HMAC) | **PASS** live: `externalAccountRequired` / `unauthorized` problem+json, no 5xx. Not yet automated (L2-12…15) |
| C2 (`orderNotReady`) | **PASS** live: re-finalizing a valid order → 403 `orderNotReady`. L2-09 is easy to automate (no issuance needed) |
| C4 (invalid CSR names) / C5 | Uppercase identifier accepted (finalize compares lowercased, OK); trailing-dot FQDN and subdomain of an allowed domain → 403 `rejectedIdentifier` (correct) |
| D4 | **PASS** live: undecodable DER → `malformed` 400; CSR with a broken self-signature → `malformed` 400. (The invalid-base64 variant is F18) |
| D5 / F7 | **OUTDATED:** F7 fixed and verified on v0.25.0 (L3-08 PASS). Still worth a pinned regression test |
| G3 | **PARTLY OUTDATED:** F9 `test_7` was rerun in run 3 and passes. The `_cert_matches_leaf()` CN/SAN heuristic is **CONFIRMED (code)**; edge cases still untested |
| A3 (disabled/pending account lockout) | **UNVERIFIED:** code paths exist (`status != "active"` rejected on kid requests, `new_account`); needs an admin to deactivate a test account |
| A1 (cross-account isolation; L3-01/03/04) | **UNVERIFIED, highest priority:** needs a second account/EAB credential. Only gap that could hide a cert-theft bug |
| B5, C3 (partial-failure), C6 (non-ACME CN collision 409), §6 (chain/key/validity checks), G1 (audit log), G2 (renewal semantics, L2-01) | **UNVERIFIED:** need issuance, fault injection or log access; C6 and §6 are straightforward once a cert is issued |

Priority order for closing the gaps follows the audit (A1 → C1 → C2/C4/A3 → B1–B4 → F11 → D1 → rest), with F18 added at the level of F7.

**Result codes:** PASS / FAIL / SKIP / N/A (deliberately unsupported) / BLOCKED.
**Levels:** 1 = must work to obtain a certificate. 2 = renewal and basic negative cases. 3 = security/isolation. 4 = other RFC conformance.

## Prerequisites (before a run)
| # | Action | Done |
|---|--------|------|
| P1 | Account created in the portal, EAB credentials in `~/.config/sucm-acme-tester/tester.env` on the test host | ☑ |
| P2 | Admin has activated the account | ☑ |
| P3 | Test domain is on the account's allow-list | ☑ |
| P4 | `[ACME]` set in `sucm_conf.ini` (ca_plugin_name, secret_path, notify_group_id), **via salt** so it survives deploys | ☑ salted 2026-10-26 (see F2) |
| P4b | Clarified which Harica environment is used and that a test cert is OK (F4) | ☐ |
| P5 | Test host can reach sucm-test (directory responds) | ☑ |

## Running
```bash
cd test                  # in the sucm repo; credentials are read from ~/.config/sucm-acme-tester/tester.env
just setup && just init  # first time only, see test/README.md
just test                # all tests without issuing certificates
just issue               # level 1 including real issuance (asks first)
just certbot             # certbot smoke test (asks first; needs its own account)
```

## Level 1 – Happy path (implemented)
Rerun on v0.14.0 2026-10-26: L1-01–08 PASS again (order 10024, cert_id 181).

| ID | Test case | RFC | Expected | Automated | Result | Notes |
|----|-----------|-----|----------|-----------|--------|-------|
| L1-01 | Directory has newNonce/newAccount/newOrder | 7.1.1 | JSON with URLs | `test_directory_has_required_resources` | **PASS** | |
| L1-02 | newNonce HEAD returns Replay-Nonce | 7.2 | 200/204 + header | `test_new_nonce_returns_replay_nonce` | **PASS** | |
| L1-03 | Nonces are unique | 6.5 | two different values | `test_nonces_are_unique` | **PASS** | |
| L1-04 | newAccount with valid EAB | 7.3.4 | 200/201 + Location | `TestFlow::test_1` | **PASS** | Account active, EAB bound to saved key |
| L1-05 | newOrder for allowed domain | 7.4 | 201, status pending/ready | `TestFlow::test_2` | **PASS** | Order 10019 |
| L1-06 | Authorization(s) are valid | 7.5 | status valid (trust-based, by design) | `TestFlow::test_3` | **PASS** | |
| L1-07 | Finalize with matching CSR | 7.4 | order becomes valid + certificate URL | `TestFlow::test_4` | **PASS** | After temporary `[ACME]` config (F1). Run 2026-10-23, 8/8 in 12 s |
| L1-08 | Download certificate | 7.4.2 | `application/pem-certificate-chain`, SAN contains the domain | `TestFlow::test_5` | **PASS** | Content-Type and SAN verified. Issuer: GEANT TLS ECC 1 (see F4) |
| L1-09 | certbot certonly end-to-end | – | cert in `live/`, `openssl x509` reads it | `e2e/certbot.sh` | ☐ | Needs its own account (different key than the tester) |
| L1-10 | Chain order, signature links, pubkey match, validity, EKU | 7.4.2 | all sane | `TestFlow::test_5b`–`5e` | **PARTIAL** (run 5) | 5c/5d/5e PASS; 5b **xfail** — chain is broken (F19) |

## Level 2 – Renewal and basic negative cases (partially implemented)
| ID | Test case | RFC | Expected | Result | Notes |
|----|-----------|-----|----------|--------|-------|
| L2-01 | New order for the same domain (renewal) | 7.4 | new cert issued, replaces previous ActiveCertificate | **PASS** (black-box, run 5) | `TestRenewal` (issues + verifies the new cert carries the renewal CSR's key, then revokes). The server-side check (same `cert_id` reused, old ActiveCertificate replaced, not orphaned) still needs DB access (G2) |
| L2-02 | Domain outside allow-list | 7.4 | `rejectedIdentifier` | **PASS** | `test_l2_02` |
| L2-03 | Wildcard (`*.domain`) | 7.4 | `rejectedIdentifier` (by design, not a bug) | **PASS** | `test_l2_03` |
| L2-04 | Unknown EAB kid | 7.3.4 | `unauthorized`/`malformed` | **PASS** | `test_l2_04` |
| L2-05 | EAB with wrong HMAC | 7.3.4 | rejected | **PASS** | `test_l2_05` (random key; the rejection may partly stem from key binding, not isolated) |
| L2-06 | Reused nonce | 6.5 | `badNonce` | **PASS** | `test_l2_06` |
| L2-07 | Invalid/old nonce | 6.5 | `badNonce` | **PASS** | `test_l2_07` |
| L2-08 | Finalize with CSR whose SAN does not match the order | 7.4 | `badCSR` | **PASS** | `test_l2_08` (no issuance) |
| L2-09 | Finalize on an order that is not ready | 7.4 | `orderNotReady` | **PASS** (v0.28.2) | `test_l2_09_failed_finalize_is_retryable` (failed finalize is retryable: order stays `ready`, retry gives `badCSR` again) and `test_l2_09b_finalize_valid_order_again_is_order_not_ready` (valid order re-finalized → `orderNotReady`) |
| L2-10 | Empty identifier list / unknown identifier type | 7.4 | `malformed`/`unsupportedIdentifier` | **PASS** | `test_l2_10`, `test_l2_10b` |
| L2-11 | Account not activated | – | `unauthorized` | **PASS** (observed manually) | 10:30, `requested but not yet activated` |
| L2-12 | newAccount without EAB | 7.3.4 | `externalAccountRequired` | **PASS** (v0.28.2) | `test_l2_12` |
| L2-13 | EAB with wrong inner `url` | 7.3.4 | rejected | **PASS** (v0.28.2) | `test_l2_13` |
| L2-14 | EAB with HS384/HS512 alg | 7.3.4 | rejected | **PASS** (v0.28.2) | `test_l2_14` (2 variants) |
| L2-15 | EAB with wrong HMAC, isolated from key binding | 7.3.4 | rejected | **PASS** (v0.28.2) | `test_l2_15` |
| L2-16 | Duplicate identifiers in one order | 7.4 | deduplicated or rejected | ☐ implemented as xfail (F17) | `test_l2_16_duplicate_identifiers_rejected` |

## Level 3 – Security and isolation (partially implemented)
| ID | Test case | RFC | Expected | Result | Notes |
|----|-----------|-----|----------|--------|-------|
| L3-01 | Account B fetches account A's order/authz/cert, or finalizes it | 10.x | denied/404 | **PASS** (v0.28.2) | `test_l3_01a`–`d` (order, authz, finalize, cert download). Needs a second account (`ACME_EAB_KID_2`) |
| L3-02 | Revoke own cert | 7.6 | 200 | **PASS** (v0.14.0) | `TestRevoke::test_6`. Earlier FAIL on v0.12.0 (F6). Cert 181 revoked 2026-10-26 15:22. Cert 180 (order 10020, pre-fix) is still not revoked |
| L3-02b | Revoke the same cert again | 7.6 | `alreadyRevoked` | **PASS** (v0.25.0) | `TestRevoke::test_7`. Earlier FAIL (F9, fixed) |
| L3-03 | Revoke another account's cert | 7.6 | `unauthorized` | **PASS** (v0.28.2) | `test_l3_03` (self-signed cert with A's CN, submitted by B; also pins the F9/G3 CN-collision edge case) |
| L3-04 | Revoke with wrong issuer/serial | 7.6 | denied | **PASS** (v0.28.2) | `test_l3_04` (self-signed cert, unrelated CN) |
| L3-05 | Invalid signature | 6.2 | `malformed`/`unauthorized` | **PASS** | `test_l3_05` |
| L3-06 | `url` in header ≠ request URL | 6.4 | rejected | **PASS** | `test_l3_06` |
| L3-07 | Both `jwk` and `kid` | 6.2 | `malformed` | **PASS** | `test_l3_07` |
| L3-08 | Unsupported alg (`none`, HS256 on outer JWS, RS256 with EC key) | 6.2 | `badSignatureAlgorithm`/`malformed`, no 500 | **PASS** (v0.25.0) | `test_l3_08`. Earlier FAIL (F7, fixed) |
| L3-09 | Broken JSON, empty body, wrong Content-Type | 6.2 | problem+json, no 500 | **PASS** | `test_l3_09`, `test_l3_09b` (5 variants + wrong Content-Type, all 4xx) |
| L3-10 | Oversized body (5 MB) | – | rejected | **PASS** | `test_l3_10` |
| L3-11 | SQL-like/hostile identifier (SQLi, 5000 chars, CRLF) | – | rejected, no 500 | **PASS** | `test_l3_11` (4 variants) |
| L3-12 | newAccount with already-bound EAB kid and a different key | 7.3.4 | rejected | **PASS** | Manually at 10:33 and automated `test_l3_12` |
| L3-13 | Disabled account is locked out of all endpoints | – | `unauthorized` everywhere | ☐ implemented (opt-in) | `test_l3_13`; needs `ACME_DISABLED_*` creds + admin deactivation, see `tester.env.example` |

## Level 4 – Other conformance (partially implemented)
| ID | Test case | RFC | Expected | Result | Notes |
|----|-----------|-----|----------|--------|-------|
| L4-01 | Error responses are `application/problem+json` with `urn:ietf:params:acme:error:*` | 6.7 | yes | **PASS** | `test_l4_01` |
| L4-02 | Replay-Nonce on all responses, including errors | 6.5 | yes | **PASS** | `test_l4_02` |
| L4-03 | `Link: <directory>;rel="index"` | 7.1 | yes | **PASS** (v0.25.0) | `test_l4_03`. Earlier FAIL (F8, fixed) |
| L4-04 | `Cache-Control: no-store` on newNonce | 7.2 | yes | **PASS** | `test_l4_04` |
| L4-05 | `onlyReturnExisting` | 7.3.1 | supported or N/A | ☐ | |
| L4-06 | Account update / deactivate | 7.3.2, 7.3.6 | supported or N/A | ☐ | |
| L4-07 | Key rollover | 7.3.5 | supported or N/A | ☐ | |
| L4-08 | Order list for account | 7.1.2.1 | supported or N/A | ☐ implemented as xfail (F10) | `test_l4_08_account_orders_lists_orders` |
| L4-09 | ARI (RFC 9773) | 9773 | supported or N/A | ☐ | |
| L4-10 | `expires` is RFC 3339 and UTC | 7.1.3 | yes | ☐ implemented as xfail (F11) | `test_l4_10_expires_is_rfc3339_utc` |
| L4-11 | GET on POST-only endpoint returns problem+json | 6.7 | yes | ☐ implemented as xfail (F14) | `test_l4_11_get_on_post_only_endpoint_is_problem_json` |
| L4-12 | POST-as-GET with non-empty payload rejected | 6.3 | yes | ☐ implemented as xfail (F15) | `test_l4_12_post_as_get_with_payload_rejected` |
| L4-13 | Malformed payload shapes never give 5xx | 6.2 | yes | ☐ implemented as xfail (F18) | `test_l4_13_malformed_payload_shapes_never_5xx` (2 variants), `test_l4_13b_bad_base64_csr_never_5xx` |
| L4-13b | Re-registration with same key returns 200 | 7.3.1 | yes | ☐ implemented as xfail (F13) | `test_l4_13b_reregistration_returns_200` |

## Run 4 – SUCM v0.28.2 (2026-10-28)
**Setup:** SUCM v0.28.2 on sucm-test, two accounts (the tester's own + a second for the isolation tests),
run from cljo1227's machine. New audit-derived tests implemented: L2-09, L2-12…15, L3-01a–d, L3-03, L3-04,
C4/C5, L4-08, L4-10, L4-11, L4-12, L4-13, F13.

| Command | Issues cert? | Result |
|---------|--------------|--------|
| `just issue` (level 1 + issuance) | yes (order 10103, authz 10203) | 10 passed; order URL saved to `last_order_url` |
| `just test` (`-m "not issuance"`) | no | **56 passed, 4 deselected, 7 xfailed** |

- Cross-account isolation (A1) now fully covered and green: L3-01a–d (order/authz/finalize/cert) and
  L3-03 (cross-account revoke; self-signed cert with A's CN → `unauthorized`, no `alreadyRevoked` leak) and
  L3-04 (unrelated self-signed cert → `unauthorized`).
- EAB negatives B1–B4 green: L2-12 `externalAccountRequired`, L2-13 wrong EAB url, L2-14 HS384/HS512, L2-15 wrong HMAC.
- L2-09 both directions green: failed finalize is retryable (`badCSR` again), re-finalize of a valid order → `orderNotReady`.
- 7 strict xfails pin the confirmed open findings: F10 (orders list stub), F11 (`expires` TZ), F13 (re-registration 201),
  F14 (HTML 405), F15 (non-empty POST-as-GET), F18 ×2 (malformed payload shapes → 500). The bad-base64url-`csr`
  variant of F18 no longer reproduces on v0.28.2 (returns 4xx), so `test_l4_13b_bad_base64_csr_never_5xx` is a passing
  regression test, not an xfail.

**Side effects:** one real, publicly trusted cert issued and revoked (order 10103), as with previous runs.

## Run 5 – SUCM v0.28.2 (2026-10-28, later same day)
**Setup:** as run 4, plus the newly implemented L1-10 (certificate content, audit §6), L2-01 (renewal, audit G2,
black-box part), L2-16 (duplicate identifiers, F17) and the opt-in L3-13 (disabled account, A3).

| Command | Issues cert? | Result |
|---------|--------------|--------|
| `just issue` | yes (orders 10154–10157, all revoked) | first attempt: **16 passed, 1 FAILED** (`test_5b_chain_is_leaf_first_and_links`) → new finding F19; after marking it xfail: **16 passed, 1 xfailed** |
| `just test` | no | 56 passed, 1 skipped (L3-13, opt-in), 8 xfailed |

**New finding (F19, confirmed live):** the served certificate chain is broken. The Harica API's `fullchain`
field contains multiple chain variants concatenated (leaf 3×, GEANT TLS ECC 1 intermediate 3×, HARICA root
variants), and SUCM stores/serves it verbatim (`sucm_certificate.py` `renew_cert_with_csr()` →
`commit_fullchain_to_db()` → `get_active_cert_pem()`). Observed chain: leaf at positions 0, 1 and 5;
`chain[1].issuer != chain[2].subject`. Real-world impact is limited (TLS clients build their own path from
the leaf + intermediates and typically ignore duplicates/misordering), but it violates RFC 8555 7.4.2's
`application/pem-certificate-chain` contract and would confuse strict clients. `test_5b` pins it as strict
xfail. The other L1-10 checks pass: pubkey matches the CSR key, EKU is serverAuth, validity period sane,
every cert's signature verifies against the following cert's key.

**L2-01 renewal (black-box part) passes:** second order for the same domain issues a new cert carrying the
renewal CSR's key, downloads fine, and is revoked afterwards (order 10155+). The server-side part of G2
(same `cert_id` reused, old ActiveCertificate replaced rather than orphaned) still needs a DB check.

## Run 6 – real certbot (L1-09), SUCM v0.28.x (2026-10-30)
**Setup:** certbot 5.9.0 on the shell host, `test/e2e/certbot.sh`, throwaway account 10021 (own EAB credentials via
`ACME_CERTBOT_EAB_KID`/`ACME_CERTBOT_EAB_HMAC_KEY`; the tester's EAB is bound to the tester's account key and is
rejected for certbot's key), allow-listed domain `haak0644.it.su.se`.

| Command | Issues cert? | Result |
|---------|--------------|--------|
| `ACME_STATE_DIR=<tmp> ./e2e/certbot.sh` | yes (real Harica cert) | **PASS**: account registered, cert issued, `openssl verify` OK |

Certificate: CN=haak0644.it.su.se, issuer GEANT TLS ECC 1, serial `5DD319B9EC39A89D575A43A0519C0EC6`,
valid until 2027-05-17. **L1-09 = PASS.**

**F19 reconfirmed with a real client:** the `fullchain.pem` certbot received contains 8 certificates (leaf at
positions 0, 1 and 5; GEANT intermediate 3x; root variants). Cause is the Harica `GetCertificate` response (see
Run 5); `harica_eab.download_certificate()` joins every PEM block verbatim without deduplication. certbot and
`openssl verify` accept it. Proposed fix: deduplicate and order leaf-first in `download_certificate()`.

## Summary (updated after each run)
| Level | PASS | FAIL | BLOCKED | Not run | Accepted? |
|-------|------|------|---------|---------|-----------|
| 1 | 11 (L1-01–08, L1-10 partial) | 0 | 0 | 1 (L1-09 certbot); L1-10 5b xfail (F19) | ☐ (waiting for certbot + F19 fix) |
| 2 | 16 (L2-01–15) | 0 | 0 | 0 (+1 xfail: L2-16/F17) | ☐ |
| 3 | 15 (L3-01a–d, 02, 02b, 03, 04, 05–12) | 0 | 0 | 1 (L3-13, opt-in) | ☐ |
| 4 | 5 (L4-01–04 + bad-csr regression) | 0 | 0 | 5 (L4-05–07, 09) + 7 xfail (L4-08, 10–13, F13) | ☐ |

**Status 2026-10-28 (run 4, v0.28.2):** the whole flow with the custom client works (directory → newAccount with EAB → newOrder → authz →
finalize → cert), after `[ACME]` was added temporarily (F1). On v0.14.0 (2026-10-26) the F6 fix is verified: issued certs get a
`Certificate` row and can be revoked via ACME. On v0.25.0 (2026-10-27, run 3) F7, F8 and F9 are fixed and all implemented tests pass. Open: certbot smoke
test (L1-09), Harica being production (F4: two real certs issued, 180 not revoked, 181 revoked). Run 4 added the audit-derived tests:
all cross-account isolation (A1) and EAB negative (B1–B4) tests pass; the remaining confirmed findings F10, F11, F13, F14, F15, F18
are pinned as strict xfails. Run 5 (same day) added L1-10, L2-01, L2-16 and the opt-in L3-13, and found **F19**:
the served certificate chain is the CA's raw concatenated `fullchain` (leaf ×3, scrambled intermediates) — pinned as
xfail in `test_5b` until the server stores a proper leaf+chain.

**Recommendation (go / no-go for SUCM v0.12.0 ACME):** `________` (decided once level 1 is green)

## Planned: tests from the audit (not yet automated)

| ID | Test | Audit/finding | Needs |
|----|------|---------------|-------|
| ~~L2-09~~ | ~~Re-finalize a valid order → `orderNotReady`~~ | C2 | **done, PASS (run 4)** |
| ~~L2-12…15~~ | ~~EAB negatives: missing, wrong `url`, non-HS256, wrong HMAC~~ | B1–B4 | **done, PASS (run 4)** |
| ~~L3-01/03/04~~ | ~~Cross-account order/authz/cert/revoke isolation~~ | A1 | **done, PASS (run 4)** |
| L3-13 | Disabled account cannot sign requests | A3 | admin deactivation |
| ~~L4-10~~ | ~~`expires` is RFC 3339 and within ±1 min of UTC now + 7 d~~ | F11 | **implemented, xfail until F11 fixed** |
| ~~L4-11~~ | ~~Non-POST on `/acme/*` returns problem+json~~ | F14 | **implemented, xfail until F14 fixed** |
| ~~L4-12~~ | ~~Non-empty POST-as-GET payload rejected~~ | F15 | **implemented, xfail until F15 fixed** |
| ~~L4-13~~ | ~~Malformed payload shapes never give 5xx~~ | F18, D4 | **implemented: 2 xfail (F18 shapes) + 1 PASS (bad-base64 csr, fixed)** |
| ~~L2-16~~ | ~~Duplicate identifiers~~ | F17 | **implemented, xfail (run 5)** — cap part still pending a decision (F16) |
| ~~L1-10~~ | ~~Chain order, signature to root, key match, validity~~ | §6 | **implemented (run 5): 5c–5e PASS, 5b xfail (F19)** |
| L3-13 | Disabled account cannot sign requests | A3 | **implemented (opt-in, run 5)** — needs `ACME_DISABLED_*` + admin deactivation |

Tests for confirmed findings (F10–F18) are implemented as **expected-fail (xfail)** until fixed.

## Planned: real ACME clients (Level 5)

Decision (2026-10-26): add real-client end-to-end tests **after** the open findings (F7, F8, F9) are fixed, so that
client failures point at new problems rather than known ones. The design can be prepared earlier.

| ID | Client | Scope | Status |
|----|--------|-------|--------|
| L5-01 | certbot | register with EAB, issue, renew, revoke (`e2e/certbot.sh`, today only L1-09 issue) | ☐ |
| L5-02 | acme.sh | register with EAB, issue, renew | ☐ |
| L5-03 | lego | register with EAB, issue | ☐ |
| L5-04 | cert-manager / Caddy / Traefik | whichever clients are used in practice at SU | ☐ |

Prerequisites: one ACME account per client (the server binds an EAB kid to the first account key), the test
domain on each account's allow-list, and a Harica test environment (F4) before more real certificates are issued.
Ask before any real issuance.

## After testing
- ☐ Accounts 10015/10016 (and any later test accounts) deactivated, EAB keys invalid
- ☐ `tester.env` and `account_key.pem` deleted from the test host
- ☐ Test cert/ActiveCertificate and Vault entries cleaned up (cert 180 not revoked and without `Certificate` row, orphan ActiveCertificate 10090; cert 181 revoked but its Vault entry/rows remain)
- ☑ Temporary `[ACME]` section replaced by the salt template (2026-10-26)
- ☐ `sucm_conf.ini.bak-acmetest` deleted from `/local/cert-app/conf/` on cert-test-app02 (still present)
