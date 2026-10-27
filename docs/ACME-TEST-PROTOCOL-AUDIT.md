# ACME Test Protocol – Blind-spot audit

| Field | Value |
|-------|-------|
| Audited document | `docs/ACME-TEST-PROTOCOL.md` (as of the v0.14.0 rerun, 2026-10-26) |
| Audit date / author | 2026-10-27 / code review against the current working tree |
| Scope | Gaps in the *test coverage* of the ACME layer (`/acme/...`), cross-referenced against `sucm_acme_server_routes.py`, `sucm_acme_order.py`, `sucm_acme_account.py`, `sucm_acme_jws.py`, `sucm_acme_nonce.py`, `sucm_certificate.py` |
| Out of scope | Findings already tracked in the protocol (F1–F9, L1-09, Harica test environment, L5 real clients) |

This document lists test-coverage blind spots found by auditing the test protocol against the actual
implementation. It does not modify the existing protocol or tests; each item notes whether closing it
needs a new/changed test, a code change, or both.

## 1. Security / isolation (highest priority)

### A1. Cross-account authorization is untested
L3-01 (account B reads A's order/authz/cert), L3-03 (B revokes A's cert) and L3-04 (revoke with wrong
issuer/serial) are all unrun. Every ownership check in the server
(`order["account_id"] != acct["account_id"]` in `get_order`/`get_authz`/`challenge`/`download_cert`,
the order-walk in `revoke_cert`) currently has **zero** automated coverage. A single wrong comparison
here is an account-takeover / cert-theft primitive, and it is exactly the class of bug happy-path
black-box testing will never see. **Needs: a second test account + the three tests.**

### A2. `account_orders` is a stub returning `{"orders": []}`
`sucm_acme_server_routes.py` `account_orders()` ignores the account's real orders. L4-08 is marked
"not run" as if the outcome were unknown — against the current code it would *fail*, or worse, a test
written against the stub would pass and certify broken behavior (RFC 8555 7.1.2.1). The protocol
should record it as **known-unimplemented**, not "supported or N/A". **Needs: code fix or explicit
documentation; then a test.**

### A3. Disabled-account lockout is untested
L2-11 covers only `pending`. The `disabled` branch exists in both `new_account()` and
`_verify_outer_jws()` (`status != "active"` rejects *all* kid-signed requests — no new orders, no
revoke, no cert downloads). The protocol's own "After testing" checklist relies on deactivation as
the kill switch, but nothing proves a disabled account is actually locked out end-to-end.
**Needs: test (disable account mid-run, verify all endpoints reject).**

### A4. EAB binding race / re-registration only tested sequentially
L3-12 tests "already-bound EAB kid + different key" one request at a time. The atomic
`bind_jwk()` (`WHERE Jwk_Json IS NULL`) exists specifically for the *concurrent* race; no test fires
two parallel first-`newAccount` requests with different keys. Also untested: re-sending `newAccount`
with the *same* key (idempotent re-registration — certbot does this on every run; the server currently
returns 201 where RFC 8555 7.3 says 200 for an existing account). **Needs: concurrency test +
idempotent-replay test.**

## 2. EAB negative coverage is thin

The outer JWS is well tested (L3-05–09) but the inner EAB JWS barely at all:

- **B1.** No test for **missing `externalAccountBinding`** → should return the specific
  `externalAccountRequired` error (the directory advertises `externalAccountRequired: true`; the
  pairing is untested).
- **B2.** No test for EAB with a **wrong inner `url`** (the check in `_verify_eab()`).
- **B3.** No test for EAB with a **wrong alg** — note `verify_signature()` *supports* HS384/HS512 but
  `SUPPORTED_EAB_ALGS` only allows HS256; that allow-list is unexercised.
- **B4.** L2-05's own notes admit the "wrong HMAC" rejection "may partly stem from key binding, not
  isolated" — a bad HMAC alone has never been proven to be the reason for rejection.
- **B5.** The EAB credential remains valid indefinitely and gates every re-registration attempt; no
  test verifies that deactivating an account actually invalidates its EAB (code-wise it does via the
  `disabled` → `unauthorized` path, but see A3 — never exercised).

## 3. Order lifecycle gaps

- **C1. Expiry is stored but never enforced — untested because unimplemented.**
  `ORDER_TTL_DAYS`/`AUTHZ_TTL_DAYS` (7 days) are written to the DB, and nothing in
  `get_order`/`finalize`/`get_authz` ever compares `expires` to now. An expired order can still be
  finalized; an expired authz stays `valid`. This is both an RFC 8555 7.1.3/7.1.4 conformance bug and
  a test hole that hides it. **Needs: code enforcement + test.**
- **C2. L2-09 (`orderNotReady`) is wrongly described as "hard to reach".** It is trivially reachable:
  finalize an already-`valid` order a second time, or finalize an `invalid` (previously failed) order.
  Both are realistic client behaviors (certbot retry) and untested. Related: **retry semantics after
  a failed finalize** (order left `invalid` with `error` set) are unexamined.
- **C3. Partial-failure side effects of finalize.** `finalize_order()` marks the order `processing`
  *before* contacting the CA and `invalid` on exception. If failure happens after Harica accepted the
  order but before Vault/DB persistence, the result is a cert issued at the CA with the ACME order in
  `invalid` — an untracked, publicly-trusted certificate. F6 fixed one variant (missing `Certificate`
  row); no test probes the remaining partial-failure paths (e.g. CA reachable, Vault write fails).
- **C4. Multi-identifier orders are completely untested.** Every issuance test uses a single domain.
  Nothing tests: 2+ domains on one order, a CSR covering a strict subset of the order's names
  (allowed by the `issubset` check), duplicate identifiers in one order (creates duplicate authzs —
  effect unknown), or the CN-less CSR fallback (`sorted(csr_names)[0]`).
- **C5. Identifier normalization boundary cases.** L2-02/L2-03/L3-11 cover outside-allow-list,
  wildcards and hostile strings, but not: uppercase identifiers (allow-list matching lowercases, but
  the *stored* authz keeps the original case — does the finalize CSR subset check still match?),
  FQDN with trailing dot, punycode/IDN, or subdomain scoping (allow-list entry `example.it.su.se`
  must not permit `x.example.it.su.se`; code says no, no test proves it).
- **C6. The non-ACME CN collision guard** (`finalize_order()`: existing non-ACME `Certificate` with
  the same CN → 409 `rejectedIdentifier`) has no test — a conflict-avoidance control that has never
  been exercised.

## 4. DoS / robustness surface

- **D1. No rate-limiting or resource-exhaustion tests at all.** A `Replay-Nonce` issuance is a DB
  `INSERT` on *every* response, and `/acme/new-nonce` is unauthenticated at the Apache layer — an
  anonymous client can grow `AcmeNonce` unboundedly between scheduler `prune_expired()` runs.
  Similarly `newOrder` has **no cap on identifier count** (L3-11 tested a 5000-char single identifier;
  nobody sent 10,000 identifiers in one order, which inserts 10,000 authz rows). L3-10 (5 MB body) is
  the only size test. **Needs at minimum a recorded decision; ideally caps + tests.**
- **D2. HTTP method mismatches return HTML.** GET on a POST-only endpoint returns Flask's default HTML
  405 — violating the layer's own "errors are `application/problem+json`, never HTML" invariant
  (module docstring of `sucm_acme_server_routes.py`), which is only tested for JWS-level errors
  (L3-09/L4-01).
- **D3. POST-as-GET with a non-empty payload is silently ignored** by `get_order`/`get_authz`/
  `download_cert`. RFC 8555 6.3 says the payload MUST be the empty string; servers should reject
  otherwise. Untested either way.
- **D4. Malformed CSR inside a well-formed JWS.** L2-08 tests SAN mismatch only. Nothing tests
  undecodable DER (`b64url_decode` / `load_der_x509_csr` failure path), a CSR with an invalid
  self-signature (`is_signature_valid` check), or a weak/absurd key (e.g. 512-bit RSA). The code paths
  exist; the tests don't.
- **D5. F7 (alg/key-type mismatch → HTTP 500) lacks a pinned regression test at the unit level.**
  The generic `except Exception` in `verify_signature()` is meant to catch this class, but L3-08 is
  still listed FAIL and nothing pins "alg/key-type mismatch → 4xx problem+json, never 500".

## 5. Timestamp bug no current test would catch

`_order_to_json()` / `_authz_to_json()` emit `order["expires"].isoformat() + "Z"` over
`datetime.now()` — **naive local time labelled as UTC**. If the app server is not on UTC, every
`expires` in every response is wrong by the TZ offset. There is no RFC 3339 format test at all in
level 4, so this sails through L1–L4 and only bites a client that honors `expires`.
**Needs: code fix (UTC-aware timestamps) + format test.**

## 6. Certificate content verification is shallow

L1-08 checks Content-Type and SAN presence only. Nothing verifies:
- the **chain is complete and ordered** (leaf first, intermediates after — RFC 8555 7.4.2
  `application/pem-certificate-chain`);
- the delivered PEM **cryptographically validates** against the Harica root;
- the cert's **public key matches the CSR's key**;
- the validity period.

A truncated or misordered chain passes the current suite and breaks real TLS clients. (The certbot
e2e, L1-09, would catch some of this — another reason its absence matters.)

## 7. Operational / observability blind spots

- **G1. Audit logging is asserted nowhere in the automated suite.** The run log mentions eyeballing
  `audit.log` once. No test asserts that newOrder/finalize/revoke produce the expected audit entries
  — the compliance trail for a trust-based CA front-end deserves automation.
- **G2. ACME renewal semantics are unverified.** The scheduler skips `cert_type == "ACME"` (renewal is
  client-driven), and `finalize` reuses the existing `Certificate` row when the CN matches an ACME
  cert. The interaction "second order for same CN → same `cert_id` → new `ActiveCertificate`" is
  entirely unverified, including what happens to the *old* ActiveCertificate row (replaced or
  orphaned?). L2-01 is the intended test and is unrun.
- **G3. F9's fix is fragile and untested in its edge cases.** The tree now resolves `alreadyRevoked`
  via a CN/SAN *heuristic* (`_cert_matches_leaf()`). Untested consequences: re-revoking a cert whose
  CN doesn't match any of the account's stored rows still returns `unauthorized`
  (correct-but-inconsistent), and submitting another party's already-revoked cert whose CN collides
  with one of *your* revoked certs leaks `alreadyRevoked`. Minor — but `test_7` was corrected after
  the run and never rerun, so even the happy re-revoke path is currently unpinned.

## Suggested priority for closing the gaps

1. **A1** — second account; run L3-01/03/04 (resolve A2 first, L4-08 will collide with the stub).
   This is the only gap that could hide a cert-theft bug.
2. **C1** — order/authz expiry enforcement + test (currently dead code pretending to be a control).
3. **C2, C4, A3** — re-classify L2-09 as easy (re-finalize a valid order), add a multi-identifier
   order test, add a disabled-account lockout test. All cheap, all touch realistic certbot behavior.
4. **B1–B5** — EAB negative tests; completes the one authentication mechanism the layer has.
5. **Section 5** — UTC-aware `expires` + RFC 3339 format test.
6. **D1** — DoS guards (identifier-count cap, nonce-table growth) or at minimum a recorded decision,
   since the endpoints are unauthenticated at the Apache layer by design.
7. **Section 6** — chain-validation assertions in L1-08 (or explicitly accept that L1-09/L5 certbot
   covers it and say so in the protocol).
