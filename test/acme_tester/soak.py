"""Soak test: `python -m acme_tester.soak` (or `just soak`).

Orders a REAL certificate every ACME_SOAK_INTERVAL seconds (default 300) for ACME_SOAK_HOURS hours (default 24),
revokes it again (ACME_SOAK_REVOKE=0 to keep), and appends one CSV row per attempt with the time of each step.
Rows are flushed and fsynced as they are written, so `python -m acme_tester.soak_report` works during the run.

Stops cleanly after the current attempt on Ctrl-C/SIGTERM, when <state dir>/soak.stop exists, after
ACME_SOAK_MAX_FAILS (default 6) consecutive failures, or after ACME_SOAK_MAX_ITER attempts (default 0 = no limit).
Attempts run on a fixed grid; if one overruns, the missed slots are skipped (no catch-up burst).
Set ACME_POST_TIMEOUT (seconds, default 60) above the longest finalize you expect to measure.
"""

import csv
import math
import os
import signal
import sys
import time
from datetime import datetime, timezone

import requests
from cryptography import x509

from acme_tester.client import AcmeClient, AcmeProblem, b64, make_csr
from acme_tester.config import STATE_DIR, Config

COLUMNS = [
    "ts_utc",
    "iter",
    "outcome",
    "http_status",
    "new_order_s",
    "authz_s",
    "finalize_post_s",
    "poll_s",
    "finalize_total_s",
    "download_s",
    "revoke_s",
    "total_s",
    "cert_serial",
    "order_url",
    "error",
]
STEP_COLUMN = {
    "new_order": "new_order_s",
    "authz": "authz_s",
    "finalize": "finalize_post_s",
    "poll": "poll_s",
    "download": "download_s",
    "revoke": "revoke_s",
}
POLL_MAX = 300
_stop = False


def _num(name, default):
    value = os.environ.get(name) or ""
    return type(default)(float(value)) if value else default


def _handle_signal(signum, _frame):
    global _stop
    _stop = True
    print(f"\nsignal {signum}: stopping after the current attempt", flush=True)


def _attempt(client, cfg, revoke):
    row = dict.fromkeys(COLUMNS, "")
    row["ts_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t_start = time.perf_counter()
    step, t_step = "new_order", t_start
    try:
        order_url, order = client.new_order([cfg.test_domain])
        row["order_url"] = order_url
        row["new_order_s"] = round(time.perf_counter() - t_step, 3)

        step, t_step = "authz", time.perf_counter()
        for authz_url in order["authorizations"]:
            authz = client.post(authz_url, None).json()
            if authz["status"] != "valid":
                raise RuntimeError(f"authorization status {authz['status']}")
        row["authz_s"] = round(time.perf_counter() - t_step, 3)

        csr_der, _key = make_csr([cfg.test_domain])
        step, t_step = "finalize", time.perf_counter()
        t_finalize = t_step
        result = client.post(order["finalize"], {"csr": b64(csr_der)}).json()
        row["finalize_post_s"] = round(time.perf_counter() - t_step, 3)

        step, t_step = "poll", time.perf_counter()
        while result["status"] in ("processing", "ready") and time.perf_counter() - t_step < POLL_MAX:
            time.sleep(3)
            result = client.get_order(order_url)
        row["poll_s"] = round(time.perf_counter() - t_step, 3)
        row["finalize_total_s"] = round(time.perf_counter() - t_finalize, 3)
        if result["status"] != "valid":
            raise RuntimeError(f"order status {result['status']}")

        step, t_step = "download", time.perf_counter()
        resp = client.download(result["certificate"])
        row["download_s"] = round(time.perf_counter() - t_step, 3)
        pem = resp.content
        row["cert_serial"] = format(x509.load_pem_x509_certificates(pem)[0].serial_number, "x")

        if revoke:
            step, t_step = "revoke", time.perf_counter()
            client.revoke(pem)
            row["revoke_s"] = round(time.perf_counter() - t_step, 3)
        row["outcome"] = "ok"
    except AcmeProblem as exc:
        row["outcome"] = f"{step}_error"
        row["http_status"] = exc.status
        row["error"] = str(exc)[:300]
    except requests.Timeout as exc:
        row["outcome"] = f"{step}_timeout"
        row["error"] = type(exc).__name__
    except Exception as exc:  # keep soaking; the row records what happened
        row["outcome"] = f"{step}_error"
        row["error"] = f"{type(exc).__name__}: {exc}"[:300]
    if row["outcome"] != "ok" and not row[STEP_COLUMN[step]]:
        row[STEP_COLUMN[step]] = round(time.perf_counter() - t_step, 3)
        if step in ("finalize", "poll") and not row["finalize_total_s"]:
            row["finalize_total_s"] = round(time.perf_counter() - t_finalize, 3)
    row["total_s"] = round(time.perf_counter() - t_start, 3)
    return row


def _wait_until(target, deadline):
    while not _stop and time.monotonic() < min(target, deadline):
        if os.path.exists(os.path.join(STATE_DIR, "soak.stop")):
            return
        time.sleep(1)


def main():
    cfg = Config.from_env()
    if not (cfg.directory_url and cfg.eab_kid and cfg.eab_hmac_key and cfg.test_domain):
        sys.exit("ACME_DIRECTORY, ACME_EAB_KID, ACME_EAB_HMAC_KEY and ACME_TEST_DOMAIN must be set (see `just doctor`)")
    stop_file = os.path.join(STATE_DIR, "soak.stop")
    if os.path.exists(stop_file):
        sys.exit(f"{stop_file} exists; remove it to start")

    interval = _num("ACME_SOAK_INTERVAL", 300.0)
    hours = _num("ACME_SOAK_HOURS", 24.0)
    revoke = (os.environ.get("ACME_SOAK_REVOKE") or "1") != "0"
    max_fails = _num("ACME_SOAK_MAX_FAILS", 6)
    max_iter = _num("ACME_SOAK_MAX_ITER", 0)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log = os.environ.get("ACME_SOAK_LOG") or os.path.join(STATE_DIR, f"soak-{stamp}.csv")

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    client = AcmeClient(cfg.directory_url, verify=cfg.verify, key_file=cfg.account_key_file)
    client.new_account(cfg.eab_kid, cfg.eab_hmac_key)
    print(
        f"soak: {cfg.directory_url} domain={cfg.test_domain} every {interval:.0f}s for {hours:g}h "
        f"revoke={revoke} post-timeout={os.environ.get('ACME_POST_TIMEOUT') or 60}s\nlog: {log}",
        flush=True,
    )

    start = time.monotonic()
    deadline = start + hours * 3600
    slot, n, fails = start, 0, 0
    with open(log, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        fh.flush()
        while not _stop and time.monotonic() < deadline and not os.path.exists(stop_file):
            n += 1
            row = _attempt(client, cfg, revoke)
            row["iter"] = n
            writer.writerow(row)
            fh.flush()
            os.fsync(fh.fileno())
            print(
                f"{row['ts_utc']} #{n} {row['outcome']} finalize={row['finalize_total_s']}s total={row['total_s']}s"
                + (f" {row['error']}" if row["error"] else ""),
                flush=True,
            )
            fails = 0 if row["outcome"] == "ok" else fails + 1
            if max_fails and fails >= max_fails:
                print(f"stopping: {fails} consecutive failures", flush=True)
                break
            if max_iter and n >= max_iter:
                break
            slot += interval
            now = time.monotonic()
            if now > slot:
                slot += math.ceil((now - slot) / interval) * interval
            _wait_until(slot, deadline)
    print(f"done: {n} attempts, log {log}", flush=True)


if __name__ == "__main__":
    main()
