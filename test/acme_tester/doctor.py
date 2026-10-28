"""Pre-flight check: `python -m acme_tester.doctor` (or `just doctor`). Sends no ACME requests that change state."""

import os
import sys

import requests

from acme_tester.config import STATE_DIR, Config


def main():
    cfg = Config.from_env()
    ok = True

    def report(good, text):
        nonlocal ok
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {text}")

    print(f"state dir: {STATE_DIR}")
    env_file = os.path.join(STATE_DIR, "tester.env")
    report(os.path.exists(env_file), f"{env_file} exists (copy tester.env.example)")
    if os.path.exists(env_file):
        mode = os.stat(env_file).st_mode & 0o077
        report(mode == 0, "tester.env is private (chmod 600)")
    report(bool(cfg.directory_url), "ACME_DIRECTORY set")
    report(bool(cfg.eab_kid and cfg.eab_hmac_key), "ACME_EAB_KID / ACME_EAB_HMAC_KEY set")
    report(bool(cfg.test_domain), "ACME_TEST_DOMAIN set")

    if cfg.directory_url:
        try:
            resp = requests.get(cfg.directory_url, verify=cfg.verify, timeout=15)
            report(resp.status_code == 200, f"directory reachable (HTTP {resp.status_code})")
            needed = {"newNonce", "newAccount", "newOrder", "revokeCert"}
            report(needed <= set(resp.json()), "directory has the required endpoints")
        except (requests.RequestException, ValueError) as exc:
            report(False, f"directory not reachable: {exc}")

    print("ready" if ok else "not ready")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
