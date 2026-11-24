"""Summarise a soak log: `python -m acme_tester.soak_report [file.csv]` (default: the newest soak-*.csv in the state dir).

Safe to run while the soak is still going. Prints outcome counts, percentiles for finalize and total time,
how many attempts exceeded common client timeouts, and a per-hour table.
"""

import csv
import glob
import os
import statistics
import sys
from collections import Counter, defaultdict

from acme_tester.config import STATE_DIR

THRESHOLDS = (30, 45, 60, 90)


def _pct(values, p):
    values = sorted(values)
    return values[min(len(values) - 1, int(round(p / 100 * (len(values) - 1))))]


def _stats(values):
    if not values:
        return "-"
    return (
        f"n={len(values)} min={min(values):.1f} p50={_pct(values, 50):.1f} p90={_pct(values, 90):.1f} "
        f"p99={_pct(values, 99):.1f} max={max(values):.1f} mean={statistics.mean(values):.1f}"
    )


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if not path:
        files = sorted(glob.glob(os.path.join(STATE_DIR, "soak-*.csv")))
        if not files:
            sys.exit(f"no soak-*.csv in {STATE_DIR}")
        path = files[-1]
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        sys.exit("log has no rows yet")

    def nums(col, only_ok=False):
        return [float(r[col]) for r in rows if r[col] != "" and (not only_ok or r["outcome"] == "ok")]

    print(f"{path}\n{rows[0]['ts_utc']} .. {rows[-1]['ts_utc']}  attempts={len(rows)}")
    print("outcomes:", dict(Counter(r["outcome"] for r in rows)))
    print("finalize_total_s (ok)  ", _stats(nums("finalize_total_s", True)))
    print("finalize_total_s (all) ", _stats(nums("finalize_total_s")))
    print("total_s (ok)           ", _stats(nums("total_s", True)))
    for col in ("new_order_s", "authz_s", "download_s", "revoke_s"):
        print(f"{col:<23}", _stats(nums(col, True)))
    fin = nums("finalize_total_s")
    if fin:
        print("finalize over:", ", ".join(f"{t}s: {sum(v > t for v in fin)}" for t in THRESHOLDS))
    print("\nper hour (UTC): attempts ok fail finalize_max_s")
    by_hour = defaultdict(list)
    for r in rows:
        by_hour[r["ts_utc"][:13]].append(r)
    for hour, rs in sorted(by_hour.items()):
        ok = sum(r["outcome"] == "ok" for r in rs)
        fins = [float(r["finalize_total_s"]) for r in rs if r["finalize_total_s"] != ""]
        print(f"{hour}  {len(rs):>3} {ok:>3} {len(rs) - ok:>3}  {max(fins) if fins else '-'}")
    errors = [r for r in rows if r["outcome"] != "ok"]
    if errors:
        print("\nlast errors:")
        for r in errors[-5:]:
            print(f"  {r['ts_utc']} #{r['iter']} {r['outcome']} {r['error'][:120]}")


if __name__ == "__main__":
    main()
