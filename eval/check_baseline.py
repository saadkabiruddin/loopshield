#!/usr/bin/env python3
"""Baseline check: does the closed loop hold the setpoint?

Pass = after settling, the TRUE room temperature stays within +/-band of the
setpoint for at least --hold seconds, and the controller reported zero
deadline misses (if stats.jsonl from the controller is present).

Usage: python3 eval/check_baseline.py runs/<timestamp> [--setpoint 22] [--band 0.5] [--hold 600]
"""
import argparse
import csv
import json
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--setpoint", type=float, default=22.0)
    ap.add_argument("--band", type=float, default=0.5)
    ap.add_argument("--hold", type=float, default=600.0, help="required seconds in band")
    a = ap.parse_args()

    with open(a.run_dir / "plant.csv", newline="") as f:
        rows = [(float(r["t_s"]), float(r["true_temp_c"])) for r in csv.DictReader(f)]
    if not rows:
        print("plant.csv is empty")
        return 1

    # Settling time: the first sample after which the temperature never leaves the band.
    settle_idx = None
    for i in range(len(rows) - 1, -1, -1):
        if abs(rows[i][1] - a.setpoint) > a.band:
            break
        settle_idx = i
    t_end = rows[-1][0]

    print(f"run:            {a.run_dir}")
    print(f"duration:       {t_end:.1f} s, {len(rows)} samples")
    if settle_idx is None:
        print(f"settled:        NO (last sample {rows[-1][1]:.3f} C)")
        return 1

    t_settle = rows[settle_idx][0]
    after = [t for _, t in rows[settle_idx:]]
    max_err = max(abs(t - a.setpoint) for t in after)
    held = t_end - t_settle
    print(f"settled at:     {t_settle:.1f} s (within +/-{a.band} C from then on)")
    print(f"held in band:   {held:.1f} s (need {a.hold:.0f})")
    print(f"max |error|:    {max_err:.3f} C after settling")

    ok = held >= a.hold

    stats_path = a.run_dir / "stats.jsonl"
    if stats_path.exists() and stats_path.stat().st_size > 0:
        last = json.loads(stats_path.read_text().strip().splitlines()[-1])
        print(f"controller:     jobs={last['jobs']} misses={last['misses']} "
              f"wcrt={last['wcrt_us']} us stale={last['stale']}")
        ok = ok and last["misses"] == 0
    else:
        print("controller:     no stats.jsonl (deadline misses not checked)")
        ok = False

    print("RESULT:         " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
