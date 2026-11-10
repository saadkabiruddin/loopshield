#!/usr/bin/env python3
"""Turn a harness session into the attack x defense matrix, plots and tables.

    eval/.venv/bin/python eval/analyze.py runs/matrix-YYYYMMDD-HHMMSS [--out results/]

Per run (one attack, one defense config, one trial):
  detected      an ENABLED layer flagged the attack inside the attack window
                (protocol: first rejected sensor message; physics: first alarm)
  ttd_s         time from attack start to that first flag
  false_pos     an enabled layer flagged anything before the attack started
                (or anywhere, in the attack-free 'none' and 'disturb' runs)
  max_dev_c     max |true temperature - setpoint| from attack start to run end
                (ground truth from the plant, which the attacker cannot touch)
  timing        control-task execution / response time, detector execution and
                per-message protocol-check cost, from the controller's
                per-period telemetry, split into pre-attack and attack phases

Outputs (in --out, default results/<session name>/):
  runs.csv       one row per run
  matrix.csv     one row per (attack, config) cell, aggregated over trials
  matrix.md      the headline table
  matrix.tex     the same for the paper
  timing.csv/.tex  real-time cost per configuration (baseline and under flooding)
  roc.csv, roc.png  CUSUM threshold sweep, recomputed offline from logged data
  temp_<attack>.png, temp_grid.png, timing.png
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

ATTACKS = ["none", "bias", "ramp", "replay", "forgery", "flood", "disturb"]
CONFIGS = ["none", "proto", "phys", "both"]
CONFIG_LABEL = {"none": "No defense", "proto": "Protocol", "phys": "Physics", "both": "Both"}
ATTACK_LABEL = {"none": "No attack", "bias": "Bias", "ramp": "Slow ramp", "replay": "Replay",
                "forgery": "Forgery", "flood": "Flooding", "disturb": "Disturbance*"}
PERIOD_US = 100_000
SETTLE_S = 5.0          # ignore the first seconds after the plant starts
MIN_SIM_SPEED = 0.90    # controller clock / wall clock; below this a run is invalid
MIN_TELEM_COVERAGE = 0.80


# --------------------------------------------------------------------------- loading

def read_csv(path: Path) -> dict[str, np.ndarray]:
    with open(path, newline="") as f:
        rows = list(csv.reader(f))
    if len(rows) < 2:
        return {}
    head, body = rows[0], rows[1:]
    cols: dict[str, np.ndarray] = {}
    for i, name in enumerate(head):
        vals = []
        for r in body:
            try:
                vals.append(float(r[i]))
            except (ValueError, IndexError):
                vals.append(math.nan)
        cols[name] = np.array(vals)
    return cols


@dataclass
class Run:
    name: str
    dir: Path
    meta: dict
    plant: dict
    telem: dict
    stats: list
    attack_start: float     # unix ms
    attack_stop: float
    plant_start: float
    plant_end: float
    metrics: dict = field(default_factory=dict)

    @property
    def attack(self) -> str: return self.meta["attack"]

    @property
    def config(self) -> str: return self.meta["config"]

    @property
    def trial(self) -> int: return self.meta["trial"]


def load_run(d: Path) -> Run | None:
    mpath = d / "run.json"
    if not mpath.exists():
        return None
    meta = json.loads(mpath.read_text())
    if not meta.get("complete"):
        print(f"  skipping incomplete run {d.name}", file=sys.stderr)
        return None
    plant = read_csv(d / "plant.csv")
    telem = read_csv(d / "telem.csv") if (d / "telem.csv").exists() else {}
    if not plant or not telem:
        print(f"  skipping {d.name}: missing plant or telemetry data", file=sys.stderr)
        return None
    stats = [json.loads(l) for l in (d / "stats.jsonl").read_text().splitlines() if l.strip()] \
        if (d / "stats.jsonl").exists() else []

    # Row time. The firmware batches telemetry (ten rows per message), so the
    # host receive time is coarse. The controller's own release time t_ms is
    # exact; map it onto the host clock with the smallest observed
    # (receive - release) offset, i.e. the least-delayed delivery.
    telem["time_ms"] = telem["t_ms"] + np.min(telem["host_unix_ms"] - telem["t_ms"])

    plant_start = float(plant["unix_ms"][0])
    plant_end = float(plant["unix_ms"][-1])
    # Attack window: the attacker's own log is authoritative; for attack-free
    # runs use the same nominal window so metrics are comparable.
    start = stop = None
    ap = d / "attack.jsonl"
    if ap.exists():
        for line in ap.read_text().splitlines():
            ev = json.loads(line)
            if ev["event"] == "attack_start":
                start = ev["unix_ms"]
            elif ev["event"] == "attack_stop":
                stop = ev["unix_ms"]
    if start is None:
        start = plant_start + meta["warmup_s"] * 1000
    if stop is None:
        stop = start + meta["attack_s"] * 1000
    return Run(d.name, d, meta, plant, telem, stats, start, stop, plant_start, plant_end)


# --------------------------------------------------------------------------- metrics

def first_time(t: np.ndarray, mask: np.ndarray) -> float | None:
    idx = np.flatnonzero(mask)
    return float(t[idx[0]]) if idx.size else None


def detection_events(run: Run) -> dict[str, np.ndarray]:
    """Per-telemetry-row boolean 'this layer has flagged something by now'."""
    T = run.telem
    ev = {}
    if run.config in ("proto", "both"):
        rej = T["rej_mac"] + T["rej_seq"] + T["rej_fresh"] + T["rej_parse"]
        # counters are cumulative: a rise means a rejection in that period
        rise = np.diff(np.concatenate([[0.0], np.nan_to_num(rej)])) > 0
        ev["proto"] = rise
    if run.config in ("phys", "both"):
        ev["phys"] = np.nan_to_num(T["alarm"]) > 0
    return ev


def compute_metrics(run: Run) -> dict:
    T, P = run.telem, run.plant
    t = T["time_ms"]
    sp = run.meta["setpoint"]
    attack_free_run = run.attack in ("none", "disturb")

    m: dict = {"attack": run.attack, "config": run.config, "trial": run.trial}

    # --- detection / false positives
    pre_mask = (t >= run.plant_start + SETTLE_S * 1000) & (t < run.attack_start)
    in_mask = (t >= run.attack_start) & (t < run.attack_stop)
    all_mask = t >= run.plant_start + SETTLE_S * 1000

    first = {}
    fp = False
    for layer, flag in detection_events(run).items():
        if attack_free_run:
            fp |= bool(np.any(flag & all_mask))
        else:
            fp |= bool(np.any(flag & pre_mask))
            ft = first_time(t, flag & in_mask)
            if ft is not None:
                first[layer] = (ft - run.attack_start) / 1000
    m["false_pos"] = int(fp)
    if attack_free_run:
        m["detected"] = None
        m["ttd_s"] = None
    else:
        m["detected"] = int(bool(first))
        m["ttd_s"] = min(first.values()) if first else None
    m["ttd_proto_s"] = first.get("proto")
    m["ttd_phys_s"] = first.get("phys")

    # --- ground truth deviation
    pt = P["unix_ms"]
    w = pt >= run.attack_start
    m["max_dev_c"] = float(np.max(np.abs(P["true_temp_c"][w] - sp))) if w.any() else None
    pre_p = (pt >= run.plant_start + SETTLE_S * 1000) & (pt < run.attack_start)
    m["pre_max_dev_c"] = float(np.max(np.abs(P["true_temp_c"][pre_p] - sp))) if pre_p.any() else None
    # Recovery after the attack ends: e.g. PI integral wound up by a slow
    # spoof keeps overheating the room after the spoof stops (stretch goal).
    post = pt >= run.attack_stop
    if post.any() and not attack_free_run:
        err = np.abs(P["true_temp_c"][post] - sp)
        m["post_max_dev_c"] = float(err.max())
        out_band = np.flatnonzero(err > 0.5)
        if out_band.size == 0:
            m["recovery_s"] = 0.0
        elif out_band[-1] == err.size - 1:
            m["recovery_s"] = None      # still outside the band when the run ended
        else:
            m["recovery_s"] = float((pt[post][out_band[-1] + 1] - run.attack_stop) / 1000)

    # --- timing, per phase
    for phase, mask in (("pre", pre_mask), ("atk", in_mask)):
        exe, rt, de = T["ctl_exec_us"][mask], T["ctl_rt_us"][mask], T["det_exec_us"][mask]
        pn, psum, pmax = T["proto_n"][mask], T["proto_sum_us"][mask], T["proto_max_us"][mask]
        dur_s = mask.sum() * PERIOD_US / 1e6
        m[f"{phase}_ctl_exec_mean_us"] = float(np.nanmean(exe)) if exe.size else None
        m[f"{phase}_ctl_exec_max_us"] = float(np.nanmax(exe)) if exe.size else None
        m[f"{phase}_ctl_rt_max_us"] = float(np.nanmax(rt)) if rt.size else None
        m[f"{phase}_ctl_misses"] = int(np.sum(rt > PERIOD_US))
        m[f"{phase}_det_exec_mean_us"] = float(np.nanmean(de)) if de.size else None
        m[f"{phase}_det_exec_max_us"] = float(np.nanmax(de)) if de.size else None
        n = float(np.nansum(pn))
        m[f"{phase}_proto_mean_us"] = float(np.nansum(psum) / n) if n else None
        m[f"{phase}_proto_max_us"] = float(np.nanmax(pmax)) if pmax.size else None
        m[f"{phase}_msgs_per_s"] = n / dur_s if dur_s else None
        m[f"{phase}_proto_load_pct"] = float(np.nansum(psum)) / (dur_s * 1e6) * 100 if dur_s else None

    # --- whole-run counters from the controller's own stats (no telemetry loss)
    if run.stats:
        s = run.stats[-1]
        m["run_misses"] = s["misses"]
        m["run_wcrt_us"] = s["wcrt_us"]
        m["run_det_misses"] = s["det_misses"]
        m["run_tx_drops"] = s["tx_drops"]
        m["host_standin"] = int(s.get("host_standin", 0))
    m["telem_rows"] = int(t.size)

    # Validity: the plant runs on wall-clock time, so the controller must too.
    # A controller restart (its clock goes backwards) or a simulation running
    # well below real time makes the run meaningless.
    ct, host = T["t_ms"], T["host_unix_ms"]
    m["controller_reset"] = int(bool(np.any(np.diff(ct) < 0)))
    wall = (host[-1] - host[0]) if host.size > 1 else 0
    m["sim_speed"] = float((ct[-1] - ct[0]) / wall) if wall > 0 and not m["controller_reset"] else None
    expected_rows = (run.plant_end - run.plant_start) / 1000 * 10
    m["telem_coverage"] = float(t.size / expected_rows) if expected_rows > 0 else None
    m["valid"] = int(not m["controller_reset"]
                     and (m["sim_speed"] or 0) >= MIN_SIM_SPEED
                     and (m["telem_coverage"] or 0) >= MIN_TELEM_COVERAGE)
    return m


# --------------------------------------------------------------------------- aggregation

def mean(xs):
    xs = [x for x in xs if x is not None and not (isinstance(x, float) and math.isnan(x))]
    return float(np.mean(xs)) if xs else None


def maxv(xs):
    xs = [x for x in xs if x is not None and not (isinstance(x, float) and math.isnan(x))]
    return float(np.max(xs)) if xs else None


def aggregate(runs: list[Run]) -> list[dict]:
    cells = []
    for a in ATTACKS:
        for c in CONFIGS:
            rs = [r.metrics for r in runs if r.attack == a and r.config == c]
            if not rs:
                continue
            det = [r["detected"] for r in rs if r["detected"] is not None]
            cells.append({
                "attack": a, "config": c, "n": len(rs),
                "detection_rate": (sum(det) / len(det)) if det else None,
                "fp_rate": sum(r["false_pos"] for r in rs) / len(rs),
                "ttd_mean_s": mean([r["ttd_s"] for r in rs]),
                "ttd_max_s": maxv([r["ttd_s"] for r in rs]),
                "max_dev_mean_c": mean([r["max_dev_c"] for r in rs]),
                "max_dev_max_c": maxv([r["max_dev_c"] for r in rs]),
                "ctl_exec_mean_us": mean([r["atk_ctl_exec_mean_us"] for r in rs]),
                "ctl_exec_max_us": maxv([r["atk_ctl_exec_max_us"] for r in rs]),
                "ctl_rt_max_us": maxv([r["atk_ctl_rt_max_us"] for r in rs]),
                "det_exec_mean_us": mean([r["atk_det_exec_mean_us"] for r in rs]),
                "proto_mean_us": mean([r["atk_proto_mean_us"] for r in rs]),
                "proto_load_pct": mean([r["atk_proto_load_pct"] for r in rs]),
                "msgs_per_s": mean([r["atk_msgs_per_s"] for r in rs]),
                "run_misses": sum(r.get("run_misses", 0) or 0 for r in rs),
                "run_wcrt_us": maxv([r.get("run_wcrt_us") for r in rs]),
            })
    return cells


# --------------------------------------------------------------------------- tables

def fmt(x, nd=1, unit=""):
    if x is None:
        return "–"
    return f"{x:.{nd}f}{unit}"


def write_csv(path: Path, rows: list[dict]):
    if not rows:
        return
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in keys})


def cell_text(c: dict, attack_free: bool) -> str:
    if attack_free:
        return f"FP {c['fp_rate']*100:.0f}% · dev {fmt(c['max_dev_max_c'], 2)}°C"
    dr = f"{c['detection_rate']*100:.0f}%" if c["detection_rate"] is not None else "–"
    ttd = fmt(c["ttd_mean_s"], 1, " s") if c["detection_rate"] else "–"
    return f"{dr} · TTD {ttd} · dev {fmt(c['max_dev_max_c'], 2)}°C · FP {c['fp_rate']*100:.0f}%"


def write_matrix_md(path: Path, cells: list[dict], session: str, standin: bool):
    by = {(c["attack"], c["config"]): c for c in cells}
    configs = [c for c in CONFIGS if any(k[1] == c for k in by)]
    lines = [f"# Attack × defense matrix", "", f"Session: `{session}`", ""]
    if standin:
        lines += ["> **Host stand-in controller data.** Detection and deviation reflect the real",
                  "> defense code, but timing numbers are from the host, not the ESP32.", ""]
    lines += ["Each cell: detection rate · mean time-to-detect · worst true-temperature",
              "deviation from the setpoint · false-positive rate (runs with a pre-attack alarm).", "",
              "| Attack | " + " | ".join(CONFIG_LABEL[c] for c in configs) + " |",
              "|---|" + "---|" * len(configs)]
    for a in ATTACKS:
        if not any((a, c) in by for c in configs):
            continue
        row = [ATTACK_LABEL[a]]
        for c in configs:
            cell = by.get((a, c))
            row.append(cell_text(cell, a in ("none", "disturb")) if cell else "")
        lines.append("| " + " | ".join(row) + " |")
    lines += ["", "\\* Disturbance is not an attack: the ambient temperature really drops "
              "(a window opens). Any alarm there is a false positive.", "",
              "## Real-time cost under each attack (mean over trials, attack window)", "",
              "| Attack | Config | ctl exec mean/max (µs) | ctl resp max (µs) | detector mean (µs) "
              "| proto check mean (µs/msg) | msgs/s | proto CPU % | deadline misses |",
              "|---|---|---|---|---|---|---|---|---|"]
    for c in cells:
        lines.append(f"| {ATTACK_LABEL[c['attack']]} | {CONFIG_LABEL[c['config']]} "
                     f"| {fmt(c['ctl_exec_mean_us'])} / {fmt(c['ctl_exec_max_us'], 0)} "
                     f"| {fmt(c['ctl_rt_max_us'], 0)} | {fmt(c['det_exec_mean_us'])} "
                     f"| {fmt(c['proto_mean_us'])} | {fmt(c['msgs_per_s'], 0)} "
                     f"| {fmt(c['proto_load_pct'], 2)} | {c['run_misses']} |")
    path.write_text("\n".join(lines) + "\n")


def tex_escape(s: str) -> str:
    return s.replace("%", r"\%").replace("°", r"$^\circ$").replace("·", r"$\cdot$").replace("–", "--")


def write_matrix_tex(path: Path, cells: list[dict]):
    by = {(c["attack"], c["config"]): c for c in cells}
    configs = [c for c in CONFIGS if any(k[1] == c for k in by)]
    out = [r"\begin{tabular}{l" + "c" * len(configs) + "}", r"\toprule",
           "Attack & " + " & ".join(CONFIG_LABEL[c] for c in configs) + r" \\", r"\midrule"]
    for a in ATTACKS:
        if not any((a, c) in by for c in configs):
            continue
        cols = []
        for c in configs:
            cell = by.get((a, c))
            if not cell:
                cols.append("")
            elif a in ("none", "disturb"):
                cols.append(rf"\makecell{{FP {cell['fp_rate']*100:.0f}\%\\{fmt(cell['max_dev_max_c'], 2)}$^\circ$C}}")
            else:
                dr = cell["detection_rate"] or 0
                ttd = fmt(cell["ttd_mean_s"], 1, " s") if dr else "--"
                cols.append(rf"\makecell{{{dr*100:.0f}\% / {ttd}\\{fmt(cell['max_dev_max_c'], 2)}$^\circ$C"
                            rf"{' / FP ' + format(cell['fp_rate']*100, '.0f') + chr(92) + '%' if cell['fp_rate'] else ''}}}")
        out.append(tex_escape(ATTACK_LABEL[a]).replace("*", "$^*$") + " & " + " & ".join(cols) + r" \\")
    out += [r"\bottomrule", r"\end{tabular}"]
    path.write_text("\n".join(out) + "\n")


def timing_rows(runs: list[Run]) -> list[dict]:
    """Real-time cost per configuration: attack-free baseline vs under flooding."""
    rows = []
    for c in CONFIGS:
        for label, attack, phase in (("baseline", "none", "atk"), ("flooding", "flood", "atk")):
            rs = [r.metrics for r in runs if r.config == c and r.attack == attack]
            if not rs:
                continue
            rows.append({
                "config": c, "condition": label, "n": len(rs),
                "ctl_exec_mean_us": mean([r[f"{phase}_ctl_exec_mean_us"] for r in rs]),
                "ctl_exec_max_us": maxv([r[f"{phase}_ctl_exec_max_us"] for r in rs]),
                "ctl_rt_max_us": maxv([r[f"{phase}_ctl_rt_max_us"] for r in rs]),
                "det_exec_mean_us": mean([r[f"{phase}_det_exec_mean_us"] for r in rs]),
                "det_exec_max_us": maxv([r[f"{phase}_det_exec_max_us"] for r in rs]),
                "proto_mean_us": mean([r[f"{phase}_proto_mean_us"] for r in rs]),
                "proto_max_us": maxv([r[f"{phase}_proto_max_us"] for r in rs]),
                "msgs_per_s": mean([r[f"{phase}_msgs_per_s"] for r in rs]),
                "proto_load_pct": mean([r[f"{phase}_proto_load_pct"] for r in rs]),
                "misses": sum(r.get("run_misses", 0) or 0 for r in rs),
                "wcrt_us": maxv([r.get("run_wcrt_us") for r in rs]),
            })
    return rows


def write_timing_tex(path: Path, rows: list[dict]):
    out = [r"\begin{tabular}{llrrrrrr}", r"\toprule",
           r"Config & Condition & \makecell{Ctl exec\\mean/max ($\mu$s)} & \makecell{WCRT\\($\mu$s)} "
           r"& \makecell{Detector\\mean ($\mu$s)} & \makecell{Check\\($\mu$s/msg)} & \makecell{Rx\\(msg/s)} & Misses \\",
           r"\midrule"]
    for r in rows:
        out.append(f"{CONFIG_LABEL[r['config']]} & {r['condition']} & {fmt(r['ctl_exec_mean_us'])} / "
                   f"{fmt(r['ctl_exec_max_us'], 0)} & {fmt(r['wcrt_us'], 0)} & {fmt(r['det_exec_mean_us'])} & "
                   f"{fmt(r['proto_mean_us'])} & {fmt(r['msgs_per_s'], 0)} & {r['misses']} \\\\")
    out += [r"\bottomrule", r"\end{tabular}"]
    path.write_text("\n".join(out) + "\n")


# --------------------------------------------------------------------------- offline CUSUM (ROC)

def offline_residuals(run: Run, l=0.01, tau=60.0, gain=20.0, tamb=15.0, dt=0.1) -> tuple[np.ndarray, np.ndarray]:
    """Re-run the detector's observer (sg_detect.c) on the logged y and u,
    WITHOUT freezing on alarm, so every threshold sees the same residuals.
    Returns (row time ms, residual) for fresh samples."""
    T = run.telem
    t_hat = None
    ts, rs = [], []
    for t, y, fresh, u_prev in zip(T["time_ms"], T["y"], T["fresh"], T["u_prev"]):
        if t_hat is None:
            if fresh > 0 and not math.isnan(y):
                t_hat = y
            continue
        pred = t_hat + dt / tau * ((tamb - t_hat) + gain * u_prev)
        if fresh > 0 and not math.isnan(y):
            r = y - pred
            t_hat = pred + l * r
            ts.append(t)
            rs.append(r)
        else:
            t_hat = pred
    return np.array(ts), np.array(rs)


def cusum_first_crossing(r: np.ndarray, k: float, h: float) -> int | None:
    sp = sn = 0.0
    for i, x in enumerate(r):
        sp = max(0.0, sp + x - k)
        sn = max(0.0, sn - x - k)
        if sp > h or sn > h:
            return i
    return None


def roc(runs: list[Run], ks=(0.03, 0.05, 0.10), hs=None) -> list[dict]:
    """Run-level ROC. Negatives: the attack-free part of every run (pre-attack
    segment, or the whole of an attack-free run). Positives: attack runs; a
    detection is a first crossing inside the attack window with no crossing
    before it. Uses every run regardless of config: y and u are logged in all
    of them, and the offline detector is independent of the online one."""
    hs = hs or [0.25, 0.5, 1, 1.5, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48]
    data = []
    for run in runs:
        ts, rs = offline_residuals(run)
        if rs.size == 0:
            continue
        settle = run.plant_start + SETTLE_S * 1000
        keep = ts >= settle
        data.append((run, ts[keep], rs[keep]))
    out = []
    for k in ks:
        for h in hs:
            fp = neg = 0
            per_attack: dict[str, list[int]] = {}
            ttd: dict[str, list[float]] = {}
            for run, ts, rs in data:
                i = cusum_first_crossing(rs, k, h)
                t_cross = ts[i] if i is not None else None
                if run.attack in ("none", "disturb"):
                    if run.attack == "none":
                        neg += 1
                        fp += t_cross is not None
                    continue
                neg += 1
                pre_alarm = t_cross is not None and t_cross < run.attack_start
                fp += pre_alarm
                hit = (t_cross is not None and not pre_alarm and t_cross < run.attack_stop)
                per_attack.setdefault(run.attack, []).append(int(hit))
                if hit:
                    ttd.setdefault(run.attack, []).append((t_cross - run.attack_start) / 1000)
            row = {"k": k, "h": h, "fpr": fp / neg if neg else None}
            for a, hits in per_attack.items():
                row[f"tpr_{a}"] = sum(hits) / len(hits)
                row[f"ttd_{a}_s"] = mean(ttd.get(a, []))
            out.append(row)
    return out


# --------------------------------------------------------------------------- plots

def plot_all(runs: list[Run], cells: list[dict], timing: list[dict], roc_rows: list[dict], out: Path, standin: bool):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    colors = {"none": "#7f7f7f", "proto": "#1f77b4", "phys": "#d62728", "both": "#2ca02c"}
    note = " (host stand-in)" if standin else ""

    def temp_axes(ax, attack):
        drew = False
        for c in CONFIGS:
            rs = sorted([r for r in runs if r.attack == attack and r.config == c], key=lambda r: r.trial)
            if not rs:
                continue
            r = rs[0]
            t = (r.plant["unix_ms"] - r.attack_start) / 1000
            ax.plot(t, r.plant["true_temp_c"], color=colors[c], lw=1.2, label=CONFIG_LABEL[c])
            drew = True
        if not drew:
            return False
        any_run = next(r for r in runs if r.attack == attack)
        if attack not in ("none", "disturb"):
            ax.axvspan(0, (any_run.attack_stop - any_run.attack_start) / 1000, color="#f4cccc", alpha=0.5, lw=0)
        if attack in ("replay", "disturb") and any_run.meta.get("disturbance_at_s") is not None:
            dist_t = any_run.meta["disturbance_at_s"] - (any_run.attack_start - any_run.plant_start) / 1000
            ax.axvline(dist_t, color="k", ls=":", lw=1)
        sp = any_run.meta["setpoint"]
        ax.axhspan(sp - 0.5, sp + 0.5, color="#d9ead3", alpha=0.6, lw=0)
        ax.set_title(ATTACK_LABEL[attack])
        ax.set_xlabel("time from attack start (s)")
        ax.set_ylabel("true temperature (°C)")
        ax.grid(alpha=0.3)
        return True

    present = [a for a in ATTACKS if any(r.attack == a for r in runs)]
    for a in present:
        fig, ax = plt.subplots(figsize=(6, 3.4))
        if temp_axes(ax, a):
            ax.legend(fontsize=8)
            fig.suptitle(f"True room temperature{note}", fontsize=9)
            fig.tight_layout()
            fig.savefig(out / f"temp_{a}.png", dpi=150)
        plt.close(fig)

    n = len(present)
    cols = 3
    rows_n = math.ceil(n / cols)
    fig, axes = plt.subplots(rows_n, cols, figsize=(12, 3.2 * rows_n), squeeze=False)
    for ax, a in zip(axes.flat, present):
        temp_axes(ax, a)
    for ax in list(axes.flat)[n:]:
        ax.axis("off")
    handles, labels = axes.flat[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=4)
    fig.suptitle(f"True room temperature under each attack (shaded: attack window; green: ±0.5 °C){note}")
    fig.tight_layout(rect=(0, 0.05, 1, 0.97))
    fig.savefig(out / "temp_grid.png", dpi=150)
    plt.close(fig)

    # ROC
    attacks_in = sorted({k[4:] for r in roc_rows for k in r if k.startswith("tpr_")},
                        key=lambda a: ATTACKS.index(a))
    if attacks_in:
        fig, axes = plt.subplots(1, len(attacks_in), figsize=(3.4 * len(attacks_in), 3.4), squeeze=False)
        for ax, a in zip(axes.flat, attacks_in):
            for k in sorted({r["k"] for r in roc_rows}):
                pts = sorted([(r["fpr"], r.get(f"tpr_{a}")) for r in roc_rows
                              if r["k"] == k and r.get(f"tpr_{a}") is not None])
                if pts:
                    xs, ys = zip(*pts)
                    ax.plot(xs, ys, marker="o", ms=3, label=f"k={k}")
            ax.plot([0, 1], [0, 1], color="#bbb", ls="--", lw=0.8)
            ax.set_xlim(-0.02, 1.02)
            ax.set_ylim(-0.02, 1.02)
            ax.set_title(ATTACK_LABEL[a])
            ax.set_xlabel("false-positive rate")
            ax.set_ylabel("detection rate")
            ax.grid(alpha=0.3)
        axes.flat[0].legend(fontsize=8)
        fig.suptitle(f"CUSUM ROC over threshold h (offline, run level){note}")
        fig.tight_layout()
        fig.savefig(out / "roc.png", dpi=150)
        plt.close(fig)

    # timing
    if timing:
        labels = [f"{CONFIG_LABEL[r['config']]}\n{r['condition']}" for r in timing]
        x = np.arange(len(timing))
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 3.8))
        w = 0.27
        ax1.bar(x - w, [r["ctl_exec_mean_us"] or 0 for r in timing], w, label="control exec (mean)")
        ax1.bar(x, [r["det_exec_mean_us"] or 0 for r in timing], w, label="detector exec (mean)")
        ax1.bar(x + w, [r["proto_mean_us"] or 0 for r in timing], w, label="protocol check (per msg)")
        ax1.set_ylabel("µs")
        ax1.set_xticks(x, labels, fontsize=7)
        ax1.legend(fontsize=8)
        ax1.set_title("Execution cost")
        ax1.grid(axis="y", alpha=0.3)
        ax2.bar(x, [(r["wcrt_us"] or 0) / 1000 for r in timing], 0.5, color="#9467bd")
        ax2.axhline(PERIOD_US / 1000, color="r", ls="--", lw=1, label="deadline (100 ms)")
        ax2.set_ylabel("ms")
        ax2.set_xticks(x, labels, fontsize=7)
        ax2.set_title("Worst-case control response time")
        ax2.legend(fontsize=8)
        ax2.grid(axis="y", alpha=0.3)
        fig.suptitle(f"Real-time cost of the defenses{note}")
        fig.tight_layout()
        fig.savefig(out / "timing.png", dpi=150)
        plt.close(fig)


# --------------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("session", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--no-plots", action="store_true")
    a = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    out = a.out or root / "results" / a.session.resolve().name
    out.mkdir(parents=True, exist_ok=True)

    runs = [r for d in sorted(a.session.iterdir()) if d.is_dir() and (r := load_run(d))]
    if not runs:
        print("no complete runs found", file=sys.stderr)
        return 1
    for r in runs:
        r.metrics = compute_metrics(r)
    all_runs = runs
    invalid = [r for r in runs if not r.metrics["valid"]]
    for r in invalid:
        m = r.metrics
        why = "controller restarted" if m["controller_reset"] else \
              f"sim speed {m['sim_speed'] or 0:.0%}, telemetry coverage {m['telem_coverage'] or 0:.0%}"
        print(f"  EXCLUDED {r.name}: {why} (rerun it: delete its folder and rerun the harness with --out)",
              file=sys.stderr)
    runs = [r for r in runs if r.metrics["valid"]]
    if not runs:
        print("no valid runs", file=sys.stderr)
        write_csv(out / "runs.csv", [r.metrics | {"run": r.name} for r in all_runs])
        return 1
    standin = any(r.metrics.get("host_standin") for r in runs)

    cells = aggregate(runs)
    timing = timing_rows(runs)
    roc_rows = roc(runs)

    write_csv(out / "runs.csv", [r.metrics | {"run": r.name} for r in all_runs])
    write_csv(out / "matrix.csv", cells)
    write_matrix_md(out / "matrix.md", cells, a.session.name, standin)
    write_matrix_tex(out / "matrix.tex", cells)
    write_csv(out / "timing.csv", timing)
    write_timing_tex(out / "timing.tex", timing)
    write_csv(out / "roc.csv", roc_rows)
    if not a.no_plots:
        plot_all(runs, cells, timing, roc_rows, out, standin)

    print((out / "matrix.md").read_text())
    print(f"{len(runs)} runs analysed -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
