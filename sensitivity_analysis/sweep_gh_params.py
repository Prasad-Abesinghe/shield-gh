#!/usr/bin/env python3
"""
Task 8.5 -- Full-system design-parameter sensitivity sweep (supervisor
instruction, 2026-08-08):

  "Identify all the tunable design parameters (some of them are already
  mentioned in the simulation along with the sweep range). Sweep over the
  full range in equal step of the variable/parameter and inspect the
  performance and select the parameter with best performance. Keep all
  other values default when sweeping a parameter. You can write one python
  script to fully automate this task. After finishing it, you need to set
  those found optimum parameters as settings of the simulation. Just need
  30s sweep for one data point in the sweep. No need to have multiple seeds."

The 7 parameters swept here are exactly the ones already documented with a
grid range in main.tex's Table tab:gh_sensitivity (Sec. "Sensitivity
Analysis and Threshold Selection") -- the report explicitly marks that
table provisional ("the observed-MCC column is populated as the full
defence-on sweep is completed"). None of the 7 previously had a CLI path;
routing.cc now exposes them as --sg_W, --sg_tau_f, --sg_eps_f, --sg_tau_it,
--sg_gamma_it, --sg_tau_ts, --sg_theta_R (see routing.cc, "Task 8.5
sensitivity-analysis CLI surface").

  Parameter (report symbol)      CLI flag        Grid (equal step, from main.tex)
  W  (observation window, slots) --sg_W          {5, 10, 20}
  tau_f   (S1 PDR threshold)     --sg_tau_f      {0.50, 0.60, 0.70}
  epsilon_f (S1 variance bound)  --sg_eps_f      {0.10, 0.20, 0.30}
  tau_it  (S2 per-slot thresh.)  --sg_tau_it     {0.60, 0.70, 0.80}
  gamma_it (S2 autocorrelation)  --sg_gamma_it   {1.10, 1.30, 1.50}
  tau_ts  (S3 KL-divergence)     --sg_tau_ts     {0.30, 0.50, 0.70}
  theta_R (DEBSC isolation)      --sg_theta_R    {0.30, 0.40, 0.50}

Each grid point = ONE real 15s NS-3 run (lightweight detection mode, S1-S6
rule signatures + DEBSC on, --attack_number=1 --drop_rate=60
--routing_algorithm=4 --architecture=0 --maxspeed=80 -- the Task 8 evidence
run's operating point). One data point per value, no repeated seeds, per
the supervisor's instruction. All parameters besides the one being swept
are held at their current compiled-in default. Fitness = the real,
end-of-run cumulative M1b MCC the simulation itself prints ("CUM M1b MCC:"),
the same metric Task 8's PEM report uses.

After the sweep, the best (highest-MCC) value per parameter is selected and
written to sensitivity_analysis/optimal_params.json; a separate step
(apply_optimal_params.py) edits routing.cc's sg_* defaults to match.

Run (from scratch/sensitivity_analysis/):
  python3 sweep_gh_params.py                # full 7-parameter sweep (~20 min)
  python3 sweep_gh_params.py --dry-run       # print the run plan, no NS-3 calls
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD_ROOT = os.path.expanduser("~/ns-allinone-3.35/ns-3.35-g62build")
BUILD_LIB = os.path.join(BUILD_ROOT, "build", "lib")
BUILD_BIN = os.path.join(BUILD_ROOT, "build")
ROUTING_BIN = os.path.join(BUILD_BIN, "scratch", "routing")

SIM_TIME = 15  # supervisor (2026-08-09): "Just run for 15s sensitivity
                # analysis each data point. Can be completed within 3 hours."
                # (revises the earlier 30s instruction; 15s is now the value
                # used for the applied optimal_params.json defaults)

# Fixed operating point (Task 8 evidence run), everything not being swept
# stays at these values -- and at each parameter's OWN compiled-in default
# from routing.cc (sg_W=10, sg_tau_f=0.75, ... see BASE_DEFAULTS below).
BASE_ARGS = [
    "--detection_mode=lightweight",
    "--enable_signatures=1",
    "--attack_number=1",
    "--drop_rate=60",
    f"--simTime={SIM_TIME}",
    "--routing_algorithm=4",
    "--architecture=0",
    "--maxspeed=80",
]

# Compiled-in defaults (routing.cc, "Task 8.5 sensitivity-analysis CLI
# surface"), used as "keep all other values default when sweeping a
# parameter" -- i.e. every OTHER flag below is passed explicitly at its
# default value on every run, so the sweep is never accidentally affected
# by argv-parsing order or a stale value from a previous flag.
BASE_DEFAULTS = dict(
    sg_W=10, sg_tau_f=0.75, sg_eps_f=0.20, sg_tau_it=0.70,
    sg_gamma_it=1.30, sg_tau_ts=0.50, sg_theta_R=0.60,
)

# (flag, grid values, report symbol, description) -- grid = main.tex tab:gh_sensitivity
PARAMS = [
    ("sg_W",        [5, 10, 20],          "W",         "Observation window (slots)"),
    ("sg_tau_f",    [0.50, 0.60, 0.70],   "tau_f",     "S1 PDR threshold"),
    ("sg_eps_f",    [0.10, 0.20, 0.30],   "epsilon_f", "S1 variance bound"),
    ("sg_tau_it",   [0.60, 0.70, 0.80],   "tau_it",    "S2 per-slot threshold"),
    ("sg_gamma_it", [1.10, 1.30, 1.50],   "gamma_it",  "S2 autocorrelation"),
    ("sg_tau_ts",   [0.30, 0.50, 0.70],   "tau_ts",    "S3 KL-divergence threshold"),
    ("sg_theta_R",  [0.30, 0.40, 0.50],   "theta_R",   "DEBSC reputation isolation threshold"),
]

MCC_RE = re.compile(r"CUM M1b MCC:\s*(-?[\d.]+)")
CONF_RE = re.compile(r"Cum TP=(\d+) TN=(\d+) FP=(\d+) FN=(\d+)")
ACC_RE = re.compile(r"CUM M1a Detection Accuracy:\s*([\d.]+)%")
FPR_RE = re.compile(r"CUM M2\s+False Positive Rate:\s*([\d.]+)%")


def run_one(flag, value):
    args = dict(BASE_DEFAULTS)
    args[flag] = value
    cli = [ROUTING_BIN] + BASE_ARGS + [f"--{k}={v}" for k, v in args.items()]
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = BUILD_LIB + ":" + BUILD_BIN + ":" + env.get("LD_LIBRARY_PATH", "")
    t0 = time.time()
    r = subprocess.run(cli, cwd=BUILD_ROOT, env=env, capture_output=True,
                        text=True, timeout=180)
    wall_s = time.time() - t0
    log = r.stdout + r.stderr
    mcc_matches = MCC_RE.findall(log)
    conf_matches = CONF_RE.findall(log)
    acc_matches = ACC_RE.findall(log)
    fpr_matches = FPR_RE.findall(log)
    if not mcc_matches:
        raise RuntimeError(f"no 'CUM M1b MCC:' line in output for {flag}={value} "
                            f"(rc={r.returncode}); tail:\n{log[-1500:]}")
    mcc = float(mcc_matches[-1])
    tp, tn, fp, fn = (int(x) for x in conf_matches[-1]) if conf_matches else (0, 0, 0, 0)
    acc = float(acc_matches[-1]) if acc_matches else float("nan")
    fpr = float(fpr_matches[-1]) if fpr_matches else float("nan")
    return dict(flag=flag, value=value, mcc=mcc, TP=tp, TN=tn, FP=fp, FN=fn,
                acc=acc, fpr=fpr, wall_s=round(wall_s, 1), cmd=" ".join(cli))


def sweep_param(flag, grid, symbol, desc, dry_run=False):
    print(f"\n[{flag}] {desc} -- grid {grid} (others at default: {BASE_DEFAULTS})")
    results = []
    for v in grid:
        if dry_run:
            args = dict(BASE_DEFAULTS); args[flag] = v
            print(f"  [DRY] would run: {ROUTING_BIN} " + " ".join(BASE_ARGS) +
                  " " + " ".join(f"--{k}={x}" for k, x in args.items()))
            continue
        r = run_one(flag, v)
        results.append(r)
        print(f"  {symbol}={v!s:<6} -> MCC={r['mcc']:+.4f}  "
              f"TP={r['TP']} TN={r['TN']} FP={r['FP']} FN={r['FN']}  "
              f"ACC={r['acc']:.1f}%  FPR={r['fpr']:.1f}%  ({r['wall_s']:.1f}s)")
    return results


def pick_best(results):
    """Best = highest MCC; ties broken by the value closest to the grid
    midpoint (stable, matches main.tex's own tie-breaking note: 'retained
    operating point is the mid-grid, literature-consistent configuration')."""
    if not results:
        return None
    best_mcc = max(r["mcc"] for r in results)
    tied = [r for r in results if abs(r["mcc"] - best_mcc) < 1e-9]
    if len(tied) == 1:
        return tied[0]
    mid_idx = len(results) // 2
    mid_value = results[mid_idx]["value"]
    tied.sort(key=lambda r: abs(r["value"] - mid_value))
    return tied[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                     help="print the run plan (21 commands) without invoking NS-3")
    ap.add_argument("--only", default=None,
                     help="comma-separated flag names to sweep (default: all 7)")
    args = ap.parse_args()

    if not args.dry_run and not os.path.exists(ROUTING_BIN):
        sys.exit(f"routing binary not found at {ROUTING_BIN} -- build it first "
                  f"(cd {BUILD_ROOT} && ./waf build --targets=routing)")

    only = set(args.only.split(",")) if args.only else None
    all_results = {}
    for flag, grid, symbol, desc in PARAMS:
        if only and flag not in only:
            continue
        all_results[flag] = sweep_param(flag, grid, symbol, desc, dry_run=args.dry_run)

    if args.dry_run:
        print("\n[dry-run] no NS-3 runs executed, no files written.")
        return

    # ---- CSV of every run ----
    csv_path = os.path.join(HERE, "gh_param_sweep_results.csv")
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["flag", "value", "MCC", "TP", "TN", "FP", "FN", "ACC_pct",
                    "FPR_pct", "wall_s"])
        for flag, results in all_results.items():
            for r in results:
                w.writerow([r["flag"], r["value"], f"{r['mcc']:.4f}", r["TP"],
                            r["TN"], r["FP"], r["FN"], f"{r['acc']:.2f}",
                            f"{r['fpr']:.2f}", r["wall_s"]])
    print(f"\n[sweep] CSV -> {csv_path}")

    # ---- pick best value per parameter ----
    optimal = {}
    print("\n" + "=" * 78)
    print(" BEST VALUE PER PARAMETER (highest CUM M1b MCC, 15s single-point run)")
    print("=" * 78)
    for flag, grid, symbol, desc in PARAMS:
        if flag not in all_results:
            continue
        best = pick_best(all_results[flag])
        default = BASE_DEFAULTS[flag]
        optimal[flag] = dict(symbol=symbol, desc=desc, grid=grid,
                              default=default, best_value=best["value"],
                              best_mcc=best["mcc"],
                              default_mcc=next(
                                  (r["mcc"] for r in all_results[flag]
                                   if r["value"] == default), None),
                              changed=(best["value"] != default))
        flag_txt = "CHANGED" if optimal[flag]["changed"] else "unchanged"
        print(f"  {symbol:10s} ({desc:32s}): default={default}  "
              f"best={best['value']}  MCC={best['mcc']:+.4f}  [{flag_txt}]")

    opt_path = os.path.join(HERE, "optimal_params.json")
    with open(opt_path, "w") as f:
        json.dump(optimal, f, indent=2)
    print(f"\n[sweep] optimal parameters -> {opt_path}")

    plot_all(all_results, optimal)
    print("\n[sweep] DONE. Next: python3 apply_optimal_params.py "
          "to write these as the new routing.cc defaults.")


def plot_all(all_results, optimal):
    n = len(all_results)
    if n == 0:
        return
    cols = 4
    rows = (n + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(5 * cols, 4 * rows))
    axes = axes.flatten() if n > 1 else [axes]
    for ax, (flag, results) in zip(axes, all_results.items()):
        xs = [r["value"] for r in results]
        ys = [r["mcc"] for r in results]
        best = optimal[flag]["best_value"]
        colors = ["#d62728" if x == best else "#1f77b4" for x in xs]
        ax.bar([str(x) for x in xs], ys, color=colors)
        ax.set_title(f"{optimal[flag]['symbol']} — {optimal[flag]['desc']}")
        ax.set_ylabel("CUM M1b MCC")
        ax.set_ylim(min(0, min(ys) - 0.05), 1.05)
        ax.grid(True, alpha=0.3, axis="y")
        ax.axhline(0, color="black", linewidth=0.6)
    for ax in axes[len(all_results):]:
        ax.axis("off")
    fig.suptitle("Task 8.5 — Full-system design-parameter sensitivity sweep "
                  "(real 15s NS-3 runs, red = best)", fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    out = os.path.join(HERE, "fig7_gh_param_sweep.png")
    fig.savefig(out, dpi=140)
    plt.close(fig)
    print(f"[sweep] figure -> {out}")


if __name__ == "__main__":
    main()
