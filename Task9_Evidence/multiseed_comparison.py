#!/usr/bin/env python3
"""
Task 9 multi-seed comparison -- SHIELD-GH vs SOA1/SOA2/SOA3.

Supervisor flagged that SOA1/SOA3's near-perfect single-run scores were
implausible. Investigation found (in order):
  1. Real data-leakage bugs in SOA1/SOA3 (fixed).
  2. A real attack-model bug: should_drop_grey_hole() re-rolled a drop
     decision on every ARQ retransmission retry, compounding a documented
     60% drop rate into ~99%+ black-hole-like loss (fixed).
  3. The deepest issue: this NS-3 simulation has ZERO run-to-run
     randomness at a fixed CLI config -- confirmed by running the same
     command 5 times and getting bit-identical CSVs/MCC. A single "real
     NS-3 run" is therefore one arbitrary deterministic sample, not a
     validated result. Fixed by wiring a new --rng_run flag into the
     grey-hole drop-decision seed (routing.cc), defaulting to run=1 so
     every prior single-run result is reproduced unchanged unless a
     script explicitly asks for a different seed.

This script runs all four methods across N_SEEDS values of --rng_run and
reports mean +/- spread, instead of a single (arbitrary) data point.

Run:
  cd scratch/Task9_Evidence && python3 multiseed_comparison.py
"""
from __future__ import annotations

import csv
import os
import subprocess
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
NS3_BUILD_ROOT = os.path.expanduser("~/ns-allinone-3.35/ns-3.35-g62build")
BUILD_LIB = os.path.join(NS3_BUILD_ROOT, "build", "lib")
BUILD_BIN = os.path.join(NS3_BUILD_ROOT, "build")
ROUTING_BIN = os.path.join(BUILD_BIN, "scratch", "routing")
RESULTS_ROOT = os.path.expanduser("~/ns-allinone-3.35/ns-3.35/62/results")

SOA1_DIR = os.path.expanduser("~/ns-allinone-3.35/ns-3.35/62/scratch/soa1_dpgha_malik")
SOA3_DIR = os.path.expanduser("~/ns-allinone-3.35/ns-3.35/62/scratch/State_of_Art_3")
SOA2_DIR = os.path.expanduser("~/ns-allinone-3.35/ns-3.35/62/scratch/soa2_blockchain_scbc_vcbc")
sys.path.insert(0, SOA1_DIR)
sys.path.insert(0, SOA3_DIR)
sys.path.insert(0, SOA2_DIR)

SEEDS = [1, 2, 3, 4, 5]
SIM_TIME = 10
ATTACK_PCT = 40
BASE_ARGS = [
    "--routing_test=true", f"--simTime={SIM_TIME}", "--routing_algorithm=4",
    "--attack_number=1", f"--attack_percentage={ATTACK_PCT}",
]


def run_routing(extra_args, seed):
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = BUILD_LIB + ":" + BUILD_BIN + ":" + env.get("LD_LIBRARY_PATH", "")
    cmd = [ROUTING_BIN] + BASE_ARGS + extra_args + [f"--rng_run={seed}"]
    r = subprocess.run(cmd, cwd=NS3_BUILD_ROOT, env=env, capture_output=True,
                        text=True, timeout=120)
    return r.stdout + r.stderr


def mcc_from_confusion(TP, TN, FP, FN):
    import math
    eps = 1e-6
    num = (TP * TN) - (FP * FN)
    den = math.sqrt((TP + FP + eps) * (TP + FN + eps) *
                    (TN + FP + eps) * (TN + FN + eps))
    return num / den if den else 0.0


def shieldgh_mcc(seed):
    log = run_routing(["--detection_mode=lightweight", "--enable_signatures=1"], seed)
    import re
    m = re.findall(r"CUM M1b MCC:\s*(-?[\d.]+)", log)
    return float(m[-1]) if m else float("nan")


def soa1_mcc(seed):
    import dpgha_sweep_real as s
    csv_path = os.path.join(RESULTS_ROOT, "malik_detection.csv")
    if os.path.exists(csv_path):
        os.remove(csv_path)
    run_routing(["--use_malik_detection=1"], seed)
    if not os.path.exists(csv_path):
        return float("nan")
    nodes = s.aggregate_from_csv(csv_path)
    r = s.evaluate(nodes)
    return r["mcc"]


def soa3_mcc(seed):
    import soa3_rf_sweep_real as s
    csv_path = os.path.join(RESULTS_ROOT, "soa3_rf_features.csv")
    if os.path.exists(csv_path):
        os.remove(csv_path)
    run_routing(["--use_soa3_detection=1", "--N_Vehicles=4"], seed)
    if not os.path.exists(csv_path):
        return float("nan")
    df = s.engineer_features(s.load_features(csv_path))
    res = s.evaluate_rf_cv(df)
    if res is None:
        return float("nan")
    return float(np.mean(res["mcc"]))


def soa2_mcc(seed):
    import scbcvcbc_bridge as b
    csv_path = os.path.join(RESULTS_ROOT, "vcbc_detection.csv")
    if os.path.exists(csv_path):
        os.remove(csv_path)
    run_routing(["--use_vcbc_detection=1"], seed)
    if not os.path.exists(csv_path):
        return float("nan")
    node_ids, delivered, not_delivered, is_attacker, windows = b.aggregate(csv_path)
    status = b.run_local(node_ids, delivered, not_delivered)
    TP = TN = FP = FN = 0
    for n in node_ids:
        mal = 1 if status[n] in ("grey", "black") else 0
        a = is_attacker[n]
        if mal and a: TP += 1
        elif mal and not a: FP += 1
        elif not mal and a: FN += 1
        else: TN += 1
    return mcc_from_confusion(TP, TN, FP, FN)


def main():
    methods = [
        ("SHIELD-GH (proposed)", shieldgh_mcc),
        ("SOA1 (Malik DPGHA)", soa1_mcc),
        ("SOA2 (SCBC/VCBC)", soa2_mcc),
        ("SOA3 (Random Forest)", soa3_mcc),
    ]
    results = {}
    for name, fn in methods:
        vals = []
        for seed in SEEDS:
            v = fn(seed)
            vals.append(v)
            print(f"  [{name}] rng_run={seed}: MCC={v:+.4f}")
        results[name] = vals

    print("\n" + "=" * 78)
    print(f" MULTI-SEED SUMMARY ({len(SEEDS)} seeds, t={SIM_TIME}s, attack_percentage={ATTACK_PCT}%)")
    print("=" * 78)
    out_csv = os.path.join(HERE, "multiseed_results.csv")
    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["method", "seed", "mcc"])
        for name, vals in results.items():
            for seed, v in zip(SEEDS, vals):
                w.writerow([name, seed, f"{v:.4f}"])
        w.writerow([])
        w.writerow(["method", "mean_mcc", "std_mcc", "min_mcc", "max_mcc"])
        for name, vals in results.items():
            arr = np.array(vals, dtype=float)
            w.writerow([name, f"{np.nanmean(arr):.4f}", f"{np.nanstd(arr):.4f}",
                        f"{np.nanmin(arr):.4f}", f"{np.nanmax(arr):.4f}"])
    for name, vals in results.items():
        arr = np.array(vals, dtype=float)
        print(f"  {name:24s} mean={np.nanmean(arr):+.4f}  std={np.nanstd(arr):.4f}  "
              f"range=[{np.nanmin(arr):+.4f}, {np.nanmax(arr):+.4f}]")
    print(f"\n[multiseed] CSV -> {out_csv}")


if __name__ == "__main__":
    main()
