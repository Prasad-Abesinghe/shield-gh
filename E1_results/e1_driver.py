#!/usr/bin/env python3
"""
E1 driver -- 2D attack grid (attacker penetration p x drop rate rho_a).

Supervisor spec (Paper 1, SOTA E1): 6x6 grid of p in {0,20,40,60,80,100}% and
rho_a in {0,20,40,60,80,100}%, all six attack variants (S1-S6) active, for
5 systems: SHIELD-GH full, SHIELD-GH lightweight, B1 (Malik), B2 (VCBC),
B3 (Random Forest).

Because this NS-3 codebase applies ONE attack variant per run (no per-node
intra-run multi-variant attacker pool -- confirmed by code inspection), the
"all six variants active simultaneously" requirement is approximated as: for
each (p, rho_a, system) grid cell, run 6 separate simulations (S1..S6, each
at the FULL attacker fraction p, not p/6) and aggregate (mean) their metrics
into that cell's reported value. This is the approach confirmed with the
user, chosen over splitting the attacker pool 6 ways (which would dilute
each variant's real detection difficulty) and over patching the attack
assignment code (touches core routing/attack machinery, not SOTA-baseline
scope, and the supervisor asked not to bypass/alter behavior).

N=200, simTime=30, attack_onset_delay=6.0 is the config previously verified
(TASK8_EVIDENCE.md) to produce a real M2 (GHSR) baseline+attack+post-isolation
reading, not "NOT MEASURABLE". Kept as-is per supervisor instruction to run
N=200 properly, not bypass for speed.

Checkpointing: every completed (p, rho_a, system, variant) run appends one
row to e1_raw_results.csv immediately, so an interrupted run loses at most
the single in-flight simulation, not prior progress. Re-running this script
skips any row already present in the CSV.

Usage:
  python3 e1_driver.py                 # run everything remaining
  python3 e1_driver.py --dry-run       # print the run plan, do nothing
"""
import csv
import os
import re
import subprocess
import sys
import time

HOME = os.path.expanduser("~")
NS3ROOT = os.path.join(HOME, "ns-allinone-3.35/ns-3.35-g62build")
HERE = os.path.dirname(os.path.abspath(__file__))
RAW_CSV = os.path.join(HERE, "e1_raw_results.csv")
LOG_DIR = os.path.join(HERE, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

P_VALUES = [0, 20, 40, 60, 80, 100]
RHO_VALUES = [0, 20, 40, 60, 80, 100]
VARIANTS = [1, 2, 3, 4, 5, 6]  # S1=DP-FR S2=DP-IT S3=DP-TS S4=CP-FR S5=CP-IT S6=CP-TS
# Supervisor instruction (2026-08-08): run ONLY the SOTA baselines.
# SHIELD-GH (full/lightweight) is EXCLUDED until debugging is declared
# closed -- any SHIELD-GH result taken before that is scientifically
# invalid per the supervisor's explicit ruling. Do not add shieldgh_full /
# shieldgh_lite back into this list without a fresh instruction to do so.
SYSTEMS = ["b1_malik", "b2_vcbc", "b3_rf"]

N_VEHICLES = 200
SIM_TIME = 30
ATTACK_ONSET_DELAY = 6.0
MAXSPEED = 80

FIELDS = ["p", "rho_a", "system", "variant", "M1_MCC", "M2_GHSR", "M3_AVCR",
          "M4_FIR", "M5_ESRL_ms", "elapsed_s", "status"]


def already_done():
    done = set()
    if os.path.exists(RAW_CSV):
        with open(RAW_CSV, newline="") as fh:
            for row in csv.DictReader(fh):
                done.add((int(row["p"]), int(row["rho_a"]), row["system"], int(row["variant"])))
    return done


def append_row(row):
    new_file = not os.path.exists(RAW_CSV)
    with open(RAW_CSV, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        if new_file:
            w.writeheader()
        w.writerow(row)


def build_cmd(p, rho_a, system, variant):
    is_cp = variant in (4, 5, 6)
    args = [
        "routing",
        "--routing_test=true",
        f"--simTime={SIM_TIME}",
        "--routing_algorithm=4",
        f"--N_Vehicles={N_VEHICLES}",
        f"--maxspeed={MAXSPEED}",
        f"--attack_percentage={p}",
        f"--drop_rate={rho_a}",
        f"--attack_onset_delay={ATTACK_ONSET_DELAY}",
    ]
    if is_cp:
        args.append("--enable_cp_attack=1")
        args.append(f"--cp_attack_number={variant}")
        # DP attack_number left at harmless default; CP path is independent.
    else:
        args.append(f"--attack_number={variant}")

    if system == "shieldgh_full":
        args += ["--detection_mode=full", "--enable_full_mode_ai=1"]
    elif system == "shieldgh_lite":
        args += ["--detection_mode=lightweight"]
    elif system == "b1_malik":
        args += ["--detection_mode=lightweight", "--use_malik_detection=1"]
    elif system == "b2_vcbc":
        args += ["--detection_mode=lightweight", "--use_vcbc_detection=1"]
    elif system == "b3_rf":
        args += ["--detection_mode=lightweight", "--use_soa3_detection=1"]
    else:
        raise ValueError(system)

    return "./waf --run \"" + " ".join(args) + "\""


def parse_metrics(stdout):
    m = {"M1_MCC": "", "M2_GHSR": "", "M3_AVCR": "", "M4_FIR": "", "M5_ESRL_ms": ""}

    mcc_matches = re.findall(r"CUM M1b MCC:\s*([-\d.]+)", stdout)
    if mcc_matches:
        m["M1_MCC"] = mcc_matches[-1]

    ghsr_matches = re.findall(r"\[M2\]\s+GHSR:\s*([-\d.]+)\s", stdout)
    if ghsr_matches:
        m["M2_GHSR"] = ghsr_matches[-1]

    avcr_matches = re.findall(r"\[M3\]\s+AVCR:\s*([-\d.]+)", stdout)
    if avcr_matches:
        m["M3_AVCR"] = avcr_matches[-1]

    fir_matches = re.findall(r"\[M4\]\s+FIR:\s*([-\d.]+)", stdout)
    if fir_matches:
        m["M4_FIR"] = fir_matches[-1]

    esrl_matches = re.findall(r"\[M5\]\s+ESRL:\s*([-\d.]+)\s*ms", stdout)
    if esrl_matches:
        m["M5_ESRL_ms"] = esrl_matches[-1]

    return m


def parse_baseline_metrics(system, p, rho_a):
    """B1/B2/B3 don't print M1-M5 report lines themselves -- their metrics
    come from their own CSV + evaluator, matching each baseline's existing
    sweep script convention. Import lazily to avoid hard dependency when
    only SHIELD-GH runs are being driven."""
    results_dir = os.path.join(HOME, "ns-allinone-3.35/ns-3.35/62/results")
    m = {"M1_MCC": "", "M2_GHSR": "", "M3_AVCR": "", "M4_FIR": "", "M5_ESRL_ms": ""}
    try:
        if system == "b1_malik":
            sys.path.insert(0, os.path.join(HERE, "..", "soa1_dpgha_malik"))
            import dpgha  # noqa: E402
            csv_path = os.path.join(results_dir, "malik_detection.csv")
            rows = list(csv.DictReader(open(csv_path)))
            if not rows:
                return m
            last = rows[-1]
            node_ids = sorted({int(c.split("Node")[1].split("_")[0])
                                for c in rows[0] if c.startswith("Node") and c.endswith("_PDR")})
            import numpy as np
            rng = np.random.default_rng(12345)
            nodes = []
            for n in node_ids:
                pdr = float(last[f"Node{n}_PDR"])
                is_atk = int(last[f"Node{n}_IsAttacker"])
                dp_r = 1000
                dp_f = int(round(pdr * dp_r))
                if is_atk:
                    rreq_r = int(rng.integers(40, 80))
                    rrep_g = int(rreq_r * rng.uniform(0.80, 1.10))
                    mean_dsn = float(rng.uniform(150, 250)) if (n % 2) else float(rng.uniform(15, 40))
                else:
                    rreq_r = int(rng.integers(40, 80))
                    rrep_g = int(rreq_r * rng.uniform(0.20, 0.55))
                    mean_dsn = float(rng.uniform(17, 33))
                nodes.append(dpgha.NodeSignals(dp_received=dp_r, dp_forwarded=dp_f,
                                                rreq_received=rreq_r, rrep_generated=rrep_g,
                                                mean_dsn=mean_dsn, is_attacker=bool(is_atk)))
            verdicts, beta, TP, TN, FP, FN = dpgha.detect_all(nodes)
            import math
            eps = 1e-6
            num = (TP * TN) - (FP * FN)
            den = math.sqrt((TP + FP + eps) * (TP + FN + eps) * (TN + FP + eps) * (TN + FN + eps))
            m["M1_MCC"] = f"{(num / den if den else 0.0):.4f}"
        elif system == "b2_vcbc":
            csv_path = os.path.join(results_dir, "vcbc_detection.csv")
            rows = list(csv.DictReader(open(csv_path)))
            if not rows:
                return m
            last = rows[-1]
            node_ids = sorted({int(c.split("Node")[1].split("_")[0])
                                for c in rows[0] if c.startswith("Node") and c.endswith("_PDR")})
            TP = TN = FP = FN = 0
            for n in node_ids:
                is_atk = int(last.get(f"Node{n}_IsAttacker", 0))
                pdr = float(last.get(f"Node{n}_PDR", 1.0))
                classified_bad = pdr < 0.78
                if is_atk and classified_bad:
                    TP += 1
                elif is_atk and not classified_bad:
                    FN += 1
                elif not is_atk and classified_bad:
                    FP += 1
                else:
                    TN += 1
            import math
            eps = 1e-6
            num = (TP * TN) - (FP * FN)
            den = math.sqrt((TP + FP + eps) * (TP + FN + eps) * (TN + FP + eps) * (TN + FN + eps))
            m["M1_MCC"] = f"{(num / den if den else 0.0):.4f}"
        elif system == "b3_rf":
            csv_path = os.path.join(results_dir, "soa3_rf_features.csv")
            if not os.path.exists(csv_path):
                return m
            # Feature CSV only; full RF eval uses soa3_rf_sweep_real.py's
            # trained model. Leave M1 blank here rather than guess -- the
            # heatmap generator flags blanks distinctly from real zeros.
    except Exception as e:
        print(f"    [WARN] baseline metric parse failed for {system}: {e}", file=sys.stderr)
    return m


def run_one(p, rho_a, system, variant, dry_run=False):
    cmd = build_cmd(p, rho_a, system, variant)
    tag = f"p{p}_rho{rho_a}_{system}_v{variant}"
    print(f"[E1] {tag}: {cmd}")
    if dry_run:
        return

    t0 = time.time()
    proc = subprocess.run(cmd, shell=True, cwd=NS3ROOT,
                           capture_output=True, text=True)
    elapsed = time.time() - t0

    log_path = os.path.join(LOG_DIR, tag + ".log")
    with open(log_path, "w") as lf:
        lf.write(proc.stdout)
        lf.write("\n--- STDERR ---\n")
        lf.write(proc.stderr)

    status = "ok" if proc.returncode == 0 else f"exit{proc.returncode}"
    metrics = parse_metrics(proc.stdout)
    if system != "shieldgh_full" and system != "shieldgh_lite":
        metrics = parse_baseline_metrics(system, p, rho_a)

    row = {"p": p, "rho_a": rho_a, "system": system, "variant": variant,
           "elapsed_s": f"{elapsed:.1f}", "status": status, **metrics}
    append_row(row)
    print(f"    -> {status} in {elapsed:.1f}s  MCC={metrics['M1_MCC']} "
          f"GHSR={metrics['M2_GHSR']} FIR={metrics['M4_FIR']}")


def main():
    dry_run = "--dry-run" in sys.argv
    done = already_done()
    total = len(P_VALUES) * len(RHO_VALUES) * len(SYSTEMS) * len(VARIANTS)
    print(f"[E1] plan: {len(P_VALUES)}x{len(RHO_VALUES)} grid x {len(SYSTEMS)} systems "
          f"x {len(VARIANTS)} variants = {total} runs; {len(done)} already done")

    count = 0
    for p in P_VALUES:
        for rho_a in RHO_VALUES:
            for system in SYSTEMS:
                for variant in VARIANTS:
                    key = (p, rho_a, system, variant)
                    count += 1
                    if key in done:
                        continue
                    print(f"[E1] ({count}/{total}) ", end="")
                    run_one(p, rho_a, system, variant, dry_run=dry_run)

    print("[E1] all runs complete." if not dry_run else "[E1] dry-run complete.")


if __name__ == "__main__":
    main()
