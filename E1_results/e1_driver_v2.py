#!/usr/bin/env python3
"""
E1 driver v2 -- 2D attack grid (attacker penetration p x drop rate rho_a).

SCOPE (decided 2026-08-09 under same-day report deadline):
  * Metric:   M1 (MCC) ONLY. M2/M3/M4/M5 (GHSR/AVCR/FIR/ESRL) are NOT
              implemented in routing.cc -- they appear only in comments.
              Verified by: grep -nE 'cout.*(GHSR|AVCR|ESRL|FIR)' routing.cc
              returns nothing. The v1 driver's regexes for them silently
              matched nothing and would have written 4 empty columns.
  * Variant:  S1 (DP-FR) only, as the representative variant. This codebase
              applies ONE attack variant per run; "all six simultaneously"
              is not expressible without patching core attack assignment.
  * N:        20 vehicles. N=200 is UNUSABLE: optimize_link_lifetime() makes
              a blocking system() call to optimization_lifetime.py (Gurobi),
              which at N=200 saturates all 32 cores and the sim blocks at 0%
              CPU indefinitely (observed: 18 CPU-hours on one 30s sim).
              N=20 does not meaningfully trigger it. ~5 min/run measured.

Grid: p in {0,20,40,60,80,100}% x rho_a in {0,20,40,60,80,100}%
Systems: shieldgh_full, shieldgh_lite, b1_malik, b2_vcbc, b3_rf
Total: 6*6*5 = 180 runs.

Parallelism: runs WORKERS sims concurrently. Each sim is single-threaded
once Gurobi is not triggered, so this scales near-linearly on 32 cores.

Checkpointing: each completed run appends one row to e1_m1_results.csv
immediately; re-running skips rows already present.

Usage:
  python3 e1_driver_v2.py                # run all remaining
  python3 e1_driver_v2.py --dry-run      # print plan only
  python3 e1_driver_v2.py --workers 8    # override parallelism
"""
import argparse
import csv
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

HOME = os.path.expanduser("~")
NS3ROOT = os.path.join(HOME, "ns-allinone-3.35/ns-3.35-g62build")
HERE = os.path.dirname(os.path.abspath(__file__))
RAW_CSV = os.path.join(HERE, "e1_m1_results.csv")
LOG_DIR = os.path.join(HERE, "logs_v2")
os.makedirs(LOG_DIR, exist_ok=True)

P_VALUES = [0, 20, 40, 60, 80, 100]
RHO_VALUES = [0, 20, 40, 60, 80, 100]
SYSTEMS = ["shieldgh_full", "shieldgh_lite", "b1_malik", "b2_vcbc", "b3_rf"]

VARIANT = 1          # S1 / DP-FR
N_VEHICLES = 20
SIM_TIME = 30
ATTACK_ONSET_DELAY = 6.0
MAXSPEED = 80
PER_RUN_TIMEOUT = 900   # 15 min hard cap; a healthy N=20 run takes ~5 min

FIELDS = ["p", "rho_a", "system", "variant", "N", "M1_MCC",
          "M1_ACC", "elapsed_s", "status"]

_csv_lock = threading.Lock()
_print_lock = threading.Lock()


def log(msg):
    with _print_lock:
        print(msg, flush=True)


def already_done():
    done = set()
    if os.path.exists(RAW_CSV):
        with open(RAW_CSV, newline="") as fh:
            for row in csv.DictReader(fh):
                try:
                    done.add((int(row["p"]), int(row["rho_a"]), row["system"]))
                except (KeyError, ValueError):
                    continue
    return done


def append_row(row):
    with _csv_lock:
        new_file = not os.path.exists(RAW_CSV)
        with open(RAW_CSV, "a", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=FIELDS)
            if new_file:
                w.writeheader()
            w.writerow(row)


def build_args(p, rho_a, system):
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
        f"--attack_number={VARIANT}",
    ]
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
    return args


def parse_metrics(stdout):
    """Only M1 is emitted by routing.cc. Take the LAST cumulative report."""
    m = {"M1_MCC": "", "M1_ACC": ""}
    mcc = re.findall(r"CUM M1b MCC:\s*([-\d.]+)", stdout)
    if mcc:
        m["M1_MCC"] = mcc[-1]
    acc = re.findall(r"CUM M1a Detection Accuracy:\s*([-\d.]+)", stdout)
    if acc:
        m["M1_ACC"] = acc[-1]
    return m


def run_one(p, rho_a, system):
    tag = f"p{p}_rho{rho_a}_{system}_v{VARIANT}_N{N_VEHICLES}"
    args = build_args(p, rho_a, system)
    # Invoke the built binary directly with LD_LIBRARY_PATH set, rather than
    # through ./waf: waf serialises on its own lock file, which would defeat
    # parallelism entirely.
    env = dict(os.environ)
    libdir = os.path.join(NS3ROOT, "build", "lib")
    env["LD_LIBRARY_PATH"] = libdir + ":" + env.get("LD_LIBRARY_PATH", "")
    # CRITICAL: routing.cc calls optimize_link_lifetime() once per simulated
    # second, which shells out to optimization_lifetime.py -- a Gurobi solve
    # over an n^2 node-pair loop. That script never sets m.setParam('Threads'),
    # so each solve defaults to ALL cores. Running W sims in parallel then
    # demands W*32 cores and the box thrashes (observed: load 260, every sim
    # at ~3% CPU, i.e. parallelism made it slower than serial).
    # Pin every solver to a single thread so W parallel sims use ~W cores.
    env["GRB_THREADS"] = "1"
    env["OMP_NUM_THREADS"] = "1"
    env["MKL_NUM_THREADS"] = "1"
    env["OPENBLAS_NUM_THREADS"] = "1"
    env["NUMEXPR_NUM_THREADS"] = "1"
    binary = os.path.join(NS3ROOT, "build", "scratch", "routing")
    cmd = [binary] + args[1:]

    t0 = time.time()
    try:
        proc = subprocess.run(cmd, cwd=NS3ROOT, env=env,
                              capture_output=True, text=True,
                              timeout=PER_RUN_TIMEOUT)
        stdout, stderr, rc = proc.stdout, proc.stderr, proc.returncode
        status = "ok" if rc == 0 else f"exit{rc}"
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = "TIMEOUT after %ds\n" % PER_RUN_TIMEOUT
        status = "timeout"
    elapsed = time.time() - t0

    with open(os.path.join(LOG_DIR, tag + ".log"), "w") as lf:
        lf.write(stdout or "")
        lf.write("\n--- STDERR ---\n")
        lf.write(stderr or "")

    metrics = parse_metrics(stdout or "")
    if status == "ok" and not metrics["M1_MCC"]:
        status = "ok_no_mcc"

    row = {"p": p, "rho_a": rho_a, "system": system, "variant": VARIANT,
           "N": N_VEHICLES, "elapsed_s": f"{elapsed:.1f}",
           "status": status, **metrics}
    append_row(row)
    log(f"    [done] {tag}: {status} {elapsed:.0f}s MCC={metrics['M1_MCC'] or '-'}")
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--workers", type=int, default=10)
    a = ap.parse_args()

    done = already_done()
    tasks = [(p, r, s) for p in P_VALUES for r in RHO_VALUES
             for s in SYSTEMS if (p, r, s) not in done]
    total = len(P_VALUES) * len(RHO_VALUES) * len(SYSTEMS)

    log(f"[E1v2] grid {len(P_VALUES)}x{len(RHO_VALUES)} x {len(SYSTEMS)} systems "
        f"= {total} runs | done={len(done)} remaining={len(tasks)}")
    log(f"[E1v2] N={N_VEHICLES} variant=S1 metric=M1(MCC) workers={a.workers}")
    if a.dry_run:
        for t in tasks[:12]:
            log(f"    would run: p={t[0]} rho={t[1]} {t[2]}")
        log(f"    ... {len(tasks)} total")
        return

    t_start = time.time()
    completed = 0
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(run_one, *t): t for t in tasks}
        for fut in as_completed(futs):
            completed += 1
            try:
                fut.result()
            except Exception as e:
                log(f"    [ERROR] {futs[fut]}: {e}")
            el = time.time() - t_start
            rate = el / completed
            eta = rate * (len(tasks) - completed)
            log(f"[E1v2] progress {completed}/{len(tasks)} "
                f"elapsed={el/60:.1f}m eta={eta/60:.1f}m")

    log(f"[E1v2] COMPLETE in {(time.time()-t_start)/60:.1f} min -> {RAW_CSV}")


if __name__ == "__main__":
    main()
