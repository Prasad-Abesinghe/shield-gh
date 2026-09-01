#!/usr/bin/env python3
"""
Task 9.5 -- Internal Ablation Study driver (pass 1).

SCOPE (user decision 2026-08-13): run the ablations that have REAL, WIRED
code knobs today. main.tex sec:ablation defines A1--A17; an audit of
routing.cc + shield_gh/ found only four with an actual implemented toggle:

  A1  MATD handoff correction   --enable_matd=0
        wired: shield_gh_integration.h:890 (CorrectPDR bypass) and :906
        (ApplyMobilityDecay bypass).
  A4  LLM semantic scorer       --enable_full_mode_ai=0
        wired: full-mode fusion (mu2*Q_i term) is simply not invoked.
  A7  DEBSC cryptographic gate  --enable_zkp_gate=0
        wired: debsc.cc:83 drops the ZKP requirement, statistical gate alone.
  A12 Multi-controller arch     --N_Controllers=1 vs 4
        wired: routing.cc:801-818 (Task 9 multi-controller model).

  Plus SIG (not a main.tex ID): --enable_signatures=0, the S1--S6 blanket
  off switch, included as the upper-bound "no signatures at all" reference
  point that contextualises A1/A4/A7.

The other 13 ablations (A2, A3, A5, A6, A8--A11, A13--A17) have NO CLI flag
and NO wiring -- they are deliberately NOT run here rather than emitted as
fabricated rows. A2/A3 need per-signature and CP-detector toggles built
first; they are the SOTA-comparable pair and are pass 2.

METRIC SCOPE: M1 (MCC) node-level, plus CP MCC for A12. M2/M3/M4/M5 are not
implemented in routing.cc (they appear only in comments -- same finding as
the E1 driver). M7--M12 do not exist at all. Ablation rows therefore carry
M1 only; the main.tex table's per-ablation metric column is aspirational
until those metrics are implemented.

BASELINE: every ablation is compared against the SAME full-system control
run (all components ON) at identical config/seed, so the delta is
attributable to the one removed component.

Attack model matches the Task 9 FINAL RESULT config EXACTLY so numbers are
comparable to the signed-off SOTA comparison: DP-FR + CP-TS jointly,
N=16 vehicles, M=4 controllers, attack_percentage=40, cp_attack_percentage
=40 (=> 2 of 4 controllers malicious), simTime=10, default onset delay.

VERIFIED 2026-08-13: this exact base config reproduces Task 9's signed-off
control numbers bit-for-bit -- TP=38 TN=80 FP=0 FN=10, M1 MCC=0.84,
CP MCC=1.00. Do NOT change simTime or attack_onset_delay without re-checking
that: an earlier draft used simTime=30/onset=6.0 and scored MCC=0.22,
because a 6s onset on a 10s sim leaves almost no attack window to detect.

Usage:
  python3 ablation_driver.py --dry-run
  python3 ablation_driver.py --workers 8
  python3 ablation_driver.py --seeds 1,2,3
"""
import argparse
import csv
import os
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

HOME = os.path.expanduser("~")
NS3ROOT = os.path.join(HOME, "ns-allinone-3.35/ns-3.35-g62build")
HERE = os.path.dirname(os.path.abspath(__file__))
RAW_CSV = os.path.join(HERE, "ablation_results.csv")
LOG_DIR = os.path.join(HERE, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# ---- Fixed scenario (mirrors Task 9 FINAL RESULT) -------------------------
N_VEHICLES = 16
N_CONTROLLERS = 4
SIM_TIME = 10               # Task 9 signed-off value; see header note
MAXSPEED = 80
ATTACK_PCT = 40
CP_ATTACK_PCT = 40          # -> round(0.4*4) = 2 malicious controllers
DP_VARIANT = 1              # DP-FR
CP_VARIANT = 6              # CP-TS (2 affected / 2 unaffected controllers)
DROP_RATE = 60
PER_RUN_TIMEOUT = 1800

# ---- Ablation definitions -------------------------------------------------
# Each entry: id -> (label, x_variable_name, [(x_value, extra_cli_args), ...])
# "control" is the all-components-ON reference at the same x point.

def _speed_sweep():
    # A1: MATD benefit scales with speed (main.tex: 30..150 km/h).
    return [(v, [f"--maxspeed={v}"]) for v in (30, 60, 90, 120, 150)]

def _droprate_sweep(vals):
    return [(r, [f"--drop_rate={r}"]) for r in vals]

ABLATIONS = {
    "A1": {
        "label": "MATD handoff correction",
        "xname": "speed_kmh",
        "points": _speed_sweep(),
        "off_args": ["--enable_matd=0"],
    },
    "A4": {
        "label": "LLM semantic scorer (mu2=0)",
        "xname": "drop_rate_pct",
        # main.tex A4: rho in {10,20,30,40}
        "points": _droprate_sweep([10, 20, 30, 40]),
        # control for A4 is full-mode AI ON; ablated is AI OFF.
        "control_args": ["--detection_mode=full", "--enable_full_mode_ai=1"],
        "off_args": ["--detection_mode=full", "--enable_full_mode_ai=0"],
    },
    "A7": {
        "label": "DEBSC cryptographic (ZKP) gate",
        "xname": "drop_rate_pct",
        # main.tex A7: rho in {10,30,50,70}
        "points": _droprate_sweep([10, 30, 50, 70]),
        "off_args": ["--enable_zkp_gate=0"],
    },
    "A12": {
        "label": "Multi-controller architecture",
        "xname": "n_controllers",
        # main.tex A12 sweeps compromised controllers; we sweep M and let
        # cp_attack_percentage=50 set the malicious count, then additionally
        # report the single-controller collapse case.
        "points": [(m, [f"--N_Controllers={m}"]) for m in (1, 2, 4, 8)],
        # The "ablated" arm IS the single-controller architecture, so the
        # sweep itself is the ablation; both arms use the same flags and the
        # contrast is across x. Handled specially below.
        "off_args": None,
    },
    "SIG": {
        "label": "All signatures S1-S6 (reference bound)",
        "xname": "drop_rate_pct",
        "points": _droprate_sweep([10, 30, 50, 70]),
        "off_args": ["--enable_signatures=0"],
    },
}

FIELDS = ["ablation", "arm", "xname", "x", "seed",
          "M1_MCC", "M1_ACC", "CP_MCC",
          "TP", "TN", "FP", "FN", "elapsed_s", "status"]

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
                    done.add((row["ablation"], row["arm"],
                              row["x"], row["seed"]))
                except KeyError:
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


def base_args(seed):
    return [
        "--routing_test=true",
        f"--simTime={SIM_TIME}",
        "--routing_algorithm=4",
        f"--N_Vehicles={N_VEHICLES}",
        f"--N_Controllers={N_CONTROLLERS}",
        f"--maxspeed={MAXSPEED}",
        f"--attack_percentage={ATTACK_PCT}",
        f"--drop_rate={DROP_RATE}",
        f"--attack_number={DP_VARIANT}",
        "--enable_cp_attack=1",
        f"--cp_attack_number={CP_VARIANT}",
        f"--cp_attack_percentage={CP_ATTACK_PCT}",
        f"--rng_run={seed}",
    ]


def build_cmd(ab_id, arm, extra, seed):
    spec = ABLATIONS[ab_id]
    args = base_args(seed)
    # Per-ablation control arm may need its own flags (e.g. A4 needs full mode
    # ON in BOTH arms, so the only difference is the AI toggle itself).
    if arm == "control":
        args += spec.get("control_args", [])
    else:
        args += spec.get("control_args", [])
        args += (spec.get("off_args") or [])
    # x-point args LAST so they override any earlier default (e.g. drop_rate,
    # maxspeed, N_Controllers all appear in base_args).
    args += extra
    return args


def parse_metrics(stdout):
    m = {"M1_MCC": "", "M1_ACC": "", "CP_MCC": "",
         "TP": "", "TN": "", "FP": "", "FN": ""}
    mcc = re.findall(r"CUM M1b MCC:\s*([-\d.]+)", stdout)
    if mcc:
        m["M1_MCC"] = mcc[-1]
    acc = re.findall(r"CUM M1a Detection Accuracy:\s*([-\d.]+)", stdout)
    if acc:
        m["M1_ACC"] = acc[-1]
    cp = re.findall(r"CP MCC:\s*([-\d.]+)", stdout)
    if cp:
        m["CP_MCC"] = cp[-1]
    cm = re.findall(
        r"Cum TP=(\d+)\s+TN=(\d+)\s+FP=(\d+)\s+FN=(\d+)", stdout)
    if cm:
        m["TP"], m["TN"], m["FP"], m["FN"] = cm[-1]
    return m


def run_one(ab_id, arm, x, extra, seed):
    tag = f"{ab_id}_{arm}_x{x}_s{seed}"
    args = build_cmd(ab_id, arm, extra, seed)

    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = (os.path.join(NS3ROOT, "build", "lib") + ":"
                              + env.get("LD_LIBRARY_PATH", ""))
    # Pin every solver to one thread: routing.cc shells out to a Gurobi
    # solve each simulated second; unpinned, W parallel sims demand W*32
    # cores and the box thrashes. (Same guard as the E1 driver.)
    for v in ("GRB_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS",
              "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
        env[v] = "1"

    binary = os.path.join(NS3ROOT, "build", "scratch", "routing")
    t0 = time.time()
    try:
        proc = subprocess.run([binary] + args, cwd=NS3ROOT, env=env,
                              capture_output=True, text=True,
                              timeout=PER_RUN_TIMEOUT)
        stdout, stderr, rc = proc.stdout, proc.stderr, proc.returncode
        status = "ok" if rc == 0 else f"exit{rc}"
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = f"TIMEOUT after {PER_RUN_TIMEOUT}s\n"
        status = "timeout"
    elapsed = time.time() - t0

    with open(os.path.join(LOG_DIR, tag + ".log"), "w") as lf:
        lf.write("CMD: " + " ".join(args) + "\n\n")
        lf.write(stdout or "")
        lf.write("\n--- STDERR ---\n")
        lf.write(stderr or "")

    metrics = parse_metrics(stdout or "")
    if status == "ok" and not metrics["M1_MCC"]:
        status = "ok_no_mcc"

    row = {"ablation": ab_id, "arm": arm, "xname": ABLATIONS[ab_id]["xname"],
           "x": x, "seed": seed, "elapsed_s": f"{elapsed:.1f}",
           "status": status, **metrics}
    append_row(row)
    log(f"    [done] {tag}: {status} {elapsed:.0f}s "
        f"MCC={metrics['M1_MCC'] or '-'} CP={metrics['CP_MCC'] or '-'}")
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--seeds", default="1")
    ap.add_argument("--only", default="",
                    help="comma-separated ablation ids to run")
    a = ap.parse_args()

    seeds = [int(s) for s in a.seeds.split(",") if s.strip()]
    want = [s.strip() for s in a.only.split(",") if s.strip()] or list(ABLATIONS)

    done = already_done()
    tasks = []
    for ab_id in want:
        spec = ABLATIONS[ab_id]
        for (x, extra) in spec["points"]:
            for seed in seeds:
                # A12's ablation IS the x sweep (M=1 is the ablated
                # architecture), so it has a single arm.
                arms = ["control"] if spec["off_args"] is None \
                    else ["control", "ablated"]
                for arm in arms:
                    if (ab_id, arm, str(x), str(seed)) in done:
                        continue
                    tasks.append((ab_id, arm, x, extra, seed))

    log(f"[ABL] {len(want)} ablations, seeds={seeds}, "
        f"{len(tasks)} runs remaining (already done: {len(done)})")
    if a.dry_run:
        for t in tasks:
            log("    would run: " + " ".join(
                build_cmd(t[0], t[1], t[3], t[4])))
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
            eta = (el / completed) * (len(tasks) - completed)
            log(f"[ABL] progress {completed}/{len(tasks)} "
                f"elapsed={el/60:.1f}m eta={eta/60:.1f}m")

    log(f"[ABL] COMPLETE in {(time.time()-t_start)/60:.1f} min -> {RAW_CSV}")


if __name__ == "__main__":
    main()
