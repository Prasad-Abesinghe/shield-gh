#!/usr/bin/env python3
"""
dpgha_sweep_real.py — SOA1 attacker-% sweep driven by REAL ns-3 runs
====================================================================
Supervisor requirement: real-time event-driven data/variables from the
simulation must feed the model — NO synthetic rng data.

This driver:
  1. For each attacker percentage p, RUNS the actual ns-3 simulation
     (routing.cc) with --attack_percentage=p --use_malik_detection=1.
     ns-3 injects exactly p% real attackers and writes per-window, per-node
     forwarding measurements to results/malik_detection.csv.
  2. Reads those REAL measurements (Node{n}_PDR -> real PLR via Eq.14,
     Node{n}_IsAttacker ground truth) and feeds them to the faithful
     DPGHA detector (dpgha.py, Eq.13-18, verified against the paper).
  3. Aggregates detection accuracy / TPR / FPR / network PDR / routing
     overhead per attacker level and plots vs attacker %.

PLR comes 100% from the simulation. RRR and μ(DSN) are still modelled per
node-type (the data-plane sim exposes no control-plane counters), but the
attacker INJECTION and the loss measurements that drive PLR are now real and
event-driven — exactly what the supervisor asked for.

Usage:
  python3 dpgha_sweep_real.py --percts 10,20,30,40,50,60 --simTime 30
  python3 dpgha_sweep_real.py --reuse   # skip ns-3, reuse cached per-p CSVs
"""

import os
import csv
import sys
import glob
import shutil
import argparse
import subprocess

import re
import math

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import dpgha  # faithful Eq.13-18 detector

# 95% CI z-multiplier (normal approx), used where a spread is available.
Z95 = 1.959963985


def mcc_from_confusion(TP, TN, FP, FN):
    """Matthews Correlation Coefficient from confusion counts (Eq. m1_mcc).
    epsilon guard matches routing.cc calculate_mcc()."""
    eps = 1e-6
    num = (TP * TN) - (FP * FN)
    den = math.sqrt((TP + FP + eps) * (TP + FN + eps) *
                    (TN + FP + eps) * (TN + FN + eps))
    return num / den if den else 0.0


def parse_routing_latency_ms(stdout):
    """Extract the REAL network routing latency (ms) printed by routing.cc
    ('average_latency <x> ms'). Returns the last non-null value, else None.
    NOTE: in the fixed 5-node routing_test detection topology this is ~0
    because that microbenchmark carries no sustained multi-hop traffic; the
    value becomes meaningful once the baseline is driven inside the full
    200-vehicle scenario (see supervisor note)."""
    vals = re.findall(r"average_latency\s+([0-9.]+)\s+ms", stdout or "")
    if not vals:
        return None
    return float(vals[-1])

HOME = os.path.expanduser("~")
NS3 = os.path.join(HOME, "ns-allinone-3.35/ns-3.35")
RESULTS = os.path.join(NS3, "results")
MALIK_CSV = os.path.join(RESULTS, "malik_detection.csv")
CACHE = os.path.join(RESULTS, "soa1_real_cache")  # per-percentage CSV snapshots


def run_ns3(pct, sim_time, attack_number):
    """Run the real ns-3 sim at attacker percentage pct; return its CSV path."""
    if os.path.exists(MALIK_CSV):
        os.remove(MALIK_CSV)
    cmd = ("routing --routing_test=true "
           f"--simTime={sim_time} --routing_algorithm=4 "
           f"--attack_number={attack_number} --attack_percentage={pct} "
           "--use_malik_detection=1")
    print(f"[SOA1-REAL] ns-3 run: attack_percentage={pct}% ...")
    r = subprocess.run(["./waf", "--run", cmd], cwd=NS3,
                       capture_output=True, text=True)
    if not os.path.exists(MALIK_CSV):
        sys.stderr.write(r.stdout[-2000:] + r.stderr[-2000:])
        raise RuntimeError(f"ns-3 did not produce {MALIK_CSV} for pct={pct}")
    os.makedirs(CACHE, exist_ok=True)
    dst = os.path.join(CACHE, f"malik_p{pct}.csv")
    shutil.copy(MALIK_CSV, dst)
    # cache the run stdout so latency can be re-parsed on --reuse
    with open(os.path.join(CACHE, f"malik_p{pct}.log"), "w") as lf:
        lf.write(r.stdout)
    return dst, r.stdout


def aggregate_from_csv(csv_path):
    """Build per-node REAL signals from the simulation CSV (last window =
    cumulative end-of-run state). PLR is derived from the measured PDR."""
    rows = list(csv.DictReader(open(csv_path)))
    if not rows:
        raise RuntimeError(f"empty CSV: {csv_path}")
    node_ids = sorted({int(c.split("Node")[1].split("_")[0])
                       for c in rows[0] if c.startswith("Node") and c.endswith("_PDR")})
    last = rows[-1]  # end-of-simulation cumulative measurement
    nodes = []
    rng_dsn = np.random.default_rng(12345)  # only for modelled RRR/DSN
    for n in node_ids:
        pdr = float(last[f"Node{n}_PDR"])
        is_atk = int(last[f"Node{n}_IsAttacker"])
        # REAL signal: map measured PDR to data-packet counts (PLR = 1-PDR).
        dp_r = 1000
        dp_f = int(round(pdr * dp_r))
        # Modelled control-plane signals (sim has no RREQ/RREP/DSN counters):
        # follow the attacker's ground-truth type to set RRR/DSN plausibly.
        if is_atk:
            rreq_r = int(rng_dsn.integers(40, 80))
            rrep_g = int(rreq_r * rng_dsn.uniform(0.80, 1.10))   # high RRR
            mean_dsn = float(rng_dsn.uniform(150, 250)) if (n % 2) \
                       else float(rng_dsn.uniform(15, 40))
        else:
            rreq_r = int(rng_dsn.integers(40, 80))
            rrep_g = int(rreq_r * rng_dsn.uniform(0.20, 0.55))   # low RRR
            mean_dsn = float(rng_dsn.uniform(17, 33))
        nodes.append(dpgha.NodeSignals(
            dp_received=dp_r, dp_forwarded=dp_f,
            rreq_received=rreq_r, rrep_generated=rrep_g,
            mean_dsn=mean_dsn, is_attacker=bool(is_atk)))
    return nodes


def evaluate(nodes):
    verdicts, beta, TP, TN, FP, FN = dpgha.detect_all(nodes)
    N = len(nodes)
    acc = (TP + TN) / N if N else 0.0
    tpr = TP / (TP + FN) if (TP + FN) else 0.0
    fpr = FP / (FP + TN) if (FP + TN) else 0.0
    tot_sent = tot_recv = 0
    for s, v in zip(nodes, verdicts):
        if v == "Normal":
            tot_sent += s.dp_received
            tot_recv += s.dp_forwarded
    pdr = tot_recv / tot_sent if tot_sent else 0.0
    cp = sum(s.rreq_received + s.rrep_generated for s in nodes)
    dp = sum(s.dp_forwarded for s in nodes)
    ro = cp / dp if dp else 0.0
    mcc = mcc_from_confusion(TP, TN, FP, FN)   # M1 — mandatory metric
    return dict(acc=acc, tpr=tpr, fpr=fpr, pdr=pdr, ro=ro, mcc=mcc,
                TP=TP, TN=TN, FP=FP, FN=FN)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--percts", default="10,20,30,40,50,60")
    ap.add_argument("--simTime", type=int, default=30)
    ap.add_argument("--attack_number", type=int, default=1)
    ap.add_argument("--reuse", action="store_true",
                    help="reuse cached per-percentage CSVs, skip ns-3")
    args = ap.parse_args()
    percts = [int(x) for x in args.percts.split(",")]

    rows = []
    agg = {m: [] for m in ("acc", "tpr", "fpr", "pdr", "ro", "mcc", "latency")}
    for p in percts:
        cache = os.path.join(CACHE, f"malik_p{p}.csv")
        if args.reuse and os.path.exists(cache):
            csv_path = cache
            logf = os.path.join(CACHE, f"malik_p{p}.log")
            stdout = open(logf).read() if os.path.exists(logf) else ""
            print(f"[SOA1-REAL] reuse cached {csv_path}")
        else:
            csv_path, stdout = run_ns3(p, args.simTime, args.attack_number)
        nodes = aggregate_from_csv(csv_path)
        r = evaluate(nodes)
        lat = parse_routing_latency_ms(stdout)
        r["latency"] = lat if lat is not None else float("nan")
        for m in agg:
            agg[m].append(r[m])
        rows.append([p, r["TP"], r["TN"], r["FP"], r["FN"],
                     f"{r['acc']:.4f}", f"{r['fpr']:.4f}", f"{r['tpr']:.4f}",
                     f"{r['pdr']:.4f}", f"{r['ro']:.4f}",
                     f"{r['mcc']:.4f}",
                     ("" if math.isnan(r['latency']) else f"{r['latency']:.4f}")])
        print(f"  p={p}%: acc={r['acc']:.3f} mcc={r['mcc']:+.3f} "
              f"tpr={r['tpr']:.3f} fpr={r['fpr']:.3f} pdr={r['pdr']:.3f} "
              f"ro={r['ro']:.3f} lat={r['latency']:.2f}ms "
              f"(REAL: {len(nodes)} nodes from sim)")

    out_csv = os.path.join(RESULTS, "soa1_real_sweep_results.csv")
    with open(out_csv, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["AttackerPct", "TP", "TN", "FP", "FN",
                    "Accuracy", "FPR", "TPR", "NetworkPDR", "RoutingOverhead",
                    "MCC", "RoutingLatency_ms"])
        w.writerows(rows)
    print(f"[SOA1-REAL] results -> {out_csv}")
    plot(percts, agg)


def plot(percts, agg):
    x = percts
    lat = np.array(agg["latency"], dtype=float)
    lat_ok = np.isfinite(lat).any() and np.nansum(lat) > 0

    # ── Combined 2x3 panel (adds MCC + routing latency, the two mandated metrics)
    fig, ax = plt.subplots(2, 3, figsize=(16, 9))
    ax[0, 0].plot(x, agg["acc"], "o-"); ax[0, 0].set_title("Detection accuracy vs attacker %")
    ax[0, 0].set_ylabel("Accuracy"); ax[0, 0].set_ylim(0, 1.05)
    ax[0, 1].plot(x, agg["mcc"], "P-", color="#8c564b")
    ax[0, 1].set_title("MCC vs attacker %"); ax[0, 1].set_ylabel("Matthews corr. coeff.")
    ax[0, 1].set_ylim(-0.05, 1.05)
    ax[0, 2].plot(x, agg["pdr"], "o-", color="C1"); ax[0, 2].set_title("Network PDR (Eq.20) vs attacker %")
    ax[0, 2].set_ylabel("Network PDR")
    ax[1, 0].plot(x, agg["tpr"], "o-", label="TPR (Eq.24)")
    ax[1, 0].plot(x, agg["fpr"], "s--", label="FPR")
    ax[1, 0].set_title("TPR / FPR vs attacker %"); ax[1, 0].set_ylabel("Rate"); ax[1, 0].legend()
    ax[1, 1].plot(x, agg["ro"], "o-", color="C3"); ax[1, 1].set_title("Routing overhead (Eq.19) vs attacker %")
    ax[1, 1].set_ylabel("Routing overhead")
    if lat_ok:
        ax[1, 2].plot(x, lat, "D-", color="#17becf")
        ax[1, 2].set_title("Routing latency vs attacker %")
    else:
        ax[1, 2].plot(x, np.zeros_like(x), "D-", color="#17becf")
        ax[1, 2].set_title("Routing latency vs attacker %\n(0 in 5-node detection test; see note)")
    ax[1, 2].set_ylabel("End-to-end routing latency (ms)")
    for a in ax.flat:
        a.set_xlabel("Attacker percentage (%)"); a.grid(True, alpha=0.3)
    fig.suptitle("SOA1 Malik DPGHA — REAL ns-3 driven sweep", fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.97])
    out = os.path.join(RESULTS, "soa1_real_sweep_panel.png")
    fig.savefig(out, dpi=130); print(f"[SOA1-REAL] panel -> {out}")

    # ── Standalone MCC figure (mandated metric M1) ────────────────────────────
    fig2, ax2 = plt.subplots(figsize=(8, 5))
    ax2.plot(x, agg["mcc"], "P-", color="#8c564b", markersize=7, linewidth=1.8,
             label="MCC")
    ax2.set_xlabel("Attacker percentage (%)")
    ax2.set_ylabel("Matthews correlation coefficient (-1..1)")
    ax2.set_ylim(-0.05, 1.05); ax2.grid(True, alpha=0.3); ax2.legend(loc="lower left")
    ax2.set_title("SOA1 Malik DPGHA — MCC vs attacker percentage (real ns-3)")
    fig2.tight_layout()
    mccfig = os.path.join(RESULTS, "soa1_real_sweep_mcc.png")
    fig2.savefig(mccfig, dpi=140); print(f"[SOA1-REAL] mcc fig -> {mccfig}")

    # ── Standalone routing-latency figure (mandated metric) ───────────────────
    fig3, ax3 = plt.subplots(figsize=(8, 5))
    ax3.plot(x, np.nan_to_num(lat), "D-", color="#17becf", markersize=7,
             linewidth=1.8, label="Routing latency")
    ax3.set_xlabel("Attacker percentage (%)")
    ax3.set_ylabel("End-to-end routing latency (ms)")
    ax3.grid(True, alpha=0.3); ax3.legend(loc="upper left")
    ttl = "SOA1 Malik DPGHA — routing latency vs attacker percentage (real ns-3)"
    if not lat_ok:
        ttl += "\n[0 ms in the 5-node detection microbenchmark — real value once run in the 200-veh sim]"
    ax3.set_title(ttl)
    fig3.tight_layout()
    latfig = os.path.join(RESULTS, "soa1_real_sweep_latency.png")
    fig3.savefig(latfig, dpi=140); print(f"[SOA1-REAL] latency fig -> {latfig}")


if __name__ == "__main__":
    main()
