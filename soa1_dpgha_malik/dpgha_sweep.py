#!/usr/bin/env python3
"""
dpgha_sweep.py — SOA1 (Malik DPGHA) attacker-percentage sweep + plots
=====================================================================
Mirrors the SOA2 sweep so the two state-of-the-art baselines are directly
comparable. Varies the independent variable (attacker %) and plots how the
DPGHA detection metrics respond.

For each attacker fraction f, builds N vehicles where f·N are malicious
(half Smart GHA, half Sequence-Number GHA — the paper's two variants),
runs the faithful Eq.13-18 detector (dpgha.py), and records:

  • Detection accuracy        (TP+TN)/N        (paper §V.F detection rate)
  • TPR (recall) / FPR        Eq.24
  • Network PDR               delivered / sent  (Eq.20)
  • Routing overhead          ΣCP / ΣDP         (Eq.19)

Node modelling (paper §II "properties of a gray-hole node" + §V settings):
  Smart GHA   : high data-packet loss; many RREPs vs few RREQs (RRR high);
                normal DSN.
  Seq-No GHA  : data loss once route established; inflated DSN (fake high
                sequence number to attract traffic); RRR high.
  Honest      : ~normal AODV (PDR 97-98%), low RRR, normal DSN.

Path-contamination confound (same rationale as SOA2): an honest node's
OBSERVED loss rises with attacker density, so the metrics actually move on
a small test network instead of sitting flat.

Usage:
  python3 dpgha_sweep.py                       # default sweep
  python3 dpgha_sweep.py --N 30 --seeds 30 \
        --fracs 0.05,0.1,0.15,0.2,0.3,0.4,0.5,0.6
"""

import os
import csv
import random
import argparse

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import dpgha  # faithful Eq.13-18 detector (verified against paper Table 2)

HOME = os.path.expanduser("~")
RESULTS = os.path.join(HOME, "ns-allinone-3.35/ns-3.35/results")

DP_BUDGET = 1000   # data packets routed through each node (resolution of PLR)
RREQ_BUDGET = 60   # control-plane request volume per node


def make_network(n_nodes, attacker_frac, rng):
    n_attackers = int(round(attacker_frac * n_nodes))
    labels = [1] * n_attackers + [0] * (n_nodes - n_attackers)
    rng.shuffle(labels)
    contamination = attacker_frac  # downstream-path loss grows with density
    beta_dsn_normal = 25.0         # typical honest DSN scale (cf. Table 2)

    nodes = []
    for i, is_atk in enumerate(labels):
        if is_atk:
            smart = (i % 2 == 0)   # split malicious evenly between the two variants
            # both variants drop data packets once the route is established
            own_loss = rng.uniform(0.20, 0.55)        # fraction dropped
            # abnormal control-plane behaviour (Eq.15 high RRR):
            rreq_r = rng.randint(40, 80)
            rrep_g = int(rreq_r * rng.uniform(0.80, 1.10))  # RRR ~80-110% (≥λ)
            if smart:
                mean_dsn = rng.uniform(15, 40)        # Smart GHA: normal DSN
            else:
                mean_dsn = rng.uniform(150, 250)      # Seq-No GHA: inflated DSN
        else:
            own_loss = rng.uniform(0.005, 0.03)       # honest ~ AODV 97-99.5%
            rreq_r = rng.randint(40, 80)
            rrep_g = int(rreq_r * rng.uniform(0.20, 0.55))  # RRR low (<λ)
            mean_dsn = rng.uniform(beta_dsn_normal - 8, beta_dsn_normal + 8)

        # observed loss = own behaviour + contaminated downstream path
        observed_loss = own_loss + (1.0 - own_loss) * 0.5 * contamination * rng.uniform(0.6, 1.0)
        observed_loss = min(max(observed_loss, 0.0), 1.0)
        dp_r = DP_BUDGET
        dp_f = int(round(dp_r * (1.0 - observed_loss)))

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

    # Network PDR (Eq.20): packets delivered through nodes NOT blacklisted.
    # Detected (blacklisted) nodes are prevented from relaying (paper §IV.C),
    # so only Normal-classified nodes contribute traffic.
    tot_sent = tot_recv = 0
    for s, v in zip(nodes, verdicts):
        if v == "Normal":
            tot_sent += s.dp_received
            tot_recv += s.dp_forwarded
    pdr = tot_recv / tot_sent if tot_sent else 0.0

    # Routing overhead (Eq.19): ΣCP_transmitted / ΣDP_transmitted.
    cp = sum(s.rreq_received + s.rrep_generated for s in nodes)
    dp = sum(s.dp_forwarded for s in nodes)
    ro = cp / dp if dp else 0.0
    return dict(acc=acc, tpr=tpr, fpr=fpr, pdr=pdr, ro=ro,
                TP=TP, TN=TN, FP=FP, FN=FN)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--N", type=int, default=30)
    ap.add_argument("--seeds", type=int, default=30)
    ap.add_argument("--fracs", default="0.05,0.1,0.15,0.2,0.3,0.4,0.5,0.6")
    args = ap.parse_args()
    fracs = [float(x) for x in args.fracs.split(",")]

    os.makedirs(RESULTS, exist_ok=True)
    rows = []
    agg = {m: [] for m in ("acc", "tpr", "fpr", "pdr", "ro")}

    print(f"[SOA1 SWEEP] N={args.N} seeds={args.seeds} fracs={fracs}")
    for f in fracs:
        samples = {m: [] for m in agg}
        for s in range(args.seeds):
            rng = random.Random(7000 * int(f * 100) + s)
            nodes = make_network(args.N, f, rng)
            r = evaluate(nodes)
            for m in samples:
                samples[m].append(r[m])
            rows.append([f, s, r["TP"], r["TN"], r["FP"], r["FN"],
                         f"{r['acc']:.4f}", f"{r['fpr']:.4f}", f"{r['tpr']:.4f}",
                         f"{r['pdr']:.4f}", f"{r['ro']:.4f}"])
        for m in agg:
            agg[m].append((float(np.mean(samples[m])), float(np.std(samples[m]))))
        print(f"  f={f:.0%}: acc={np.mean(samples['acc']):.3f} "
              f"tpr={np.mean(samples['tpr']):.3f} fpr={np.mean(samples['fpr']):.3f} "
              f"pdr={np.mean(samples['pdr']):.3f} ro={np.mean(samples['ro']):.3f}")

    csv_path = os.path.join(RESULTS, "soa1_sweep_results.csv")
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["AttackerFrac", "Seed", "TP", "TN", "FP", "FN",
                    "Accuracy", "FPR", "TPR", "NetworkPDR", "RoutingOverhead"])
        w.writerows(rows)
    print(f"[SOA1 SWEEP] raw -> {csv_path}")
    plot(fracs, agg, args)


def _curve(ax, x, agg, metric, ylabel, title, color="C0"):
    means = [m for m, _ in agg[metric]]
    stds = [s for _, s in agg[metric]]
    ax.errorbar(x, means, yerr=stds, marker="o", capsize=3, color=color,
                label="DPGHA")
    ax.set_xlabel("Attacker percentage (%)")
    ax.set_ylabel(ylabel); ax.set_title(title)
    ax.grid(True, alpha=0.3); ax.legend()


def plot(fracs, agg, args):
    x = [f * 100 for f in fracs]
    fig, ax = plt.subplots(2, 2, figsize=(12, 9))
    _curve(ax[0, 0], x, agg, "acc", "Detection accuracy",
           "Detection accuracy vs attacker %")
    _curve(ax[0, 1], x, agg, "pdr", "Network PDR (Eq.20)",
           "Packet delivery ratio vs attacker %", color="C1")
    a = ax[1, 0]
    a.errorbar(x, [m for m, _ in agg["tpr"]], yerr=[s for _, s in agg["tpr"]],
               marker="o", capsize=3, label="TPR (Eq.24)")
    a.errorbar(x, [m for m, _ in agg["fpr"]], yerr=[s for _, s in agg["fpr"]],
               marker="s", linestyle="--", capsize=3, label="FPR")
    a.set_xlabel("Attacker percentage (%)"); a.set_ylabel("Rate")
    a.set_title("TPR / FPR vs attacker %"); a.grid(True, alpha=0.3); a.legend()
    _curve(ax[1, 1], x, agg, "ro", "Routing overhead (Eq.19)",
           "Routing overhead vs attacker %", color="C3")
    fig.suptitle(f"SOA1 Malik DPGHA sweep (N={args.N}, {args.seeds} seeds)",
                 fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.97])
    panel = os.path.join(RESULTS, "soa1_sweep_panel.png")
    fig.savefig(panel, dpi=130); print(f"[SOA1 SWEEP] panel -> {panel}")

    for metric, ylabel, title in [
            ("acc", "Detection accuracy", "Detection accuracy vs attacker %"),
            ("pdr", "Network PDR (Eq.20)", "Packet delivery ratio vs attacker %"),
            ("ro", "Routing overhead (Eq.19)", "Routing overhead vs attacker %")]:
        fig, a = plt.subplots(figsize=(7, 5))
        _curve(a, x, agg, metric, ylabel, title)
        out = os.path.join(RESULTS, f"soa1_sweep_{metric}.png")
        fig.tight_layout(); fig.savefig(out, dpi=130); plt.close(fig)
        print(f"[SOA1 SWEEP] {metric} -> {out}")


if __name__ == "__main__":
    main()
