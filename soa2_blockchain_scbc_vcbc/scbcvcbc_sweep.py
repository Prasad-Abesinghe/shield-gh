#!/usr/bin/env python3
"""
scbcvcbc_sweep.py — SOA2 attacker-percentage sweep + plots
==========================================================
Supervisor's ask: "vary the independent variable (usually the attack
percentage) and plot what happens to the metrics."

For each attacker fraction f in a sweep range, this builds a network of N
vehicles where f·N are malicious (mix of blackhole + greyhole), generates each
node's relay statistics, classifies every node with the SCBC/VCBC smart
contract, and records the resulting metrics:

  • Classification Accuracy   (TP+TN)/N
  • TPR (recall) / FPR
  • Network PDR (Eq.1)         delivered / total relays
  • Routing Overhead (Eq.3)    (Dnet+Dctrl)/Dnet

Two contracts are swept side by side (paper §6):
  SCBC — classify from delivered ratio only (no prior knowledge)
  VCBC — miner voting pre-filter (Alg.4) removes grey/black up front, then SCBC

Backends:
  --backend local   (default)  Alg.3 classifier in-process — fast, many seeds
  --backend fabric             real chaincode invoke/query per node on Fabric

Outputs:
  results/soa2_sweep_results.csv
  results/soa2_sweep_<metric>.png   (accuracy, fpr_tpr, pdr, overhead)

Usage
-----
  python3 scbcvcbc_sweep.py                          # local, default sweep
  python3 scbcvcbc_sweep.py --N 30 --seeds 20
  python3 scbcvcbc_sweep.py --backend fabric --N 10  # real blockchain (slow)
"""

import os
import csv
import json
import time
import random
import argparse

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# reuse the bridge's classifier + Fabric plumbing (single source of truth)
import importlib.util
_BRIDGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scbcvcbc_bridge.py")
_spec = importlib.util.spec_from_file_location("scbcvcbc_bridge", _BRIDGE)
bridge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bridge)

HOME = os.path.expanduser("~")
RESULTS = os.path.join(HOME, "ns-allinone-3.35/ns-3.35/results")
RELAYS = 100           # relay opportunities per node (resolution of the rating)
RATING_THR = bridge.RATING_THRESHOLD


# ── one network realisation at a given attacker fraction ────────────────────
# attacker mix: half blackhole (PDR~0), half greyhole (PDR~τ-band); honest high.
#
# Realistic confound (why the curves move): in a multi-hop VANET a node's
# OBSERVED forwarding ratio is its own behaviour AND the downstream path. As
# attacker density rises, more of an honest node's forwarded packets are dropped
# by malicious relays further along, so its observed PDR sags toward the
# threshold (path-contamination ≈ attacker_frac). Greyholes sit right on τ, so
# rising contamination pushes honest nodes into the grey band (false positives)
# and lets some greyholes masquerade — exactly the regime the supervisor expects
# to see in the plots.
def make_network(n_nodes, attacker_frac, rng):
    n_attackers = int(round(attacker_frac * n_nodes))
    labels = [1] * n_attackers + [0] * (n_nodes - n_attackers)
    rng.shuffle(labels)
    # downstream path contamination grows with attacker density
    contamination = attacker_frac
    nodes = []
    for i, is_atk in enumerate(labels):
        if is_atk:
            if i % 2 == 0:                       # blackhole — drops ~everything
                own = rng.uniform(0.0, 0.05)
            else:                                # greyhole — straddles τ
                own = rng.uniform(0.35, 0.60)
        else:                                    # honest — forwards faithfully
            own = rng.uniform(0.88, 0.99)
        # observed = own behaviour attenuated by contaminated downstream path
        # (blackholes already ~0, so contamination barely changes them)
        observed = own * (1.0 - 0.5 * contamination * rng.uniform(0.6, 1.0))
        observed = min(max(observed, 0.0), 1.0)
        delivered = int(round(observed * RELAYS))
        nodes.append({
            "id": f"n{i}",
            "delivered": delivered,
            "not_delivered": RELAYS - delivered,
            "is_attacker": is_atk,
        })
    return nodes


# ── miner reputation vote for VCBC (Alg.4): noisy oracle of true status ──────
# Models the paper's "minimum awareness": miners vote correctly with prob p_vote.
def miner_vote(node, rng, p_vote=0.85):
    _, true_status = bridge.classify(node["delivered"], node["not_delivered"])
    if rng.random() < p_vote:
        return {"white": "w", "grey": "g", "black": "b"}[true_status]
    return rng.choice(["w", "g", "b"])


# ── classify all nodes with one contract, return metrics ────────────────────
def evaluate(nodes, contract, backend, rng, env=None):
    # VCBC voting pre-filter (Alg.4): drop grey/black-voted nodes before classify
    considered = nodes
    if contract == "VCBC":
        kept = []
        for node in nodes:
            if miner_vote(node, rng) in ("g", "b"):
                # excluded up front; counts as correctly-handled if truly malicious
                node["_excluded"] = True
            else:
                node["_excluded"] = False
                kept.append(node)
        considered = nodes  # keep all for scoring; excluded ones are "flagged"

    TP = TN = FP = FN = 0
    tot_delivered = tot_relays = 0
    for node in considered:
        excluded = node.get("_excluded", False)
        if excluded:
            status = "black"  # voting removed it = treated as malicious
        else:
            status = classify_status(node, backend, env)
        flagged = 1 if status in ("grey", "black") else 0
        a = node["is_attacker"]
        if flagged and a: TP += 1
        elif flagged and not a: FP += 1
        elif not flagged and a: FN += 1
        else: TN += 1
        # only white (used) relays contribute to delivered network traffic
        if status == "white":
            tot_delivered += node["delivered"]
            tot_relays += node["delivered"] + node["not_delivered"]

    N = len(considered)
    acc = (TP + TN) / N if N else 0.0
    fpr = FP / (FP + TN) if (FP + TN) else 0.0
    tpr = TP / (TP + FN) if (TP + FN) else 0.0
    # network PDR over the relays actually routed through white nodes
    net_pdr = tot_delivered / tot_relays if tot_relays else 0.0
    d_net = max(sum(n["delivered"] + n["not_delivered"] for n in considered), 1)
    d_ctrl = N  # one 100-byte contract call per node
    ro = (d_net + d_ctrl) / d_net
    return dict(acc=acc, fpr=fpr, tpr=tpr, pdr=net_pdr, ro=ro,
                TP=TP, TN=TN, FP=FP, FN=FN)


def classify_status(node, backend, env):
    if backend == "local":
        return bridge.classify(node["delivered"], node["not_delivered"])[1]
    # fabric: commit + read back the on-chain verdict. The invoke returns once
    # endorsed, but the ordered block takes a moment to commit to the query
    # peer's state DB — retry the read until the record appears.
    args = json.dumps({"function": "CommitRelayRecord",
                       "Args": [node["id"], str(node["delivered"]),
                                str(node["not_delivered"]), str(node["is_attacker"])]})
    bridge.peer_invoke(args, env)
    q = json.dumps({"function": "ReadNode", "Args": [node["id"]]})
    for attempt in range(8):
        time.sleep(1.0)
        try:
            return json.loads(bridge.peer_query(q, env))["status"]
        except Exception:
            if attempt == 7:
                raise
    return "white"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--N", type=int, default=20, help="nodes per network")
    ap.add_argument("--seeds", type=int, default=15, help="repetitions per point")
    ap.add_argument("--fracs", default="0.1,0.2,0.3,0.4,0.5,0.6",
                    help="attacker fractions to sweep")
    ap.add_argument("--backend", choices=["local", "fabric"], default="local")
    args = ap.parse_args()

    fracs = [float(x) for x in args.fracs.split(",")]
    env = bridge.fabric_env() if args.backend == "fabric" else None
    contracts = ["SCBC", "VCBC"]

    os.makedirs(RESULTS, exist_ok=True)
    csv_path = os.path.join(RESULTS, "soa2_sweep_results.csv")
    rows = []
    # agg[contract][metric] = list over fracs of (mean, std)
    agg = {c: {m: [] for m in ("acc", "fpr", "tpr", "pdr", "ro")} for c in contracts}

    print(f"[SWEEP] backend={args.backend} N={args.N} seeds={args.seeds} "
          f"fracs={fracs}")
    for c in contracts:
        for f in fracs:
            samples = {m: [] for m in ("acc", "fpr", "tpr", "pdr", "ro")}
            for s in range(args.seeds):
                rng = random.Random(1000 * int(f * 100) + s)
                nodes = make_network(args.N, f, rng)
                r = evaluate(nodes, c, args.backend, rng, env)
                for m in samples:
                    samples[m].append(r[m])
                rows.append([c, f, s, r["TP"], r["TN"], r["FP"], r["FN"],
                             f"{r['acc']:.4f}", f"{r['fpr']:.4f}",
                             f"{r['tpr']:.4f}", f"{r['pdr']:.4f}", f"{r['ro']:.4f}"])
            for m in samples:
                agg[c][m].append((float(np.mean(samples[m])),
                                  float(np.std(samples[m]))))
            print(f"  {c} f={f:.0%}: acc={np.mean(samples['acc']):.3f} "
                  f"tpr={np.mean(samples['tpr']):.3f} fpr={np.mean(samples['fpr']):.3f} "
                  f"pdr={np.mean(samples['pdr']):.3f}")

    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["Contract", "AttackerFrac", "Seed", "TP", "TN", "FP", "FN",
                    "Accuracy", "FPR", "TPR", "NetworkPDR", "RoutingOverhead"])
        w.writerows(rows)
    print(f"[SWEEP] raw results -> {csv_path}")

    plot(fracs, agg, contracts, args)


def _curve(ax, fracs, agg, contracts, metric, ylabel, title):
    x = [f * 100 for f in fracs]
    for c in contracts:
        means = [m for m, _ in agg[c][metric]]
        stds = [s for _, s in agg[c][metric]]
        ax.errorbar(x, means, yerr=stds, marker="o", capsize=3, label=c)
    ax.set_xlabel("Attacker percentage (%)")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(True, alpha=0.3)
    ax.legend()


def plot(fracs, agg, contracts, args):
    # combined 2x2 panel
    fig, axes = plt.subplots(2, 2, figsize=(12, 9))
    _curve(axes[0, 0], fracs, agg, contracts, "acc",
           "Classification accuracy", "Detection accuracy vs attacker %")
    _curve(axes[0, 1], fracs, agg, contracts, "pdr",
           "Network PDR (Eq.1)", "Packet delivery ratio vs attacker %")
    # FPR/TPR on one axis
    ax = axes[1, 0]
    x = [f * 100 for f in fracs]
    for c in contracts:
        ax.errorbar(x, [m for m, _ in agg[c]["tpr"]], marker="o", capsize=3,
                    label=f"{c} TPR")
        ax.errorbar(x, [m for m, _ in agg[c]["fpr"]], marker="s", linestyle="--",
                    capsize=3, label=f"{c} FPR")
    ax.set_xlabel("Attacker percentage (%)"); ax.set_ylabel("Rate")
    ax.set_title("TPR / FPR vs attacker %"); ax.grid(True, alpha=0.3); ax.legend()
    _curve(axes[1, 1], fracs, agg, contracts, "ro",
           "Routing overhead (Eq.3)", "Routing overhead vs attacker %")
    fig.suptitle(f"SOA2 SCBC/VCBC sweep (N={args.N}, {args.seeds} seeds, "
                 f"backend={args.backend})", fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.97])
    panel = os.path.join(RESULTS, "soa2_sweep_panel.png")
    fig.savefig(panel, dpi=130)
    print(f"[SWEEP] combined panel -> {panel}")

    # individual figures too (for slides)
    singles = [("acc", "Classification accuracy", "Detection accuracy vs attacker %"),
               ("pdr", "Network PDR (Eq.1)", "Packet delivery ratio vs attacker %"),
               ("ro", "Routing overhead (Eq.3)", "Routing overhead vs attacker %")]
    for metric, ylabel, title in singles:
        fig, ax = plt.subplots(figsize=(7, 5))
        _curve(ax, fracs, agg, contracts, metric, ylabel, title)
        out = os.path.join(RESULTS, f"soa2_sweep_{metric}.png")
        fig.tight_layout(); fig.savefig(out, dpi=130); plt.close(fig)
        print(f"[SWEEP] {metric} -> {out}")


if __name__ == "__main__":
    main()
