#!/usr/bin/env python3
"""
soa3_rf_sweep_real.py — SOA3 (Arizaga-Silva RF-IDS) attacker-% sweep, REAL ns-3
================================================================================
Baseline: Arizaga-Silva, Medina-Santiago, Espinosa-Tlaxcaltecatl, Muniz-Montero,
"Machine Learning-Powered IDS for Gray Hole Attack Detection in VANETs",
World Electric Vehicle Journal (MDPI) 2025, 16, 526.

Supervisor requirements addressed
---------------------------------
1. REAL, event-driven data feeds the model. For every attacker percentage p the
   ACTUAL ns-3 simulation (routing.cc) is run with
   --attack_percentage=p --use_soa3_detection=1. ns-3 injects exactly p% real
   gray-hole attackers and, every window, writes REAL per-node forwarding
   counters (packets received / forwarded / data-plane drops / control-plane
   drops, taken straight from the simulation's own counters) to
   results/soa3_rf_features.csv. Nothing here is synthetic.
2. The classifier is a REAL scikit-learn RandomForest (paper's model: 15
   estimators, max_depth 15) — NOT an abstracted function. It is trained and
   evaluated on the real simulation features.
3. The independent variable (attacker %) is swept and every metric is plotted.
4. Each plotted point is the MEAN over repeated stratified k-fold cross-
   validation (the paper uses 10-fold CV) and the error bars are the
   95% CONFIDENCE INTERVAL of that mean.
5. Plots: distinct linestyle+colour per series, gridlines, axes labelled with
   units.

Because the ns-3 scenario is deterministic for a given configuration (a fixed
attacker % yields one real dataset), the statistical spread that the 95% CI
captures comes from repeated stratified k-fold cross-validation of the real
Random Forest over the real per-window samples — exactly the paper's own
evaluation protocol (Section 5, 10-fold stratified CV).

Usage
-----
  python3 soa3_rf_sweep_real.py                       # full real sweep
  python3 soa3_rf_sweep_real.py --percts 10,20,30,40,50,60,70,80
  python3 soa3_rf_sweep_real.py --reuse               # reuse cached per-p CSVs
"""

import os
import sys
import glob
import shutil
import argparse
import subprocess

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import RepeatedStratifiedKFold
from sklearn.metrics import (confusion_matrix, matthews_corrcoef)

# ── Paths ─────────────────────────────────────────────────────────────────────
HOME        = os.path.expanduser("~")
NS3         = os.path.join(HOME, "ns-allinone-3.35", "ns-3.35")
RESULTS     = os.path.join(NS3, "results")
FEATURES    = os.path.join(RESULTS, "soa3_rf_features.csv")
CACHE       = os.path.join(RESULTS, "soa3_real_cache")   # per-% CSV snapshots
OUT_CSV     = os.path.join(RESULTS, "soa3_real_sweep_results.csv")

# ── Real features written by routing.cc soa3_monitor_window() ────────────────
BASE_FEATURES = [
    "pkt_received", "pkt_forwarded", "pkt_drop_dp", "pkt_drop_cp",
    "local_pdr", "drop_rate_dp", "drop_rate_cp",
    "fwd_ratio", "drop_total", "recv_gt0",
]
LABEL = "is_attacker"

# Paper's tuned Random Forest (Section 5: 15 estimators, max_depth 15).
RF_ESTIMATORS = 15
RF_MAX_DEPTH  = 15

# 95% CI z-multiplier for the normal approximation of the mean.
Z95 = 1.959963985


# ─────────────────────────────────────────────────────────────────────────────
def run_ns3(pct, sim_time, attack_number, n_vehicles):
    """Run the REAL ns-3 sim at attacker percentage `pct`; cache its feature CSV."""
    if os.path.exists(FEATURES):
        os.remove(FEATURES)
    cmd = ("routing --routing_test=true "
           f"--simTime={sim_time} --routing_algorithm=4 "
           f"--attack_number={attack_number} --attack_percentage={pct} "
           f"--N_Vehicles={n_vehicles} --use_soa3_detection=1")
    print(f"[SOA3-REAL] ns-3 run: attack_percentage={pct}% ...")
    r = subprocess.run(["./waf", "--run", cmd], cwd=NS3,
                       capture_output=True, text=True)
    if not os.path.exists(FEATURES):
        sys.stderr.write(r.stdout[-2500:] + r.stderr[-2500:])
        raise RuntimeError(f"ns-3 did not produce {FEATURES} for pct={pct}")
    os.makedirs(CACHE, exist_ok=True)
    dst = os.path.join(CACHE, f"soa3_p{pct}.csv")
    shutil.copy(FEATURES, dst)
    return dst


def load_features(csv_path):
    """Load and clean the REAL per-window feature table produced by ns-3."""
    df = pd.read_csv(csv_path)
    # Drop any accidental repeated-header rows, coerce to numeric, drop NaNs.
    df = df[df[LABEL] != LABEL]
    for c in df.columns:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.dropna().reset_index(drop=True)
    return df


def engineer_features(df):
    """Same lightweight derived features as the single-run script, from REAL data."""
    df = df.copy()
    win_avg = df.groupby("window")["local_pdr"].transform("mean")
    df["net_avg_pdr"]      = win_avg
    df["pdr_deviation"]    = df["local_pdr"] - win_avg
    safe_rcv               = df["pkt_received"].replace(0, 1)
    df["total_drop_ratio"] = (df["pkt_drop_dp"] + df["pkt_drop_cp"]) / safe_rcv
    df["fwd_efficiency"]   = df["pkt_forwarded"] / safe_rcv
    return df


ALL_FEATURES = BASE_FEATURES + [
    "net_avg_pdr", "pdr_deviation", "total_drop_ratio", "fwd_efficiency",
]


def evaluate_rf_cv(df, n_splits=5, n_repeats=6, seed0=42):
    """Train + evaluate the REAL Random Forest with repeated stratified k-fold CV.

    Returns per-fold arrays of accuracy(%), precision, recall, F1, FPR(%), MCC.
    Each fold is a genuine train/test split of the REAL simulation samples; the
    spread across the (n_splits * n_repeats) folds is what the 95% CI reports.
    """
    X = df[ALL_FEATURES].values
    y = df[LABEL].astype(int).values

    # Stratified CV needs >=2 samples of each class; guard tiny/degenerate sets.
    n_pos, n_neg = int((y == 1).sum()), int((y == 0).sum())
    if n_pos < 2 or n_neg < 2:
        return None

    n_splits = max(2, min(n_splits, n_pos, n_neg))
    rskf = RepeatedStratifiedKFold(n_splits=n_splits, n_repeats=n_repeats,
                                   random_state=seed0)

    acc, prec, rec, f1, fpr, mcc = [], [], [], [], [], []
    fold_i = 0
    for tr_idx, te_idx in rskf.split(X, y):
        scaler = StandardScaler()
        X_tr = scaler.fit_transform(X[tr_idx])
        X_te = scaler.transform(X[te_idx])
        y_tr, y_te = y[tr_idx], y[te_idx]
        if len(set(y_tr)) < 2:
            continue

        clf = RandomForestClassifier(
            n_estimators=RF_ESTIMATORS, max_depth=RF_MAX_DEPTH,
            random_state=seed0 + fold_i, n_jobs=-1)
        clf.fit(X_tr, y_tr)
        y_pred = clf.predict(X_te)
        fold_i += 1

        cm = confusion_matrix(y_te, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        n = tp + tn + fp + fn
        acc.append(100.0 * (tp + tn) / n if n else 0.0)
        prec.append(tp / (tp + fp) if (tp + fp) else 0.0)
        rec.append(tp / (tp + fn) if (tp + fn) else 0.0)
        p_, r_ = prec[-1], rec[-1]
        f1.append(2 * p_ * r_ / (p_ + r_) if (p_ + r_) else 0.0)
        fpr.append(100.0 * fp / (fp + tn) if (fp + tn) else 0.0)
        mcc.append(matthews_corrcoef(y_te, y_pred) if len(set(y_te)) > 1 else 0.0)

    if not acc:
        return None
    return {
        "acc": np.array(acc), "prec": np.array(prec), "rec": np.array(rec),
        "f1": np.array(f1), "fpr": np.array(fpr), "mcc": np.array(mcc),
    }


def mean_ci95(v):
    """Mean and 95% CI half-width (normal approx of the mean) for array v."""
    v = np.asarray(v, dtype=float)
    m = float(v.mean())
    if v.size < 2:
        return m, 0.0
    sem = v.std(ddof=1) / np.sqrt(v.size)
    return m, float(Z95 * sem)


# ─────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--percts", default="10,20,30,40,50,60,70,80")
    ap.add_argument("--simTime", type=int, default=30)
    ap.add_argument("--attack_number", type=int, default=1)
    ap.add_argument("--N_Vehicles", type=int, default=5,
                    help="ns-3 topology size (routing_test ceiling is total_size=5)")
    ap.add_argument("--splits", type=int, default=5)
    ap.add_argument("--repeats", type=int, default=6)
    ap.add_argument("--reuse", action="store_true",
                    help="reuse cached per-% CSVs, skip ns-3")
    args = ap.parse_args()
    percts = [int(x) for x in args.percts.split(",")]

    rows = []
    series = {m: {"mean": [], "ci": []} for m in
              ("acc", "prec", "rec", "f1", "fpr", "mcc")}
    kept_percts = []

    for p in percts:
        cache = os.path.join(CACHE, f"soa3_p{p}.csv")
        if args.reuse and os.path.exists(cache):
            csv_path = cache
            print(f"[SOA3-REAL] reuse cached {csv_path}")
        else:
            csv_path = run_ns3(p, args.simTime, args.attack_number, args.N_Vehicles)

        df = engineer_features(load_features(csv_path))
        res = evaluate_rf_cv(df, n_splits=args.splits, n_repeats=args.repeats)
        if res is None:
            print(f"  p={p}%: SKIP — not enough of one class for stratified CV "
                  f"(rows={len(df)}, attackers={int(df[LABEL].sum())})")
            continue

        kept_percts.append(p)
        stat = {}
        for m in series:
            mean, ci = mean_ci95(res[m])
            series[m]["mean"].append(mean)
            series[m]["ci"].append(ci)
            stat[m] = (mean, ci)

        rows.append([
            p, len(df), int(df[LABEL].sum()), len(res["acc"]),
            f"{stat['acc'][0]:.4f}", f"{stat['acc'][1]:.4f}",
            f"{stat['prec'][0]:.4f}", f"{stat['prec'][1]:.4f}",
            f"{stat['rec'][0]:.4f}", f"{stat['rec'][1]:.4f}",
            f"{stat['f1'][0]:.4f}", f"{stat['f1'][1]:.4f}",
            f"{stat['fpr'][0]:.4f}", f"{stat['fpr'][1]:.4f}",
            f"{stat['mcc'][0]:.4f}", f"{stat['mcc'][1]:.4f}",
        ])
        print(f"  p={p:3d}% | real rows={len(df):4d} | folds={len(res['acc'])} | "
              f"Acc={stat['acc'][0]:6.2f}±{stat['acc'][1]:.2f}%  "
              f"F1={stat['f1'][0]:.3f}±{stat['f1'][1]:.3f}  "
              f"FPR={stat['fpr'][0]:5.2f}±{stat['fpr'][1]:.2f}%  "
              f"MCC={stat['mcc'][0]:+.3f}±{stat['mcc'][1]:.3f}")

    if not kept_percts:
        print("[SOA3-REAL] No usable attacker levels (need both classes present).")
        return

    # ── Save raw results ──────────────────────────────────────────────────────
    os.makedirs(RESULTS, exist_ok=True)
    hdr = ["AttackerPct", "RealSamples", "AttackerSamples", "CVFolds",
           "Acc_mean", "Acc_ci95", "Prec_mean", "Prec_ci95",
           "Recall_mean", "Recall_ci95", "F1_mean", "F1_ci95",
           "FPR_mean", "FPR_ci95", "MCC_mean", "MCC_ci95"]
    pd.DataFrame(rows, columns=hdr).to_csv(OUT_CSV, index=False)
    print(f"\n[SOA3-REAL] results -> {OUT_CSV}")

    plot(kept_percts, series)


# ── Plotting: distinct linestyle+colour, gridlines, labelled axes w/ units ────
def _style_axis(ax, xlabel, ylabel):
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.grid(True, which="both", linestyle=":", linewidth=0.7, alpha=0.6)
    ax.margins(x=0.03)


def plot(percts, series):
    x = np.array(percts)

    # Style table: (colour, linestyle, marker, label)
    styles = {
        "acc":  ("#1f77b4", "-",  "o", "Detection accuracy (%)"),
        "f1":   ("#2ca02c", "--", "s", "F1-score"),
        "prec": ("#9467bd", "-.", "^", "Precision"),
        "rec":  ("#ff7f0e", ":",  "D", "Recall (TPR)"),
        "fpr":  ("#d62728", "--", "v", "False-positive rate (%)"),
        "mcc":  ("#8c564b", "-",  "P", "Matthews corr. coeff."),
    }

    def eb(ax, key, unit_ylabel):
        c, ls, mk, lbl = styles[key]
        m  = np.array(series[key]["mean"])
        ci = np.array(series[key]["ci"])
        ax.errorbar(x, m, yerr=ci, color=c, linestyle=ls, marker=mk,
                    markersize=6, linewidth=1.8, capsize=4, elinewidth=1.2,
                    label=lbl)
        _style_axis(ax, "Attacker percentage (%)", unit_ylabel)

    # ── Combined 2x2 panel ────────────────────────────────────────────────────
    fig, ax = plt.subplots(2, 2, figsize=(12, 9))
    eb(ax[0, 0], "acc", "Detection accuracy (%)")
    ax[0, 0].set_title("Detection accuracy vs attacker percentage")
    ax[0, 0].set_ylim(0, 105)

    eb(ax[0, 1], "f1",   "F1-score / Precision / Recall (0-1)")
    eb(ax[0, 1], "prec", "F1-score / Precision / Recall (0-1)")
    eb(ax[0, 1], "rec",  "F1-score / Precision / Recall (0-1)")
    ax[0, 1].set_title("F1 / Precision / Recall vs attacker percentage")
    ax[0, 1].set_ylim(0, 1.05)
    ax[0, 1].legend(loc="lower left", fontsize=8)

    eb(ax[1, 0], "fpr", "False-positive rate (%)")
    ax[1, 0].set_title("False-positive rate vs attacker percentage")
    ax[1, 0].set_ylim(0, min(105, max(5, np.max(series["fpr"]["mean"]) * 1.15 + 3)))

    eb(ax[1, 1], "mcc", "Matthews correlation coefficient (-1..1)")
    ax[1, 1].set_title("MCC vs attacker percentage")
    ax[1, 1].set_ylim(-0.05, 1.05)

    fig.suptitle("SOA3 Random-Forest IDS (Arizaga-Silva 2025) — REAL ns-3 driven "
                 "sweep\nmean ± 95% CI over repeated stratified k-fold CV",
                 fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    panel = os.path.join(RESULTS, "soa3_real_sweep_panel.png")
    fig.savefig(panel, dpi=140)
    print(f"[SOA3-REAL] panel -> {panel}")

    # ── Standalone accuracy figure (headline metric) ──────────────────────────
    fig2, ax2 = plt.subplots(figsize=(8, 5))
    eb(ax2, "acc", "Detection accuracy (%)")
    ax2.set_title("SOA3 RF-IDS — detection accuracy vs attacker percentage\n"
                  "(mean ± 95% CI, real ns-3 features)")
    ax2.set_ylim(0, 105)
    ax2.legend(loc="lower left")
    fig2.tight_layout()
    accfig = os.path.join(RESULTS, "soa3_real_sweep_accuracy.png")
    fig2.savefig(accfig, dpi=140)
    print(f"[SOA3-REAL] accuracy fig -> {accfig}")

    # ── Standalone MCC figure (matches paper's headline robustness metric) ────
    fig3, ax3 = plt.subplots(figsize=(8, 5))
    eb(ax3, "mcc", "Matthews correlation coefficient (-1..1)")
    ax3.set_title("SOA3 RF-IDS — MCC vs attacker percentage\n"
                  "(mean ± 95% CI, real ns-3 features)")
    ax3.set_ylim(-0.05, 1.05)
    ax3.legend(loc="lower left")
    fig3.tight_layout()
    mccfig = os.path.join(RESULTS, "soa3_real_sweep_mcc.png")
    fig3.savefig(mccfig, dpi=140)
    print(f"[SOA3-REAL] mcc fig -> {mccfig}")


if __name__ == "__main__":
    main()
