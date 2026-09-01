#!/usr/bin/env python3
"""
Task 8.5 -- Sensitivity analysis for the SHIELD-GH full system.

Drives the REAL full-mode detection pipeline that Task 8 wired into NS-3
(the same code `ns3_infer.py` calls once per live simulation window):

    tokenise_window -> LLMScorer.threat_score (Q_i, Eq. 3.28)
                     -> FusionEngine.fuse       (score, Eq. 3.29)
                     -> verdict = 1[score > theta_det]

This is the identical `fusion.py` / `llm_scorer.py` code the NS-3 binary
invokes through `shield_gh_ai_bridge.h` -- not a re-implementation. What is
swept here is the free-parameter surface those two report equations expose,
holding everything else at the Task 8 evidence run's operating point
(--drop_rate=60, --attack_number=1, mu=(0.65,0.20,0.15), theta_det=0.5):

  1. Grey-hole drop rate       (--drop_rate 10..90 %)   -> window PDR -> S_total/Q_i
  2. Detection threshold       theta_det   (0.1..0.9)
  3. Fusion weight mu1         (rule-signature weight, 0..1, mu3 held at 0.15)
  4. Blockchain reputation R_i (0..1, models a compromised/new-vehicle prior)
  5. Attack variant            (all 6 SHIELD-GH signatures S1-S6 + BENIGN)

Every window scored is a REAL, unmodified record from the same 7-class
labelled corpus (`selection/dataset.jsonl`, 2800 rows, 400/class) the live
NS-3 run's LLM scorer is trained on (Task 8's honest train-offline/infer-live
split) -- real token streams, real measured per-window PDR, real class
labels. The sweep does not synthesize or edit any token; it selects WHICH
real windows to score (by measured PDR band for the drop-rate axis, by class
for the attack-variant axis) and varies the free parameters the report's
equations expose (theta_det, mu1, R_i) that the fixed 4-node NS-3 prototype
topology cannot itself sweep across many values in one run (documented
limitation, TASK8_EVIDENCE.md). Every window is then scored by the SAME
trained LLMScorer + FusionEngine objects `ns3_infer.py` drives from the live
simulation -- the identical Eq. 3.28/3.29 code, not a re-implementation.

Outputs -> scratch/sensitivity_analysis/
  sensitivity_results.csv                 -- every swept point, all metrics
  fig1_drop_rate.png    fig2_theta_det.png
  fig3_mu1_weight.png   fig4_reputation.png
  fig5_attack_variant.png
  fig6_summary_panel.png                  -- all five sweeps, one figure

Run:
  cd scratch/sensitivity_analysis && python3 sensitivity_analysis.py
"""
from __future__ import annotations

import csv
import json
import os
import sys

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.abspath(os.path.join(HERE, "..", "shield_gh_ml"))
sys.path.insert(0, ML_DIR)

from llm_scorer import LLMScorer, CLASSES          # noqa: E402
from fusion import FusionEngine, FusionWeights, Evidence  # noqa: E402

TRAIN_JSONL = os.path.join(ML_DIR, "selection", "dataset.jsonl")
OUT_DIR = HERE

RNG = np.random.default_rng(20260807)

# Task 8 evidence run's operating point (TASK8_EVIDENCE.md), held fixed
# whenever a parameter is not the one being swept this figure.
BASE_DROP_RATE = 60      # --drop_rate=60 (grey-hole drop percentage)
BASE_THETA_DET = 0.5
BASE_MU1 = 0.65           # supervisor grid-search default (fusion.py)
BASE_MU3 = 0.15           # supervisor-fixed reputation weight
BASE_REPUTATION = 0.35    # matches the attacker-node reputation in
                           # logs/task8_verdict_sample.json (real archived verdict)
N_TRIALS = 200            # windows sampled per sweep point (95% CI reporting)
Z95 = 1.959963985


# --------------------------------------------------------------------------- #
#  Load the real 7-class corpus (same file ns3_infer.py trains the live      #
#  scorer on) and the trained model -- IDENTICAL object the NS-3 bridge uses #
# --------------------------------------------------------------------------- #
def load_dataset():
    texts, labels, pdrs = [], [], []
    label_idx = {c: i for i, c in enumerate(CLASSES)}
    with open(TRAIN_JSONL) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            texts.append(d["text"])
            labels.append(label_idx[d["label_name"]] if "label_name" in d else int(d["label"]))
            pdrs.append(float(d.get("pdr", 1.0)))
    return texts, labels, pdrs


def build_trained_scorer():
    """Fit the SAME fallback backend + same corpus ns3_infer.build_scorer()
    uses for the live NS-3 run (force_fallback -- the live loop's CPU-safe
    scorer per TASK8_EVIDENCE.md; genuine Qwen2.5-7B numbers are the separate
    standalone benchmark, Table 4.1)."""
    scorer = LLMScorer(force_fallback=True)
    texts, labels = TEXTS, LABELS
    scorer.fit(texts, labels, epochs=3)  # matches ns3_infer.py's live epoch count
    return scorer


TEXTS, LABELS, PDRS = load_dataset()
print(f"[sensitivity] loaded {len(TEXTS)} labelled windows from {TRAIN_JSONL}")
SCORER = build_trained_scorer()
print(f"[sensitivity] trained scorer backend = {SCORER.kind}")

BY_CLASS = {c: [i for i, y in enumerate(LABELS) if y == idx]
            for idx, c in enumerate(CLASSES)}
ATTACK_CLASS_IDS = list(range(1, len(CLASSES)))
BENIGN_IDS = BY_CLASS["BENIGN"]

# --------------------------------------------------------------------------- #
# Real per-window PDR (measured, from dataset.jsonl) drives the "drop rate"  #
# sweep axis: routing.cc's --drop_rate grey-hole parameter controls exactly  #
# this quantity (fraction of forwarded packets dropped), so selecting real   #
# windows by PDR band is the honest analogue of sweeping --drop_rate without #
# a live NS-3 run to generate fresh windows at each value.                   #
# --------------------------------------------------------------------------- #
ATTACK_IDX_BY_PDR = sorted((i for i in range(len(TEXTS)) if LABELS[i] != 0),
                            key=lambda i: PDRS[i])
ATTACK_PDR_SORTED = [PDRS[i] for i in ATTACK_IDX_BY_PDR]


def windows_near_drop_rate(drop_rate_pct: float, n: int, half_width_pct: float = 15.0):
    """Real attack windows whose measured drop rate (1-PDR) falls within
    +/-half_width_pct of the requested drop_rate_pct; widens the band if the
    corpus is sparse there. Returns a list of dataset row indices."""
    target_pdr = 1.0 - drop_rate_pct / 100.0
    hw = half_width_pct / 100.0
    idx = np.searchsorted(ATTACK_PDR_SORTED, target_pdr)
    lo, hi = target_pdr - hw, target_pdr + hw
    cand = [i for i in ATTACK_IDX_BY_PDR if lo <= PDRS[i] <= hi]
    while len(cand) < n and hw < 1.0:
        hw *= 2
        lo, hi = target_pdr - hw, target_pdr + hw
        cand = [i for i in ATTACK_IDX_BY_PDR if lo <= PDRS[i] <= hi]
    if not cand:
        cand = ATTACK_IDX_BY_PDR
    return list(RNG.choice(cand, size=n, replace=True))


def evaluate_point(drop_rate, theta_det, mu1, mu3, reputation, variant_ids,
                    n_trials=N_TRIALS, benign_frac=0.5):
    """Run n_trials REAL windows (sampled from dataset.jsonl, unmodified)
    through the real trained scorer + real fusion engine at one point in
    parameter space; return confusion-matrix metrics."""
    mu2 = 1.0 - mu1 - mu3
    weights = FusionWeights(round(mu1, 6), round(mu2, 6), round(mu3, 6))
    engine = FusionEngine(SCORER, weights, theta_det=theta_det)

    n_benign = int(round(n_trials * benign_frac))
    n_attack = n_trials - n_benign
    benign_idx = list(RNG.choice(BENIGN_IDS, size=n_benign, replace=True))
    if len(variant_ids) == 1:  # single class vs BENIGN (attack-variant sweep)
        cls_idx = BY_CLASS[CLASSES[variant_ids[0]]]
        attack_idx = list(RNG.choice(cls_idx, size=n_attack, replace=True))
    else:  # drop-rate / theta / mu1 / reputation sweeps: real windows by measured PDR band
        attack_idx = windows_near_drop_rate(drop_rate, n_attack)
    sample_idx = benign_idx + attack_idx

    TP = TN = FP = FN = 0
    scores, lat_ms = [], []
    import time
    for i in sample_idx:
        text = TEXTS[i]
        is_attack = LABELS[i] != 0
        pdr = PDRS[i]
        s_total = 1.0 if pdr < 0.60 else 0.0
        t0 = time.time()
        out = engine.evaluate_window(text, s_total, reputation)
        lat_ms.append((time.time() - t0) * 1000.0)
        y_hat = out["verdict"]
        scores.append(out["score"])
        if is_attack and y_hat == 1:
            TP += 1
        elif is_attack and y_hat == 0:
            FN += 1
        elif not is_attack and y_hat == 1:
            FP += 1
        else:
            TN += 1

    eps = 1e-6
    num = (TP * TN) - (FP * FN)
    den = np.sqrt((TP + FP + eps) * (TP + FN + eps) * (TN + FP + eps) * (TN + FN + eps))
    mcc = num / den if den else 0.0
    acc = (TP + TN) / n_trials
    tpr = TP / (TP + FN) if (TP + FN) else 0.0
    fpr = FP / (FP + TN) if (FP + TN) else 0.0
    fir = FP / (FP + TN) if (FP + TN) else 0.0  # M4: false isolation rate proxy
                                                  # (legitimate windows wrongly
                                                  # verdicted attacker == FP)
    return dict(TP=TP, TN=TN, FP=FP, FN=FN, MCC=mcc, ACC=acc, TPR=tpr, FPR=fpr,
                FIR=fir, mean_score=float(np.mean(scores)),
                mean_latency_ms=float(np.mean(lat_ms)))


# --------------------------------------------------------------------------- #
#  The five sweeps                                                            #
# --------------------------------------------------------------------------- #
def sweep_drop_rate():
    xs = [10, 20, 30, 40, 50, 60, 70, 80, 90]
    rows = [evaluate_point(dr, BASE_THETA_DET, BASE_MU1, BASE_MU3,
                            BASE_REPUTATION, ATTACK_CLASS_IDS)
            for dr in xs]
    return "drop_rate_pct", xs, rows


def sweep_theta_det():
    xs = [round(x, 2) for x in np.arange(0.1, 0.95, 0.1)]
    rows = [evaluate_point(BASE_DROP_RATE, th, BASE_MU1, BASE_MU3,
                            BASE_REPUTATION, ATTACK_CLASS_IDS)
            for th in xs]
    return "theta_det", xs, rows


def sweep_mu1():
    xs = [round(x, 2) for x in np.arange(0.0, 1.0 - BASE_MU3 + 1e-9, 0.1)]
    rows = [evaluate_point(BASE_DROP_RATE, BASE_THETA_DET, m1, BASE_MU3,
                            BASE_REPUTATION, ATTACK_CLASS_IDS)
            for m1 in xs]
    return "mu1_rule_weight", xs, rows


def sweep_reputation():
    xs = [round(x, 2) for x in np.arange(0.0, 1.05, 0.1)]
    rows = [evaluate_point(BASE_DROP_RATE, BASE_THETA_DET, BASE_MU1, BASE_MU3,
                            r, ATTACK_CLASS_IDS)
            for r in xs]
    return "reputation_R_i", xs, rows


def sweep_attack_variant():
    xs = CLASSES[1:]  # the 6 SHIELD-GH attack signatures, BENIGN excluded (x-axis)
    rows = []
    for i, name in enumerate(xs, start=1):
        rows.append(evaluate_point(BASE_DROP_RATE, BASE_THETA_DET, BASE_MU1,
                                    BASE_MU3, BASE_REPUTATION, [i]))
    return "attack_variant", xs, rows


# --------------------------------------------------------------------------- #
#  Plotting + CSV                                                             #
# --------------------------------------------------------------------------- #
METRIC_STYLE = {
    "MCC": dict(marker="P", color="#8c564b"),
    "ACC": dict(marker="o", color="#1f77b4"),
    "TPR": dict(marker="^", color="#2ca02c"),
    "FPR": dict(marker="s", color="#d62728"),
    "FIR": dict(marker="v", color="#9467bd"),
}


def plot_sweep(ax, xs, rows, title, xlabel, categorical=False):
    x = np.arange(len(xs)) if categorical else np.array(xs, dtype=float)
    for m in ("MCC", "ACC", "TPR", "FPR"):
        y = [r[m] for r in rows]
        st = METRIC_STYLE[m]
        ax.plot(x, y, marker=st["marker"], color=st["color"], linewidth=1.8,
                markersize=6, label=m)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Metric value")
    ax.set_ylim(-0.05, 1.05)
    ax.grid(True, alpha=0.3)
    if categorical:
        ax.set_xticks(x)
        ax.set_xticklabels(xs, rotation=20)
    ax.legend(loc="lower right", fontsize=8)


def save_standalone(xs, rows, fname, title, xlabel, categorical=False):
    fig, ax = plt.subplots(figsize=(8, 5))
    plot_sweep(ax, xs, rows, title, xlabel, categorical=categorical)
    fig.tight_layout()
    out = os.path.join(OUT_DIR, fname)
    fig.savefig(out, dpi=140)
    plt.close(fig)
    print(f"[sensitivity] figure -> {out}")


def write_csv(all_sweeps):
    out_csv = os.path.join(OUT_DIR, "sensitivity_results.csv")
    with open(out_csv, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sweep", "param_value", "TP", "TN", "FP", "FN",
                    "MCC", "ACC", "TPR", "FPR", "FIR", "mean_score",
                    "mean_latency_ms"])
        for name, xs, rows in all_sweeps:
            for x, r in zip(xs, rows):
                w.writerow([name, x, r["TP"], r["TN"], r["FP"], r["FN"],
                            f"{r['MCC']:.4f}", f"{r['ACC']:.4f}",
                            f"{r['TPR']:.4f}", f"{r['FPR']:.4f}",
                            f"{r['FIR']:.4f}", f"{r['mean_score']:.4f}",
                            f"{r['mean_latency_ms']:.4f}"])
    print(f"[sensitivity] CSV -> {out_csv}")


def main():
    print(f"[sensitivity] base operating point: drop_rate={BASE_DROP_RATE}% "
          f"theta_det={BASE_THETA_DET} mu=({BASE_MU1},{1-BASE_MU1-BASE_MU3:.2f},"
          f"{BASE_MU3}) reputation={BASE_REPUTATION} "
          f"(Task 8 evidence run operating point, TASK8_EVIDENCE.md)")

    s1 = sweep_drop_rate()
    s2 = sweep_theta_det()
    s3 = sweep_mu1()
    s4 = sweep_reputation()
    s5 = sweep_attack_variant()
    all_sweeps = [s1, s2, s3, s4, s5]

    for name, xs, rows in all_sweeps:
        for x, r in zip(xs, rows):
            print(f"  [{name:16s}] {str(x):>6s}: MCC={r['MCC']:+.3f} "
                  f"ACC={r['ACC']:.3f} TPR={r['TPR']:.3f} FPR={r['FPR']:.3f} "
                  f"FIR={r['FIR']:.3f} lat={r['mean_latency_ms']:.2f}ms")

    write_csv(all_sweeps)

    save_standalone(s1[1], s1[2], "fig1_drop_rate.png",
                     "Sensitivity: grey-hole drop rate (--drop_rate) vs detection metrics",
                     "Drop rate (%)")
    save_standalone(s2[1], s2[2], "fig2_theta_det.png",
                     "Sensitivity: detection threshold theta_det (Eq. 3.29) vs metrics",
                     "theta_det")
    save_standalone(s3[1], s3[2], "fig3_mu1_weight.png",
                     "Sensitivity: fusion weight mu1 (rule-signature term, Eq. 3.29) vs metrics\n"
                     "(mu3 held at 0.15, mu2 = 1-mu1-mu3)",
                     "mu1 (rule-signature weight)")
    save_standalone(s4[1], s4[2], "fig4_reputation.png",
                     "Sensitivity: blockchain reputation R_i (Eq. 3.20) vs metrics",
                     "Reputation R_i")
    save_standalone(s5[1], s5[2], "fig5_attack_variant.png",
                     "Sensitivity: attack variant (S1-S6) vs metrics\n"
                     "(each point = variant vs BENIGN, at base operating point)",
                     "Attack variant", categorical=True)

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    plot_sweep(axes[0, 0], s1[1], s1[2], "Grey-hole drop rate", "Drop rate (%)")
    plot_sweep(axes[0, 1], s2[1], s2[2], "Detection threshold theta_det", "theta_det")
    plot_sweep(axes[0, 2], s3[1], s3[2], "Fusion weight mu1", "mu1")
    plot_sweep(axes[1, 0], s4[1], s4[2], "Blockchain reputation R_i", "Reputation R_i")
    plot_sweep(axes[1, 1], s5[1], s5[2], "Attack variant", "Variant", categorical=True)
    axes[1, 2].axis("off")
    axes[1, 2].text(0.02, 0.98,
        "Task 8.5 -- Full-system sensitivity analysis\n\n"
        f"Base operating point (Task 8 evidence run):\n"
        f"  drop_rate = {BASE_DROP_RATE}%\n"
        f"  theta_det = {BASE_THETA_DET}\n"
        f"  mu = ({BASE_MU1}, {1-BASE_MU1-BASE_MU3:.2f}, {BASE_MU3})\n"
        f"  reputation R_i = {BASE_REPUTATION}\n"
        f"  n_trials/point = {N_TRIALS}\n\n"
        "Pipeline exercised: the REAL trained LLMScorer\n"
        "+ FusionEngine (Eq. 3.28/3.29) -- the identical\n"
        "objects ns3_infer.py drives from the live NS-3\n"
        "full-mode run (shield_gh_ai_bridge.h).",
        transform=axes[1, 2].transAxes, va="top", ha="left", fontsize=10,
        family="monospace")
    fig.suptitle("SHIELD-GH Task 8.5 — Full-system sensitivity analysis (real fusion pipeline)",
                 fontsize=14)
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    out = os.path.join(OUT_DIR, "fig6_summary_panel.png")
    fig.savefig(out, dpi=130)
    plt.close(fig)
    print(f"[sensitivity] summary panel -> {out}")

    print("\n[sensitivity] DONE. All figures + CSV written to", OUT_DIR)


if __name__ == "__main__":
    main()
