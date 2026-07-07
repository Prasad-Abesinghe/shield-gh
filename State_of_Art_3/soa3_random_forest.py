"""
SOA3 — Arízaga-Silva et al. (2025) Random Forest IDS
=====================================================
This script implements the high-level concept of the paper:
  "Machine Learning-Powered IDS for Gray Hole Attack Detection in VANETs"
  World Electric Vehicle Journal, MDPI, 2025.

The paper trains a Random Forest on network traffic features extracted
from NS-3 logs to classify vehicles as malicious (grey hole) or benign.

WORKFLOW  (single real run — for the attacker-% sweep + CI plots use
           soa3_rf_sweep_real.py instead)
--------
1. Run the NS-3 simulation with the real feature feed enabled:
       ./waf --run "routing --routing_test=true --routing_algorithm=4 \
                    --attack_number=1 --attack_percentage=50 --N_Vehicles=5 \
                    --use_soa3_detection=1"
2. A file results/soa3_rf_features.csv is produced (one row per node per window,
   filled from the simulation's OWN forwarding/drop counters — real data).
3. Run this script:
       python3 soa3_random_forest.py
4. Output files:
       results/soa3_rf_predictions.csv   — per-node predictions
       results/soa3_rf_metrics.csv       — Detection Accuracy, FPR, MCC per window

REQUIREMENTS
------------
    pip install scikit-learn pandas numpy
"""

"""
SOA3 — Arízaga-Silva et al. (2025) Random Forest IDS
Run from scratch/State_of_Art_3/:  python3 soa3_random_forest.py
"""

import os, sys
import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, matthews_corrcoef, confusion_matrix
from sklearn.preprocessing import StandardScaler

# ── Paths (auto-detected from script location) ────────────────────────────────
# This script lives in scratch/State_of_Art_3/, so the ns-3 root is two levels up.
SCRIPT_DIR      = os.path.dirname(os.path.abspath(__file__))
NS3_ROOT        = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
RESULTS_DIR     = os.path.join(NS3_ROOT, "results")
FEATURES_CSV    = os.path.join(RESULTS_DIR, "soa3_rf_features.csv")
PREDICTIONS_CSV = os.path.join(RESULTS_DIR, "soa3_rf_predictions.csv")
METRICS_CSV     = os.path.join(RESULTS_DIR, "soa3_rf_metrics.csv")

FEATURE_COLS = [
    "pkt_received", "pkt_forwarded",
    "pkt_drop_dp",  "pkt_drop_cp",
    "local_pdr",    "drop_rate_dp", "drop_rate_cp",
    "fwd_ratio",    "drop_total",   "recv_gt0",
]
LABEL_COL = "is_attacker"

# ─────────────────────────────────────────────────────────────────────────────

def load_and_clean(path):
    if not os.path.exists(path):
        sys.exit(f"\n[SOA3] ERROR: Not found: {path}\n"
                 "Make sure use_soa3_detection=true and the sim ran.\n")

    df = pd.read_csv(path)

    # ── Fix: drop any rows where the header was written again (string values) ─
    before = len(df)
    df = df[df[LABEL_COL] != LABEL_COL]          # drop "is_attacker" literal rows
    df = df[df["window"] != "window"]             # drop "window" literal rows
    dropped = before - len(df)
    if dropped:
        print(f"[SOA3] Cleaned {dropped} duplicate-header row(s) from CSV.")

    # ── Cast all columns to numeric ───────────────────────────────────────────
    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df.dropna(inplace=True)
    df = df.astype({
        "window": int, "node_id": int, LABEL_COL: int,
        "pkt_received": int, "pkt_forwarded": int,
        "pkt_drop_dp": int, "pkt_drop_cp": int, "drop_total": int, "recv_gt0": int,
    })

    print(f"[SOA3] Loaded {len(df)} rows | {df['window'].nunique()} windows "
          f"| {df['node_id'].nunique()} nodes")
    print(f"       Labels — benign: {(df[LABEL_COL]==0).sum()}, "
          f"attacker: {(df[LABEL_COL]==1).sum()}")

    if df[LABEL_COL].nunique() < 2:
        sys.exit("[SOA3] ERROR: Only one class in labels. "
                 "Make sure an attack is active in routing.cc.")
    return df


def engineer_features(df):
    df = df.copy()
    win_avg                = df.groupby("window")["local_pdr"].transform("mean")
    df["net_avg_pdr"]      = win_avg
    df["pdr_deviation"]    = df["local_pdr"] - win_avg
    safe_rcv               = df["pkt_received"].replace(0, 1)
    df["total_drop_ratio"] = (df["pkt_drop_dp"] + df["pkt_drop_cp"]) / safe_rcv
    df["fwd_efficiency"]   = df["pkt_forwarded"] / safe_rcv
    return df


def compute_metrics(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    n   = len(y_true)
    acc = 100.0 * (tp + tn) / n if n > 0 else 0.0
    fpr = 100.0 * fp / (fp + tn) if (fp + tn) > 0 else 0.0
    mcc = matthews_corrcoef(y_true, y_pred) if len(set(y_true)) > 1 else 0.0
    return acc, fpr, mcc, int(tp), int(tn), int(fp), int(fn)


def run(df, all_features):
    # Stratified k-fold CV over ALL real per-window samples — the paper's own
    # protocol (Section 5). Stratification keeps both classes in every fold, so
    # it is robust even when SHIELD-GH isolates attackers and the class balance
    # gets skewed (a naive leave-one-window-out split collapses in that case).
    X = df[all_features].values
    y = df[LABEL_COL].astype(int).values
    n_pos, n_neg = int((y == 1).sum()), int((y == 0).sum())
    n_splits = max(2, min(10, n_pos, n_neg))
    print(f"\n[SOA3] Stratified {n_splits}-fold CV over {len(df)} real samples "
          f"(benign={n_neg}, attacker={n_pos}) …\n")

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    pred_rows, met_rows = [], []

    for fold, (tr_idx, te_idx) in enumerate(skf.split(X, y)):
        scaler = StandardScaler()
        X_tr = scaler.fit_transform(X[tr_idx])
        X_te = scaler.transform(X[te_idx])
        y_tr, y_te = y[tr_idx], y[te_idx]

        # Paper's tuned Random Forest: 15 estimators, max_depth 15 (Section 5).
        clf = RandomForestClassifier(n_estimators=15, max_depth=15,
                                     random_state=42, n_jobs=-1)
        clf.fit(X_tr, y_tr)
        y_pred = clf.predict(X_te)

        acc, fpr, mcc, tp, tn, fp, fn = compute_metrics(y_te, y_pred)

        met_rows.append({
            "fold": fold,
            "detection_accuracy_%": round(acc, 4),
            "fpr_%": round(fpr, 4), "mcc": round(mcc, 4),
            "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        })
        print(f"  Fold {fold:2d} | "
              f"DetAcc={acc:6.2f}%  FPR={fpr:5.2f}%  MCC={mcc:+.4f}  "
              f"TP={tp} TN={tn} FP={fp} FN={fn}")

        nid_te = df.iloc[te_idx]["node_id"].values
        win_te = df.iloc[te_idx]["window"].values
        for nid, win, pred, true in zip(nid_te, win_te, y_pred, y_te):
            pred_rows.append({
                "fold": fold, "window": int(win),
                "node_id": int(nid), "is_attacker": int(true),
                "rf_predicted": int(pred), "correct": int(pred == true),
            })

    return pred_rows, met_rows


def main():
    print("="*67)
    print("  SOA3 — Random Forest IDS  (Arízaga-Silva et al., MDPI 2025)")
    print("="*67)

    df = load_and_clean(FEATURES_CSV)
    df = engineer_features(df)

    extra        = ["net_avg_pdr", "pdr_deviation", "total_drop_ratio", "fwd_efficiency"]
    all_features = FEATURE_COLS + extra

    pred_rows, met_rows = run(df, all_features)

    if not met_rows:
        print("[SOA3] No metrics produced.")
        return

    os.makedirs(RESULTS_DIR, exist_ok=True)
    mdf = pd.DataFrame(met_rows)
    mdf.to_csv(METRICS_CSV, index=False)
    print(f"\n[SOA3] Metrics saved     → {METRICS_CSV}")

    if pred_rows:
        pd.DataFrame(pred_rows).to_csv(PREDICTIONS_CSV, index=False)
        print(f"[SOA3] Predictions saved → {PREDICTIONS_CSV}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "="*67)
    print("  AGGREGATE RESULTS")
    print("="*67)
    print(f"  CV folds evaluated     : {len(mdf)}")
    print(f"  Avg Detection Accuracy : {mdf['detection_accuracy_%'].mean():.4f} %")
    print(f"  Avg FPR                : {mdf['fpr_%'].mean():.4f} %")
    print(f"  Avg MCC                : {mdf['mcc'].mean():.4f}")
    print(f"  Total TP/TN/FP/FN      : "
          f"{mdf['TP'].sum()}/{mdf['TN'].sum()}/{mdf['FP'].sum()}/{mdf['FN'].sum()}")
    print("="*67)
    print("  Paper benchmark  :  DetAcc ≈ 99.27%   FPR ≈ 0.37%   MCC ≈ 0.9852")
    print("  Compare with your MATD results from the main routing CSV.")
    print("="*67 + "\n")


if __name__ == "__main__":
    main()