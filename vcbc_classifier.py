#!/usr/bin/env python3
"""
vcbc_classifier.py
==================
Alabdulatif et al. (2024) — Blockchain Smart Contract (VCBC) classifier.

This script reads the per-window PDR log produced by NS-3 (vcbc_detection.csv)
and applies the Voting-Classification Blockchain Contract (VCBC) logic:

  FOR EACH NODE
    vote_count  = number of windows where PDR < pdr_threshold
    vote_fraction = vote_count / total_windows
    IF vote_fraction > vote_fraction_threshold  →  MALICIOUS
    ELSE                                         →  BENIGN

It then computes:
  • Per-node classification
  • Detection accuracy, FPR, TPR
  • Network-wide PDR summary
  • Writes a clean results CSV: vcbc_final_results.csv

Usage
-----
    python vcbc_classifier.py

The script auto-discovers node columns from the CSV header.
Edit the CONFIG section below if your paths or thresholds differ.
"""

import os
import csv
import sys

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG — edit these to match your environment
# ═══════════════════════════════════════════════════════════════════════════════

INPUT_CSV  = os.path.expanduser(
    "~/ns-allinone-3.35/ns-3.35/results/vcbc_detection.csv"
)
OUTPUT_CSV = os.path.expanduser(
    "~/ns-allinone-3.35/ns-3.35/results/vcbc_final_results.csv"
)

# VCBC thresholds (match the C++ values)
PDR_THRESHOLD           = 0.78   # window PDR below this = "bad" vote
VOTE_FRACTION_THRESHOLD = 0.50   # if >50% of windows are "bad" → malicious

# ═══════════════════════════════════════════════════════════════════════════════


def run_vcbc(input_csv: str, output_csv: str,
             pdr_thr: float, vote_thr: float) -> None:

    if not os.path.isfile(input_csv):
        print(f"[VCBC] ERROR: input file not found: {input_csv}")
        print("       Make sure NS-3 has run at least one simulation window")
        sys.exit(1)

    # ── 1. Read CSV ───────────────────────────────────────────────────────────
    with open(input_csv, newline="") as f:
        reader = csv.DictReader(f)
        rows   = list(reader)

    if not rows:
        print("[VCBC] ERROR: CSV is empty — no windows recorded yet.")
        sys.exit(1)

    # ── 2. Discover nodes from header ────────────────────────────────────────
    header = rows[0].keys()
    # Node columns look like "Node0_PDR", "Node1_PDR", …
    node_ids = sorted({
        int(col.split("Node")[1].split("_")[0])
        for col in header
        if col.startswith("Node") and col.endswith("_PDR")
    })

    total_windows = len(rows)
    print(f"[VCBC] {total_windows} windows found, {len(node_ids)} nodes detected")

    # ── 3. Accumulate per-node votes and ground truth ─────────────────────────
    vote_count    = {n: 0   for n in node_ids}
    is_attacker   = {n: 0   for n in node_ids}   # ground truth (0/1)
    pdr_sum       = {n: 0.0 for n in node_ids}   # for average PDR

    for row in rows:
        for n in node_ids:
            pdr_key     = f"Node{n}_PDR"
            attk_key    = f"Node{n}_IsAttacker"

            pdr_val  = float(row.get(pdr_key,  1.0))
            attk_val = int(  row.get(attk_key, 0))

            pdr_sum[n]     += pdr_val
            is_attacker[n]  = attk_val   # same every window; last value is fine

            if pdr_val < pdr_thr:
                vote_count[n] += 1

    # ── 4. VCBC majority-vote decision ───────────────────────────────────────
    classified = {}
    for n in node_ids:
        fraction       = vote_count[n] / total_windows if total_windows > 0 else 0.0
        classified[n]  = 1 if fraction > vote_thr else 0

    # ── 5. Compute TP / TN / FP / FN ─────────────────────────────────────────
    TP = TN = FP = FN = 0
    for n in node_ids:
        c = classified[n]
        a = is_attacker[n]
        if c and a:  TP += 1
        if c and not a: FP += 1
        if not c and a: FN += 1
        if not c and not a: TN += 1

    N = len(node_ids)
    detection_accuracy = (TP + TN) / N if N > 0 else 0.0
    fpr = FP / (FP + TN) if (FP + TN) > 0 else 0.0
    tpr = TP / (TP + FN) if (TP + FN) > 0 else 0.0   # recall / sensitivity

    # Network-wide average PDR over all windows
    net_pdr_per_window = []
    for row in rows:
        active = [float(row.get(f"Node{n}_PDR", 1.0)) for n in node_ids]
        if active:
            net_pdr_per_window.append(sum(active) / len(active))
    avg_net_pdr = sum(net_pdr_per_window) / len(net_pdr_per_window) \
                  if net_pdr_per_window else 0.0

    # ── 6. Print summary ──────────────────────────────────────────────────────
    print("\n╔══════════════════════════════════════════════════════╗")
    print("║   VCBC (Alabdulatif et al.) — Final Classification   ║")
    print("╠══════════════════════════════════════════════════════╣")
    print(f"║  PDR threshold        : {pdr_thr:.2f}                         ║")
    print(f"║  Vote fraction thr    : {vote_thr:.2f}                         ║")
    print(f"║  Total windows        : {total_windows:<5}                       ║")
    print(f"║  Nodes                : {N:<5}                       ║")
    print("╠══════════════════════════════════════════════════════╣")
    print(f"║  TP={TP}  TN={TN}  FP={FP}  FN={FN}                          ║")
    print(f"║  Detection Accuracy   : {detection_accuracy*100:6.2f}%                    ║")
    print(f"║  False Positive Rate  : {fpr*100:6.2f}%                    ║")
    print(f"║  True Positive Rate   : {tpr*100:6.2f}%  (recall)           ║")
    print(f"║  Network Avg PDR      : {avg_net_pdr*100:6.2f}%                    ║")
    print("╠══════════════════════════════════════════════════════╣")
    print("║  Per-node classification:                            ║")
    for n in node_ids:
        label   = "MALICIOUS" if classified[n] else "BENIGN   "
        truth   = "ATTACKER " if is_attacker[n] else "BENIGN   "
        correct = "✓" if classified[n] == is_attacker[n] else "✗"
        votes   = vote_count[n]
        avg_pdr = pdr_sum[n] / total_windows if total_windows > 0 else 0.0
        print(f"║    Node {n:>2}: classified={label}  truth={truth}  "
              f"votes={votes}/{total_windows}  avgPDR={avg_pdr:.3f}  {correct}  ║")
    print("╚══════════════════════════════════════════════════════╝\n")

    # ── 7. Write final results CSV ────────────────────────────────────────────
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Technique", "TotalWindows", "Nodes",
            "TP", "TN", "FP", "FN",
            "DetectionAccuracy", "FPR", "TPR",
            "NetworkAvgPDR",
            "PDR_Threshold", "VoteFractionThreshold"
        ])
        writer.writerow([
            "Alabdulatif_VCBC", total_windows, N,
            TP, TN, FP, FN,
            f"{detection_accuracy:.4f}",
            f"{fpr:.4f}",
            f"{tpr:.4f}",
            f"{avg_net_pdr:.4f}",
            pdr_thr, vote_thr
        ])

        # also write per-node detail
        writer.writerow([])
        writer.writerow([
            "Node", "AvgPDR", "VoteCount", "TotalWindows",
            "VoteFraction", "Classified", "IsAttacker", "Correct"
        ])
        for n in node_ids:
            avg_pdr      = pdr_sum[n] / total_windows if total_windows > 0 else 0.0
            vote_fraction = vote_count[n] / total_windows if total_windows > 0 else 0.0
            correct_flag  = 1 if classified[n] == is_attacker[n] else 0
            writer.writerow([
                n,
                f"{avg_pdr:.4f}",
                vote_count[n], total_windows,
                f"{vote_fraction:.4f}",
                classified[n],
                is_attacker[n],
                correct_flag
            ])

    print(f"[VCBC] Final results written to: {output_csv}")


if __name__ == "__main__":
    run_vcbc(INPUT_CSV, OUTPUT_CSV, PDR_THRESHOLD, VOTE_FRACTION_THRESHOLD)