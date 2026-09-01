#!/usr/bin/env python3
"""
Integrity check on e1_m1_results.csv before anything is copied into the paper.

Checks:
  1. all 180 (p, rho_a, system) cells present, no duplicates
  2. every run exited ok
  3. every cell carries an MCC value
  4. MCC values are inside [-1, 1]
  5. reports means over GENUINE attack cells (p>0 AND rho_a>0) only,
     since the p=0 row and rho_a=0 column are undetectable by construction
"""
import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(HERE, "e1_m1_results.csv")

P_VALUES = [0, 20, 40, 60, 80, 100]
RHO_VALUES = [0, 20, 40, 60, 80, 100]
SYSTEMS = ["shieldgh_full", "shieldgh_lite", "b1_malik", "b2_vcbc", "b3_rf"]

rows = list(csv.DictReader(open(CSV_PATH)))
problems = []

seen = {}
for r in rows:
    key = (int(r["p"]), int(r["rho_a"]), r["system"])
    if key in seen:
        problems.append(f"DUPLICATE cell {key}")
    seen[key] = r

expected = {(p, rr, s) for p in P_VALUES for rr in RHO_VALUES for s in SYSTEMS}
missing = expected - set(seen)
for m in sorted(missing):
    problems.append(f"MISSING cell {m}")

for key, r in seen.items():
    if r["status"] != "ok":
        problems.append(f"BAD STATUS {key}: {r['status']}")
    v = r.get("M1_MCC", "")
    if v in ("", None):
        problems.append(f"EMPTY MCC {key}")
    else:
        try:
            f = float(v)
            if not (-1.0 <= f <= 1.0):
                problems.append(f"MCC OUT OF RANGE {key}: {f}")
        except ValueError:
            problems.append(f"NON-NUMERIC MCC {key}: {v!r}")

print(f"rows in csv: {len(rows)}   unique cells: {len(seen)}/180")
if problems:
    print(f"\n{len(problems)} PROBLEM(S):")
    for p in problems[:25]:
        print("  -", p)
    if len(problems) > 25:
        print(f"  ... and {len(problems)-25} more")
else:
    print("\nAll 180 cells present, all runs ok, all MCC values valid.")

import statistics as st
print("\nMean MCC over GENUINE attack cells (p>0 AND rho_a>0):")
agg = {}
for (p, rr, s), r in seen.items():
    if p > 0 and rr > 0 and r.get("M1_MCC"):
        agg.setdefault(s, []).append(float(r["M1_MCC"]))
for s, v in sorted(agg.items(), key=lambda kv: -st.mean(kv[1])):
    sd = st.pstdev(v) if len(v) > 1 else 0.0
    print(f"  {s:16s} n={len(v):3d} mean={st.mean(v):.3f} sd={sd:.3f} "
          f"min={min(v):.2f} max={max(v):.2f}")

print("\nFalse-positive check, accuracy at p=0 (no attackers):")
fp = {}
for (p, rr, s), r in seen.items():
    if p == 0 and r.get("M1_ACC"):
        fp.setdefault(s, []).append(float(r["M1_ACC"]))
for s, v in sorted(fp.items(), key=lambda kv: -st.mean(kv[1])):
    print(f"  {s:16s} n={len(v):2d} mean acc={st.mean(v):.2f}%")

sys.exit(1 if problems else 0)
