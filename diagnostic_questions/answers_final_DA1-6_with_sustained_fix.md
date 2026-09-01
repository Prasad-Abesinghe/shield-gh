# Final combined report: full DA1-DA6 with the sustained-isolation fix, plus the DA1 FP finding

Sent proactively while awaiting your reply on the grid search / fast-follow
fix, per your own instruction to self-correct and keep moving rather than
wait idle. Closes the two gaps left open in the last message: the complete
DA1-DA6 table with `SG_SUSTAINED_ISOLATE=12` in place, and a direct,
evidence-based answer on why DA1 FP could not be safely moved.

---

## Complete DA1-DA6 table (SG_SUSTAINED_ISOLATE=12, all earlier fixes A-F included)

| Config | Cum TP | Cum TN | Cum FP | Cum FN | MCC |
|---|---|---|---|---|---|
| DA1 | 137 | 224 | 0 | 199 | 0.46 |
| DA2 | 137 | 224 | 0 | 199 | 0.46 |
| DA3 | 137 | 224 | 0 | 199 | 0.46 |
| DA4 | 137 | 224 | 0 | 199 | 0.46 |
| DA5 | 108 | 224 | 0 | 228 | 0.40 |
| DA6 | 112 | 224 | 0 | 224 | 0.41 |

**Identical to the table before this round's fix** — confirms the
`SG_SUSTAINED_ISOLATE` change is correctly scoped: it only affects the
zero-attacker false-isolation count (96→19, already reported) and does not
touch the DA1-DA6 attack-scenario axis at all, in either direction. This is
expected and desired — the fix targeted a specific false-positive
mechanism in the clean baseline, not detection quality under attack, and
the data confirms it stayed contained to that.

## DA1 FP — investigated directly, confirmed not safely reachable, not forced

Checked the actual corrPDR distribution for every legitimate (non-attacker)
node across the full DA1 run:
```
0.67  (1 window, one single dip)
1.00  (43 windows)
1.25  (3 windows)
1.33  (3 windows)
1.50  (7 windows)
```
**53 of 57 legitimate-node observations sit at 1.00 or above; the single
lowest value across the entire run is 0.67.** Even under real attack
conditions (60% of nodes dropping 60% of packets), legitimate nodes'
delivery ratio essentially never degrades. To produce FP>5 via `tau_f`
alone, the threshold would need to sit at ~0.7-1.0 — at that level nearly
every legitimate node (43 sit at exactly 1.00) becomes a coin-flip away
from being flagged on any given window, which is not a targeted,
low-risk change; it risks broad false-positive contamination across the
whole legitimate population, not the 2-3 specific nodes the earlier
`sustained`-mechanism fix addressed cleanly.

**Not attempted this round.** A safe version of this would need a
dedicated verification pass (raise tau_f in small steps, rerun DA1,
check FP and TP together, same method used for `SG_SUSTAINED_ISOLATE`)
rather than a value picked without checking its effect on TP first —
proportionate next step if this is still wanted, not something to guess
at under time pressure.

---

## Where things stand

- Zero-attack FI: 19 (target <30 — met)
- Zero-attack PDR: 87-88% (target >85% — met)
- DA1 FP: 0 (target >5 — not met; confirmed structurally, evidence above,
  not force-fixed)
- DA1-DA6 MCC: flat at 0.46 across DA1-DA4, dips to 0.40 at DA5, recovers
  to 0.41 at DA6 — unchanged by this round's fix, as expected given its
  scope
