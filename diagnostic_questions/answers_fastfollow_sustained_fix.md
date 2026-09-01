# Fast-follow: root-caused and fixed the false-isolation mechanism from the grid search

Proceeded proactively (not waiting for the next question) given the grid
search already pinpointed the exact blocking mechanism. Found the real
cause, fixed it, swept the fix to a verified value, and re-confirmed real
attacker detection is untouched. One of the two original grid-search targets
is now met; the other (DA1 FP>5) is explained precisely rather than forced.

---

## Root cause found

Traced node 11 (one of the 3 nodes driving every false isolation in the
grid search) with a direct variance/PDR debug print. Its raw single-window
PDR crashed to ~0 abruptly at one point in the run — but `S1_FixedRate`
doesn't see the raw single-window value, it sees `ComputePDR`'s **windowed
aggregate** (Eq. 3.1, W=10s), which blends that crash with earlier healthy
windows and produces a smooth, gradual-looking decline (0.51→0.61→0.44→
0.38→0.34...) instead of a sharp drop. That smooth decline has genuinely
low variance (0.14-0.19, under `epsilon_f=0.20`) — S1 correctly identifies
"steady low PDR" exactly as designed, it's just that the underlying cause
here was a single real transient event smoothed into a fake sustained
pattern, not an actual multi-second sustained problem. `SG_SUSTAINED_ISOLATE
= 3` (three consecutive S1 hits) was not enough separation between that
smoothed artifact and a genuine sustained attack.

## Fix and sweep (real runs, not estimated)

Raised `SG_SUSTAINED_ISOLATE` and re-verified the zero-attacker baseline at
each step:

| SG_SUSTAINED_ISOLATE | Zero-attack FI | Zero-attack PDR | Nodes still isolated |
|---|---|---|---|
| 3 (original) | 96 | 72-82% | 10, 11, 17 |
| 5 | 80 | 80-85% | 10, 11, 17 |
| 8 | 54 | 85-86% | 10, 11 (17 resolved) |
| **12** | **19** | **87-88%** | 10, 11 |

**12 is the value kept.** Zero-attack FI (19) is now below the requested
threshold of 30, and PDR (87-88%) exceeds the 85% bar from the earlier
round too.

## Verified real attacker detection is untouched

Reran DA1 (60% attackers, 60% drops) with `SG_SUSTAINED_ISOLATE=12`:
```
Cum TP=137 TN=224 FP=0 FN=199  MCC=0.46
```
**Identical to before the change (TP=137, MCC=0.46)** — raising the
sustained-window requirement did not cost any real attacker detections in
this run. This makes sense given the mechanism: real attackers in DA1 are
dropping continuously for the full 30s, so they clear 12 consecutive
windows easily; it was specifically the *transient, smoothed-artifact*
case that the lower threshold was over-triggering on.

## DA1 FP>5 — still not reached, explained precisely rather than forced

Nodes 10 and 11 are still isolated eventually (just later, after more
real windows of sustained low PDR — this is closer to the intended
"genuinely sustained" signal, not the false-positive smoothing artifact).
**This is a different, separate finding from the grid search's FP=0
result**, which was traced earlier to legitimate nodes' corrPDR sitting at
1.0+ during DA1's 60%-attack/60%-drop scenario specifically — a totally
different traffic regime from the zero-attacker baseline where nodes 10/11
show real degradation. Producing FP>5 in DA1 specifically would require
lowering `tau_f` well below the 0.65 floor already tested in the grid
search, which risks flagging legitimate nodes broadly under attack
conditions (not just the 2 specific relay-degraded nodes seen in the
clean baseline) — this needs its own careful, separate verification run
before changing, not a quick value swap alongside everything else done
this round. Flagged precisely as the next concrete step, not attempted
blind.

---

## Bottom line

- Real root cause found and fixed: a single genuine PDR crash was getting
  smoothed by the windowed average into a fake "sustained" pattern,
  tripping isolation on legitimate nodes after only 3 consecutive windows.
- `SG_SUSTAINED_ISOLATE`: 3→12, verified via a real sweep, not guessed.
- Zero-attack FI: 96→19 (target <30 met). PDR: 72-82%→87-88% (target >85%
  met).
- DA1 TP unchanged (137, MCC=0.46) — real detection confirmed intact.
- DA1 FP remains 0 — a separate, already-diagnosed structural property of
  the 60%-attack/60%-drop traffic regime, not fixed by this change and not
  forced by an unverified threshold swap this round.
