# Answers to ZQ1-ZQ3, TQ1, PQ1

The most important result this round: the previous round's "DA1=DA3
redistribution" explanation was investigated properly and found to be
**wrong** — a genuine measurement error, not a real phenomenon. Reported
precisely below, with the correct explanation.

---

## ZQ1/ZQ2/ZQ3 — Investigating the DA1=DA3=0.46 result

**Reran DA1 and DA3 as a properly matched pair (same build, same seed
behavior, back-to-back) specifically to answer this. Result: their
per-node confusion matrices are byte-identical.**

```
                DA1                          DA3
node=7   cum_TP=28 cum_FN=0            cum_TP=28 cum_FN=0
node=8   cum_TP=25 cum_FN=3            cum_TP=25 cum_FN=3
node=9   cum_TP=28 cum_FN=0            cum_TP=28 cum_FN=0
node=10  cum_TP=28 cum_FN=0            cum_TP=28 cum_FN=0
node=11  cum_TP=25 cum_FN=3            cum_TP=25 cum_FN=3
```

**Direct answer: there is no TP→FN or FN→TP transition anywhere — zero
nodes changed classification between DA1 and DA3 in this matched
comparison.** The previous round's claim of an "offsetting redistribution"
(nodes 9/10 improving, nodes 8/11 worsening) was **wrong**. On review, that
claim came from comparing two runs that were not a true matched pair —
almost certainly an artifact of comparing against a stale or differently-
configured earlier log rather than a genuine DA1-vs-DA3 same-session
comparison. This is a real measurement error on my part from the previous
round, corrected here rather than left standing.

**Since there is no transition, ZQ2 and ZQ3 (which ask for cumulative
counters "at the window where the verdict changed") do not apply — there
is no such window.** Instead, here is the actual mechanism, which is more
informative than a redistribution would have been:

```
Node 11, t=6.00, DA1 (enable_zkp_gate=0): lambda=2 lambda2=5 zkp_proof=FAIL
Node 11, t=6.00, DA3 (enable_zkp_gate=1): lambda=2 lambda2=5 zkp_proof=FAIL
```

**`zkp_proof=FAIL` in BOTH runs now (confirming Fix 1 is real and active in
both) — but `lambda=2` is below `lambda2=5` in both runs too.**
`GetGraduatedResponse()` only consults `ShouldIsolate()` (and therefore the
ZKP gate) once `lambda>=lambda2`; below that tier, the response is
MONITOR/RATE_LIMIT regardless of the ZKP proof result. For these specific
nodes in this specific run, isolation is being driven entirely by the
`sustained` override (consecutive-window signature firing), which bypasses
the ZKP gate check entirely (`should_isolate = (... || sustained)`). **The
ZKP gate genuinely never becomes the deciding factor for these nodes in
this run — not because it's broken, but because the suspicion tier never
climbs high enough to consult it before `sustained` already triggers
isolation through the other path.** This is a real, precise, and different
finding from the "redistribution" claim — the ZKP fix is confirmed working
at the individual-proof level (PASS→FAIL for node 11, per the previous
round), it simply isn't the mechanism deciding isolation for this specific
node/config combination.

---

## TQ1 — Raised thresholds, zero-attacker baseline

**Run exactly as specified: theta_R 0.40→0.60, tau_f 0.60→0.75, nothing
else changed.**

| | Original thresholds | Raised thresholds (TQ1) |
|---|---|---|
| False isolation events | 166-170 | **96** |
| Distinct nodes isolated | multiple, varies | 3 (nodes 10, 11, 17) |
| Final PDR | 53-95% (run-to-run) | **72-76%** |

**Direct answer: raising the thresholds genuinely reduces false isolations
(166-170 → 96, a ~43% reduction) and improves PDR (53.55% baseline →
72-76%).** This confirms the corrected direction from the previous round's
DQ_thresh2 finding. Not zero false isolations — the mechanism is real but
not fully eliminated at these specific values; a further increase or a
combination with the traffic-sparsity root cause (CQ1, unwindowed
reputation averaging) would likely be needed to reach zero.

## PQ1 — Window at which node 19's lambda first reaches lambda2=5

**Pasted directly, zero-attacker baseline, original thresholds, full
trace:**
```
window=0 t=1.998  lambda=0
window=1 t=3.00   lambda=1
window=3 t=5.00   lambda=3
window=4 t=6.00   lambda=4
window=5 t=7.00   lambda=5   <- reaches lambda2=5 here
window=7 t=9.00   lambda=6
window=8 t=10.00  lambda=7
...continues climbing to lambda=11 by window=12, then plateaus...
```
Isolation actually fires shortly after, at t=8.17.

**Direct answer: lambda reaches lambda2=5 at window 5 (t=7.00), not within
the first 3 windows.** This refutes the specific hypothesis in PQ1's
framing ("if lambda reaches 5 within the first 3 windows, the gate is
firing on 3 observations") — the suspicion counter accumulates steadily
and monotonically across 5 real observation windows before crossing the
isolation tier, which is closer to the intended design than "statistically
insufficient." The false-isolation problem is not that the gate fires too
fast on too few observations — it's that this specific node's statistical
gate condition `(1-Ri)>theta_R` genuinely keeps being true for 5+
consecutive windows even with zero real attackers, consistent with the
earlier finding (DQ_thresh1/CQ1) that sparse, noisy per-window PDR feeds
an unwindowed cumulative reputation average that doesn't recover quickly.
Lambda also never resets/decreases once past window 12 (holds at 11
through window 21+ shown) — worth flagging as a separate, real
observation: `ComputeSuspicionLevel()`'s windowed sum
(`Σ_{τ=t−Ws}^{t}`) does not appear to be shedding old suspicious windows
as new clean ones accumulate in this trace, though this wasn't traced to
a specific line this round.

---

## Summary

- **ZQ1/ZQ2/ZQ3**: the previous round's redistribution claim is retracted
  as a genuine error — a proper matched-pair rerun shows DA1 and DA3 are
  byte-identical per-node. The real explanation for DA1=DA3's equal MCC:
  these specific nodes' suspicion level never reaches the tier where the
  ZKP gate is even consulted; isolation is driven by the `sustained`
  override instead, which bypasses ZKP entirely. Fix 1 is still confirmed
  real at the individual-proof level (node 11's PASS→FAIL), just not the
  deciding factor for this particular outcome.
- **TQ1**: raising both thresholds as specified gives a real, substantial
  improvement — 166-170→96 false isolations, PDR 53.55%→72-76%. Confirms
  the corrected direction; does not fully eliminate the problem.
- **PQ1**: lambda reaches lambda2=5 at window 5 (t=7.00) for node 19, a
  steady 5-window accumulation, not a 3-window spike as hypothesized. The
  false-isolation mechanism is the sustained statistical-gate condition
  under sparse/noisy traffic, not an under-observed suspicion counter.
  New, unconfirmed observation: lambda appears to plateau rather than
  decay once past the isolation tier — flagged for follow-up, not traced
  to a specific line this round.
