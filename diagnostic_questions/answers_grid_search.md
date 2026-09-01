# Grid Search Results (tau_f x theta_R) — sent first, as requested, before any further ablation runs

All 6 cells run to completion. Neither target condition (zero-attack FI<30
AND DA1 FP>5) is met by any cell in this grid — and the reason is now
precisely diagnosed, not just reported as a negative result.

## The table

| tau_f | theta_R | Zero-attack FI | DA1 FP |
|---|---|---|---|
| 0.65 | 0.45 | 96 | 0 |
| 0.65 | 0.50 | 96 | 0 |
| 0.70 | 0.45 | 96 | 0 |
| 0.70 | 0.50 | 96 | 0 |
| 0.75 | 0.45 | 96 | 0 |
| 0.75 | 0.50 | 96 | 0 |

**Every single cell gives identical results: FI=96, FP=0.** This is not a
run-to-run coincidence — it was checked directly.

## Why the grid is flat: traced to the exact mechanism, not guessed

**Zero-attack FI=96 is invariant to this grid because it isn't
theta_R/tau_f-driven for these three specific nodes.** The same three
nodes (10, 11, 17) are isolated in every single cell. Their gate state at
the moment of isolation (pasted directly from the tau_f=0.75/theta_R=0.50
cell, representative of all six):

```
node=11 t=6.00  lambda=5 statistical_gate=1 zkp_proof=FAIL sustained=1
node=10 t=15.00 lambda=1 statistical_gate=0 zkp_proof=FAIL sustained=1
node=17 t=24.00 lambda=0 statistical_gate=0 zkp_proof=FAIL sustained=1
```

**Nodes 10 and 17 have `statistical_gate=0`** — theta_R is not even part of
their isolation condition; they are isolated purely through the
`sustained` (consecutive-window signature) path, which Fix A now also
requires ZKP to fail, and it genuinely does fail for all three (confirming
Fix A itself is working correctly, independently of this grid search).
**Node 11 does use the statistical gate (`lambda=5`), but 5 already equals
`lambda2` at every theta_R tested (0.45-0.50) — the grid's range simply
never reduces its suspicion level.** In short: this specific grid varies
two thresholds that are not the binding constraint for any of the three
nodes actually producing false isolations in this run. Recalibrating
theta_R/tau_f within 0.45-0.75 cannot move FI below 96 — a different
mechanism (the `sustained` override, or these three nodes' underlying
PDR/reputation trajectory) would need to change instead.

**DA1 FP=0 is invariant to this grid for a different, already-confirmed
reason (from earlier this session): every legitimate node's corrPDR at
drop_rate=60 sits at or above 1.0** (checked directly across all six
cells — no legitimate node's corrected PDR ever drops below 1.0 in this
traffic regime), **far above even the lowest tau_f tested (0.65).** No
threshold in the requested 0.65-0.75 range can produce a false positive
here, because the underlying signal never gets close to any of them. This
is a genuine structural property of this drop_rate/topology combination
found and confirmed earlier this session, not new to this round, and it
explains directly why "recalibrate within this range" cannot satisfy the
DA1 FP>5 condition — the range tested doesn't reach where legitimate
nodes' PDR actually is.

## What this means for next steps (not run yet, holding for your direction per your instruction to send the grid first)

To get **both** conditions genuinely satisfiable, two different
mechanisms need addressing, not one shared threshold:
- **FI reduction below 30** requires touching the `sustained` override's
  window-count threshold (`SG_SUSTAINED_ISOLATE`) or investigating why
  these three specific nodes' PDR pattern triggers it under zero attack —
  not `theta_R`/`tau_f`.
- **DA1 FP>5** requires a lower tau_f than tested here (well below 0.65,
  since legitimate corrPDR sits at ~1.0-1.5) — but lowering tau_f that far
  would need to be checked against how much it also affects real attacker
  detection, and was outside this grid's requested range.

Not attempted without direction, per "send the grid search table first. Do
not run the full ablation until we confirm the threshold selection."
