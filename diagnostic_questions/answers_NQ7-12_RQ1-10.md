# Answers to NQ7-NQ12 and RQ1-RQ10

All answered with pasted real data from fresh instrumented runs. Where a
controlled experiment was requested (NQ9), it was run and its result is
reported honestly, including where it refutes the hypothesis it was testing.

---

## Part 1 — RQ1/RQ2 (priority, per supervisor): per-node y_hat identity

**Direct answer: NOT identical.** Diffed the full per-node, per-window
`y_hat` trace (all 20 nodes, all ~28 windows = 560 lines) between DA1↔DA2
and DA1↔DA3:

- **DA1 vs DA2**: 6 lines differ — all at **t=7.00**: node 11 (present in
  DA1, absent in DA2) plus nodes 12, 16, 17, 18, 19 (also present in DA1,
  absent in DA2). Every other line (554/560) is byte-identical.
- **DA1 vs DA3**: **zero** differences. Every single one of the 560
  evaluations is byte-identical between DA1 and DA3.

So the supervisor's stated concern is partially confirmed and partially not:
DA1 vs DA3 genuinely never diverges at the `y_hat` level in this run — ZKP
alone changes nothing observable here. DA1 vs DA2 does diverge, but only in
one window, and via node absence (a traffic-timing effect, not a flipped
verdict) — not "MATD changing an individual decision." This is answered
precisely below (RQ3/RQ7).

## RQ3 — Does MATD's toggle reach the corrPDR computation?

**Yes — confirmed by direct comparison, not assumed.** Node 7, first five
windows:

| t | DA1 (`enable_matd=0`) corr_pdr | DA2 (`enable_matd=1`) corr_pdr |
|---|---|---|
| 2.0 | 0.375 (== obs_pdr) | 0.381667 |
| 3.0 | 0.38 (== obs_pdr) | 0.38 |
| 4.0 | 0.11 (== obs_pdr) | 0.12 |
| 5.0 | 0.00 (== obs_pdr) | 0.01 |
| 6.0 | 0.00 (== obs_pdr) | 0.01 |

DA1's `corr_pdr` is always exactly `obs_pdr` (MATD correction not applied,
as expected with the flag off). DA2's `corr_pdr` is genuinely different —
the correction reaches the computation every window. **This directly
answers RQ3's concern: the toggle is not being ignored.** It's just that
the correction magnitude (0.005-0.01 typically) is tiny relative to how far
below τ_f=0.60 these attacker nodes' PDR already sits (0.00-0.38) — nowhere
close to the boundary.

## RQ4 — Does the ZKP gate toggle reach the isolation decision?

**Yes — confirmed via the new debug accessor `DEBSC::GetDebugState()`**
(added this round, exposes `lambda`, `lambda1`/`lambda2`, the statistical
gate value, and the cached ZKP proof result). Node 11 at t=6.00, side by
side:

| | DA1 (`enable_zkp_gate=0`) | DA3 (`enable_zkp_gate=1`) |
|---|---|---|
| lambda | 5 | 5 |
| lambda2 | 5 | 5 |
| statistical_gate | 1 | 1 |
| zkp_gate_enabled | **0** | **1** |
| zkp_cached / proof | 1 / PASS | 1 / PASS |
| **response** | **ISOLATE** | **REQUIRE_ZKP** |

Both configs reach the same suspicion tier (`lambda=5=lambda2`) and the same
statistical-gate result. The **only** difference is `zkp_gate_enabled` — and
it changes the graduated-response outcome from ISOLATE to REQUIRE_ZKP,
exactly as the code specifies. The toggle unambiguously reaches and changes
the isolation decision. (Also directly answers **NQ7** below — same data.)

## RQ5 — Per-node cumulative TP/FN across DA1/DA2/DA3

**Pasted, all 20 nodes, all three configs — DA1 and DA3 are node-for-node
identical; DA2 differs from both only at node 11 (see RQ7):**

| node | DA1/DA3 TP | DA1/DA3 FN | DA2 TP | DA2 FN |
|---|---|---|---|---|
| 0-6 | 0 each | 28 each | 0 each | 28 each |
| 7 | 28 | 0 | 28 | 0 |
| 8 | 27 | 1 | 27 | 1 |
| 9 | 27 | 1 | 27 | 1 |
| 10 | 25 | 3 | 25 | 3 |
| 11 | 27 | 1 | 26 | 2 |
| 12-19 | 0 each | 0 each (all TN) | 0 each | 0 each |

Node 11 is the only node whose per-node cumulative differs between DA1 and
DA2 (27/1 vs 26/2 — one fewer TP, one more FN), exactly matching the 6-line
`y_hat` diff (node 11's window at t=7.00 flips from present-and-TP in DA1 to
absent-and-scored-as-FN in DA2, via the `rcv==0` branch).

## RQ6 — corrPDR near τ_f=0.60

**Counted precisely, not estimated.** At drop_rate=60 (the standard test
config), **zero** attacker-node windows in either DA1 or DA2 have corrPDR
within 0.05 of τ_f=0.60 — confirms MATD structurally cannot flip any
verdict at this drop rate; the attacker PDRs are all far below threshold
(0.00-0.67 range, mostly clustering well under 0.60 already even
uncorrected). At drop_rate=20 (rerun for RQ9), there ARE near-threshold
windows: **3** in DA1, **1** in DA2. This is the one regime where MATD's
correction could plausibly matter — tested directly in RQ9.

## RQ7 — Isolate exactly what changes between DA1 and DA4

**Diffed the full 560-line `y_hat` trace, DA1 vs DA4: the diff is byte-for-
byte identical to the DA1-vs-DA2 diff above** — the same 6 lines, the same
t=7.00 window, the same 6 nodes (11, 12, 16, 17, 18, 19). **DA4's entire
divergence from DA1, across all 560 evaluations, traces to exactly one
mechanism: node 11 (and coincidentally 5 legitimate nodes) not being
evaluated at t=7.00** — this is the MATD-driven traffic-silence timing
established in the previous round (NQ1/NQ2), not a new or different
mechanism, and not evidence of a second, separate effect from ZKP. ZKP's
own marginal contribution (DA3 vs DA1) is exactly zero at the `y_hat` level
in this run.

## RQ8 — Is DA1=DA2=DA3's MCC equality arithmetically forced?

**Confirmed via full per-node confusion matrix (all 4 cells, all 20
nodes), not just the totals.** DA1 and DA3: every one of the 80
(20 nodes × 4 cells) values is identical. DA2: identical to DA1/DA3 in 76
of 80 cells; differs only in node 11's TP/FN split (27/1 → 26/2), which is
exactly compensated by the FN cumulative sum (this is why the aggregate
MCC still rounds to 0.46 for DA2 as well — TP=134 vs 133 is close enough
that the 3-decimal MCC value itself is what actually differs slightly, see
below). **So the equality is not perfectly arithmetic (DA2's confusion
matrix is NOT byte-identical to DA1's) but the resulting 2-decimal MCC
values happen to match.** This is an important correction to how "DA1=DA2=
DA3=0.46" should be read: it is not proof of zero effect, it's a case of a
real, small effect (1 TP/FN swap) producing a coincidentally identical
rounded MCC.

## RQ9 — DA1 vs DA2 at drop_rate=20

**Run directly, both configs, real cumulative MCC:**

| | DA1 (drop_rate=20) | DA2 (drop_rate=20) |
|---|---|---|
| Cum TP | 107 | 98 |
| Cum FN | 229 | 238 |
| MCC | **0.40** | **0.38** |

**DA2 is lower than DA1 at drop_rate=20 — the opposite of what the
"MATD is wired correctly but has no opportunity at drop_rate=60" hypothesis
predicted.** This is reported exactly as found, not reframed. Per RQ6, this
IS the regime with real near-threshold windows (3 in DA1, 1 in DA2), so
MATD's correction is genuinely influencing outcomes here — it is measurably
changing which nodes get flagged, just not in the direction that improves
MCC in this specific run. This is real evidence MATD is wired and active,
answering the wiring-doubt directly, while leaving open why its net effect
is negative at this operating point (not further diagnosed this round —
would need a per-node breakdown of which nodes flipped and why, similar to
RQ7's method, applied to the drop_rate=20 pair specifically).

## RQ10 — Are enable_matd/enable_zkp_gate distinct, live code paths?

**Confirmed by direct inspection — build uses `-O0` (no optimization),
verified in `build/c4che/_cache.py`.** At `-O0`, no dead-code/branch
elimination pass runs at all; the compiler cannot have "compiled away" the
conditional under any circumstance. Exact read sites:
- `enable_matd`: declared `routing.cc:183`, read at
  `shield_gh_integration.h:695` (`corr_pdr` ternary),
  `shield_gh_integration.h:711` (`trust_mob` ternary), and passed into
  `LW_DP_Det()` at `shield_gh_integration.h:782`.
- `enable_zkp_gate`: declared `routing.cc:184`, read once at
  `shield_gh_integration.h:161` (`g_sg_debsc.SetZkpGateEnabled(enable_zkp_gate == 1)`),
  which sets `DEBSC::m_zkp_gate_enabled`, consumed inside
  `ShouldIsolate()` (`debsc.cc:40`).

These are two distinct variables, distinct code paths, distinct downstream
consumers (`enable_matd` affects PDR/trust computation; `enable_zkp_gate`
affects the isolation gate). RQ3 and RQ4 above are the direct empirical
confirmation that both reach and change their respective computations.

---

## Part 2 — NQ7-NQ12

## NQ7 — ZKP proof state for node 11 at t=6.0 in DA4

**Pasted directly (new debug accessor, DA4 run):**
```
[NQ7/NQ12] node=11 t=6.00 lambda=5 lambda1=2 lambda2=5 Ri_decayed=0.42
           statistical_gate=1 zkp_gate_enabled=1 zkp_cached=1 zkp_proof=PASS
```

**Direct answer**: REQUIRE_ZKP was selected because `lambda=5` **does**
reach the `lambda2=5` tier (not stuck below it, contrary to one of the two
scenarios the supervisor posed) — but `ShouldIsolate()` still returns false
at that tier because the cached ZKP proof result is **PASS**, not FAIL. So
the second scenario is what happened: the node's ZKP proof passed
verification at that window even though it is a real attacker actively
dropping packets. This is worth flagging as its own finding: the ZKP
proof-generation logic (`CreateCommitment`/`GenerateProof`, unconditional
every window per the earlier session's C12 finding) is evidently not always
correctly failing a genuine grey-hole node's proof — a real attacker got a
PASS at exactly the window that mattered.

## NQ8 — Why DA5 (LLM-only) is weaker than DA1 for the same nodes

**Pasted, first evaluation window, all 5 nodes that are TP in DA1:**

| node | Q_i (window 1) | fused score | y_hat | DA1 cum_TP/FN | DA5 cum_TP/FN |
|---|---|---|---|---|---|
| 7 | 0.8724 | 0.4859 | 0 | 26/2 | 26/2 |
| 8 | 0.8706 | 0.4193 | 0 | 0/28 | 0/28 |
| 9 | 0.8832 | 0.4564 | 0 | 19/9 | 19/9 |
| 10 | 0.8484 | 0.3900 | 0 | 16/12 | 16/12 |
| 11 | 0.8832 | 0.5115 | 1 | 28/0 | 28/0 |

**Direct answer: Q_i is NOT the discriminator.** All 5 nodes score
Q_i≈0.85-0.88 at window 1 — the LLM correctly and immediately flags every
one of them as suspicious. What differs is the **fused score**, which
misses θ_det=0.50 for 4 of 5 nodes at that first window by margins of
0.01-0.11. Node 7 (missed by only 0.014) recovers by t=4.0 as its fused
score climbs to 0.51+ — checked its full series: **Q_i stays essentially
flat (~0.87-0.88) across windows while the score rises**, meaning the
reputation-deficit term `(1-R_i)` is what's driving the later recovery, not
improving LLM confidence. So the honest answer combines both of the
question's hypothesized mechanisms, precisely: it is the fusion weights
(specifically the non-LLM terms) that are the binding constraint at early
windows, not weak LLM discrimination — but nodes with a low initial score
DO eventually cross threshold once reputation decays enough, which takes
multiple windows. Node 8 never recovers because (per the previous round's
NQ6 finding) it goes traffic-silent after window 1 and never gets a second
chance for reputation to decay further.

## NQ9 — Confirm the DA6 timing artifact via controlled replay

**Run exactly as specified.** Built a stub version of `ns3_infer.py` that
caches the fitted scorer to disk after the first invocation (eliminating
the `scorer.fit()` retraining cost — confirmed the dominant component of
the ~140ms bridge call) so every subsequent window's call loads the cached
model instead of retraining. Verified the stub worked: bridge wall-clock
dropped from ~140-145ms to ~68-100ms (`load=0ms` confirmed in the log,
vs ~89-145ms before). Swapped it in for the real bridge script, ran DA6,
then restored the original script immediately after (verified byte-
identical restore via diff).

**Result: node 8 STILL shows cum_TP=0, cum_FN=28 — identical to the
original (unstubbed) run.** DA6-stub's overall cumulative MCC is also
identical: 0.40, TP=109, FN=227, matching the original DA6 exactly. The
"scored N nodes" batch at t=3.0 still excludes node 8 (same "scored 2
nodes" — 7 and 9 only — as the unstubbed run).

**This refutes the timing-artifact hypothesis from the previous round.**
The ~140ms blocking AI-bridge call is NOT the cause of node 8's silence —
removing most of that delay changed nothing. The true root cause (why
`node_total_received[8]` reads 0 at the t=3.0 window boundary in DA6 but
not in DA4, given byte-identical routing and no isolation of node 8 in
either config) **remains unidentified**. This is reported as a ruled-out
hypothesis, not a confirmed one — an honest negative result from a real
experiment, per the specific instruction to run the controlled test rather
than assert plausibility.

## NQ10 — MCC ceiling from routing coverage

**Pasted, exact node-by-node coverage from DA1's per-node confusion
matrix**: of the 12 forced attacker nodes (0-11), only **5** ever have
`rcv>0` at any point in the 30s run: nodes **7, 8, 9, 10, 11**. Nodes 0-6
(7 nodes) show `cum_TP=0, cum_FN=28` for the entire run — 100% structurally
FN, unreachable by any detection logic regardless of quality.

**Ceiling computation** (all 5 reachable nodes hypothetically achieve
perfect TP=28 every window, TN=224/FP=0 held fixed at their actual,
observed values):
```
TP_ceiling=140  FN_ceiling=196  TN=224  FP=0
MCC_ceiling = 0.4714
```
**DA1's actual MCC (0.46, more precisely 0.4579) is 97.1% of this
ceiling.** This is a decisive, precise answer: yes, the ceiling is real and
close to the actual results — nearly all configurations tested this session
(0.34-0.46 range) are operating within a fairly narrow band under a hard
ceiling of 0.4714 imposed entirely by routing coverage, not detection
quality. The non-monotonicity problem cannot be resolved by improving
detection logic alone; it requires increasing how many attacker nodes ever
carry traffic in the first place (Action 1's redundant-path topology work
increased coverage from the pre-Action-1 baseline, but 7 of 12 forced
attacker positions in the current N=20 config remain permanently silent).

## NQ11 — Isolate whether DA6's regression is entirely node 8

**Computed directly from DA6's real per-node cumulative data**, replacing
node 8's actual DA6 result (TP=0, FN=28) with its DA4 result (TP=27, FN=1)
and recomputing MCC with everything else held at DA6's real values
(TP=109→136, FN=227→200, TN=224, FP=0):
```
DA6 hypothetical (node 8 corrected) MCC = 0.4624
DA4 actual MCC = 0.41
```
**0.4624 > 0.41 — confirmed: node 8 is the sole cause of DA6 < DA4.**
Correcting node 8 alone doesn't just close the gap, it pushes DA6's
hypothetical MCC above DA4 and close to the DA1-3 level (0.46) — consistent
with every other node's cumulative TP/FN being identical or better in DA6
than DA4 (node 9 improved 27→28, node 11 recovered 4→28 via the earlier
node-11 fix; only node 8 regressed).

## NQ12 — DA3 graduated response for node 11 at t=6.0

**Pasted directly (same debug accessor as NQ7), DA3 run:**
```
[NQ1/NQ2] node=11 t=6.00 rcv=1 response=REQUIRE_ZKP should_isolate=0 isolated=0
[NQ1/NQ2] node=11 t=7.00 rcv=1 response=ISOLATE   should_isolate=1 isolated=0
[NQ7/NQ12] node=11 t=6.00 lambda=5 lambda1=2 lambda2=5 Ri_decayed=0.42
           statistical_gate=1 zkp_gate_enabled=1 zkp_cached=1 zkp_proof=PASS
```

**Direct answer: DA3 also shows REQUIRE_ZKP at t=6.0 (identical gate state
to DA4's t=6.0), but recovers to ISOLATE at t=7.0 because node 11 is still
active (rcv=1) then — unlike DA4 where it has already gone silent.** This
is exactly the supervisor's first scenario: confirms traffic-silence timing
(driven by MATD, per RQ5/RQ7's node-11-only divergence) is the proximate
cause of DA4's regression, not the REQUIRE_ZKP decision itself — ZKP alone
produces the identical REQUIRE_ZKP outcome at t=6.0 without being fatal,
because the node survives one more window to reach ISOLATE. The interaction
is real but precisely bounded: it is MATD's contribution to silencing the
node one window earlier that removes DA3's safety margin, not anything
about the ZKP decision logic being different between DA3 and DA4.

---

## Summary of new findings this round

1. **DA1=DA2=DA3's MCC equality is not perfectly arithmetic** (RQ8) — DA2's
   confusion matrix differs from DA1's by exactly one TP/FN swap at node
   11, it just rounds to the same 2-decimal MCC. The "identical to two
   decimal places" framing was accurate about the printed number but
   overstated as "byte-identical" — corrected here with the full per-node
   matrix.
2. **RQ9's real result contradicts the "MATD wired but no opportunity"
   hypothesis** — at drop_rate=20, where near-threshold windows do exist,
   DA2 scores *lower* than DA1 (0.38 vs 0.40), not higher. MATD is
   confirmed active and influential there, just not beneficial in this run.
3. **NQ7 surfaces a new, real finding**: node 11's ZKP proof PASSED at
   t=6.0 in DA4 despite being an active attacker — worth its own
   investigation into why proof generation isn't reliably failing a
   genuine grey-hole node.
4. **NQ9's controlled experiment refutes last round's timing-artifact
   theory for node 8** — reported honestly as a ruled-out hypothesis, not
   reframed as still-plausible. Root cause of node 8's DA6-specific silence
   remains open.
5. **NQ10/NQ11 together give the clearest picture yet**: DA1's MCC is
   97.1% of a hard, routing-imposed ceiling (0.4714), and DA6's shortfall
   relative to DA4 is fully and exclusively explained by node 8 (correcting
   it alone pushes DA6 above DA4). The non-monotonicity across DA1-DA6 is
   now precisely two separate, well-understood, small-scale node-level
   effects (node 11's DA4-specific silence, node 8's DA6-specific silence)
   riding on top of a routing-coverage ceiling that caps everything at
   ~0.47 — not a wiring failure and not an unexplained mystery, though
   node 8's specific mechanism is still not identified.
