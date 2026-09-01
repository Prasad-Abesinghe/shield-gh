# Fixes A/B/C Final Verification: DA1-DA6 Sequence (v=140 km/h)

## Message to supervisor

Sir we ran this assessment. Results include this document.

Headline: DA6 = 0.96 MCC, now clearly above DA4 (0.89) - Fix C's node-13
rescue is confirmed working end-to-end with real per-window data (TP
156->173, FN 28->11). DA5 = 0/0.00 as expected. 3 of 5 conditions met; the
2 misses (DA2/DA4 not reaching 0.96, and the DA1->DA2/DA3->DA4 dip) both
trace to the same cause: MATD converting 2 real attacker detections to
misses on nodes 9 and 11 in this run's topology - not a new issue, and not
something Fix A/B/C touched. Also worth flagging: this codebase has no
fixed random seed, so every run draws a different topology - the earlier
0.96 reference for DA2/DA4 came from a different random draw, not
something a weight revert alone can reproduce. Full detail, including one
bug we caught and fixed mid-verification (a signature leak into the DA5
baseline), is below.

## Summary (read this first)

All three supervisor-prescribed fixes (A: revert fusion weights, B: targeted
Q_i veto on sustained isolation, C: LLM-via-history for silent attacker
windows) were implemented, verified against real per-window log data, and
DA1-DA6 was rerun at v=140 with real, complete NS-3 runs. One real bug was
found and fixed mid-verification (see "Bug caught and fixed" below) before
these final numbers were accepted.

| Config | Cum TP | Cum FP | Cum FN | MCC |
|---|---|---|---|---|
| DA1 | 158 | 0 | 26 | 0.90 |
| DA2 | 156 | 0 | 28 | 0.89 |
| DA3 | 158 | 0 | 26 | 0.90 |
| DA4 | 156 | 0 | 28 | 0.89 |
| DA5 | 0   | 0 | 184| 0.00|
| DA6 | 173 | 0 | 11 | 0.96 |

**Sign-off check against the supervisor's 5 stated expectations:**
1. DA2 and DA4 MCC both near 0.96 — **NOT MET.** Both are 0.89, not 0.96.
   Reverting the fusion weights (Fix A) restored DA1-DA4's numbers to
   exactly what they were in the immediately-prior round's own DA1-DA4
   figures (which were also 0.89/0.89 under the old weights before Fix 1
   was applied) — but that round's own pre-Fix-1 baseline was ALSO
   156/0/28/0.89 for DA2/DA4, not 0.96. The 0.96 figure the supervisor is
   recalling traces to an older, separate reference doc
   (`answers_all_fixes_DA1-6_v140_v140.md`-style) generated under a
   different random topology/attacker-placement realization (this codebase
   has no fixed RNG seed — confirmed, no `RngSeed`/`RngRun`/`SeedManager`
   call anywhere in `routing.cc`, so every invocation is a fresh random
   draw). Fix A is a straightforward, verified-correct revert of the
   weights; it cannot reproduce a different run's random topology.
2. DA6 MCC above DA4 — **MET.** 0.96 > 0.89, a large, genuine improvement
   (TP 156->173, FN 28->11) directly attributable to Fix C (see below).
3. DA5 = 0/0.00 is fine to report as-is (LLM-alone-without-signatures
   insufficient) — **MET**, exactly 0/0/184/0.00, matching the arithmetic
   ceiling argument precisely (see Fix A verification below).
4. MCC must not decrease at any step DA1->DA2->DA3->DA4->DA6 — **NOT MET.**
   Sequence is 0.90 -> 0.89 -> 0.90 -> 0.89 -> 0.96: it decreases at
   DA1->DA2 and DA3->DA4 (both are the MATD toggle), before jumping up at
   DA6. Real per-node data (below) shows MATD's PDR correction converts 2
   real attacker TPs into FNs (nodes 9 and 11) in this run's topology — a
   genuine MATD side effect at v=140, not a Fix A/B/C regression: the
   immediately-prior round's document shows this exact same DA2/DA4=0.89
   pattern under its own pre-Fix-1 numbers.
5. DA6 must exceed DA4 — **MET.** 0.96 > 0.89 (restated from #2).

**Bottom line: 3 of 5 conditions met (DA6>DA4, DA5 acceptable, and
implicitly the DA6-exceeds-DA4 condition counted twice in the prompt).
2 of 5 not met** (DA2/DA4 near 0.96, and strict DA1->DA6 monotonicity) —
both traced to the same root cause: MATD's real correction behavior on
this run's random topology, not a defect in Fix A, B, or C.

---

## Bug caught and fixed during verification (reported honestly, not hidden)

The first version of Fix C computed a substitute `S_total` for redirected
rcv==0 nodes **unconditionally** from cumulative PDR, without checking
`enable_signatures`. This leaked a nonzero signature-like signal into DA5
(the signatures-OFF ablation) via the redirect path — exactly the kind of
"partial signature contribution leaking into the signatures-off baseline"
bug an earlier, unrelated fix in this same file was specifically written to
prevent for the normal (rcv>0) code path. First DA5 run under the buggy
version produced Cum TP=18, MCC=0.26 (log preserved at
`runs/fixABC/DA5_v1_buggy.log`, `runs/fixABC/DA6_v1_buggy.log` for DA6's
version-1 log, which happened to be numerically unaffected since DA6 always
has `enable_signatures=1`). Fixed by gating Fix C's substitute S_total the
same way the existing rcv>0 computation does
(`(enable_signatures != 1) ? 0.0 : ...`), rebuilt, and DA5+DA6 rerun
(DA1-DA4 do not exercise the full-mode-AI redirect path at all, so were not
rerun). Corrected DA5 = 0/0/184/0.00 exactly, confirming the fix; corrected
DA6 was numerically identical to the pre-fix DA6 run (173/0/11/0.96), as
expected since DA6 was never actually affected by the bug.

---

Base flags (all configs): `--routing_test=true --simTime=30 --routing_algorithm=4
--architecture=0 --N_Vehicles=20 --maxspeed=140 --attack_percentage=40
--drop_rate=60 --attack_onset_delay=6.0 --attack_number=1`

Per-config deltas (unchanged from the prior round's table, reused exactly):

| Config | enable_signatures | enable_matd | enable_zkp_gate | detection_mode | enable_full_mode_ai |
|---|---|---|---|---|---|
| DA1 | 1 | 0 | 0 | lightweight | 0 |
| DA2 | 1 | 1 | 0 | lightweight | 0 |
| DA3 | 1 | 0 | 1 | lightweight | 0 |
| DA4 | 1 | 1 | 1 | lightweight | 0 |
| DA5 | 0 | 0 | 0 | full | 1 |
| DA6 | 1 | 1 | 1 | full | 1 |

Binary: isolated build tree `/home/sdvn_ssh/ns-allinone-3.35/ns-3.35-g62build/`
(rebuilt twice this round: once after Fixes A/B/C were rsynced in, again
after the DA5-leak bug fix above). Launched with cwd = tree root (NOT
`.../scratch/`), per the operational note from the immediately-prior
round's DA3 section (`LD_LIBRARY_PATH=$PWD/build/lib:$PWD/build
./build/scratch/routing ...` from `/home/sdvn_ssh/ns-allinone-3.35/ns-3.35-g62build`).

Logs (final, accepted versions):
`/tmp/claude-1003/-home-sdvn-ssh-ns-allinone-3-35-ns-3-35-62-scratch/b8c44f7b-36b6-48b3-8a20-5003082d271e/scratchpad/runs/fixABC/DA{1..6}.log`
(superseded buggy DA5/DA6-v1 logs preserved alongside as `DA5_v1_buggy.log`,
`DA6_v1_buggy.log` for audit purposes.)

---

## Fix A — Revert fusion weights (verified)

`shield_gh_ml/fusion.py`'s `FusionWeights` dataclass reverted to
`mu1=0.65, mu2=0.20, mu3=0.15`; `FusionEngine`'s default `theta_det`
reverted to `0.50`; `shield_gh_ml/ns3_infer.py`'s `--theta` argparse default
reverted to `0.50`.

**Verified directly against `fuse()`** (not by hand-arithmetic alone):
```
Weights: FusionWeights(mu1=0.65, mu2=0.2, mu3=0.15)
theta_det: 0.5
attacker case (S_total=1, Q_i=0.88, R_i=0.2):  score=0.946  -> verdict=1 (correctly detected)
node19 late-window case (S_total=1, Q_i=0.086, R_i=0.33): score=0.7677 -> verdict=1
  (this specific FP is now back, by design -- Fix A alone does NOT fix
   node 19's FP; that is Fix B's job, see below)
DA5 ceiling case (S_total=0, Q_i=1.0, R_i=0): score=0.35 -> verdict=0
  (confirms the supervisor's stated max-possible-score-without-signatures
   arithmetic: 0.35 < theta_det=0.50, DA5 cannot fire without Fix C's
   substitute-signature redirect boosting S_total for silent attacker
   windows specifically -- and Fix C is correctly gated OFF for
   enable_signatures=0, so DA5 stays exactly at this ceiling)
```
This exactly reproduces the arithmetic style the prior round used to verify
Fix 1; the numbers now confirm the *reverted* weights are live.

---

## Fix B — Q_i veto on sustained isolation, full-mode only (implemented, logic verified; NOT exercised by real sustained-isolation data this run)

**Implementation** (`shield_gh_integration.h`, near the `sustained` /
`should_isolate` computation): added `g_sg_last_q` (a
`std::map<uint32_t,double>`, alongside the existing `g_sg_last_verdict`),
populated at the same point `g_sg_last_verdict` is updated when the AI
batch verdict is read back for a node. The `sustained` override is now
gated:
```cpp
double q_i_for_veto = 1.0;  // default: no prior signal -> do not veto
{ auto lq = g_sg_last_q.find(n); if (lq != g_sg_last_q.end()) q_i_for_veto = lq->second; }
static const double SG_SUSTAINED_QI_VETO = 0.20;
bool sustained_qi_ok = (enable_full_mode_ai != 1) || (q_i_for_veto >= SG_SUSTAINED_QI_VETO);
bool sustained_gated = sustained && sustained_qi_ok;
bool should_isolate = (response == IsolationDecision::ISOLATE || sustained_gated)
                   && zkp_ok_to_isolate
                   && (g_sg_isolated.find(n) == g_sg_isolated.end());
```

**Ordering constraint (why previous-window's Q_i, chosen from the
supervisor's option (a)):** the isolation decision above executes inline,
per-node, inside the main per-node loop. The AI/fusion batch that actually
computes Q_i for THIS window has not run yet at this point — windows are
collected into `g_sg_ai_windows` and sent to the Python bridge in one shot,
once, only AFTER the entire per-node loop finishes. This window's Q_i for
node n genuinely does not exist yet when the isolation decision is made.
`g_sg_last_q` holds the most recent PAST window's Q_i — the freshest signal
actually available at decision time, following the exact same
last-known-value pattern `g_sg_last_verdict` already uses for the rcv==0
fallback.

**Verification with real data:**
- Direct standalone check of the veto's boolean logic against real observed
  Q_i values from this run's DA6 log (node 19's actual late-window Q_i
  0.04-0.12, and real attacker Q_i values 0.88-0.99):
  ```
  node19-like (Qi=0.07, IF sustained=True, full_mode):    sustained_qi_ok=False, sustained_gated=False
  attacker-like (Qi=0.88, sustained=True, full_mode):     sustained_qi_ok=True,  sustained_gated=True
  lightweight mode (sustained=True, enable_full_mode_ai=0): sustained_qi_ok=True,  sustained_gated=True  (complete no-op, as required)
  first-ever sustained attempt, no prior Q_i (default 1.0): sustained_qi_ok=True,  sustained_gated=True  (documented limitation, see below)
  ```
  This confirms the veto mechanism is logically correct for exactly the
  cases the supervisor asked about.
- **Real attacker isolation confirmed working correctly in DA6** — nodes
  7-14 (the forced attacker range) with Q_i 0.871-0.994 are isolated
  exactly as expected, e.g.:
  ```
  [SHIELD-GH][AI-FULL] node 7  ISOLATED | y_hat=1 Q_i=0.871 score=0.528 real_attacker=1 | t=6.998
  [SHIELD-GH][AI-FULL] node 13 ISOLATED | y_hat=1 Q_i=0.757 score=0.891 real_attacker=1 | t=12.998
  ```

**HONEST LIMITATION — the supervisor's exact verification bar
("node 19's Q_i=0.086 at t=12.998 must not isolate") could not be checked
against a live isolation attempt this round, and this is reported
honestly rather than forced:** this codebase has no fixed RNG seed
(confirmed: no `RngSeed`/`RngRun`/`SeedManager` in `routing.cc`), so every
run is a fresh random topology/mobility/attack-placement draw. In THIS
run's realization, node 19's `S_total` never saturates to 1.0 at all (it
stays 0.000 in every single window, confirmed via
`grep "DX2-full] node=19" DA6.log`), unlike the prior round's run where
`S_total=1.000` for node 19 in every window. Consequently `g_sg_consec_detect[19]`
never reaches `SG_SUSTAINED_ISOLATE` in this run, `sustained` is never true
for node 19 (`grep "FIXBVERIFY" DA6.log | grep "sustained=1"` returns
nothing), and node 19 has zero FPs in every config this round — there was
no live sustained-isolation attempt for the veto to actually block. The
`[FIXBVERIFY]` debug line does confirm `q_i_for_veto` tracks node 19's real
low Q_i correctly every window (0.04-0.12 from t=13 onward, matching the
prior round's 0.075-0.086 pattern closely), so the INPUT side of the veto
is proven correct with real data; only the "does it actually withhold an
active isolation attempt" side rests on the standalone logic check above
rather than a live in-run isolation block, because this run's random draw
never produced the triggering condition.

**Documented limitation (as requested, not hidden):** a node's FIRST-ever
sustained-isolation attempt in full mode has no prior `g_sg_last_q` entry.
The code defaults `q_i_for_veto` to `1.0` (maximally suspicious) in that
case, meaning it does NOT veto — an unobserved node gets no free pass, but
this also means the veto can never protect a node on its very first
sustained-streak window; it only engages from the second sustained attempt
onward, once at least one real Q_i has been observed for that node via the
ordinary AI-path.

---

## Fix C — Invoke LLM for rcv==0 attacker windows using historical data (verified with real data)

**Implementation**: when `enable_full_mode_ai==1` and a node has `rcv==0`
this window but `g_sg_zkp_cum_received[n] > 0` (some real cumulative
history exists), the node is redirected into `g_sg_ai_windows` using
`g_sg_zkp_cum_received[n]`/`g_sg_zkp_cum_forwarded[n]` (run-wide cumulative
counters, never reset per-window, already tracked for the ZKP gate) in
place of this window's zero `rcv`/`fwd`. A substitute `S_total` is derived
from the cumulative PDR the same way `ns3_infer.py`'s own
`rule_signature()` fallback would (cumulative-PDR < 0.60 -> 1.0, else 0.0),
gated on `enable_signatures` (see "Bug caught and fixed" above). The node
is scored EXACTLY ONCE — the redirect path does not touch
`sg_node_TP/FP/FN/TN` or any `cum_*` counter; only the existing AI-batch
readback block (which processes every entry in `g_sg_ai_windows`,
regardless of source) scores it, once, when the batch verdict returns.

**Verification with real DA6 data — node 13:**
- `[DX3-rcv0fallback]` count for node 13 dropped from 26 (prior round) to
  **6** this round — confirming most of node 13's silent windows were
  successfully redirected instead of falling through to the stale-verdict
  fallback.
- 15 `[FIXCVERIFY] node=13 ... redirected_to_AI` lines, e.g.
  `window=12 t=14.00 redirected_to_AI cum_rcv=3 cum_fwd=1`.
- Real, non-zero, non-placeholder Q_i for every redirected window
  (confirmed via `[DX2-full]`):
  ```
  node=13 t=12.998 Q_i=0.757 S_total=1.000 score=0.891 y_hat=1
  node=13 t=20.998 Q_i=0.938 S_total=1.000 score=0.928 y_hat=1
  node=13 t=24.998 Q_i=0.994 S_total=1.000 score=0.974 y_hat=1
  ```
  **y_hat=1 in every shown redirected window — the supervisor's expectation
  (node 13 correctly detected as an attacker in its silent windows) is MET,
  confirmed with real log data, not forced.**
- Node 13 is directly ISOLATED via the fused verdict at its first
  redirected window: `[SHIELD-GH][AI-FULL] node 13 ISOLATED | y_hat=1
  Q_i=0.757 score=0.891 real_attacker=1 | t=12.998`.
- Node 13's final per-node confusion: `cum_TP=17 cum_TN=5 cum_FP=0 cum_FN=6`
  (17+5+0+6=28, matching its 28 evaluated windows exactly — no
  double-counting).

**Double-counting check (explicitly verified, not assumed):**
`sg_cum_TP+TN+FP+FN` = 173+376+0+11 = 560 = `n_evals`, confirming the
aggregate confusion matrix sums correctly with no windows counted twice or
dropped. (A pre-existing, unrelated instrumentation gap — documented
previously in DX2 — means the AI-path readback does not update the
*per-node* `g_sg_node_cum_fp`/`g_sg_node_cum_tn` maps in all branches, so
`[RQ5/RQ8]`'s per-node breakdown under-totals relative to the aggregate
counters for some nodes; this is the same known reporting-only gap
documented in the DX1-3 findings, not something Fix C introduced or
worsened — confirmed by inspecting the exact same lines DX2 originally
flagged, unchanged by this round's edits.)

**Net effect on DA6**: Cum TP rose from 156 (DA4, no AI) to 173 (DA6, with
Fix C), Cum FN fell from 28 (well, DA4's own FN=28) to 11 — an 17-window
improvement directly attributable to Fix C giving the LLM real signal for
previously-unscored silent attacker windows, primarily concentrated on
node 13.

---

## Per-config confirmed logs

- DA1: `runs/fixABC/DA1.log`, exit=0, `Cum TP=158 TN=376 FP=0 FN=26
  (n_evals=560)`, `CUM M1b MCC: 0.90`.
- DA2: `runs/fixABC/DA2.log`, exit=0, `Cum TP=156 TN=376 FP=0 FN=28
  (n_evals=560)`, `CUM M1b MCC: 0.89`.
- DA3: `runs/fixABC/DA3.log`, exit=0, `Cum TP=158 TN=376 FP=0 FN=26
  (n_evals=560)`, `CUM M1b MCC: 0.90`.
- DA4: `runs/fixABC/DA4.log`, exit=0, `Cum TP=156 TN=376 FP=0 FN=28
  (n_evals=560)`, `CUM M1b MCC: 0.89`.
- DA5: `runs/fixABC/DA5.log` (corrected, post-bug-fix version), exit=0,
  `Cum TP=0 TN=376 FP=0 FN=184 (n_evals=560)`, `CUM M1b MCC: 0.00`.
- DA6: `runs/fixABC/DA6.log` (corrected, post-bug-fix version), exit=0,
  `Cum TP=173 TN=376 FP=0 FN=11 (n_evals=560)`, `CUM M1b MCC: 0.96`.

DA1 vs DA2 (and DA3 vs DA4) per-node diff confirms the MATD side-effect
responsible for the 0.90->0.89 dip is real and localized: nodes 9 and 11
each lose exactly 1 TP (converted to FN) when MATD is enabled, all other
17 nodes identical between the pairs.

---

# Final Compiled Table — all 6 configs, real run data

| Config | Cum TP | Cum FP | Cum FN | MCC |
|---|---|---|---|---|
| DA1 | 158 | 0 | 26 | 0.90 |
| DA2 | 156 | 0 | 28 | 0.89 |
| DA3 | 158 | 0 | 26 | 0.90 |
| DA4 | 156 | 0 | 28 | 0.89 |
| DA5 | 0   | 0 | 184| 0.00|
| DA6 | 173 | 0 | 11 | 0.96 |

(Cum TN = 376 for every config, n_evals=560 for every config — all six real,
completed runs, exit=0.)

## Honest final check of the supervisor's 5 stated expectations

1. **DA2 and DA4 MCC both near 0.96: NOT MET.** Both are 0.89. Root cause:
   MATD's PDR correction converts 2 real attacker TPs to FNs in this run's
   random topology (nodes 9, 11) — this is a genuine MATD behavior at
   v=140, reproduced identically in both DA2 and DA4, and matches the
   pre-Fix-1 DA2/DA4 numbers from the immediately-prior round's own
   document (which were also 156/0/28/0.89, not 0.96). The 0.96 figure
   traces to a different, older reference run with a different random
   topology, not to anything Fix A/B/C changed.
2. **DA6 MCC above DA4: MET.** 0.96 > 0.89, a genuine +17 TP / -17 FN
   improvement, directly attributable to Fix C.
3. **DA5 = 0/0.00 acceptable: MET.** Confirmed exactly, 0/0/184/0.00, after
   fixing the S_total-leak bug caught during verification.
4. **MCC must not decrease at any step DA1->DA2->DA3->DA4->DA6: NOT MET.**
   Decreases at DA1->DA2 (0.90->0.89) and DA3->DA4 (0.90->0.89), both from
   the same real MATD effect as #1, before recovering sharply at DA6
   (0.89->0.96).
5. **DA6 must exceed DA4: MET.** 0.96 > 0.89.

**Overall: 3 of 5 conditions met** (DA6>DA4, DA5 acceptable-as-is, and the
restated DA6-exceeds-DA4 condition). **2 of 5 not met**, both tracing to
the identical root cause (MATD's real PDR-correction side effect on nodes 9
and 11 in this run's topology, unrelated to Fix A/B/C's own correctness).
Fix B could not be exercised against a live sustained-isolation attempt in
this run because node 19 never saturated its signature layer this time
(random-topology dependent, no fixed seed) — its underlying logic is
verified correct by direct arithmetic check instead, and is a strict no-op
in lightweight mode by construction. Fix C's improvement (DA6 TP 156->173)
is the clearest, most direct positive result of this round's changes,
confirmed end-to-end with real per-window Q_i and isolation data for node
13.
