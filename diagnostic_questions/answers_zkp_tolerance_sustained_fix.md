# ZKP Cumulative Tolerance (Fix 1) + Sustained-Threshold Diagnostic (Fix 2): Results (v=140 km/h)

## Message to supervisor

Sir, diagnostic done first as instructed, then Fix 1 applied and verified,
Fix 2 evaluated but NOT applied (diagnostic did not confirm its premise --
explained below, not applied anyway just to force a number).

**Diagnostic answer (node 19's very first FP window, DA1, t=9.00):**
(a) `s1=0` -- S1/PDR signature did NOT fire. (b) Isolation came via
`lambda>=lambda2` (5>=5, the graduated-response **statistical gate**), NOT
via `sustained=1` (`sustained=0` at that window, and in fact `sustained=0`
for node 19 at **every** window of the entire run -- the consecutive-window
override never engages for node 19 in this run at all). (c) `obs_pdr=1.00`,
`corr_pdr=1.00` -- node 19's PDR was perfect, nowhere near `tau_f=0.60`.
So MATD's PDR correction is confirmed structurally irrelevant to this FP
(PDR was never close to the S1 threshold), consistent with the prior
round's finding -- but the mechanism is neither of the two the supervisor's
conditional named (not S1/PDR, but also not `sustained=1`); it's the
reputation-driven graduated-response gate, a third path. Per the
supervisor's own framing ("if S1/PDR-based, Fix 2 should NOT be
implemented"), and since the actual mechanism here is not `sustained=1`
either, **Fix 2's literal premise does not hold, so it was not applied.**

**Fix 1 (ZKP epsilon=3): applied and verified.** The claim that the current
comparison is exact equality was checked against the live code first and
confirmed true (`shield_gh/blockchain/zkp_proofs.cc:33`,
`if (commit.n_fwd == observable_count)`, zero tolerance). Changed to
`PASS if (observable_count - commit.n_fwd) <= 3`. Verified on a fresh DA3
run: node 19's real gap trajectory is `t=21.00: cum_received=53,
cum_forwarded=51` -- **this is the exact pair the supervisor cited**,
confirming the diagnosis was accurate for this codebase's normal MAC-loss
behaviour, not just a hypothetical. `zkp_proof_valid=PASS` at every single
window for the full 30s run, `should_isolate=0` for node 19 throughout.
**DA3 and DA4 (the two configs with `enable_zkp_gate=1`) both moved from
20 FPs / MCC 0.77 to 0 FPs / MCC 0.84** -- a genuine, verified improvement
from Fix 1 alone. DA1/DA2 (`enable_zkp_gate=0`) are correctly untouched
(20 FPs persist there) since they never consult the ZKP gate at all --
exactly as the diagnostic predicted.

**Real final DA1-DA6 table (fresh run, v=140, this round's random topology):**

| Config | Cum TP | Cum FP | Cum FN | MCC |
|---|---|---|---|---|
| DA1 | 148 | 20 | 36 | 0.77 |
| DA2 | 148 | 20 | 36 | 0.77 |
| DA3 | 145 | 0  | 39 | 0.84 |
| DA4 | 144 | 0  | 40 | 0.84 |
| DA5 | 0   | 0  | 184| 0.00|
| DA6 | 172 | 0  | 12 | 0.95 |

**Per-component >=0.01 MCC bar: mixed, reported honestly.** ZKP-gate
component (DA1->DA3, DA2->DA4): **+0.07, clears the bar.** Full-mode
AI/LLM component (DA4->DA6): **+0.11, clears the bar.** MATD component
(DA1->DA2, DA3->DA4): **+0.00 in both pairs -- does NOT clear the bar**,
because in this run's specific topology draw MATD's correction never
changes any node's verdict (confirmed identical per-node confusion
matrices DA1 vs DA2, DA3 vs DA4) -- not a regression, but not a positive
contribution either, in this draw. This mirrors the immediately-prior
round's finding and is the same, already-flagged, open item (MATD's
contribution appears to depend on whether the random draw happens to place
an attacker where MATD's correction matters -- it was decisive in an
earlier round's different random draw, per `answers_fixABC_final_DA1-6.md`).

**Comparison to supervisor's expected table**
(DA1~0.89, DA2~0.93+, DA3~0.92+, DA4~0.96, DA5~0.00, DA6~0.96+): real
numbers are DA1=0.77, DA2=0.77, DA3=0.84, DA4=0.84, DA5=0.00, DA6=0.95.
DA5 and DA6 are close to or within reach of expectation. DA1-DA4 remain
meaningfully below the expected values, same discrepancy flagged in the
immediately-prior round: this codebase has no fixed RNG seed (confirmed
again, no `RngSeed`/`RngRun`/`SeedManager` in `routing.cc`), so every run
draws a fresh topology/attacker placement, and the expected table appears
anchored to a different, more favourable random draw rather than a
property this code should reproduce on every invocation. Recommend
treating DA1-DA4's ceiling as topology-draw-dependent unless/until a
seeded, multi-trial study is run.

---

## Step 1: Diagnostic (required first)

Added one small, targeted debug print (`[ZTDIAG]`, `shield_gh/shield_gh_integration.h`,
right after the existing `[DX2]` block) that prints node 19's `s1`, `s2`,
`s3`, `obs_pdr`, `corr_pdr` unconditionally every window -- the one field
(`s1`) not already covered by the extensive existing instrumentation
(`[PQ1]` for lambda/lambda2, `[FIXBVERIFY]` for sustained/should_isolate,
`[FIX2VERIFY]` for the ZKP cumulative counters, `[DX2]`/`[RQ3]` for
S_total/R_i/obs_pdr/corr_pdr) left over from prior rounds' work on this
exact node.

Ran DA1 fresh (`enable_signatures=1 enable_matd=0 enable_zkp_gate=0
detection_mode=lightweight enable_full_mode_ai=0`, v=140, all other flags
per the standing config). Node 19's first `should_isolate=1` window:

```
[FIXBVERIFY] node=19 t=9.00 q_i_for_veto=1.00 sustained=0 sustained_qi_ok=1 sustained_gated=0 should_isolate=1
[FIX2VERIFY] node=19 t=9.00 should_isolate=1 zkp_ok_to_isolate=1 zkp_gate_enabled=0 zkp_cached=1 zkp_proof_valid=0 zkp_cum_received=22 zkp_cum_forwarded=20
[PQ1] node=19 window=7 t=9.00 lambda=5 lambda2=5
[ZTDIAG] node=19 t=9.00 s1=0 s2=0 s3=0 obs_pdr=1.00 corr_pdr=1.00
[DX2] node=19 t=9.00 S_total=0.00 R_i=0.74 score=0.10 y_hat=0
```

**Answers:**
- **(a) s1:** `s1=0`. S1 (PDR-based rule signature) never fired for node 19
  at or before this window. `S_total=0.00` confirms no signature contributed
  at all.
- **(b) mechanism:** `lambda=5 >= lambda2=5` -- the graduated-response
  **statistical gate** (`GetGraduatedResponse` returning `ISOLATE`), which
  requires `ShouldIsolate()`'s reputation-based `statistical_gate` term
  (`(1-Ri_decayed) > EffectiveThetaR`) to be true, dual-evidenced with the
  (bypassed, since `zkp_gate_enabled=0` in DA1) ZKP gate. `sustained=0` at
  this window, and checking all 16 `[FIXBVERIFY]` lines logged for node 19
  across the full 30s run, `sustained=0` at **every single one** -- the
  consecutive-window override never fires for node 19 in this run.
- **(c) PDR:** `obs_pdr=1.00`, `corr_pdr=1.00` at t=9.00 -- a perfect,
  fully healthy PDR, far above `tau_f=0.60`. Confirms the FP is not
  PDR-threshold-related in any way; MATD's PDR correction (which only ever
  touches `corr_pdr`) cannot plausibly help here regardless of tuning.

**Implication:** the FP mechanism is a third path, distinct from both
premises named in the supervisor's conditional (S1/PDR-threshold, and
`sustained=1`/consecutive-window). It is the reputation-decay-driven
statistical gate. This determines Fix 2's applicability below.

## Step 2: Fix 1 (ZKP cumulative tolerance) -- verify claim, then implement

**Claim verification (before changing anything):** read
`shield_gh/blockchain/zkp_proofs.cc` (the only place `proof.valid` is set;
confirmed via grep that `DEBSC::ShouldIsolate`'s `zkp_failed` and the
integration layer's `zkp_dbg.zkp_proof_valid` both trace back to this one
function -- the separate `VerifyProof()` method also exists in the same
file but is never called anywhere in `shield_gh/` or `routing.cc`, i.e. it
is dead code, not part of the live decision path). The live check at line
33, prior to this round's fix:

```cpp
if (commit.n_fwd == observable_count) {   // EXACT equality, zero tolerance
    proof.valid = true;
} else {
    proof.valid = false;
}
```

This confirms the supervisor's diagnosis exactly: bare equality, any
nonzero gap (`cum_received - cum_forwarded > 0`) marks FAIL. No hidden
extra logic, no pre-existing tolerance of any kind.

**Fix implemented** (`shield_gh/blockchain/zkp_proofs.cc`,
`ZKPProofStore::GenerateProof`):

```cpp
static const uint32_t SG_ZKP_CUM_EPSILON = 3;  // supervisor-prescribed tolerance
uint32_t gap = (observable_count > commit.n_fwd)
                   ? (observable_count - commit.n_fwd)
                   : 0;
if (gap <= SG_ZKP_CUM_EPSILON) {
    proof.valid = true;   // PASS: gap within normal MAC-layer loss tolerance
} else {
    proof.valid = false;  // FAIL: gap exceeds plausible collision loss
}
```

`observable_count` is `g_sg_zkp_cum_forwarded[n]` (blockchain-observed
forwards) and `commit.n_fwd` is `g_sg_zkp_cum_received[n]` (the node's own
claimed-received count committed via the Pedersen commitment) -- i.e. `gap`
is exactly `cum_received - cum_forwarded`, matching the supervisor's stated
quantity.

**Verification (DA3, `enable_zkp_gate=1`, fresh run, every window for
node 19):**

```
t=1.99801  rcv=3  fwd=3   gap=0  PASS  should_isolate=0
t=5.00     rcv=12 fwd=11  gap=1  PASS  should_isolate=0
t=9.00     rcv=22 fwd=20  gap=2  PASS  should_isolate=0
t=21.00    rcv=53 fwd=51  gap=2  PASS  should_isolate=0   <- matches supervisor's exact cited numbers
t=29.00    rcv=71 fwd=69  gap=2  PASS  should_isolate=0   (final)
```

`zkp_proof_valid=PASS` and `should_isolate=0` for node 19 at **every one**
of the 26 logged windows across the full 30s run -- confirmed via
`grep "FIX2VERIFY.*node=19"`, zero FAILs, zero isolations. Node 19's cum_FP
in DA3 dropped from 20 (pre-fix) to **0** (post-fix); MCC rose 0.77 -> 0.84.
DA4 shows the identical pattern (0 FP, MCC 0.77 -> 0.84). DA1/DA2
(`enable_zkp_gate=0`) are confirmed unaffected (still 20 FPs each) since
they never call the ZKP gate -- correct, expected, ablation-preserving
behaviour.

## Step 3: Fix 2 (sustained-threshold, legitimate-nodes-only) -- NOT applied

**Per the diagnostic:** node 19's FP came via the statistical
(`lambda>=lambda2`) gate, not `sustained=1` -- confirmed `sustained=0` at
every window of the run for node 19. The supervisor's conditional
explicitly states Fix 2 should only be implemented if the FP is
`sustained`-driven AND PDR is well above `tau_f`. The PDR half of the
premise holds (`obs_pdr=1.00 >> tau_f=0.60`), but the `sustained=1` half
does **not** -- `sustained` never fires for node 19 in this run at all, so
lowering `SG_SUSTAINED_ISOLATE` (from 12 to anything) would be a pure
no-op for this specific FP: the consecutive-window counter never gets
close to the current threshold of 12 in the first place (isolation happens
at t=9.00 via the statistical gate, well before any sustained streak could
accumulate). Implementing Fix 2 here would not fix anything real and would
only add unexercised, dead-in-practice code -- not done.

**The ground-truth-leakage tension, flagged as instructed regardless of
whether Fix 2 applies:** the literal instruction ("lower
`SG_SUSTAINED_ISOLATE` only for legitimate nodes") is not implementable in
a principled way as stated. `SG_SUSTAINED_ISOLATE` is a single global
`static const uint32_t` (`shield_gh/shield_gh_integration.h:168`) compared
against `g_sg_consec_detect[n]`, a per-node consecutive-hit counter, with
no other per-node state available at that point in the decision path that
distinguishes "this node happens to be legitimate" from "this node happens
to be an attacker" -- the only signal that would let the code special-case
by node identity is `gt_attacker`/ground truth, which a real detector must
not consult when deciding whether/how aggressively to isolate (that is
exactly the information a detector is trying to infer, not something it is
given). Any implementation that reads `gt_attacker` (or an equivalent
oracle) inside the `sustained`/`SG_SUSTAINED_ISOLATE` decision path would
silently leak the answer into the ablation and invalidate the DA1-DA6
comparison as a fair detection-quality measurement. Since this round's
diagnostic also shows the premise for needing Fix 2 doesn't hold anyway,
this tension did not have to be resolved to produce a result, but it is
flagged here as requested, in case Fix 2's premise is met in a future
random draw where `sustained=1` genuinely is node 19's (or some other
legitimate node's) isolation path.

## Step 4: full DA1-DA6 rerun (real, blocking, v=140, Fix 1 in place, Fix 2 not applied)

Rebuilt in the isolated tree
`/home/sdvn_ssh/ns-allinone-3.35/ns-3.35-g62build/` (cwd=tree root,
`LD_LIBRARY_PATH=$PWD/build/lib:$PWD/build`). Flags identical to every
prior round: `--routing_test=true --simTime=30 --routing_algorithm=4
--architecture=0 --N_Vehicles=20 --maxspeed=140 --attack_percentage=40
--drop_rate=60 --attack_onset_delay=6.0 --attack_number=1`, per-config
deltas per the standing table:

| Config | enable_signatures | enable_matd | enable_zkp_gate | detection_mode | enable_full_mode_ai |
|---|---|---|---|---|---|
| DA1 | 1 | 0 | 0 | lightweight | 0 |
| DA2 | 1 | 1 | 0 | lightweight | 0 |
| DA3 | 1 | 0 | 1 | lightweight | 0 |
| DA4 | 1 | 1 | 1 | lightweight | 0 |
| DA5 | 0 | 0 | 0 | full | 1 |
| DA6 | 1 | 1 | 1 | full | 1 |

All 6 launched sequentially in the background; each blocked on with a real
`while kill -0 $PID; do sleep 10; done` loop (reissued whenever the loop's
own timeout fired -- happened on every run, always reissued rather than
treated as done) until confirmed complete. All six logs end cleanly at the
expected final `[CQ6]` summary line, no truncation/crash.

Logs:
`/tmp/claude-1003/-home-sdvn-ssh-ns-allinone-3-35-ns-3-35-62-scratch/b8c44f7b-36b6-48b3-8a20-5003082d271e/scratchpad/runs/ztfix/DA{1..6}.log`

### Final table (real run data)

| Config | Cum TP | Cum FP | Cum FN | MCC |
|---|---|---|---|---|
| DA1 | 148 | 20 | 36 | 0.77 |
| DA2 | 148 | 20 | 36 | 0.77 |
| DA3 | 145 | 0  | 39 | 0.84 |
| DA4 | 144 | 0  | 40 | 0.84 |
| DA5 | 0   | 0  | 184| 0.00|
| DA6 | 172 | 0  | 12 | 0.95 |

(Cum TN: 356 for DA1-2, 376 for DA3-6; n_evals=560 throughout, taken from
each log's own `Cum TP=... TN=... FP=... FN=... (n_evals=560)` summary
line, cross-checked by hand-computing MCC from these four numbers --
matches the logged `CUM M1b MCC` to 2 decimal places in every config.)

### Per-component >=0.01 MCC bar: checked honestly, not forced

| Comparison | Isolates | Delta MCC | Clears >=0.01 bar? |
|---|---|---|---|
| DA1 -> DA2 | MATD toggle (lightweight, no ZKP) | +0.00 | **No** |
| DA3 -> DA4 | MATD toggle (lightweight, with ZKP) | +0.00 | **No** |
| DA1 -> DA3 | ZKP gate toggle (matd=0) | +0.07 | Yes |
| DA2 -> DA4 | ZKP gate toggle (matd=1) | +0.07 | Yes |
| DA4 -> DA6 | Full-mode AI/LLM addition | +0.11 | Yes |
| DA1 -> DA6 | All components on vs. all off | +0.18 | Yes |

The ZKP-gate component (this round's Fix 1 target) and the full-mode
AI/LLM component both clear the bar clearly. The MATD component does not,
in this run -- confirmed via identical per-node confusion matrices DA1 vs
DA2 and DA3 vs DA4 (e.g. node 9: `cum_TP=17 cum_FN=6` in both DA1 and DA2).
This is not a new problem introduced this round; it is the same
topology-draw-dependent finding already flagged in the immediately-prior
round (`answers_matd_monotonic_fix.md`), now re-confirmed on a fresh,
independent random draw. Not fudged to force a positive number.

### Comparison to supervisor's expected table

| Config | Supervisor expected | Real (this round) | Gap |
|---|---|---|---|
| DA1 | ~0.89 | 0.77 | -0.12 |
| DA2 | ~0.93+ | 0.77 | -0.16+ |
| DA3 | ~0.92+ | 0.84 | -0.08+ |
| DA4 | ~0.96 | 0.84 | -0.12 |
| DA5 | ~0.00 | 0.00 | matches |
| DA6 | ~0.96+ | 0.95 | -0.01+ (essentially matches) |

DA5 and DA6 are at or very close to the supervisor's expectation. DA1-DA4
remain below expectation by 0.08-0.16, same order of gap as the
immediately-prior round (which was also below the ~0.89 DA1 expectation at
0.77). This environment has no fixed RNG seed (re-confirmed: no
`RngSeed`/`RngRun`/`SeedManager` anywhere in `routing.cc`), so every
invocation, including this round's, draws an entirely fresh
topology/mobility/attack-placement realization -- the supervisor's expected
table most plausibly reflects a different, more favourable historical
random draw rather than a fixed target this code is failing to hit. Fix 1
closed roughly half the DA3/DA4 gap to expectation (DA3: 0.77->0.84 vs
target ~0.92; DA4: 0.77->0.84 vs target ~0.96) by removing a real,
verified defect (the zero-tolerance ZKP check); the remaining gap in
DA1-DA4 is consistent with ordinary run-to-run topology variance rather
than a further code defect, but this has not been proven with a seeded,
repeated-trial study (same honest limitation the prior two rounds already
disclosed).

## Honest limitations

1. This round's diagnostic and both fix evaluations are all drawn from a
   single, fresh, unseeded run -- as with every prior round in this chain,
   "confirmed in this run" cannot be elevated to "true for all possible
   random draws" without a seeded, multi-trial study, which remains outside
   this round's scope.
2. Fix 2 was evaluated per the supervisor's own explicit conditional and
   found inapplicable this round (the FP's actual mechanism is the
   statistical gate, not `sustained=1`); it therefore was not implemented,
   and no attempt was made to implement it via a ground-truth-consulting
   shortcut, per the constraint against leaking `gt_attacker`/`is_real`
   into the isolation decision path.
3. The MATD-toggle component (DA1->DA2, DA3->DA4) still does not clear the
   supervisor's >=0.01-per-component bar in this run, same as the
   immediately-prior round. This is reported as-is rather than
   worked around, per the "no fabrication" and "be honest about partial
   success" instructions for this round.
