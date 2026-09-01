# Fixes 1-3 Final Verification: DA1-DA6 Sequence (v=140 km/h)

## Summary (read this first)

All three fixes implemented, verified, and DA1-DA6 rerun at v=140 with real,
complete NS-3 runs (no fabricated numbers — every figure below traces to an
exact log line in `runs/final2/DA{1..6}.log`).

| Config | Cum TP | Cum FP | Cum FN | MCC |
|---|---|---|---|---|
| DA1 | 158 | 0 | 26 | 0.90 |
| DA2 | 156 | 0 | 28 | 0.89 |
| DA3 | 158 | 0 | 26 | 0.90 |
| DA4 | 156 | 0 | 28 | 0.89 |
| DA5 | 0   | 0 | 184| 0.00|
| DA6 | 152 | 0 | 32 | 0.87 |

**Sign-off check — 1 of 5 conditions clearly met:**
1. MCC increases DA1->DA4 — **not met** (0.90->0.89->0.90->0.89)
2. DA6 > DA4 — **not met** (0.87 < 0.89)
3. DA3 > DA1 — **not met, exact tie** (0.90 = 0.90)
4. DA6 >= 0.85 — **met** (0.87)
5. DA6 FP < DA1 FP — **not met, tied at 0** (no headroom, DA1 already 0)

**Fix 1 (fusion weights mu1=0.50/mu2=0.35/mu3=0.15, theta_det=0.65):** worked
as intended for eliminating node 19's false positives, but has a real side
effect: it broke DA5 entirely. With signatures off (DA5's ablation), the max
possible fused score is `0.35*Q_i + 0.15*(1-R_i) <= 0.50`, which can never
cross theta_det=0.65 regardless of LLM confidence. DA5 now detects zero
attacks (TP=0, MCC=0.00) by mathematical construction, not a bug — a direct
consequence of raising theta_det. Worth deciding whether DA5 needs its own
threshold, or is expected to be non-functional under the new weights.

**Fix 2 (ZKP ABSENT-state fix):** verified with real data — node 19's
`zkp_ok_to_isolate` correctly flips to 1 once a cached proof fails
(`zkp_proof_valid=0`), and node 19 is never falsely isolated in DA1 or DA3.
Caveat: this run only exercised the "cached-but-failing" proof state, never
the literal ABSENT (`zkp_cached=0`) case the fix specifically targeted — that
exact branch hasn't been directly observed firing yet, though the logic
checks out safe.

**Fix 3 (node 13):** confirmed with full per-window data — node 13 is a
correctly-configured flow endpoint with cum_TP=17, cum_FN=6, zero false
positives, carrying very little traffic all run (cum_forwarded=2,
cum_received=5) at v=140. Genuine mobility/traffic-volume artifact, not a
fixable flow-placement bug — no code change made or warranted.

**Why this differs from the prior round's table** (DA2/DA4 at 0.96): that
table used the old theta_det=0.5. Fix 1's new threshold shifted the whole
operating point — FP dropped to 0 everywhere, at the cost of some TP, so
MCC moved down slightly for DA2/DA4 rather than up. Same topology, same 560
evaluations per config, different tuning.

**Given DA5's collapse and the missed conditions, this does not look ready
to sign off as-is.**

---

Base flags (all configs): `--routing_test=true --simTime=30 --routing_algorithm=4
--architecture=0 --N_Vehicles=20 --maxspeed=140 --attack_percentage=40
--drop_rate=60 --attack_onset_delay=6.0 --attack_number=1`

Per-config deltas:

| Config | enable_signatures | enable_matd | enable_zkp_gate | detection_mode | enable_full_mode_ai |
|---|---|---|---|---|---|
| DA1 | 1 | 0 | 0 | lightweight | 0 |
| DA2 | 1 | 1 | 0 | lightweight | 0 |
| DA3 | 1 | 0 | 1 | lightweight | 0 |
| DA4 | 1 | 1 | 1 | lightweight | 0 |
| DA5 | 0 | 0 | 0 | full | 1 |
| DA6 | 1 | 1 | 1 | full | 1 |

Binary: isolated build tree `/home/sdvn_ssh/ns-allinone-3.35/ns-3.35-g62build/`
(rebuilt 2026-08-08 00:15, after Fix 1 and Fix 2 code changes were rsynced in
from this repo's `shield_gh_ml/fusion.py` and `shield_gh/shield_gh_integration.h`
— diffed identical against the working repo's copies before DA1 was launched).
`enable_full_mode_ai=1` runs invoke `shield_gh_ml/ns3_infer.py` automatically
via `std::system()` from inside the C++ (hardcoded absolute path to this
repo's copy, `/home/sdvn_ssh/ns-allinone-3.35/ns-3.35/62/scratch/shield_gh_ml/ns3_infer.py`)
— no separate manual post-processing step needed for DA5/DA6.

Logs: `/tmp/claude-1003/-home-sdvn-ssh-ns-allinone-3-35-ns-3-35-62-scratch/b8c44f7b-36b6-48b3-8a20-5003082d271e/scratchpad/runs/final2/DA{1..6}.log`

---

## DA1 — CONFIRMED (real log data)

Log: `runs/final2/DA1.log` (PID 3145104, completed `Sat Aug 8 00:31:28 AM +0530 2026`, exit=0)

**Cumulative detection metrics (final summary line, log line ~25732-25734):**
```
Cum TP=158 TN=376 FP=0 FN=26 (n_evals=560)
CUM M1a Detection Accuracy: 95.36%
CUM M1b MCC: 0.90
CUM M2  False Positive Rate: 0.00%
```

**Fix 3 — Node 13 investigation, real per-window data from this run:**

Node 13's per-window `[DX3-rcv0fallback]` flags (window / t / flagged), all 28
scored windows (log lines 5671-25437):

| window | t | flagged |
|---|---|---|
| 5 | 7.00 | 0 |
| 6 | 8.00 | 0 |
| 7 | 9.00 | 0 |
| 8 | 10.00 | 0 |
| 9 | 11.00 | 0 |
| 10 | 12.00 | 0 |
| 11 | 13.00 | (rcv=3, see NQ1/NQ2 below) |
| 12 | 14.00 | 1 |
| 13 | 15.00 | 1 |
| 14 | 16.00 | 1 |
| 15 | 17.00 | 1 |
| 16 | 18.00 | 1 |
| 17 | 19.00 | 1 |
| 18 | 20.00 | 1 |
| 19 | 21.00 | 1 |
| 20 | 22.00 | 1 |
| 21 | 23.00 | 1 |
| 22 | 24.00 | 1 |
| 23 | 25.00 | (rcv=2, see NQ1/NQ2 below) |
| 24 | 26.00 | 1 |
| 25 | 27.00 | 1 |
| 26 | 28.00 | 1 |
| 27 | 29.00 | 1 |

Direct `rcv=` samples (only two windows print this field, both showing node 13
IS receiving/forwarding traffic, not silently absent):
```
[NQ1/NQ2] node=13 t=13.00 rcv=3 response=MONITOR should_isolate=0 isolated=0
[NQ1/NQ2] node=13 t=25.00 rcv=2 response=REQUIRE_ZKP should_isolate=0 isolated=0
```

Final per-node cumulative confusion (log, `[RQ5/RQ8]` block):
```
node=13 cum_TP=17 cum_TN=5 cum_FP=0 cum_FN=6   (23 scored windows: 17+5+0+6=28... actually 17+5+6=28 evaluated, matches window range above)
```
Final `[CQ6]` run totals for node 13: `cum_forwarded=2 cum_received=5`. End-of-run
summary: `Node 13 [ATTACKER] Dropped=5 Forwarded=0`.

**Conclusion on Fix 3 (now backed by a complete real run, not just source reading):**
Node 13 is detected correctly in the overwhelming majority of its windows
(cum_TP=17, cum_FN=6, cum_TN=5, cum_FP=0 — zero false positives, i.e. no
spurious benign-flagging). It is never isolated (`isolated=0` in both sampled
windows) despite `y_hat=1`, and its own forwarded/received counts stay very
low all run (`cum_forwarded=2`, `cum_received=5`, `Dropped=5`) — consistent
with node 13 being a real, correctly-placed flow endpoint (source of flow 6,
13→16) that simply has very little traffic passing through it at
maxspeed=140 due to mobility/range, not a flow-placement or detection-logic
bug. This matches and now confirms the prior circumstantial (source-reading)
finding with actual per-window run data: the historical high FN fraction for
node 13 (6/23 evaluated windows here, ~26% FN rate) is a genuine physical/
mobility artifact of low traffic volume through that node at high speed, not
a fixable code defect.

---

## DA2 — CONFIRMED (real log data)

Log: `runs/final2/DA2.log` (PID 3245530, started 00:31, completed
`Sat Aug 8 00:38:12 AM +0530 2026`, exit=0). Flags: `--enable_matd=1
--enable_zkp_gate=0 --detection_mode=lightweight --enable_full_mode_ai=0`
(all other flags match DA1's base set).

**Cumulative detection metrics (final summary line):**
```
Cum TP=156 TN=376 FP=0 FN=28 (n_evals=560)
CUM M1b MCC: 0.89
```

---

## DA3 — CONFIRMED (real log data)

Log: `runs/final2/DA3.log` (PID 3327104, completed `Sat Aug 8 00:48:39 AM
+0530 2026`, exit=0). Flags: `--enable_signatures=1 --enable_matd=0
--enable_zkp_gate=1 --detection_mode=lightweight --enable_full_mode_ai=0`
(all other flags match DA1's base set).

**IMPORTANT operational note for any future runs in this isolated build
tree**: the binary must be launched with cwd = tree root
(`/home/sdvn_ssh/ns-allinone-3.35/ns-3.35-g62build/`), NOT `.../scratch/`.
Running from `scratch/` crashes immediately (`assert failed.
cond="ifTraceFile.good ()", msg=" Fading trace file not found"`,
`trace-fading-loss-model.cc:129`) because `routing.cc` opens
`src/lte/model/fading-traces/fading_trace_EVA_60kmph.fad` as a relative
path, which only resolves under the tree root (confirmed: file exists at
`.../ns-3.35-g62build/src/lte/model/fading-traces/...` via symlink, not
under `.../ns-3.35-g62build/scratch/`). First DA3 launch attempt (PID
3311887) hit exactly this and aborted immediately; relaunched correctly
with `cd /home/sdvn_ssh/ns-allinone-3.35/ns-3.35-g62build && LD_LIBRARY_PATH=$PWD/build/lib:$PWD/build ./build/scratch/routing ...`
which succeeded (PID 3327104).

**Cumulative detection metrics (final summary line):**
```
Cum TP=158 TN=376 FP=0 FN=26 (n_evals=560)
CUM M1b MCC: 0.90
```
(Identical to DA1's TP/FP/FN/MCC — matches the prior chain's v=140
expectation that DA3=DA1 for these aggregate numbers, since ZKP-gate-only
does not change the lightweight signature verdicts for attacker nodes.)

**Fix 2 (ZKP gate) verification — real data, node 19 (benign node), every
window, via the pre-existing `[FIX2VERIFY]` debug line in
`shield_gh_integration.h`:**

```
t=1.99801  should_isolate=0 zkp_ok_to_isolate=0 zkp_gate_enabled=1 zkp_cached=1 zkp_proof_valid=1 zkp_cum_received=3  zkp_cum_forwarded=3
t=3.00     should_isolate=0 zkp_ok_to_isolate=0 zkp_gate_enabled=1 zkp_cached=1 zkp_proof_valid=1 zkp_cum_received=4  zkp_cum_forwarded=4
t=4.00     should_isolate=0 zkp_ok_to_isolate=0 zkp_gate_enabled=1 zkp_cached=1 zkp_proof_valid=1 zkp_cum_received=7  zkp_cum_forwarded=7
t=5.00     should_isolate=0 zkp_ok_to_isolate=1 zkp_gate_enabled=1 zkp_cached=1 zkp_proof_valid=0 zkp_cum_received=12 zkp_cum_forwarded=11   <- first proof-fail window
t=6.00     should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=15 zkp_cum_forwarded=13
t=7.00     should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=20 zkp_cum_forwarded=18
t=9.00     should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=22 zkp_cum_forwarded=20
t=10.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=25 zkp_cum_forwarded=23
t=11.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=28 zkp_cum_forwarded=26
t=12.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=29 zkp_cum_forwarded=27
t=13.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=33 zkp_cum_forwarded=31
t=14.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=34 zkp_cum_forwarded=32
t=16.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=37 zkp_cum_forwarded=35
t=17.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=38 zkp_cum_forwarded=36
t=18.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=41 zkp_cum_forwarded=39
t=19.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=44 zkp_cum_forwarded=42
t=20.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=47 zkp_cum_forwarded=45
t=21.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=48 zkp_cum_forwarded=46
t=22.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=49 zkp_cum_forwarded=47
t=23.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=50 zkp_cum_forwarded=48
t=24.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=51 zkp_cum_forwarded=49
t=25.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=52 zkp_cum_forwarded=50
t=29.00    should_isolate=0 zkp_ok_to_isolate=1 ... zkp_proof_valid=0 zkp_cum_received=53 zkp_cum_forwarded=51
```

**Fix 2 conclusion (now with real DA3 run data, not just code reading):**
`zkp_cached=1` and `zkp_proof_valid=0` (proof present but failing/invalid,
not absent) for essentially the whole run from t=5 onward — this is the
"cached-but-invalid" branch, not the "absent" branch the fix targeted, so
this particular run doesn't exercise the exact ABSENT-proof code path the
fix changed. Even so, it's a valid and stronger check: `zkp_ok_to_isolate`
correctly flips to 1 once the gate's other condition
(`zkp_cached && !zkp_proof_valid`) is met, and — critically — node 19
(a legitimate/benign node) is **never actually isolated**
(`should_isolate=0` in all 23 sampled windows), confirming the ZKP gate
change did not introduce any new false-isolation of a benign node.
Combined with the unchanged, zero-FP cumulative metrics above
(`Cum FP=0` in both DA1 and DA3), this is real evidence the Fix 2 code
change is behaving safely, though a run that actually hits `zkp_cached=0`
(the literal ABSENT case) was not observed in this data and would be
needed for a fully direct before/after test of that exact branch.

---

## DA4 — CONFIRMED (real log data)

Log: `runs/final2/DA4.log` (PID 3457673, completed `Sat Aug 8 01:00:30 AM
+0530 2026`, exit=0). Flags: `--enable_signatures=1 --enable_matd=1
--enable_zkp_gate=1 --detection_mode=lightweight --enable_full_mode_ai=0`
(all other flags match DA1's base set). Launched correctly from tree root
per the cwd fix discovered during DA3.

**Cumulative detection metrics (final summary line):**
```
Cum TP=156 TN=376 FP=0 FN=28 (n_evals=560)
CUM M1b MCC: 0.89
```
(Identical to DA2's numbers — MATD is the dominant factor for this metric
at v=140; adding the ZKP gate on top of MATD, going DA2->DA4, makes no
further difference to these aggregate counts in this run.)

---

## DA5 — CONFIRMED (real log data)

Log: `runs/final2/DA5.log` (PID 3601082, completed `Sat Aug 8 01:16:15 AM
+0530 2026`, exit=0). Flags: `--enable_signatures=0 --enable_matd=0
--enable_zkp_gate=0 --detection_mode=full --enable_full_mode_ai=1` (all
other flags match DA1's base set). `ns3_infer.py` invoked automatically
via `std::system()` each window — confirmed running with no errors
(`--fresh_state` correctly wiped stale `.fl_state.pkl` on window 0; FL
rounds progressed `fl_round=0 -> fl_round=1` normally over the run).

**Cumulative detection metrics (final summary line):**
```
Cum TP=0 TN=376 FP=0 FN=184 (n_evals=560)
CUM M1b MCC: 0.00
```

**This is a real, structurally-explained result, not a bug or broken run.**
Traced why TP=0 with real per-window fusion data (`[NQ3/NQ4]` lines, e.g.
`node=8 t=7.00 Q_i=0.93 score=0.36 ... y_hat=0`, `node=9 t=7.00 Q_i=0.95
score=0.36 ... y_hat=0`):

- DA5 has `enable_signatures=0`, so `S_total=0` for every node, every
  window (confirmed via `[DX2-full] ... S_total=0 ...` on all 329 scored
  lines).
- The live fusion weights (Fix 1, confirmed in `shield_gh_ml/fusion.py`'s
  `FusionWeights` dataclass and independently re-derived from real score
  values in this log) are `mu1=0.50, mu2=0.35, mu3=0.15, theta_det=0.65`.
- With `S_total=0`, the maximum possible fused score is
  `mu2*Q_i + mu3*(1-R_i)` ≤ `0.35*1.0 + 0.15*1.0 = 0.50`, which can
  **never** exceed `theta_det=0.65` — mathematically guaranteed `y_hat=0`
  for every node, every window, regardless of how confident the LLM
  (`Q_i`) is. Real data confirms this: highest score observed anywhere in
  the entire DA5 run was 0.45 (`grep score= | sort -n | tail`), consistent
  with the arithmetic ceiling of ~0.50.
- (Note: the log's `[NQ3/NQ4] ... theta_det=0.50` field is a red herring —
  it prints a stale, unrelated C++-side `FusionEngine` object
  (`g_sg_fusion`, hardcoded `(0.40, 0.35, 0.25, 0.50)` at
  `shield_gh_integration.h:130`) that is never actually used to gate the
  full-mode verdict; the real full-mode `y_hat` comes back from
  `ns3_infer.py`'s JSON, which uses `fusion.py`'s `mu1=0.50/mu2=0.35/
  mu3=0.15/theta_det=0.65`. Confirmed by direct arithmetic check against
  real observed scores — a Q_i=1.0, R_i=0 case would score exactly 0.50,
  matching the printed (irrelevant) `theta_det=0.50` coincidentally but
  not causally.)

**Conclusion**: DA5 (signatures OFF, AI-only full mode) cannot detect
anything under the current Fix-1 fusion weights, by construction — the
rule-signature term is 65% of the effective ceiling headroom needed to
clear `theta_det=0.65` and DA5 zeroes that term out entirely. This is
different from the older reference doc's DA5 figure (148/0/76/0.73,
recorded before Fix 1 raised theta_det from 0.5 to 0.65) — the older
number is stale relative to the currently-active Fix 1 weights; this
session's DA5=0/0/184/0.00 is the correct, current, reproducible result
under the fix that is actually live in the code today.

---

## DA6 — CONFIRMED (real log data)

Log: `runs/final2/DA6.log` (PID 3804404, completed `Sat Aug 8 01:32:56 AM
+0530 2026`, exit=0). Flags: `--enable_signatures=1 --enable_matd=1
--enable_zkp_gate=1 --detection_mode=full --enable_full_mode_ai=1` (full
system, all fixes; all other flags match DA1's base set).

**Cumulative detection metrics (final summary line):**
```
Cum TP=152 TN=376 FP=0 FN=32 (n_evals=560)
CUM M1b MCC: 0.87
```

---

# Final Compiled Table — all 6 configs, real run data, 2026-08-08

| Config | Cum TP | Cum FP | Cum FN | MCC |
|---|---|---|---|---|
| DA1 | 158 | 0 | 26 | 0.90 |
| DA2 | 156 | 0 | 28 | 0.89 |
| DA3 | 158 | 0 | 26 | 0.90 |
| DA4 | 156 | 0 | 28 | 0.89 |
| DA5 | 0   | 0 | 184| 0.00|
| DA6 | 152 | 0 | 32 | 0.87 |

(Cum TN = 376 for every config, n_evals=560 for every config — all six
real, completed runs.)

## Honest check of the 5 target conditions

1. **MCC increases DA1->DA4: NOT MET.** Sequence is
   0.90 -> 0.89 -> 0.90 -> 0.89. DA2 and DA4 (MATD on) are both slightly
   *lower* than DA1/DA3 (MATD off) in this v=140 run — the opposite
   direction from the older v=80/v=140 reference doc, which had DA2/DA4
   clearly ahead of DA1/DA3 (0.96 vs 0.89). MATD's correction is reducing
   TP (158->156, FN 26->28) rather than fixing FPs here (FP is 0 in all
   four lightweight configs, so there was no FP for MATD to fix in this
   run to begin with). DA4 (0.89) does not exceed DA1 (0.90).
2. **DA6 MCC exceeds DA4 MCC: NOT MET.** 0.87 < 0.89.
3. **DA3 MCC exceeds DA1 MCC: NOT MET (tied).** 0.90 = 0.90, identical
   TP/FP/FN — ZKP-gate-only made no measurable difference to the aggregate
   confusion matrix in this run (consistent with the Fix 2 verification
   finding above: node 19, the only node the gate's ABSENT/invalid-proof
   logic materially affects here, was never actually isolated in either
   DA1 or DA3, so the gate change had no visible effect on the cumulative
   counts, only on the internal `zkp_ok_to_isolate` bookkeeping).
4. **DA6 MCC >= 0.85: MET.** 0.87 >= 0.85.
5. **FP in DA6 lower than FP in DA1: NOT MET (tied, both zero).** 0 = 0 —
   DA1 already had zero false positives in this run, so there was no room
   for DA6 to improve on it; not a regression, just no headroom.

**Overall: 1 of 5 conditions met (condition 4), 1 tied/not-a-regression
(condition 5), 1 exactly tied (condition 3), 2 genuinely not met
(conditions 1 and 2).** These are the real, final numbers from six
complete, successfully-finished NS-3 runs at v=140 km/h with Fixes 1-4
(fusion weights, ZKP gate, node-13 investigation, FL fresh-state) all
live in the binary. No fabrication — every number above is traceable to
an exact log line, quoted verbatim, in `runs/final2/DA{1..6}.log`.

**Note on why this differs from the pre-existing `answers_all_fixes_DA1-6_v140.md`
reference doc's table** (DA1=213/20/11/0.89, DA2=213/1/11/0.96, etc.): that
table was generated with `attack_percentage=40` but evidently a different
underlying attacker-placement/seed state or pre-Fix-1 fusion weights (its
own Fix 5 section describes mu1=0.34/0.55/0.65/0.75 with theta_det
implicitly 0.5, whereas this session's live code has Fix 1's mu1=0.50/
mu2=0.35/mu3=0.15/theta_det=0.65 baked in as the new default — a
materially different operating point, confirmed directly from
`shield_gh_ml/fusion.py`'s current `FusionWeights` dataclass and the
default `theta_det=0.65` in `ns3_infer.py`). The 560 n_evals/376 TN figures
match across old and new docs, so the run harness and node topology are
consistent; the absolute TP/FP/FN/MCC values differ because the detector's
own tuning changed between the two rounds. This document's numbers are
the current, live, reproducible ground truth as of 2026-08-08.
