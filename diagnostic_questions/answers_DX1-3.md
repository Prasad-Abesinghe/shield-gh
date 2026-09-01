# DX1-3 Diagnostic Findings

All numbers below are pulled directly from the real fresh log files:
- `runs/v140_fresh/DA4.log` (lightweight ablation, no full-mode AI)
- `runs/v140_fresh/DA6.log` (full system, `enable_full_mode_ai=1`)

Source code references are to `shield_gh/shield_gh_integration.h` and `routing.cc`
in this repo (`scratch/`), at the line numbers current as of this analysis.

---

## DX1 — Does the ZKP gate have a discrete "proof-fail" path that could itself
produce false positives?

**Finding (carried forward from earlier in this chain — confirmed, not
re-derived here):** ZKP has no discrete proof-result concept anywhere in the
codebase. There is no `zkp_proof`/PASS/FAIL symbol that gates detection
independently — the "ZKP gate" (`GenerateProof`/`StoreProof`/
`RecordZKPResult`, `shield_gh_integration.h` ~lines 667-684) is purely a
threshold check on cumulative received/forwarded counters
(`g_sg_zkp_cum_received[n]` vs `g_sg_zkp_cum_forwarded[n]`), consumed later as
one input into the DEBSC suspicion-tier/statistical-gate logic. DA3's 20 FPs
were traced entirely to node 19's signature layer (S1-S3); DEBSC/ZKP was never
invoked for those specific FP windows (DA3 disables ZKP — that's what DA3
ablates).

**Root cause (plain English):** The ZKP gate has no proof-fail state of its
own — it cannot manufacture a false positive by itself. DA3's false positives
come entirely from the rule-signature layer, not from ZKP miscounting.

---

## DX2 — Is DA6's extra FP burden (28 vs DA4's 1) coming from LLM
overconfidence (high Q_i) or signature over-firing (high S_total)?

### Real data pulled from the logs

**DA6 (full mode) `[DX2]` / `[DX2-full]` — all FP instances found (only node
19 ever appears in either print):**

```
[DX2]      node=19 t=29.00  S_total=1.00  R_i=0.33 score=0.87 y_hat=1   (10 occurrences total, all node 19)
[DX2-full] node=19 t=1.998  is_real=0 Q_i=0.868 S_total=1.000 score=0.884 y_hat=1
[DX2-full] node=19 t=3.998  is_real=0 Q_i=0.885 S_total=1.000 score=0.907 y_hat=1
[DX2-full] node=19 t=8.00   is_real=0 Q_i=0.88  S_total=1.00  score=0.91  y_hat=1
[DX2-full] node=19 t=8.998  is_real=0 Q_i=0.885 S_total=1.000 score=0.917 y_hat=1
[DX2-full] node=19 t=9.998  is_real=0 Q_i=0.882 S_total=1.000 score=0.918 y_hat=1
[DX2-full] node=19 t=12.998 is_real=0 Q_i=0.086 S_total=1.000 score=0.767 y_hat=1
[DX2-full] node=19 t=17.998 is_real=0 Q_i=0.086 S_total=1.000 score=0.767 y_hat=1
[DX2-full] node=19 t=20.00  is_real=0 Q_i=0.08  S_total=1.00  score=0.77  y_hat=1
[DX2-full] node=19 t=23.998 is_real=0 Q_i=0.075 S_total=1.000 score=0.765 y_hat=1
[DX2-full] node=19 t=28.998 is_real=0 Q_i=0.075 S_total=1.000 score=0.765 y_hat=1
```

10 `[DX2-full]` false-flag instances total, all node 19. **`S_total=1.000` in
every single instance, with no exception.** `Q_i` is NOT uniformly low as
first suspected: the first 5 windows (t=1.998–9.998) actually show HIGH Q_i
(0.868–0.885 — the LLM agrees the node is suspicious), and only the last 5
windows (t=12.998–28.998) show low Q_i (0.075–0.086 — the LLM disagrees). In
every one of the 10 cases, regardless of what Q_i does, `S_total` is pinned
at its maximum (1.000) and the fused verdict is `y_hat=1`.

### The 18-vs-28 reconciliation (resolved, not left open)

Prior instance flagged: run-summary total `sg_cum_FP=28` (log line 26636,
`Cum TP=213 TN=308 FP=28 FN=11`) vs. `[RQ5/RQ8]` per-node sum = 18 (node 19
only; every other node 0-18 shows `cum_FP=0`). **This is fully reconciled —
it is a genuine code inconsistency, not a data error:**

- Three separate call sites increment the FP counters in
  `shield_gh_integration.h`:
  - **Line 661** (`rcv==0` early-continue / lightweight-fallback path):
    increments `sg_cum_FP` **and** `g_sg_node_cum_fp[n]`.
  - **Line 1075** (lightweight-mode branch, only reachable when
    `enable_full_mode_ai==0`): increments both counters too — but DA6 runs
    with `enable_full_mode_ai=1`, so this branch never executes in DA6.
  - **Line 1321** (full-mode AI/fusion-verdict branch, the one actually
    active for DA6's rcv>0 windows): increments `sg_cum_FP` **only** —
    it does **not** increment `g_sg_node_cum_fp[v.node]`. This looks like an
    oversight relative to lines 661/1075.
- Node 19 has 28 total evaluated windows in DA6 (window 0-27, confirmed via
  `[PQ1] node=19 window=...` entries spanning t=1.998 to t=29.00). Of those,
  exactly 10 have `rcv>0` (confirmed: `[NQ5] node=19` — gated on `rcv>0` —
  appears exactly 10 times, matching the 10 `[DX2-full]` prints 1:1). The
  remaining 18 windows have `rcv==0` and fall through to line 661's fallback.
- **10 windows** go through line 1321 (AI path): `sg_cum_FP` +10, but
  `g_sg_node_cum_fp[19]` **not** incremented.
- **18 windows** go through line 661 (rcv==0 fallback): `sg_cum_FP` +18
  **and** `g_sg_node_cum_fp[19]` +18.
- Total: `sg_cum_FP` = 10 + 18 = **28** (matches the run summary exactly).
  `g_sg_node_cum_fp[19]` = **18 only** (matches `[RQ5/RQ8]` exactly).

**Conclusion: both numbers are internally correct given what each counter
actually measures — they are just not the same counter.** `sg_cum_FP`/28 is
the true total false-positive count for the run. `g_sg_node_cum_fp`/18 (and
by extension the `[RQ5/RQ8]` per-node table) silently under-reports FPs that
originate from the full-mode AI/fusion verdict path, because line 1321 omits
the per-node map update that lines 661 and 1075 both perform. This is a
**reporting/instrumentation gap, not a detection-logic bug** — worth flagging
to the supervisor as something to fix in the per-node bookkeeping (not
touched here per the no-fixes constraint), because any per-node FP analysis
drawn from `[RQ5/RQ8]` alone will undercount full-mode AI-path FPs.

### Answer to the supervisor's question

**S_total (signature layer) is the consistent driver, not Q_i (LLM
confidence).** `S_total=1.00` (maximum) in all 10 AI-path FP windows and all
10 lightweight-print FP windows — never varies. `Q_i` swings from very high
(0.87-0.89) to very low (0.075-0.086) across the same FP node without
changing the outcome. Since the fused score stays high enough to cross
`theta_det` in both the high-Q_i and low-Q_i cases, the signature signal
(`S_total`) is what's actually pinning the verdict at `y_hat=1` — the LLM's
assessment (Q_i) doesn't override it either way. The extra FP burden in DA6
vs DA4 is a signature/fusion-weighting issue, not an LLM-overconfidence issue.

### DA4's 1 FP (ablation baseline, lightweight-only, no AI/fusion path)

```
[DX2] node=19 t=1.99801 S_total=1 R_i=0.6 score=0.76 y_hat=1
```

DA4 log confirms lightweight mode only (0 `[DX2-full]` lines, 0 "full-mode:
dumped" lines). `sg_cum_FP=1` (log line 25912: `Cum TP=213 TN=335 FP=1
FN=11`) matches `sum([RQ5/RQ8] cum_FP)=1` exactly (node 19 only) — no
reconciliation gap in DA4, because DA4 never exercises the line-1321 AI path
that causes the DA6 gap. Same node (19), same `S_total=1` maximal-signature
signature, single window (t=1.998). This is the direct signature-only
analogue of DA6's node-19 FPs — same root trigger (signature saturation),
just without the AI/fusion path adding 10 more evaluated windows on top of
it.

---

## DX3 — `[DX3-rcv0fallback]` (real attacker nodes hitting the rcv==0
fallback) — concentration check

Gated on `gt_attacker==true` (`shield_gh_integration.h` line 655) — this is
about real attacker nodes going silent (no received traffic that window) and
falling back to the last signature-only verdict instead of reaching the
AI/fusion path. Separate question from DX2 (which is about legitimate node
19 being falsely flagged).

**DA6: 49 total `[DX3-rcv0fallback]` lines**, spanning window 0 through
window 27 (t=1.998 to t=29.00) — i.e., present in nearly every window of the
run, not a one-off. Per-node breakdown:

| node | count |
|------|-------|
| 13   | 26    |
| 10   | 9     |
| 12   | 5     |
| 9    | 4     |
| 8    | 3     |
| 11   | 1     |
| 14   | 1     |

**Concentrated, not spread evenly: node 13 alone accounts for 26/49 (53%)**
of all rcv==0 fallback events, and appears in almost every window from 0
through 27. The remaining 23 events are spread thinly across 6 other attacker
nodes (1-9 occurrences each). Node 13 is also the node with the run's only
FN burden (`[RQ5/RQ8] node=13 cum_TP=17 cum_FN=11` in both DA4 and DA6) — its
near-constant rcv==0 state (traffic essentially stops reaching it, dropping
straight to the fallback path every window) is consistent with it being the
node whose detections are most often missed, since the fallback path can only
repeat its last known verdict rather than re-evaluate fresh signature/AI
evidence.

**DA4 (lightweight ablation), for comparison:** 46 total
`[DX3-rcv0fallback]` lines, nearly identical distribution (node 13: 26 of 46
= 57%; nodes 8,9,10,11,12,14 making up the rest) — confirming this is a
structural property of the topology/traffic pattern (node 13 going quiet),
not something introduced by the AI/fusion path.

**Root cause (plain English):** One attacker node (node 13) is responsible
for over half of all rcv==0 fallback events across both DA4 and DA6, because
it genuinely stops receiving traffic in most windows of the run — this
concentrates the run's only FN burden on a single node whose silence forces
the detector to keep repeating a stale verdict instead of re-evaluating.

---

## Files referenced

- `/home/sdvn_ssh/ns-allinone-3.35/ns-3.35/62/scratch/shield_gh/shield_gh_integration.h`
  (lines 643-665, 1022-1078, 1279-1391 — the three FP-increment sites and the
  DX2/DX2-full/DX3 debug prints)
- `/home/sdvn_ssh/ns-allinone-3.35/ns-3.35/62/scratch/routing.cc`
  (line 117404-117427 `print_shield_gh_detection_metrics`, line 117463-117474
  `[RQ5/RQ8]` per-node print)
- Fresh logs analyzed (this session's scratchpad):
  `runs/v140_fresh/DA4.log`, `runs/v140_fresh/DA6.log`
