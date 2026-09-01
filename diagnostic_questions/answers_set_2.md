# Answers to 60 Diagnostic Questions + Actions 1-3

**Status: Categories C and D fully answered with evidence. Categories A and B answered
as far as real evidence supports; items still needing a dedicated run are marked
explicitly rather than guessed at. Four real bugs found and fixed this session — see
below — which changed the numbers mid-investigation; all figures here are from the
final, most-corrected build unless a section says otherwise.**

---

## Four bugs found and fixed this session (read this first — it explains why numbers moved)

### Bug 1 — Topology had zero redundant paths (Action 1)
The mobility scenario's connectivity graph is a pure chain (zero redundancy) for
the first third of node IDs and a genuine 2-row mesh (real alternate paths via
cross-links) for the rest — confirmed deterministic, not random per-run. Flow
source/destination placement (`routing.cc`, `routing_test==true` block) was
redesigned to land in the meshed region. This also surfaced a logic bug in the
route-check itself: `ALT_ROUTE_EXISTS_ANY_FLOW()` was requiring nodes to have
"an alternate route excluding themselves" for flows where they're the
source/destination — a contradiction that always evaluates false. Fixed: only
intermediate-relay membership blocks isolation now, not endpoint membership.

### Bug 2 — AI bridge hang (blocked DA5/DA6)
Traced via `strace` to `shield_gh_integration.h`: `w.per_src[f] = {ff, fr - ff}`
computed in unsigned arithmetic. When `ff > fr` (forwarded count exceeds
received — happens in practice), this underflows to `4294967295`. The Python
bridge's tokenizer does `for _ in range(drp)`, turning that into a
runaway-memory-allocation loop (confirmed: single thread doing continuous 1MB
`mmap` calls until killed). Fixed with a clamp. (Also fixed a secondary,
non-root-cause issue: the fallback LLM classifier was retraining 200 epochs
from scratch on every window instead of 3.)

### Bug 3 — Reputation never consulted MATD or ZKP (the real Problem-1 cause)
`BlockchainLedger::ComputeReputation()` — the function that drives the actual
isolation decision via `DEBSC::ShouldIsolate()`/`ComputeSuspicionLevel()` —
computed trust from raw forwarding counts only. It has an existing comment
admitting this ("MATD correction applied by caller") but no caller ever did
that, even though the report's own Eq. 3.18 specifies reputation should
average `T_mob_i` (MATD-decayed trust, Eq. 3.17). MATD's correction and the
ZKP-gate result only ever reached the separate confusion-matrix path
(`S_total`/`flagged`), never the isolation path. Fixed: added
`DEBSC::RecordMobilityDecay()` + `DecayedReputation()`; the caller now records
each window's decay ratio. **Verified via debug trace**: `decay_ratio=0.8007`
at speed=22.2 m/s — the wiring is genuinely connected end-to-end now.

### Bug 4 — `mesh_start` off-by-one
`mesh_start = N_Vehicles/3` landed exactly ON the chain/mesh boundary, not past
it — confirmed via a real baseline run where flow 0 (6→9) got **zero** stable
paths for the entire run, even with 0 attackers. Node 6 is still chain-only;
the mesh genuinely starts at node 7. Fixed: `mesh_start = N_Vehicles/3 + 1`.
This alone raised DA1's TP from 2→4 and the 0-attacker baseline PDR from ~43%
to 68-100% (see B1 below).

---

## Action 1/2/3 status

- **Action 1 (redundant-path topology)**: done, verified (bugs 1 and 4 above).
  Real isolation now fires (hundreds of events per run, vs. 0 in every run
  before this session).
- **Action 2 (Q-new9/N=200)**: already reported complete in an earlier
  exchange — N=200 does not crash but cannot complete a Gurobi solve in
  practical time (measured: 15m29s for one solve, standalone).
- **Action 3 (60 questions)**: this document.

---

## Category A — MCC Monotonicity

**A1.** DA1 FN node IDs vs zero-traffic node IDs.
Ground truth: attackers are nodes 0-11 (12 forced sequentially). Of those,
nodes 0-5 show `Dropped=0 Forwarded=0` in every run (confirmed in
`repfix_DA1.log`, `v2_DA1.log`) — genuinely zero traffic, structurally
unreachable by any flow at this attacker/flow configuration. Nodes 7-11 do
carry real traffic. Post-bug-4-fix, TP=4 (up from 2), meaning more of the
traffic-carrying attacker nodes are now correctly flagged, but FN=8 remains —
some FN nodes are the zero-traffic ones (unreachable, can never be flagged
regardless of detection quality) and some are traffic-carrying nodes the
signatures still miss. **Precise per-node TP/FN node-ID list not printed by
the current code** (the confusion matrix is a per-window aggregate count, not
a labeled node list — see C15 finding below); would need a small print added
to confirm the exact split.

**A2.** corrPDR values for attacker nodes, DA1.
From `[LW-DP-Det]` debug lines (real run data): observed corrPDR values for
traffic-carrying attacker nodes at drop_rate=60 range roughly 0.0-0.58 —
**consistently below** τ_f=0.60, not above it. So the "paradoxically above
threshold" failure mode this question hypothesizes does not occur in this
data; attackers dropping 60% of packets do show correspondingly low PDR. The
FN nodes are FN because they carry no traffic at all (A1), not because their
PDR reads artificially high.

**A3.** DA5 (LLM-only) vs DA1 (signatures) — same or different nodes detected?
DA5's isolation log shows node 9 isolated; DA5's traffic-carrying attacker set
(7,8,9,10) overlaps with DA1's. Both pipelines are detecting from the same
small pool of traffic-carrying nodes (7-11), not disjoint sets — so the
"fusion should produce 10 TP" scenario the question describes does not apply
here; there aren't 10 independently-detectable attackers to begin with, only
~5 ever carry traffic.

**A4.** DA6 fusion terms for FN nodes at final window.
**Not fully answered — needs a dedicated print.** Category C's C3 finding is
directly relevant: `Q_i` and `(1-R_i)` are confirmed non-zero and contributing
for TP nodes (Q_i≈0.85-0.88), but the exact per-FN-node weighted-sum margin
against θ_det was not captured this session. Recommend a follow-up run with a
print of all three fusion terms for the FN set specifically.

**A5.** attack_percentage=20, drop_rate=60.
**Not run this session** — flagged for follow-up rather than estimated.

**A6.** drop_rate=20 vs 60 (same attacker count).
Run directly: at drop_rate=20 (pre-bug-4-fix topology), MCC and TP/TN/FP/FN
were identical to drop_rate=60 (TP=2/TN=8/FP=0/FN=10 both). Isolation *count*
did differ (64 vs 123), meaning MATD/timing effects are real but don't flip
the final classification at either drop rate in this configuration. This
was re-confirmed independently by the reputation-path debug trace (Bug 3):
the ~20% MATD correction is real but too small to cross the isolation
threshold at either 20% or 60% drop rate for these specific nodes — so
τ_f=0.60 itself is not obviously the problem; the attacker nodes' raw PDR is
already far enough below threshold that a 20% relative correction doesn't
matter either way.

**A7.** DA6 Q_i for FN nodes across windows.
**Not fully answered.** C3 confirms Q_i is non-zero for TP nodes generally;
a dedicated per-FN-node time series was not captured. Follow-up needed.

**A8.** Confirm Q_i=0 in DA1 (signatures-only, LLM off).
By construction: DA1 uses `--detection_mode=lightweight` (no
`--enable_full_mode_ai`), so `ns3_infer.py`/the LLM scorer is never invoked at
all in DA1 — there is no code path that could produce a non-zero Q_i, since
the full-mode AI block (`shield_gh_integration.h`, gated on
`enable_full_mode_ai==1`) is not entered. Confirmed by absence: no
`[SHIELD-GH][AI]` log lines appear anywhere in `v2_DA1.log`.

**A9.** Confirm S_total=0 in DA5 (LLM-only, signatures off).
By construction: DA5 passes `--enable_signatures=0`, which (per this
session's earlier fix) skips the `LW_DP_Det()` call entirely, leaving
`s1=s2=s3=false` and therefore `S_total` computed from the `else` branch
(`corr_pdr < 0.6 ? 0.5 : 0.0`) — **not hard-zero**, but not signature-driven
either. This is worth flagging precisely: DA5 is not a *pure* LLM-only
baseline; `S_total` can still be 0.5 from the PDR-fallback term even with
signatures disabled. A stricter ablation would need to also zero that
fallback when `enable_signatures=0`.

**A10.** DA4 at simTime=120, MCC at t=30/60/90/120.
**Not run this session** (each 30s run already takes ~9 minutes wall-clock at
N=20 with Gurobi; 120s would take proportionally longer). Flagged for
follow-up with a longer time budget.

**A11.** R_i(t) for FN nodes at windows 3/6/9/12.
Directly relevant finding from Category C (C8): reputation is confirmed
**not monotonically decreasing** for a real attacker node even with continuous
drops — it drops slightly then plateaus (0.83→0.73→0.75→0.74 across windows
0/5/10/17), because `ComputeReputation()` averages over the node's *entire
history since t=0* (no rolling window), so early clean windows permanently
dilute the average. This is a genuine, precise answer to A11's underlying
concern: reputation is being fed detection events, but the unwindowed average
makes it respond far more slowly than intended.

**A12.** DA1 vs DA2 FP count; attack_percentage=60/drop_rate=0 test.
FP=0 in both DA1 and DA2 in every run this session — confirmed directly.
Per the question's own logic, this means there's nothing for MATD to visibly
suppress in this metric. The suggested drop_rate=0 test (attackers present,
not dropping) was not run this session — flagged for follow-up, since it's
specifically designed to surface false positives MATD could then suppress.

**A13.** DA3 ZKP gate evaluation count vs route-gate bypass count.
Answered precisely in Category C, C1: the gate order is statistical → ZKP →
route-availability → final decision, confirmed via code trace and log
evidence (`ShouldIsolate()` in `debsc.cc` evaluates both gates before
`shield_gh_integration.h` checks route availability). The ZKP gate **is**
reached whenever suspicion crosses the lambda2 tier, so it is not dead code
in this topology — it's evaluated, just not always the final blocking factor.

**A14.** FL weight-norm at window 1 vs 10, DA5/DA6.
Answered decisively in Category C, C6: **FL never runs during a live NS-3
simulation at all.** The bridge script never imports `federated.py`; the
"LLM+FL" model is actually a plain classifier re-trained from scratch on a
static offline dataset every single window, not a federated model with
evolving weights. There is no weight norm to compare — confirming the
question's suspicion in the strongest possible form.

**A15.** FL per-class accuracy on training data, DA6.
Not directly measured live (consistent with A14 — no live FL to measure).
The offline evidence harness (`gen_evidence.py`) does have this data in
principle but it's a separate, disconnected artifact from any live DA6 run.

---

## Category B — PDR Root Cause

**B1.** N=20, 0 attackers, 0 drops, PDR over time.
Re-run after Bug 4's fix: PDR starts at 100%, degrades to ~68-95% and appears
to be stabilizing in that range by t=17-20s (run did not fully reach t=60s in
the available wall-clock budget — was at t=17/20 when captured). This is a
dramatic improvement over the pre-fix baseline (~43% and still declining) —
directly resolves the worst part of Problem 2's premise ("PDR should be ~92%
with 0 attackers, not 3-9%"): the true clean-baseline PDR is now in the
high-60s to high-90s range depending on how long the run continues, not
single digits. A full 60s run to confirm final convergence was started but
not completed this session (see D15's note on the same run).

**B2.** N=20, attack_percentage=60, drop_rate=0.
**Not run separately post-Bug-4-fix.** Given B1's improvement, this should be
re-run to see if attacker *designation* alone (without dropping) now also
tracks close to B1, but wasn't captured this session.

**B3.** Breakdown of drop causes (attack logic / MAC collision / no-next-hop).
**Not instrumented.** No existing code path separately counts these three
categories — would need new counters added to distinguish
`should_drop_grey_hole()`-caused drops from NS-3 MAC-layer retry exhaustion
from routing-failure (no valid next hop). Flagged as real follow-up work,
not answered from existing logs.

**B4/B5.** Per-flow PDR and Gurobi INFEASIBLE fraction.
Answered precisely in Category D (D1, D3): only 4 flows exist, not 6 (`flows
= 2` constant, so `2*flows=4`). Flow 0 (6→9, pre-fix) or its equivalent
post-fix needs re-checking, but the broader finding stands: `optimization_lifetime.py`
never checks Gurobi's solve status at all (`m.Status` is never read) — there
is no INFEASIBLE-fraction counter in the code, so this cannot be answered
numerically without adding that instrumentation. What is confirmed: pairs
beyond `d_max=270m` are short-circuited to lifetime=0 without ever calling
Gurobi, and no "AttributeError" (the only visible failure signature) appeared
in any log checked.

**B6.** Routing table for node 0 at t=5s.
Not directly printable — see D8: no standalone/isolated way to query the
path-finder's routing table; would need new instrumentation to dump `conn[]`
per node.

**B7.** Per-link success rate, 0 attackers.
Not separately instrumented at the individual-link level; only aggregate
per-node RelayPDR is currently logged (see D9).

**B8.** Offered load vs DSRC channel capacity.
Not computed this session — would need the packet generation rate (known:
`data_transmission_period` defaults to 1.0s) cross-referenced against NS-3's
configured WiFi/DSRC PHY rate, not done here.

**B9.** Timestamp of first successful delivery, DA1.
Not specifically extracted this session; would need a targeted log grep on a
fresh run.

**B10.** Geographic distance vs 3×270m=810m limit, post-Fix-A.
Answered precisely in Category D (D2, D5): flow endpoints 6→9 (1187m,
pre-off-by-one-fix numbering) and 7→10 (600m) are both **far beyond** the
810m 3-hop budget under the `d_max=270` model — confirming these flows
structurally require more than 3 hops or fail. Average inter-node distance
across the topology: 718.6m; nearest-neighbor average: 200m (matches the
270m per-hop range reasonably, but only for adjacent grid nodes).

**B11.** Original 2 flows vs Fix-A's new flows, PDR comparison.
Superseded by the fact that the "original" hardcoded (0,3) pair no longer
exists in the code at all post-Fix-A — there's no longer a control group to
compare against without reverting the fix. Not applicable as originally
framed.

**B12.** Does traffic reroute after detection, DA6?
Not directly observed this session. The isolation mechanism
(`should_drop_grey_hole` gated on `shield_gh_isolated_nodes[]`) blocks
traffic *at* the isolated node but does not trigger a route recomputation
around it — confirmed indirectly by D10 (no reactive route recomputation
mechanism exists at all; routes are purely proactive on a fixed 1s interval).
So the honest answer is: isolation stops packets flowing INTO the blocked
node, but per D10/D12, nothing forces an immediate reroute — the next
scheduled Gurobi solve (up to 1s later) would need to happen to pick a new
path, and there's no guarantee it picks one avoiding the isolated node
specifically.

**B13.** Gurobi solve count in a 30s run + staleness estimate.
Confirmed: ~28-30 solves in a 30s run (one per simulated second, per D3's
"28 delay lines" observation and the `data_transmission_period=1.0` default).
Staleness formula not computed numerically this session.

**B14.** B1 at simTime=300.
Not run — B1 itself (simTime=20-60) already took most of the available
budget this session; a 300s run would take proportionally longer given the
per-second Gurobi solve pattern. Flagged for follow-up.

**B15.** NS-3 propagation model.
Answered in Category D (D2): `Cost231PropagationLossModel` with
`RxSensitivity=-105dBm` — a probabilistic/path-loss model, not a binary
constant-range cutoff. This means the question's concern is valid in
principle (probabilistic per-hop success, compounding over multi-hop routes)
but the exact per-hop success probability at the actual node spacing (200m)
was not computed numerically this session.

---

## Category C — Component Wiring Deep Verification

**Full answers (C1-C15) below, produced from direct code tracing, log
evidence, and a small number of short targeted runs. No new code changes
were made while answering these — this is investigation only.**

**C1.** Gate order in DA3 confirmed correct: statistical gate (`debsc.cc:34-50`
in `ShouldIsolate()`) → ZKP gate (only if `enable_zkp_gate=1`) → both combined
by AND → feeds `GetGraduatedResponse()` → route-availability gate
(`ALT_ROUTE_EXISTS_ANY_FLOW`) only checked if the DEBSC verdict is ISOLATE.
Log evidence: a withheld isolation shows `RATE-LIMITED | Λ=3` after the
route gate blocks it, confirming stages (a)+(b) fired before (c) blocked it.

**C2.** MATD's `CorrectPDR()` is designed to add back handoff loss (raw + ρ_ho,
capped at 1.0), so corrected ≥ raw is the code's contract. No run this
session printed ρ_ho and corrected-PDR side-by-side for 3 specific legitimate
(non-attacker) nodes unconditionally — the existing debug print only fires
when a signature actually triggers, which legitimate nodes rarely do. Needs
new unconditional instrumentation to fully confirm numerically for benign
nodes specifically.

**C3.** DA6 window 5: Q_i≈0.85-0.88 for attacker nodes, confirmed non-zero and
contributing (fused score ≈0.80-0.82, verdict=1). Reputation-deficit term
also confirmed non-zero and contributing in a separate CSV snapshot (S_total=0
in that window, yet fused score was still positive from reputation alone) —
i.e. multiple terms are demonstrably live, not just one dominating.

**C4.** Signatures and CP-detection both correctly use a genuine rolling W=10s
window (`ComputePDR`/`ComputePDRVariance` filter `timestamp >= t-W`). The LLM
tokenizer processes one window's worth of events per call (aligned in
cadence, not literally a 10s token history). **Reputation does not use W=10
at all** — it's unwindowed/cumulative since t=0 (`ComputeReputation()` only
filters `timestamp <= t`, no lower bound). This is a genuine, confirmed
misalignment between components.

**C5.** DA4 signature fire counts for the full run: S1=48, S2=36 (co-firing
with S1 in most cases), **S3=0, S4=0, S5=0, S6=0**. S3 never fires because its
strict pre-filter (≥2 flows with >0.5 PDR spread per node) is never satisfied
in this flow configuration. S4-S6 never fire because DA4's config doesn't
enable any controller-plane attack type — confirms this specific run
(correctly) has zero CP-attack coverage by design, not by a wiring failure,
though it does mean the framework's practical coverage in tested
configurations is currently S1/S2-only.

**C6.** FL is **not exercised at all** during any live run. `ns3_infer.py`
never imports `federated.py`. The only place FL's aggregator/hash-commitment
code is invoked is a standalone offline script (`gen_evidence.py`), entirely
disconnected from the NS-3 bridge. DA5/DA6's "LLM+FL" model is a plain
classifier re-fit from a static offline dataset on every single window call,
not a federated model with evolving weights.

**C7.** Confirmed: the LLM scorer receives a genuine token sequence (e.g.
`FWD:s0 DRP:s1`), not a raw numerical vector — `tokenise_window()` reconstructs
per-source forward/drop tokens from aggregate counts. Caveat: this is a
synthetic bag-of-repeated-tokens reconstruction from counts, not a true
per-packet chronological event log, so its "temporal reasoning" content is
limited even though the format is token-based.

**C8.** Confirmed not monotonically decreasing for a real attacker node
(0.83→0.73→0.75→0.74 across windows 0/5/10/17) — plateaus rather than
continuing to fall, consistent with the unwindowed-average root cause (C4).
Separately found: a `results/blockchain_log.csv` column (`is_real_attacker`)
disagrees with the console's ground-truth attacker tagging for the same
node in the same run — a real, reproducible data-consistency bug worth
fixing, not fully root-caused this session (the CSV was being actively
written by a concurrent run during investigation).

**C9.** The poison-rejection mechanism exists and is verified working
**offline** (5/5 poisoned gradients correctly rejected, MCC gap 0.747 vs
0.409 with/without the check) — but per C6, this mechanism never runs inside
a live DA6 simulation, so it cannot currently be tested "in DA6" as the
question asks without first wiring FL into the live bridge.

**C10.** DA4 (post all fixes): 123 total per-node evaluations, 21 isolation
attempts withheld by the route gate (nodes 7,8), 1 full isolation executed
(node 9). Route-availability gate remains the dominant constraint on full
isolation (21 withheld vs 1 executed) but is no longer 100%-blocking as it
was before Action 1.

**C11.** Not run as a synthetic single-pair test (would require a code
change, out of scope for pure investigation) — but effectively already
demonstrated as a natural experiment: pre-Action-1 (zero redundancy
anywhere), isolation never fired in any of dozens of runs; post-Action-1
(genuine redundancy for some nodes), isolation does fire for node 9 while
remaining withheld for nodes still lacking a redundant path. This is real
evidence the gate works correctly and topology, not gate logic, is the
constraint.

**C12.** Confirmed: ZKP proof generation (`CreateCommitment`/`GenerateProof`)
runs unconditionally for every node with `rcv>0` every window, before any
flagging decision — not gated on prior flags. This means the plumbing could
support a 3-state PASS/FAIL/ABSENT model, but the `ZKPProof` struct itself
still only has a `bool valid` field — no ABSENT state exists in the data
structure, so the earlier-known 2-state limitation stands.

**C13.** Zero FL aggregation rounds occur during any live NS-3 run (same root
cause as C6/C9) — the "5 rounds" the question anticipates is exclusively an
offline artifact with no connection to simulated time at all.

**C14.** The paper's specified new-vehicle probationary mode (Eq.
`eq:vehicle_mode`, main.tex) is **not implemented anywhere in the live C++
detection pipeline** — a repo-wide grep for "probation" in the detection code
returns zero matches (the only hit anywhere in the codebase is an unrelated
RSU-endorser-eligibility flag in a separate blockchain subsystem). This is a
specified-but-unimplemented feature, confirmed by absence, not a subtle bug.

**C15.** DA1's confusion-matrix definitions match the standard formula exactly
(verified in code). More importantly: discovered the printed TP/TN/FP/FN
values are reset to 0 at the top of every single evaluation window
(`shield_gh_integration.h`), meaning the "final" printed numbers reflect only
the **last window's** classification of all 20 nodes, not a run-wide/
cumulative tally as their presentation implies. This is a real finding
worth fixing or at minimum clearly relabeling.

---

## Category D — Routing Diagnostics

**D1.** Only 4 flows exist (`flows=2` constant → `2*flows=4`), not 6 as the
question assumes. Current placement touches 7 unique nodes out of 20.

**D2.** Exact node-by-node path per flow is not printed anywhere in the
current code (the relevant print is commented out). Confirmed via distance
calculation that some flow endpoint pairs are 600-1187m apart — far beyond
any single hop's range, requiring genuine multi-hop relay.

**D3.** No INFEASIBLE-fraction counter exists — `optimization_lifetime.py`
never checks Gurobi's solve status at all. Cannot be answered numerically
without adding that instrumentation. Out-of-range pairs are skipped before
ever calling Gurobi (not counted as solver failures).

**D4.** **The Gurobi objective has zero packet-delivery or capacity term** —
it purely maximizes a single kinematic "link lifetime" variable subject to a
distance constraint. Confirms the question's exact concern: a long-lived but
useless link can be selected as "optimal."

**D5.** Real position/distance data: average pairwise distance 718.6m,
nearest-neighbor average 200m, against the model's effective range of 270m —
network is sparse for anything beyond immediate neighbors.

**D6.** 87.1% of the link-lifetime matrix's off-diagonal entries are exactly
zero (unreachable under the model) — confirms a genuinely sparse routing
fabric before any attack.

**D7.** Cannot show decay for the specific flow examined because it never had
a path at all in the run checked (permanently 0 stable paths, not
decaying from nonzero) — a structural disconnection, not a mid-run
degradation effect.

**D8.** No standalone/isolated harness exists to time the path-finder in
isolation — would need new test-mode instrumentation. From normal runs,
`.paths` counts are in the tens, not millions, consistent with the earlier
`==`/`=` bugfix having resolved the exponential blowup, but this is not a
controlled, isolated measurement.

**D9.** Found a **dead counter**: `node_forwarded_count[]` is declared but
never incremented anywhere in the ~142k-line file — the "GREY HOLE DROP
SUMMARY" always prints `Forwarded=0` for every node regardless of actual
activity. The real signal (RelayPDR from the separate "Per Node PDR" block)
shows several nodes genuinely near-zero forwarding even with 0 attackers.

**D10.** **No reactive route recomputation exists.** Routes are purely
proactive on a fixed ~1s interval (tied to `data_transmission_period`); a
link failure between recomputes produces sustained 0% PDR on the affected
flow until the next scheduled solve.

**D11.** Cannot print actual selected hop counts (same missing instrumentation
as D2/D8). Geometry suggests some flows require significantly more than 3
hops given the confirmed endpoint distances.

**D12.** **No minimum-lifetime constraint exists** in the Gurobi model — `l`'s
only bound is `≥0`, so Gurobi can select a path that's about to expire as
"optimal" with nothing preventing it.

**D13.** Real N=8 data gathered this session: 0 attackers/0 drops still shows
some 0%-PDR nodes even with a clean network (a real anomaly, not
attack-driven); 50% attackers/50% drops gives MCC=0.38 with all node
deliveries collapsing to 0%. Degradation is visible at N=8, not something
that first appears at N=20.

**D14.** Cannot directly compare a flow against its reverse (none of the 4
active flows is the mirror of another). The underlying link-lifetime matrix
is confirmed symmetric by construction, but the path-finding DFS runs
independently per flow with no shared/reverse-flow state — nothing in the
code guarantees symmetric route selection even over a symmetric graph.

**D15.** No clean post-fix 60s/0-attacker run completed within this session's
time budget (in progress at time of writing, reached ~t=20/60s). The
available pre-fix reference data was noisy near-zero throughout with no
clear convergence/stable/degradation phases — should not be used to choose
simTime; needs a completed post-fix run.

---

## Summary for the go/no-go decision

**Fixed, verified, real improvements:**
- Isolation now genuinely fires (was 0 in every run before this session)
- 0-attacker baseline PDR: ~43% → 68-100% (Bug 4 fix)
- DA1 TP: 2 → 4 (Bug 4 fix)
- MATD and ZKP gate are now genuinely wired into the isolation decision
  (verified via debug trace), not just the confusion-matrix path

**Still open, honestly reported rather than fixed or hidden:**
- MCC still doesn't strictly increase DA1→DA4 at drop_rate=60 — confirmed
  *not* a wiring bug (both components demonstrably reach the decision path
  now) but a real "operating point" effect: the correction magnitude is too
  small relative to how far below threshold these specific attacker nodes'
  raw PDR already sits at this attack intensity
- PDR under attack is still low (~7-9% at drop_rate=60) even after all
  fixes — attack damage plus the confirmed-sparse routing fabric (87% zero
  link-lifetime entries) plus the Gurobi model's total disregard for
  packet-delivery capacity are all real, independent contributing factors
- Several newly-found gaps are real and unfixed: unwindowed reputation
  averaging, per-window (not cumulative) confusion-matrix reporting, FL/
  gradient-integrity never running live, no ABSENT ZKP state, no
  probationary-mode implementation, no minimum-lifetime routing constraint,
  a dead forwarding counter, and a ground-truth-label CSV inconsistency

**Not yet run (flagged, not guessed at):** A4, A5, A7, A10, A14/A15
(numerically), B2, B3, B6-B9, B13 (numeric staleness), B14, D15 (completion).
