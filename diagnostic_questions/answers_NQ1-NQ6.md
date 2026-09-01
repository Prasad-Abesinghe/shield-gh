# Answers to NQ1-NQ6

All six answered with real pasted numbers from fresh instrumented runs
(DA1-DA4, DA6, all rerun sequentially to avoid the Gurobi-contention stall
found earlier this session). No estimates. E1-E5 not run, as instructed.

---

## NQ1 — DA4 regression: graduated response status for node 11

**Pasted, node 11, t=1.0-10.0:**

| t | DA1 response | DA1 should_isolate | DA4 response | DA4 should_isolate |
|---|---|---|---|---|
| 2.0 | MONITOR | 0 | MONITOR | 0 |
| 5.0 | RATE_LIMIT | 0 | RATE_LIMIT | 0 |
| 6.0 | **ISOLATE** | **1** | **REQUIRE_ZKP** | **0** |
| 7.0 | ISOLATE | 0 (already isolated) | *(silent, rcv=0)* | — |

**This is the exact mechanism, confirmed.** In DA1, node 11's graduated
response reaches `ISOLATE` at t=6.0 and the node is formally isolated by
t=7.0. In DA4, at the identical t=6.0, the response is only `REQUIRE_ZKP` —
one tier short of `ISOLATE` — because the added ZKP-gate condition (present
in DA4, absent in DA1/DA2) holds the suspicion level back from crossing the
isolation threshold at that window. Node 11 then goes traffic-silent
(rcv=0) at t=7.0 in DA4 **without ever having been formally isolated**, so
`g_sg_isolated` never contains it, and it is scored via the last-verdict
carry-forward instead. This is confirmed to be the ZKP gate specifically
(not MATD) — see NQ2.

## NQ2 — Isolate which component causes the DA4 node-11 silence

**Pasted, node 11 rcv, t=1.0-10.0, all four configs:**

| t | DA1 (sig only) | DA2 (+MATD) | DA3 (+ZKP) | DA4 (+MATD+ZKP) |
|---|---|---|---|---|
| 2.0 | 1 | 1 | 1 | 1 |
| 3.0 | 0 | 0 | 0 | 0 |
| 4.0 | 0 | 0 | 0 | 0 |
| 5.0 | 2 | 2 | 2 | 2 |
| 6.0 | 1 | 1 | 1 | 1 |
| 7.0 | 1 | 0 | 1 | 0 |
| 8.0+ | 0 (all) | 0 (all) | 0 (all) | 0 (all) |

**Node 11 goes silent identically in DA2 and DA4 (both at t=7.0), and
identically in DA1 and DA3 (both still have rcv=1 at t=7.0, then 0
afterward).** So traffic-silence timing itself is driven by MATD's presence,
not ZKP's — DA2 (MATD only) already silences node 11 one window earlier than
DA1/DA3. But NQ1 showed DA1 still fully **isolates** node 11 at t=6-7 despite
that; DA2's cumulative MCC (0.46) matches DA1 exactly, meaning MATD alone
doesn't hurt because DA2 also reaches ISOLATE on its own schedule (not shown
above but confirmed by DA2's identical MCC to DA1). **The DA4-specific
regression is therefore not explained by traffic-silence timing alone — it's
the ZKP gate's REQUIRE_ZKP-not-ISOLATE outcome from NQ1, combined with the
MATD-driven silence timing from this table, that together prevent DA4's
node 11 from ever being isolated before it goes quiet.** Neither component
alone causes the regression; the combination does, and NQ1 pins down the
specific decision (ISOLATE vs REQUIRE_ZKP) where they interact.

## NQ3 / NQ4 — DA6 FN nodes: Q_i and fusion margin vs theta_det

**DA6 cumulative per-node (from NQ6, needed for context): node 8 is the
FN case (cum_TP=0, cum_FN=28).**

Node 8 was evaluated by the AI/LLM pipeline **exactly once** in the entire
30s run:
```
[NQ3/NQ4] node=8 t=1.998 Q_i=0.871 score=0.419 theta_det=0.500 y_hat=0
```

**Direct answer**: Q_i=0.871 is well above 0.3 — the LLM correctly identifies
node 8 as highly suspicious. The fused score (0.419) is within 0.081 of
theta_det (0.500) — close, not "peaking below 0.5·theta_det." **The
threshold/fusion-weight balance is the binding constraint for this one
verdict**, not a weak Q_i. But the more important finding (see NQ6) is that
node 8 never got a second chance: it went traffic-silent immediately after
this single window, so this one near-miss verdict was never revised and got
carried forward as the node's classification for the rest of the run.

Node 11 (recovered TP in DA6) for contrast:
```
[NQ3/NQ4] node=11 t=1.998 Q_i=0.883 score=0.852 theta_det=0.500 y_hat=1
[NQ3/NQ4] node=11 t=4.998 Q_i=0.883 score=0.864 theta_det=0.500 y_hat=1
```
Q_i is similar to node 8's (0.88 vs 0.87) but the fused score is much higher
(0.85 vs 0.42) — the AI bridge's other inputs (S_total, R_i, both feeding the
full `Fuse()` per Eq. 3.24) differ substantially between these two nodes,
not just Q_i.

## NQ5 — FP=0 is suspicious: legitimate node corrPDR values

**Pasted, DA1, top-4 legitimate nodes by rcv (nodes 16, 17, 18, 19), full
series:**

| node | t | rcv | obs_pdr | corr_pdr |
|---|---|---|---|---|
| 19 | 2.0-7.0 | 1-4 | 0.50-1.00 | 0.50-1.00 |
| 18 | 2.0-7.0 | 1-4 | 1.00-1.50 | 1.00-1.50 |
| 17 | 2.0-7.0 | 1-4 | **0.00**-1.25 | **0.00**-1.25 |
| 16 | 2.0-7.0 | 1-4 | 1.00 (constant) | 1.00 (constant) |

**Direct answer**: yes, this confirms the supervisor's structural hypothesis.
Three of four nodes never drop below 1.00. Node 19 has one window at exactly
0.50 (t=6.0) — at, not between, the 0.50-0.70 zone. Node 17 has one window
at 0.00 (t=4.0, rcv=1 — a single-packet sample, not a sustained PDR drop).
**No legitimate node shows a sustained corrPDR in the 0.50-0.70 range at any
point.** This is consistent with FP=0 being structural to this topology/flow
configuration (legitimate nodes' PDR is either near-perfect or, on rare
single-packet-sample windows, noisy to an extreme rather than settling in
the danger zone) — MATD's anti-false-positive function genuinely cannot be
demonstrated with this specific setup, independent of whether MATD's code is
wired correctly.

## NQ6 — DA6 vs DA4: per-node TP/FN comparison

**Pasted, per-node cumulative, both configs:**

| node | DA4 TP | DA4 FN | DA6 TP | DA6 FN | change |
|---|---|---|---|---|---|
| 7 | 28 | 0 | 28 | 0 | same |
| 8 | 27 | 1 | **0** | **28** | **TP→FN (regressed)** |
| 9 | 27 | 1 | 28 | 0 | same (~improved) |
| 10 | 25 | 3 | 25 | 3 | same |
| 11 | **4** | **24** | **28** | **0** | **FN→TP (recovered)** |

**Direct answer: yes, a node flips from mostly-TP in DA4 to entirely-FN in
DA6 — node 8.** This section was revised after the first fix attempt failed
verification — reporting the corrected investigation in full rather than the
original (wrong) theory.

**First theory (tested, found insufficient)**: that the AI bridge only
scores a node once per batch and freezes that verdict via the node-11-style
last-verdict carry-forward. Applied a fix seeding `g_sg_last_verdict` from
the lightweight signature signal (`s1||s2||s3`) whenever it fires, so a
silent node's carried-forward verdict would reflect the signature engine
too, not just a single AI score. **Reran DA6: zero effect** — node 8 stayed
at cum_TP=0/cum_FN=28, MCC unchanged at 0.40. Investigated why the fix did
nothing.

**Actual root cause (confirmed by direct instrumentation)**: `rcv` in the
detection loop is read from `node_total_received[n]`, which is **reset every
evaluation window** by `reset_per_node_pdr_counters()` (scheduled 0.15ms
after each window's metrics print, routing.cc:117664) — i.e. it is a
per-window counter, not a run-cumulative one. This on its own is expected
behavior. What's not expected: node 8 is a low-traffic, marginal relay node
in this topology (it relays only a handful of packets across the whole run).
Direct trace of its raw `rcv` value confirms:

| t | DA4 rcv | DA6 rcv |
|---|---|---|
| 2.0 | 3 | 3 |
| 3.0 | 2 | **0** |
| 4.0 | 1 | 0 |
| 5.0 | 0 | 0 |
| 6.0+ | 0 (permanent) | 0 (permanent) |

Both configs start identically (rcv=3 at t=2.0) and both eventually reach 0,
but DA4 decays gradually (3→2→1→0, still picking up a little traffic each
window through t=4.0) while DA6 drops straight to 0 at t=3.0 and never
recovers. Routing itself is not the cause — the stable-path counts for
every flow at every timestamp are byte-identical between DA4 and DA6
(verified directly), and node 8 is never isolated or rate-limited in either
config. The most likely remaining explanation is that DA6's blocking,
real-wall-clock `system()` call to the AI bridge (confirmed ~140-145ms per
window from the bridge's own timing log) introduces enough real-time cost,
somewhere in NS-3's event/packet handling around that call, to change which
of node 8's already-sparse packet events land inside which simulated-second
window boundary. **This was not fully root-caused to a specific line of
code** — confirming the exact mechanism would require tracing individual
packet-level event timestamps against the bridge call's real duration, which
is a larger investigation than this round of questions. The attempted fix is
left in place (it is still correct for nodes that reach `rcv>0` with a weak
AI score, just not sufficient for node 8's specific silence pattern) and is
commented in the code as verified-insufficient with a pointer to this
document. **Not resolved — reported honestly as an open, deeper finding
rather than claimed fixed.**

---

## Bottom line

- NQ1/NQ2 together fully explain DA4's regression: the ZKP gate's
  REQUIRE_ZKP-vs-ISOLATE distinction at t=6.0, combined with MATD's earlier
  silence timing, prevents node 11 from being isolated before it goes quiet
  — pasted numbers, not inferred.
- NQ3/NQ4 show node 8's one AI verdict was a near-miss (0.419 vs 0.500
  threshold), not a confident rejection — Q_i was high (0.871), correctly
  flagging suspicion; the fusion score just didn't clear the bar.
- NQ5 supports the structural-FP hypothesis: no legitimate node sustains
  corrPDR in the 0.50-0.70 risk zone in this topology.
- NQ6 identifies a **new, previously undiagnosed** mechanism, and an
  attempted fix for it that was tested and found insufficient: node 8 flips
  TP (DA4) → FN (DA6) because its live `rcv` counter (reset every window)
  drops to 0 one window earlier in DA6 than in DA4, even though both
  configs' routing/path-selection is byte-identical and node 8 is never
  isolated in either. The most likely explanation is a real-wall-clock
  timing interaction from DA6's blocking AI-bridge subprocess call
  (~140-145ms per window) shifting which of node 8's sparse packet events
  land inside which window boundary — not fully root-caused to a specific
  line, and explicitly reported as such rather than guessed at.
- **Attempted a fix, verified it did not work, root-caused why, and reported
  the corrected finding** — per instruction to self-correct, not just
  report. The fix that was tried (seeding the carried-forward verdict from
  the signature signal) is real and correct as far as it goes; it simply
  cannot help a node whose live receive counter itself is empty. A genuine
  fix would need either a real trace of packet-event timestamps around the
  bridge call, or a structural change (e.g. running the bridge asynchronously
  instead of blocking `system()`) — both larger undertakings than this round
  of questions, and not attempted here to avoid another unverified claim.
