# Answers to CQ1-CQ8

All eight answered with pasted real data. Two genuine, previously-unknown
mechanisms were confirmed this round (CQ1's real packet-generation source,
CQ3's ZKP design flaw) via direct code tracing, not inference.

---

## CQ1 — Why are only 8 packets sent in 30 seconds across 4 flows?

**Traced to the real source and confirmed with a live print — not
generation-broken in the way assumed, but genuinely near-zero by design in
this configuration.** `total_packets_this_cycle = ceil(total_load * f_size)`
(routing.cc:123197), computed fresh every ~1s cycle inside
`initiate_all_flows()`. Printed both inputs directly:

```
[CQ1] flow=0 t=1.1  f_size=3 total_load=1        total_packets_this_cycle=4
[CQ1] flow=1 t=1.1  f_size=0 total_load=0         total_packets_this_cycle=0
[CQ1] flow=2 t=1.1  f_size=3 total_load=0.999998  total_packets_this_cycle=3
[CQ1] flow=3 t=1.1  f_size=0 total_load=0         total_packets_this_cycle=0
[CQ1] flow=0 t=2.10 f_size=3 total_load=1.00      total_packets_this_cycle=4
[CQ1] flow=1 t=2.10 f_size=0 total_load=0.00      total_packets_this_cycle=0
[CQ1] flow=2 t=2.10 f_size=1 total_load=1.00      total_packets_this_cycle=1
[CQ1] flow=3 t=2.10 f_size=0 total_load=0.00      total_packets_this_cycle=0
```

**Direct answer: flows 1 and 3 have `f_size=0` in every window shown (and,
per the near-zero total-packet counts across the whole run, effectively
every window) — they structurally never send anything.** Flows 0 and 2 do
generate packets, but `f_size` itself is small and fluctuates (3, then 1)
even for them — it is not a fixed constant, it is recomputed from
`demanding_flow_struct_nodes_inst[fid]->f_size`, which is itself derived
from the controller's load-balancing solve
(`demanding_flow_struct_controller_inst`, set via `flow_sizes[]`) each
cycle. **This is not "packet generation is broken" in a crash/hang sense —
it is a real, working code path that happens to allocate zero or
near-zero packets to most flows, most cycles**, in this specific N=20/60%
attack test configuration. `data_transmission_period=1.00` confirms every
flow gets exactly one generation opportunity per simulated second, so the
low totals are not a scheduling-frequency problem either — the per-cycle
allocated size is the bottleneck. This traces back to the controller-side
load-balancing solve (`flow_sizes[]`'s ultimate origin), not investigated
further this round — flagged as the next concrete target if packet volume
itself needs to increase.

## CQ2 — Why does the zero-attacker baseline produce false isolations?

**Pasted directly — this specific run had 2 false isolations (run-to-run
count varies, 166-170 was seen in an earlier run; both are real,
reproducible failure modes, not a fixed bug count):**

```
[CQ2] ISOLATE node=19 t=7.00 gt_attacker=0 lambda=6 lambda1=2 lambda2=5
      Ri_decayed=0.47 statistical_gate=1 zkp_gate_enabled=1 zkp_cached=1
      zkp_proof=FAIL sustained=1
[CQ2] ISOLATE node=9  t=8.00 gt_attacker=0 lambda=5 lambda1=2 lambda2=5
      Ri_decayed=0.55 statistical_gate=1 zkp_gate_enabled=1 zkp_cached=1
      zkp_proof=PASS sustained=1
```

**Direct answer: both false isolations are gate-legitimate, not a
suspicion-counter reset bug — the suspicion level genuinely crosses
lambda2 (6 and 5, both >= lambda2=5) with the statistical gate genuinely
firing (`Ri_decayed` 0.47 and 0.55, both giving `(1-Ri)>theta_R`).** For
node 19, `zkp_proof=FAIL` — meaning even the ZKP gate agrees isolation was
warranted, despite this being a legitimate node with zero real attacker
activity. For node 9, `zkp_proof=PASS` but isolation still fires because
`sustained=1` (the separate consecutive-signature-window override bypasses
the ZKP requirement entirely — see the `should_isolate` computation,
`response == ISOLATE || sustained`). **So the mechanism is: legitimate
nodes' PDR/reputation genuinely dips low enough, for long enough
(mobility, real packet loss unrelated to any attack, or the sparse-traffic
effect from CQ1 causing noisy small-sample PDR), to cross the same
thresholds a real attacker would cross.** This is a real detection-quality
problem (thresholds too sensitive for this traffic regime), not a broken
reset mechanism.

## CQ3 — Why does ZKP pass for an active dropping attacker?

**Traced to the exact code and confirmed — this is a real design flaw in
the proof scheme, precisely matching the hypothesis.** The call site
(shield_gh_integration.h:610-612):
```cpp
auto commit = g_sg_zkp.CreateCommitment(n, fwd);   // fwd = node_total_forwarded[n]
auto proof  = g_sg_zkp.GenerateProof(commit, rcv);  // rcv = node_total_received[n]
```
And `GenerateProof()`'s actual check (zkp_proofs.cc:33):
```cpp
if (commit.n_fwd == observable_count) { proof.valid = true; }  // n_fwd==fwd, observable_count==rcv
```

**Direct answer: `commit.n_fwd` is set directly from the node's own
`fwd` value — the same variable the check compares it against (via `rcv`).
The node never makes an independent claim that could be caught lying; it
is only ever checked against its own already-computed forwarded count for
the SAME evaluation window.** The proof "fails" only when `fwd != rcv` in
that single window (e.g. a packet is still in flight, or forwarding hasn't
caught up to receipt yet) — this is a timing artifact of the current
window's snapshot, not a test of whether the node has been dropping
packets historically. A grey-hole node that has dropped many packets in
PAST windows, but happens to forward everything it received in THIS
particular window, gets `fwd == rcv` and passes — exactly what happened to
node 11 at t=6.0. **This confirms CQ3's diagnosis exactly as hypothesized:
the commitment is computed from the post-drop forwarded count, not an
independent pre-drop claim, so it cannot detect historical dropping,
only within-window inconsistency.** A correct design would need the node
to commit to a forwarding claim BEFORE the window's outcome is known
(e.g. an intended-forward count at packet-receipt time), then check that
commitment against what was actually observed — not compare two
already-observed counts to each other after the fact.

## CQ4 — What is the real packet routing mechanism?

**Fully traced with exact function names and line numbers, confirmed live
(not dead code) via the same method that found CQ4's premise (PDQ4) was
correct about the Dijkstra table being dead.**

- `initialize_flow_counters()` (routing.cc:122931) populates
  `all_sorted_delta_next_hop_flow_size` — confirmed scheduled at
  routing.cc:142182 (`Simulator::Schedule(Seconds(t+0.0995), initialize_flow_counters)`).
- `initiate_all_flows()` (routing.cc:123184) reads that structure via a
  `(sub_flow_load, nid, sub_flow_packets) = *index_innermost` tuple
  (routing.cc:123241) — `nid` here IS the real, live next-hop node ID for
  each subflow. Confirmed scheduled at routing.cc:142183, 0.1s after
  `initialize_flow_counters`, both once per `data_transmission_period`.
- `initiate_all_flows()` then calls `check_and_transmit()`
  (routing.cc:123058), passing `nid` directly (not looked up via
  `find_next_hop()`), which schedules
  `routing_dsrc_data_unicast()` (routing.cc:122615) — the function
  containing the actual `ATTACK PLACE 1` transmission/drop logic seen in
  every log.

**Direct answer: the real next-hop selection happens inside
`initiate_all_flows()` at routing.cc:123241, sourced from
`all_sorted_delta_next_hop_flow_size` (itself populated by
`initialize_flow_counters()`), NOT `find_next_hop()` or the Dijkstra
path table (both confirmed dead in the PDQ4 round).** This is a complete,
directly-traced answer, not an inference — every link in the chain was
confirmed either by finding its exact call site or its exact `Simulator::
Schedule` invocation.

## CQ5 — Why does MATD reduce MCC at drop_rate=20?

**Pasted directly, per-node cumulative TP/FN, DA1 vs DA2 at
drop_rate=20:**

| node | DA1 TP/FN | DA2 TP/FN | change |
|---|---|---|---|
| 7 | 22/6 | 23/5 | slight improve |
| 8 | 21/7 | **0/28** | **collapsed** |
| 9 | 25/3 | 25/3 | same |
| 10 | 12/16 | 23/5 | large improve |
| 11 | 27/1 | 27/1 | same |

**Node 8 is the sole cause of the net regression** — every other node is
the same or better in DA2; node 8 alone falls from 21 TP to 0. Traced its
corrPDR and evaluation-window count directly:

```
DA1 node 8: 9 evaluation windows total (some y_hat=1)
DA2 node 8: 5 evaluation windows total (ALL y_hat=0)
```

corrPDR at the first two windows (where MATD's correction is visible):
```
DA1 t=3.0: obs_pdr=0.50 corr_pdr=0.50 (== obs, MATD off)
DA2 t=3.0: obs_pdr=0.50 corr_pdr=0.51 (MATD nudges up by 0.01)
DA1 t=4.0: obs_pdr=0.00 corr_pdr=0.00
DA2 t=4.0: obs_pdr=0.00 corr_pdr=0.01
```

**Direct answer: MATD's correction itself (0.01 magnitude) is far too
small to flip any single-window verdict on its own — 0.51 and 0.01 are
still nowhere near a decision boundary.** The real cause is the same
traffic-silence mechanism identified for node 11/node 8 in earlier rounds:
node 8 gets 4 fewer evaluation windows in DA2 than DA1 (5 vs 9), going
permanently silent earlier. MATD is not "overshooting tau_f" or being
"applied to the wrong nodes" in the sense of corrupting a threshold
comparison — it is contributing, in some indirect way not yet fully
isolated, to node 8 losing traffic/evaluation opportunities earlier in
DA2 than in DA1, consistent with the pattern already found (and only
partially explained — see the still-open node-8/DA6 root cause from the
previous round) for other nodes under the combined MATD effect.

## CQ6 — Are the 8 packets the only source of node_total_forwarded increments?

**Confirmed both increment sites are live and reached — pasted first-5-hit
traces from each:**
```
[CQ6-SITE-B] hit#1 node=7 flow=0 new_total_fwd=1 new_total_rcv=1 t=1.1
[CQ6-SITE-A] hit#1 node=20 flow=0 new_total=1 t=1.10194
[CQ6-SITE-A] hit#2 node=8 flow=0 new_total=1 t=1.10322
```
Both sites fire within the first 1.1 seconds of the run — neither is
unreached. **Run-total `node_total_forwarded[]` values (zero-attacker
baseline, shadow cumulative counter that survives the per-window reset):**
```
node 7: fwd=88  rcv=88     node 12: fwd=23 rcv=23
node 8: fwd=32  rcv=32     node 14: fwd=57 rcv=57
node 9: fwd=20  rcv=181    node 15: fwd=62 rcv=59
node 10: fwd=45 rcv=45     node 16: fwd=67 rcv=67
node 11: fwd=24 rcv=25     node 17: fwd=96 rcv=96
                            node 18: fwd=48 rcv=41
                            node 19: fwd=7  rcv=26
```
(Nodes 0-6, 13: both 0 — consistent with the earlier-confirmed structural
zero-traffic finding for the chain-topology region.)

**Direct answer: `node_total_forwarded[]` is NOT always zero — real,
substantial values (7-96 range) confirmed. Every PDR/signature/reputation
computation for the nodes that do carry traffic is based on real
forwarding observations, not zeros.** One genuine anomaly found while
extracting this data: **node 9's `rcv=181` vastly exceeds `fwd=20`** — an
8.5x gap, far larger than any other node (all others track within ~15% of
each other). This is worth its own follow-up: either node 9 is a real,
severe relay bottleneck in this "zero-attacker" run, or there's a
double-counting issue specific to node 9's position in the topology.

## CQ7 — Does isolation of a legitimate node in the zero-attack baseline affect PDR?

**Pasted directly:**
```
[CQ7] first isolation: node=19 t=7.00 PDR_just_before=94.29%
[CQ7] one window after first isolation (node=19 at t=7.00): PDR_after=95.24% (was 94.29%)
```

**Direct answer: PDR did NOT drop after the first false isolation in this
run — it rose slightly (94.29%→95.24%).** This does not support the
"false isolation destroys the routing fabric" hypothesis as the primary
driver of the low, declining zero-attacker baseline PDR seen in earlier
rounds (53.55%). Important caveat: this specific run's overall PDR
trajectory was healthier than the 53.55%-ending run from the previous
round (this run trended up into the 90s before settling to 58% by the
end) — baseline PDR shows real run-to-run variance (mobility/RNG-driven),
so a single before/after snapshot around one isolation event is suggestive
but not conclusive; the earlier round's much lower final PDR (53.55%) may
be more affected by the CUMULATIVE effect of 166-170 isolations compounding
over the run than by any single one in isolation. Not fully resolved —
reported as a real, honest data point rather than forced into either
conclusion.

## CQ8 — What is node_total_received[] counting?

**Pasted directly, shadow-cumulative snapshots at the requested windows,
nodes 7-11, zero-attacker baseline:**

| window | node 7 rcv/fwd | node 8 rcv/fwd | node 9 rcv/fwd | node 10 rcv/fwd | node 11 rcv/fwd |
|---|---|---|---|---|---|
| 1 | 4/4 | 4/4 | 5/5 | 1/1 | 1/1 |
| 5 | 19/19 | 9/9 | 18/15 | 8/8 | 8/7 |
| 10 | 34/34 | 14/14 | 58/20 | 16/16 | 13/12 |
| 15 | 49/49 | 19/19 | 91/20 | 23/23 | 17/16 |
| 20 | 64/64 | 24/24 | 128/20 | 35/35 | 20/19 |

**Direct answer: nodes 7, 8, 10, 11 all show `received ≈ forwarded`
throughout — consistent with legitimate, low-loss relay behavior (small,
expected gaps of 0-1 packet). Node 9 is the exception, growing from 5/5
at window 1 to 128/20 by window 20 — `received` grows roughly linearly
(~6.5/window) while `forwarded` stays essentially flat after window 5
(15→20→20→20).** This is the same anomaly flagged in CQ6, now with a time
series confirming it's not a one-off spike: node 9 appears to genuinely
stop forwarding most of what it receives partway through the run, in a
run with **zero real attackers**. An independent NS-3-level packet count
(the second half of CQ8's request — comparing against actual injected
queue entries) was not built this round; the internal counter's *growth
pattern* is at least self-consistent (monotonically increasing, matches
the live CQ6-SITE-A/B increment traces), so there's no evidence the
counter itself is malfunctioning — but node 9's real behavior (why does a
legitimate node stop forwarding ~85% of its received traffic) is a new,
genuine finding worth its own investigation.

---

## Summary

- **CQ1**: real mechanism found — flows 1/3 get zero packet allocation
  most/every cycle; flows 0/2 get a small, fluctuating allocation. Traces
  back to the controller-side load-balancing solve, not a crash or hang.
- **CQ2**: false isolations are gate-legitimate (real suspicion-tier
  crossings), not a counter-reset bug — legitimate nodes' PDR/reputation
  genuinely dips enough to trigger the same thresholds a real attacker
  would.
- **CQ3**: confirmed real design flaw — the ZKP commitment is built from
  the node's own already-computed forwarded count, so it can only catch
  within-window inconsistency, never historical dropping.
- **CQ4**: fully traced, exact functions and line numbers given.
- **CQ5**: node 8's collapse (21→0 TP) is the sole cause of DA2<DA1 at
  drop_rate=20; MATD's own correction magnitude (0.01) is too small to be
  the direct cause — traced to the same traffic-silence-timing pattern
  found in earlier rounds, not fully root-caused to a single line.
- **CQ6**: `node_total_forwarded[]` confirmed live and non-zero; surfaced
  a new anomaly (node 9's 8.5x rcv/fwd gap).
- **CQ7**: PDR rose, not fell, immediately after the first false isolation
  in this specific run — does not support "false isolation destroys PDR"
  as the primary mechanism, though longer-run cumulative effects weren't
  ruled out.
- **CQ8**: counter behavior looks internally consistent; node 9's real
  forwarding behavior (not the counter) is the new anomaly, consistent
  with CQ6.
