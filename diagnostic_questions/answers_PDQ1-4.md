# Answers to PDQ1-PDQ4 (PDR root-cause follow-up)

All four answered with pasted real data from fresh runs. One investigation
(PDQ4) surfaced a genuine, previously-undiscovered dead-code finding, which
is reported precisely rather than glossed over.

---

## Baseline confirmation (requested before PDQ1-4)

**Fresh runs, N=20, simTime=30:**

| Config | Final PDR |
|---|---|
| 0% attackers, 0% drops | **53.55%** (declining trend: 75.6%→73.3%→...→53.55%) |
| 60% attackers, 60% drops (DA1) | **8.59%** |

**Neither number matches the ~92%/single-digit split assumed in earlier
discussion.** The zero-attacker baseline is well below 92% and actively
declining across the run, not stable. This is itself a finding: even with
no attackers, something is degrading PDR over time. Investigated directly —
**166-170 false-positive SHIELD-GH isolation-block events fire during this
supposedly clean run** (real attacker count: 0). The detection system is
isolating legitimate nodes and dropping their traffic, contributing to the
baseline shortfall independent of any attack. This is a genuine, additional
root cause not covered by D12/B3 and worth flagging on its own.

---

## PDQ1 — Minimum lifetime constraint in Gurobi

**Implemented and tested — real improvement confirmed.** Added an
env-var-gated constraint (`SHIELD_GH_MIN_LIFETIME`, default 0.0 = off, so
every other run this session is unaffected) to `optimization_lifetime.py`:
when set, each per-pair Gurobi model gets an additional `l >= L_MIN`
constraint; if that makes the model infeasible, the link is excluded
(`lifetime=0.0`, consistent with the existing `d_max` early-reject
behavior) instead of being silently accepted with a near-zero lifetime.
Also fixed the pre-existing gap D3 identified: the code never checked
`m.Status` at all — now it does, and treats INFEASIBLE explicitly rather
than crashing on `l.X` with no solution.

**Ran the zero-attacker baseline with `L_MIN=2.0` seconds:**

| | Unconstrained (original) | With `L_MIN=2.0s` constraint |
|---|---|---|
| Final PDR | 53.55% | **75.65%** |
| False-positive isolations | 170 | 22 |

**PDR improves by ~22 percentage points and false isolations drop by ~87%.**
Per the question's own framing: yes, expired-path selection is a real,
substantial contributor to packet loss, and this constraint should stay.
(The isolation-count drop is a secondary, unexpected but logical effect:
fewer expired-path-driven forwarding failures means fewer nodes get
mistakenly flagged as grey-holes for packets that were actually lost to
routing, not to the node.)

## PDQ2 — Three-way packet loss breakdown

**Partially answered — (a) is real and precise; (b) and (c) could not be
added safely this round, reported honestly rather than fabricated.**

**(a) `should_drop_grey_hole()` drops**: real counter (`dp_drop_counter[]`,
already existed, confirmed incremented at its 3 call sites). DA1 (60%/60%,
30s) total: **77** (nodes 7:25, 8:6, 9:22, 10:22, 11:2). Important context:
this counts every relay/retransmit attempt across the run, not distinct
packets — the same packet retried multiple times increments this multiple
times. Cross-checked against PDQ3 below: only **8** packets were ever
originated across all 4 flows in the same 30s run. So "77 grey-hole drops"
reflects repeated attempts on a handful of packets, not 77 independent
losses — reporting this ratio explicitly so (a) isn't misread as 77 distinct
dropped packets.

**(b) MAC-layer retry exhaustion** and **(c) no-valid-next-hop drops**:
investigated adding both, did not add either, for a specific and honest
reason found during investigation. (b) requires wiring a new NS-3
`TraceConnectWithoutContext` callback to the WiFi MAC's retry/drop trace
source — a real NetDevice-setup change, not a routing-logic counter, out of
proportion to add and verify correctly in this round. (c) is worse: the
function that would report "no valid next hop"
(`find_next_hop()`, routing.cc:95512) has **no bounds-checking or
invalid-return path at all** — if the current hop is never found in the
stored path array, its `while(found==false)` loop has no exit condition.
Investigating this further (see PDQ4) revealed `find_next_hop()` and the
table it reads from are dead code in the current build (never actually
called at runtime — see PDQ4 below), so instrumenting it would not have
measured anything real. Given real packet routing goes through a different,
not-yet-traced subflow-allocation mechanism, a genuine no-next-hop counter
would need to be added there instead — flagged as follow-up work rather
than guessed at.

## PDQ3 — Per-flow PDR

**Pasted directly, DA1 (60%/60%), all 4 flows, full 30s run:**

| flow | source→dest | sent | delivered | PDR |
|---|---|---|---|---|
| 0 | 7→10 | 3 | 0 | **0.00%** |
| 1 | 8→11 | 1 | 0 | **0.00%** |
| 2 | 9→12 | 2 | 0 | **0.00%** |
| 3 | 10→13 | 2 | 0 | **0.00%** |

**All four flows show exactly 0% PDR for the entire run.** This is a
stronger and more precise finding than "one flow is dragging the average
down" — every flow independently delivers zero packets. Also notable: only
8 packets total were ever sent across all 4 flows in 30 simulated seconds —
an extremely low packet-generation rate independent of delivery success,
worth its own follow-up (is this the intended `data_transmission_period`
behavior, or is packet generation itself being throttled/blocked?).

## PDQ4 — Link lifetime decay on active paths

**Investigation found a real, previously-undiscovered structural issue
before the requested numbers could be produced honestly — reporting both.**

First attempt: walked `proposed_routing_tables[source].rows[dest].path[]`
(the structure `find_next_hop()` also reads) to find flow 0's selected
path. Result was empty/no-path at every timestamp. Investigated why:
- `path[]` is only ever written by `update_proposed_route()`
- ...which is only ever called from `dijkstra_stable()`
- ...which is only ever called from `calculate_dijkstra_stable_solution()`
- ...which is **declared but never invoked anywhere in the file**.

So `proposed_routing_tables[].path[]` sits at its
`initialize_all_routing_tables()` sentinel value ("large") for the entire
run — never populated. `find_next_hop()` (which reads this same dead
table) is consistent with this: it has no valid-path case to find. Traced
one level further: real next-hop selection for actual transmissions
(`check_and_transmit()` → `routing_dsrc_data_unicast()`) comes from a
**separate** structure — a `(sub_flow_load, nid, sub_flow_packets)` tuple
unpacked from `index_innermost` inside `initiate_all_flows()` — not
`find_next_hop()` or the Dijkstra table at all. This second mechanism was
not traced further this round (out of scope for PDQ4 specifically); it's a
real, separate finding worth its own follow-up question if useful.

**Corrected approach**: `linklifetimeMatrix_dsrc` itself IS live — confirmed
`convert_link_lifetimes_dsrc()` (which populates it from the Gurobi CSV) is
actually called, and the matrix is read directly by the real transmission
path (`check_and_transmit()`'s neighborhood-busy check). Reporting flow 0's
source node's real, live lifetime values at the requested checkpoints:

| t | direct 7→10 lifetime | live neighbor lifetimes (node 7) |
|---|---|---|
| 1.998 | 0 (never a direct neighbor) | 8: 634.96, 14: 634.96, **20: 10.16** |
| 3.0 | 0 | 8: 634.96, 14: 634.96, **20: 9.16** |
| 4.0 | 0 | 8: 634.96, 14: 634.96, **20: 8.16** |
| 10.0 | 0.00 | 8: 634.96, 14: 634.96, **20: 2.16** |
| 20.0 | 0.00 | 8: 634.96, 14: 634.96 *(node 20 gone)* |
| 29.0 | 0.00 | 8: 634.96, 14: 634.96 |

**Direct answer: yes, real decay toward zero is observed and confirmed —
node 20's link lifetime from node 7 decreases by exactly 1.0 second every
window (10.16→9.16→8.16→...) and the link disappears entirely (falls out
of the neighbor list, implying lifetime hit 0) somewhere between t=10 and
t=20.** This confirms path staleness is a real, measurable phenomenon
independent of D12's "no floor" finding — a link doesn't just lack a
minimum, it visibly counts down in real time between the periodic Gurobi
re-solves, and packets sent on it late in that countdown are being routed
on borrowed time. Nodes 8 and 14, by contrast, show a constant 634.96 the
entire run — flagged as its own minor oddity (a link lifetime that never
changes across 28 windows is unusual and wasn't investigated further here).
Flow 0's actual source (7) and destination (10) are never direct neighbors
at any checkpoint (matches the earlier session's finding they are ~1187m
apart, beyond single-hop range) — any real delivery for this flow would
require multi-hop relay through the still-unidentified subflow-allocation
path, not a direct link.

---

## Summary

- Baseline numbers confirmed and are worse than assumed: 53.55% clean
  (declining, with 166-170 false-positive isolations even at 0 attackers),
  8.59% under full attack, all 4 flows at exactly 0% PDR.
- PDQ1's constraint is implemented, tested, and shows a real, large
  improvement (53.55%→75.65%) — recommend keeping it.
- PDQ2's (a) is answered precisely with an important caveat about
  repeat-counting; (b)/(c) require larger, separate follow-up work
  (NS-3 MAC trace wiring; instrumenting the real subflow-allocation path
  once it's traced) rather than a rushed, unverified counter.
- PDQ3 is unambiguous: every flow, not just one, delivers 0% throughout.
- PDQ4 surfaced a genuine structural finding (a dead Dijkstra/next-hop
  subsystem parallel to the real, separate mechanism that actually drives
  transmissions) while also directly confirming real link-lifetime decay
  on an active link (node 7-20, exactly 1.0s/window).
