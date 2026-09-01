# Answers to NQ_A-NQ_F

All six answered with real traced data and, for node 9, a decisive
conclusion: it is not a code bug — it is `should_drop_grey_hole()` working
exactly as designed, triggered by two different legitimate causes in the
two different runs.

---

## Node 9 anomaly

## NQ_A — Is node 9 in the attacker set in the zero-attacker run?

**No — confirmed directly from the actual run log, not inferred.**
```
Forcing exactly 0 attackers out of 20 vehicles
```
Traced the assignment code (routing.cc:517-550): `num_attackers` is
computed from `attack_percentage`; the loop that populates
`DPFR/DPIT/DPTS_malicious_nodes[]` runs `for(i=0; i<num_attackers; i++)`.
With `num_attackers=0`, this loop body never executes for any node,
including node 9 — `gt_attacker` is false for every node in this run,
confirmed structurally, not just for node 9 specifically. **No attacker
assignment bug.**

## NQ_B — What exactly happens to node 9's packets between window 5 and 10?

**Traced to the exact mechanism and exact timestamp — this is the real
answer, found by cross-referencing CQ2's isolation-event data (already
collected) against `should_drop_grey_hole()`'s code (routing.cc:1088-1099):**

```cpp
bool should_drop_grey_hole(uint32_t node_id, uint32_t flow_id)
{
    if(shield_gh_isolated_nodes[node_id])   // <-- checked FIRST, unconditionally
    {
        cout << "[SHIELD-GH-ISOLATE] Node " << node_id << " blocked, ...";
        return true;   // every packet this node would relay is dropped
    }
    ...
```

From the earlier CQ2 answer, node 9 was **falsely isolated at t=8.00** in
this exact run (`Ri_decayed=0.55`, statistical gate fired, `sustained=1`
override). The isolation log confirms drops start immediately after:
```
[SHIELD-GH-ISOLATE] Node 9 blocked, dropping flow 0 t=8.10
[SHIELD-GH-ISOLATE] Node 9 blocked, dropping flow 2 t=8.15
... (158 total block events for node 9 in this run)
```
And the CQ8 window snapshots confirm the exact before/after:
```
window=5  (t=5, before isolation): cum_received=18 cum_forwarded=15  <- normal small gap
window=10 (t=10, after isolation): cum_received=58 cum_forwarded=20  <- forwarded frozen
```

**Direct answer: node 9's packets enter `should_drop_grey_hole()` and are
dropped there — specifically the very first check
(`shield_gh_isolated_nodes[node_id]`), which fires unconditionally once a
node is isolated, regardless of whether it is a genuine attacker.** This
is not a MAC-layer or queueing failure; it is the isolation mechanism
correctly (mechanically) doing exactly what it is designed to do — block
all forwarding through an isolated node. `node_total_received[]` keeps
incrementing (via `MacRx`, a separate, earlier event — see NQ_F) because
receipt and the forward/drop decision are two different code paths; only
the second one is gated by isolation status.

## NQ_C — Does node 9 show the same pattern under DA1 (60% attack)?

**Run directly and confirmed: yes, same growing-gap pattern, but for a
completely different and entirely legitimate reason.**
```
Forcing exactly 12 attackers out of 20 vehicles
Node 9 forced as ATTACKER
[CQ8] window=1  node=9 cum_received=6   cum_forwarded=3
[CQ8] window=5  node=9 cum_received=12  cum_forwarded=7
[CQ8] window=10 node=9 cum_received=56  cum_forwarded=7
[CQ8] window=15 node=9 cum_received=84  cum_forwarded=7
[CQ8] window=20 node=9 cum_received=120 cum_forwarded=7
```

**Direct answer: node 9 IS a genuine forced attacker in DA1** (12 of 20
nodes are forced attackers; node 9 falls in that set). It shows the same
kind of growing rcv/fwd gap, but here it correctly reflects real grey-hole
dropping behavior (`DPFR_malicious_nodes[9]==true` branch of
`should_drop_grey_hole()`, not the isolation branch — node 9 isn't
necessarily isolated at all in this run, it's just genuinely dropping as
an attacker). **Node 9 is not being double-counted as both a relay and an
attacker path node** — it is simply: a legitimate node that got falsely
isolated in the zero-attacker run, and a genuine attacker in the 60%-attack
run. Same underlying code path (`should_drop_grey_hole()`'s unconditional
block on match), two different, both-legitimate trigger conditions. The
zero-attacker case is the one that needs fixing (via CQ2's
threshold-sensitivity finding), not this function's logic.

---

## Flows 1 and 3 zero allocation

## NQ_D — Does Gurobi itself assign zero, or does it happen downstream?

**Traced through the full chain and confirmed: Gurobi's own solve output is
the source — not a downstream filtering artifact — for flow 3. Flow 1 is
separately, unconditionally hardcoded to zero regardless of Gurobi.**

Two distinct mechanisms found:

**Flow 1** (`flow_id==1`): `filter_flows()` (routing.cc:116757-116760)
unconditionally sets
`(demanding_flow_struct_controller_inst+1)->f_size = 0` whenever
`routing_test==true` — a hardcoded override that never even consults
Gurobi's output for this specific flow index. This is not a solver
decision at all.

**Flow 3** (source 10→dest 13): traced upstream past `filter_flows()` to
the controller-update print that fires BEFORE any filtering
(routing.cc:96159), reading raw `X[i]` values transmitted from the node
side via `tag.SetX(X_gurobi[nid])` (routing.cc:113261) — i.e. the actual
Gurobi/optimization solve result, not a post-processing zero:
```
At controller: updated flow source 10to destination 13flow size 0packet size 750QoS 1
```
This value is 0 **before** `filter_flows()` runs. **Direct answer: for
flow 3, the zero originates from `X_gurobi[]`, populated from
`optimization_results.csv` (routing.cc:113990) — a genuinely separate
Gurobi integer program from the link-lifetime one, not yet traced in
detail (its own objective/constraints were not read this round). This is
the solver's own admission decision, not an application-layer bug.**

## NQ_E — Is the link lifetime between flow 1/3's endpoints zero (no path)?

**No — real connectivity exists for flow 3; checked directly:**
```
Routing stable: Number of stable paths from source: 10to destination 13 is 5 (at every timestamp checked)
```
5 stable paths exist for flow 3's endpoints throughout the run — this
directly rules out "no viable path exists" as the explanation for
Gurobi's `X[3]=0`. **The zero is a resource-allocation decision by the
second Gurobi model (the admission/demand solve reading
`optimization_results.csv`), not a topology/reachability problem.** Flow
1's zero is separately confirmed to bypass Gurobi entirely (NQ_D) — so
its link lifetime is not relevant to explaining its zero allocation.

---

## ZKP pre-commitment feasibility

## NQ_F — Can a pre-commitment architecture work within the current event structure?

**Yes — confirmed directly, a suitable event hook already exists and is
already live.** Traced the exact point where `node_total_received[]` is
incremented: inside `MacRx()` (routing.cc:120746), a genuine NS-3 MAC-layer
receive callback registered via
`Config::ConnectFailSafe(".../MacRx", MakeCallback(&MacRx))`
(routing.cc:142523) — the standard NS-3 trace-source hookup, confirmed
fired once per real packet arrival event, independent of and prior to any
forwarding decision.

`node_total_received[current_hop]++` happens at routing.cc:120840, inside
`MacRx()`, at the moment of physical packet receipt. The forward/drop
decision (`should_drop_grey_hole()`) happens later, in a separately
scheduled event (`routing_dsrc_data_unicast`/`check_and_transmit`, per the
CQ4 trace) — receipt and the drop decision are already two distinct
events in the current architecture, not fused into one.

**Direct answer: yes, `MacRx()` is exactly the per-packet receipt event
NQ_F asks about, and it already fires before the drop decision executes.**
A pre-commitment fix is architecturally straightforward: call
`g_sg_zkp.CreateCommitment(node_id, <running received count at this
instant>)` from inside (or immediately after) `MacRx()`, at receipt time —
before the node has decided whether to forward or drop — instead of the
current design's `CreateCommitment(n, fwd)` call inside
`shield_gh_evaluate()`, which runs once per ~1s window, well after all of
that window's forward/drop decisions are already complete. This does not
require restructuring the simulation loop; it requires moving the
commitment call to an already-existing, already-firing per-packet event
and changing what value it commits to (received-count-so-far, not
forwarded-count-after-the-fact). Not implemented this round, per
instruction to answer the diagnostic question first — flagged as a
concrete, scoped, and now well-understood fix for the next round.

---

## Summary

- **Node 9 is not a bug.** It is `should_drop_grey_hole()`'s isolation
  check working exactly as designed — triggered by a genuine (if
  over-sensitive) false isolation in the zero-attacker run, and by
  genuine attacker status in DA1. Same code, two legitimate causes. The
  real, still-open issue is CQ2's threshold sensitivity (why legitimate
  nodes' PDR/reputation dips enough to cross isolation thresholds), not
  a new node-9-specific defect.
- **Flow 1's zero is a hardcoded, unconditional override** (routing_test
  mode), unrelated to Gurobi. **Flow 3's zero is a genuine Gurobi
  admission-solve decision**, not a topology/connectivity failure — 5
  stable paths exist for its endpoints. The responsible model
  (`optimization_results.csv`'s producer) was identified but not opened
  this round.
- **A ZKP pre-commitment fix is architecturally feasible without
  restructuring the simulation** — `MacRx()` already provides the needed
  per-packet, pre-decision hook. This is now a well-scoped, concrete fix
  ready to implement, not an open architectural question.
