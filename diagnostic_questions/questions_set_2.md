## Assessment

The two bugs found and fixed (ablation toggle bypass in LW_DP_Det, = vs == in update_stable) are genuine and important. However the diagnostic results are not acceptable and cannot be signed off as evidence of a working system. Three specific problems demand immediate action before any experiment runs.

**Problem 1 — MCC is not monotonically increasing.** DA1 through DA4 are all 0.47 — flat. DA5 (LLM+FL only) is 0.30 — lower than signatures alone. DA6 is 0.50 — higher than all but only by 0.03. Adding components must strictly increase MCC. A component that reduces MCC or leaves it unchanged either has a wiring bug or is actively interfering. This is not a topology excuse — it is a wiring failure.

**Problem 2 — PDR of 3-9% is unacceptable.** The no-attack baseline was 92%. Under attack it collapses to 3-9%. This is not all attack damage — at 60% attackers dropping 60% of packets, some degradation is expected, but not 90% collapse. Something in the routing or traffic generation is also contributing to packet loss independently of the attack.

**Problem 3 — Route-availability gate blocks all isolation.** 92/92 isolation decisions withheld. No isolation means PDR cannot recover regardless of detection quality. This is a topology design problem that must be resolved by ensuring the simulation has redundant paths, not accepted as a structural constraint.

---

## 60 Diagnostic Questions

---

### Category A — MCC Monotonicity (15 questions)

**A1.** In DA1, print the exact node IDs of the FN=7 nodes (attackers not detected). Then print whether each of those 7 nodes had any packets forwarded or received during the entire run. If FN node IDs exactly match the zero-traffic node IDs, MCC is capped by routing blindness, not detection failure.

**A2.** In DA1, print the corrPDR value for every attacker node at every observation window. Which attackers have corrPDR consistently above τ_f=0.60 despite dropping 60% of packets? Those are your structural FN — nodes the signature can never flag because observed PDR is paradoxically above the threshold.

**A3.** In DA5 (LLM+FL only, MCC=0.30), print the specific TP and FN node IDs. Compare against DA1's TP and FN node IDs. Are different nodes being detected by LLM vs signatures? If DA5 detects a completely different set of 5 nodes than DA1, fusion should produce 10 TP — but DA6 shows only 5 TP. This means the fusion is not combining them correctly.

**A4.** In DA6, print the three fusion terms (μ1·S_total, μ2·Q_i, μ3·(1-R_i)) for each FN node at the final observation window. How far below θ_det is the weighted sum for those 7 nodes? If any FN node is within 0.05 of θ_det, the threshold is the issue, not the component performance.

**A5.** Run DA1 with attack_percentage=20, drop_rate=60 (fewer attackers, same intensity). Report MCC and which nodes are FN. This tests whether 60% attacker density is itself the problem — too many attacker nodes means routing cannot find paths that avoid them, making many attackers structurally undetectable.

**A6.** Run DA1 with attack_percentage=60, drop_rate=20 (same attacker count, lower intensity, closer to τ_f threshold). Report MCC, FIR, and FN count. At lower drop rates, MATD correction matters more. If MCC improves substantially here, the τ_f=0.60 threshold is too permissive for the 60% drop scenario and needs adjustment.

**A7.** In DA6, print Q_i (LLM threat score) for the 7 FN nodes at every window. If Q_i is near 0 for all FN nodes throughout, the LLM is receiving no meaningful log data for those nodes — routing blindness. If Q_i is non-zero but the fusion sum stays below θ_det, the weights are the issue.

**A8.** Confirm that disabling LLM in DA1-DA4 genuinely sets Q_i=0 for all nodes every window. Print Q_i for 3 attacker nodes in DA1. If Q_i is non-zero in DA1, the LLM is running when it should be off and DA1 is not a true signatures-only baseline.

**A9.** Confirm that disabling signatures in DA5 genuinely sets S_total=0 for all nodes every window. Print S_total for 3 attacker nodes in DA5. If S_total is non-zero in DA5, the signature pipeline is still running when it should be off and DA5 is not a true LLM-only baseline.

**A10.** Run DA4 with simTime=120 instead of 30. Print MCC at t=30, t=60, t=90, t=120. If MCC increases over time (more windows accumulate more reputation evidence), 30s is too short for reputation-based detection to converge. If MCC stays flat at 0.47 at t=120, the detection has a genuine ceiling at this configuration.

**A11.** Print the reputation score R_i(t) for each of the 7 FN attacker nodes at windows 3, 6, 9, 12. Does reputation decrease toward 0 over time for these nodes? If R_i stays near 1.0 for all FN nodes throughout the run, the reputation update is not being fed detection events — the DEBSC is never accumulating evidence against those nodes.

**A12.** In DA1 vs DA2 (MATD added), print FP count separately. If FP=0 in both, MATD has no measurable effect because there are zero false positives to suppress. Run both configs with attack_percentage=60, drop_rate=0 (attackers present but not dropping) — under this config, PDR-based signatures may generate false positives on legitimate fast-moving nodes, revealing MATD's suppression effect.

**A13.** In DA3 (ZKP gate enabled), print how many times the ZKP gate was evaluated (code reached the ZKP check) vs how many times it was bypassed by the route-availability gate. If ZKP evaluations = 0, the gate is dead code in this topology and DA3 is identical to DA1 by construction, not by result.

**A14.** For the FL model in DA5/DA6, print the global model weight norm after round 1 and round 5. If the norms are identical, the FL aggregation loop is not updating the model — it is a static pre-trained model, not federated, and DA5/DA6 performance is the ceiling of a fixed model on this data.

**A15.** In DA6, print the FL model's per-class accuracy on the training data for each class (BENIGN, S1, S2, S3, S4, S5, S6). If accuracy for S3/S4/S5/S6 is near chance level (14%), those attack variants are invisible to the LLM component and LLM detection is effectively S1/S2 only.

---

### Category B — PDR Root Cause (15 questions)

**B1.** Run N=20, attack_percentage=0, drop_rate=0, simTime=60. Print PDR at t=10, t=20, t=30, t=40, t=50, t=60 separately. This is the true routing baseline after all fixes. If PDR is below 80% even with zero attackers at t=60, routing itself is the primary source of packet loss — not the attack.

**B2.** Run N=20, attack_percentage=60, drop_rate=0, simTime=30. Print PDR. With 12 attacker nodes but zero drop rate, PDR should match B1. If PDR is significantly lower than B1, the attacker node designation itself (before any dropping) disrupts routing — possibly because attacker nodes are excluded from route selection or their routing tables are different.

**B3.** In a DA1 run, print separately: packets dropped by the grey hole attack logic, packets dropped by NS-3 MAC-layer collision/retry exhaustion, packets dropped by no-next-hop (routing failure). These three must sum to total loss. If MAC-layer or routing failure drops are a large fraction, PDR is being hurt by the simulation environment, not the attack.

**B4.** Print the per-flow PDR separately for each of the 6 flows after Fix A. If 3 of 6 flows have 0% PDR and 3 have 30%, network-wide average is 15% even with some flows working. Identify which flows have 0% PDR and whether those flows have INFEASIBLE Gurobi solutions.

**B5.** After Fix A, print the fraction of Gurobi solves that return INFEASIBLE for each flow. An INFEASIBLE solution means zero packets can travel that flow regardless of attack — these are dead flows that drag down the network average. Report the count of INFEASIBLE flows out of the total 6.

**B6.** Print the routing table for node 0 at t=5s. How many of the other 19 nodes have a valid next-hop entry from node 0? If only 3-4 of 19 nodes are reachable from node 0, the routing fabric is severely incomplete and PDR will be low even with no attackers.

**B7.** Run N=20, no attackers, and print PDR at the per-link level: for each (sender, receiver) pair that is on any active route, print the fraction of packets successfully received at that specific hop. If specific links have <50% per-link success rate, those links are unreliable and any route using them will have poor end-to-end PDR.

**B8.** How many total packets per second is the NS-3 application layer generating across all 20 nodes? Print offered load in packets/second and compare against the theoretical maximum DSRC channel capacity at 5.9GHz. If offered load exceeds channel capacity, MAC-layer congestion alone will produce severe PDR degradation independent of routing or attack.

**B9.** In a DA1 run, print the simulation timestamp of the first successfully received packet at any destination. If the first successful delivery occurs at t=8s or later, the routing has a 8s convergence period during which PDR=0%. For a 30s run, this means 27% of the simulation time has PDR=0%, dragging the time-average down substantially.

**B10.** After Fix A's hop-distance-3 routing, print the actual geographic distance in meters between each source-destination pair. If any pair is >810m apart (3 hops × 270m range), the hop-distance-3 constraint still cannot bridge that gap and the Gurobi solver will return INFEASIBLE.

**B11.** Compare PDR of the original 2 flows (nodes 0↔3, known to work before Fix A) against the 4 new flows added by Fix A separately. If original flows have PDR=25% but new flows all have PDR=0%, Fix A added flows with no viable paths and is dragging the network-wide average below the original 2-flow result.

**B12.** In DA6 (full system), after an attacker is detected (verdictmalicious=1), does any traffic get rerouted away from that attacker, or does the same flow continue through the same route? Print whether any flow paths change after a detection event. If detected attackers continue carrying all traffic, detection improves MCC but cannot improve PDR.

**B13.** Print how many route recomputations (Gurobi solves) occur during a 30s simulation. If routes are computed once at t=0 and never updated, stale routes accumulate as nodes move. Compute the expected staleness: average node speed × time since last solve ÷ transmission range. If staleness >1.0, routes are likely broken by the time packets use them.

**B14.** Run B1 (no attack baseline) but with simTime=300 instead of 60. Print PDR at t=60, t=120, t=180, t=240, t=300. If PDR degrades over time even with no attackers, routes are becoming stale as nodes move and routing tables are not being updated fast enough for the vehicle speed.

**B15.** What is the NS-3 wireless propagation model and its parameters? Is it using a constant-range model (binary: in range or not) or a probabilistic model (variable success rate based on distance)? If using a probabilistic model, packets between adjacent nodes may have 60-70% success probability at 250m separation, meaning 3-hop routes have only 0.6³=21.6% end-to-end success rate before any attack.

---

### Category C — Component Wiring Deep Verification (15 questions)

**C1.** In DA3 (ZKP gate enabled), trace the code path for the first attacker node at the first window where the statistical gate fires: print (a) statistical gate result, (b) whether code reaches the ZKP gate evaluation, (c) ZKP gate result if reached, (d) route-availability gate result, (e) final isolation decision. Confirm all four are being evaluated in the correct order.

**C2.** In DA2 (MATD enabled), print for 3 legitimate nodes: raw PDR, ρ_ho value, corrected PDR, and S1 threshold comparison result. The corrected PDR must always be ≥ raw PDR for legitimate nodes (correction adds back handoff loss). If corrected < raw for any node, MATD is subtracting instead of adding.

**C3.** In DA6, for each attacker node print the exact values of all three fusion inputs at window 5: S_total (from signatures), Q_i (from LLM), (1-R_i) (from reputation). All three must be non-zero for at least the TP nodes. If any term is 0 for all nodes, that component is not contributing to any fusion decision.

**C4.** Confirm the observation window W=10 is consistent across all three detection components. Print the window boundaries used by: (a) signature evaluation, (b) LLM tokenizer, (c) reputation averaging. If they are misaligned (signatures use slots 1-10, LLM uses events 5-15), components are evaluating different evidence and their combination is incoherent.

**C5.** In DA4 (full lightweight), print the total count across the whole run of: S1 fires, S2 fires, S3 fires, S4 fires, S5 fires, S6 fires. If S3/S4/S5/S6 all show zero, only S1 and S2 are functional — the framework is a 2-signature system and coverage of controller-plane attacks is zero.

**C6.** In DA5 (LLM+FL only), confirm FL is actually updating the global model. Print the global model weight L2 norm after window 1 and window 10. They must differ. If identical, the FL aggregation loop is not running and the model is static — DA5 is measuring a fixed pre-trained model, not a federated one.

**C7.** In DA5, print the exact input passed to the LLM scorer for node 0 at window 5. Is it a token sequence (FWD:s0, DRP:s1, HOF:s2 etc.) or a raw numerical feature vector? If numerical, the LLM is not processing sequential log tokens as specified and its temporal reasoning capability is not being used.

**C8.** In DA6, print the blockchain reputation R_i(t) for a TP attacker node at windows 1, 5, 10, 15. Reputation must decrease over time as detection events accumulate. If R_i stays near 1.0 for a correctly detected attacker, the reputation update is not connected to the detection output.

**C9.** Confirm gradient integrity is working in DA6. Deliberately inject a poisoned gradient from one node (modify Δw after hash commitment) and confirm the aggregator rejects it. Print the accept/reject decision and the hash mismatch evidence. If the poisoned gradient is accepted, the blockchain gradient verification (eq:gradient_commit) is not running.

**C10.** In DA4, print the DEBSC evaluation count, isolation-withheld count, and isolation-executed count for the entire 30s run. They must satisfy: evaluated = withheld + executed + no-action. If evaluated = withheld exactly and executed = 0, every DEBSC call is blocked by the route-availability gate — confirm this is the binding constraint.

**C11.** Create a minimal test: in the simulation, temporarily force one node pair to have a redundant path (add a direct link), then run DA4 and check whether isolation fires for the attacker on that specific path. This isolates whether the route-availability gate is the only reason isolation never fires — if isolation fires when a redundant path is present, the gate is working correctly and the topology needs more redundancy, not a code fix.

**C12.** In DA1, print whether the ZKP proof generation is being called for every node every window, or only for flagged nodes. Every node must submit a proof every window — if only flagged nodes submit, the ABSENT state cannot be triggered and the three-state ZKP model is structurally incomplete regardless of whether ABSENT is implemented.

**C13.** In DA6, print the total number of FL training rounds completed during a 30s run. With a 1s data_transmission_period and 5 rounds configured, there should be 5 aggregation events. If only 1 aggregation occurs (at the start), FL is not running incrementally during the simulation.

**C14.** Print the probationary mode status for each new node at t=1s, t=5s, t=10s. How many windows does a node spend in probationary mode before moving to active? If all 20 nodes are in probationary mode for the first 10 windows of a 30s run, the statistical gate is suppressed for 33% of the simulation duration for all nodes simultaneously.

**C15.** In DA1, confirm the confusion matrix counts TP, TN, FP, FN based on the correct definition: TP = attacker correctly flagged, TN = legitimate correctly not flagged, FP = legitimate incorrectly flagged, FN = attacker not flagged. Print the specific node IDs in each category. If any legitimate node appears in the TP set, the ground truth labeling is wrong.

---

### Category D — Routing Diagnostics (15 questions)

**D1.** After Fix A, print the complete list of (source, destination, hop count) for all 6 active flows. How many unique nodes appear as source or destination? If only 8 of 20 nodes appear, Fix A still leaves 12 nodes unreachable by any flow.

**D2.** For each active flow, print the exact sequence of node IDs in the selected path (e.g. 0→5→12→3). For each consecutive hop, print whether those two nodes are within NS-3 transmission range at t=5s. If any hop in any path exceeds range, that hop will fail and the entire flow collapses to 0% PDR.

**D3.** Print how many total Gurobi sub-problems are solved per simulated second at N=20, and how many return INFEASIBLE. The INFEASIBLE fraction at N=20 predicts the routing coverage gap at N=200. If 40% of sub-problems are INFEASIBLE at N=20, routing coverage is structurally 60% regardless of attack or detection quality.

**D4.** In the Gurobi MILP, what exactly is the objective function? Print the mathematical form. Confirm that the objective function includes actual packet delivery as a constraint, not just link lifetime maximization. A path with high link lifetime but zero channel capacity will be selected as optimal but carry no traffic.

**D5.** Print the node positions (x, y in meters) for all 20 nodes at t=5s. Then compute the average inter-node distance. Compare against the NS-3 transmission range. If average distance exceeds range/2, the network is sparse and multi-hop paths of 3 hops will only succeed when nodes happen to be collinear — structurally low PDR.

**D6.** Print the link lifetime matrix L[i][j] for all 20×20 node pairs at t=5s after convert_link_lifetimes() runs. How many entries are 0 or near-0? These are the link pairs the Gurobi MILP treats as unreachable — a high fraction of zero-lifetime entries means the routing fabric is sparse before any attack.

**D7.** How does the link lifetime of existing routes change between Gurobi solves? Print the link lifetime of the path used by flow 0 at t=1s, t=10s, t=20s, t=30s. If link lifetime decays to near-0 between solves (because nodes moved), packets are being sent on routes that are already invalid by the time they are used.

**D8.** Run the stable path finder (update_stable/run_stable_path_finding) in isolation on the N=20 topology and print: (a) how long it takes in wall-clock milliseconds and (b) how many unique paths it finds. After the = vs == fix, this should be fast — confirm the path count is reasonable (not millions) and the runtime is <100ms.

**D9.** After all routing fixes, run N=20 with 0 attackers and print the per-node forwarding rate: how many packets per second does each node forward on average? If many nodes have near-zero forwarding rates, they are isolated in the routing topology and will have MCC=undefined (neither TP nor TN) when selected as attackers.

**D10.** Is there any mechanism in the current code to recompute routes when a node's link lifetime drops below a threshold mid-simulation? Print whether any reactive route update is triggered during a 30s run. If routes are only computed proactively at fixed intervals, link failures between intervals produce sustained 0% PDR on those flows.

**D11.** Print the maximum, minimum, and median flow path length (hops) across all 6 active flows after Fix A. If median path length is 4+ hops and per-hop success probability is 70%, median end-to-end success rate is 0.7⁴=24%, explaining low PDR without any attack.

**D12.** In the current Gurobi model, is there a constraint that each selected path must have a minimum link lifetime (e.g. at least 2 seconds)? Print the constraint. If no minimum lifetime constraint exists, Gurobi may select paths that expire within 0.1s of selection, producing routes that are already dead when first used.

**D13.** Run at N=8 (between N=4 which works and N=20 which is marginal). Print PDR with 0 attackers and 0 drops. Then run with 50% attackers, 50% drops. Report both PDRs and MCC. This finds the N at which routing first degrades — if N=8 still has good PDR but N=20 does not, the scaling problem begins between N=8 and N=20.

**D14.** Does the routing algorithm produce symmetric routes (0→3 uses the same path as 3→0 in reverse)? Print both directions for one flow pair. If routes are asymmetric, bidirectional flows use different nodes as relays — attacker placement that disrupts one direction may not affect the other, producing asymmetric PDR per flow direction.

**D15.** After all routing fixes, run N=20 with 0% attackers and plot (or print in CSV format) PDR vs simulation time at 1s intervals for 60s. The shape of this curve tells us whether the routing has a convergence phase, a stable operating region, and a degradation phase — essential for choosing the correct simTime for ablation experiments.

---

## WhatsApp Message

---

Hi team 👋

The two bugs found and fixed are genuine and the diagnostic work quality is excellent. However the results are not acceptable and cannot proceed to final experiments. Here is what the diagnostics reveal and what must be done.

---

**What the results reveal**

MCC must increase monotonically as components are added. DA1 through DA4 are all 0.47 — flat. DA5 (LLM+FL only) is 0.30 — lower than signatures alone. This is not acceptable. A component that reduces or does not change MCC is either not wired or actively interfering with detection. "The topology has no redundant paths" is not an explanation for flat MCC — it explains why isolation does not fire but not why adding MATD, ZKP, or LLM fails to improve detection classification.

PDR of 3-9% under attack is also unacceptable. The no-attack baseline was 92%. Even with 60% attackers dropping 60% of packets, 3% PDR suggests routing itself is contributing to packet loss beyond the attack. These two problems must be diagnosed and fixed before any experiment runs.

---

**Three immediate actions**

**Action 1 — Generate a topology with redundant paths.** The route-availability gate correctly withholds isolation when no alternate path exists — this is right by design. But the current N=20 topology has zero redundant paths for any flow, meaning isolation can never fire, PDR can never recover after detection, and MATD/ZKP effect on FIR can never be demonstrated. Fix the flow generation so at least 30% of flows have at least one redundant path. This does not change the algorithm — it changes the test topology to one where the algorithm can actually be observed.

**Action 2 — Run Q-new9 result (already in progress) and N=200 re-attempt.** Report these as soon as they complete. Do not wait — send results immediately when they finish.

**Action 3 — Run all 60 diagnostic questions below.** These are grouped into four categories: MCC monotonicity, PDR root cause, component wiring, and routing. Send all answers grouped by category — do not send one at a time.

---

**60 diagnostic questions — send all answers grouped by category**

*(paste all 60 questions here — Categories A through D as written above)*

---

Do not run E1-E5 until: (a) MCC increases monotonically across DA1→DA6, (b) baseline PDR (zero attackers) at N=20 is above 80%, and (c) at least one isolation event fires and produces a measurable PDR improvement in the full system run. 👍

Dr. Wijesekara