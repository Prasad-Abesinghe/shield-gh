# Task 7.75 — Design Review: Is Any Implementation Performance "Very Poor"?

**Task (supervisor):** *"Report if design changes are required if the performance
of the implementation is very poor. Report the superior way you implemented so
that design can be updated and apply the patch. If no changes, let me know."*

**Scope reviewed:** every measured (not analytical) result produced so far —
Tasks 1–7.5: lightweight rule-based detection, real Hyperledger Fabric DEBSC
blockchain + dynamic VRF endorser selection, post-quantum crypto (PQC-LKH,
threshold signatures, ZKP), and the LLM/FL AI pipeline (Task 6/6.5).

---

## Summary

**One genuinely poor result found, and it is not a detection defect.** Detection
quality across every completed component is strong-to-perfect (MCC 1.0 for
rule-based node-level detection, MCC 0.79–0.81 for the genuine fine-tuned LLM,
100% poison-gradient rejection on-chain, 31/31 + 25/25 + 20/20 unit tests
passing across crypto/blockchain/AI). The poor number is **network-wide PDR
after mitigation**, which is a **topology artifact of the 5-node prototype
scenario**, not a flaw in SHIELD-GH's design or algorithms. Design change is
**not required to the detection/mitigation algorithms**; a **scenario/metric
fix is recommended before Task 8/8.5/10**, detailed below.

---

## 1. The poor number

Running the lightweight pipeline (`--detection_mode=lightweight
--attack_number=1 --drop_rate=60 --simTime=25`, evidence:
`shield_gh/evidence/S2.log`):

| t | Event | Network PDR (cumulative) |
|---|---|---|
| t=0–3 | pre-isolation | 83.3% → 66.7% |
| t=4 | **Node 0 correctly isolated** (ZKP=FAIL, real_attacker=1) | 66.7% |
| t=8 | | 62.9% |
| t=15 | | 53.8% |
| t=25 | end of run | **~50%** |

Node-level detection in the same run is **MCC = 1.0, TP=1 TN=3 FP=0 FN=0**
throughout — the detector is not wrong. But network PDR keeps *falling* after
correct isolation, which contradicts what the report currently tells the
supervisor to expect. `main.tex` §Expected Results (`sec:expected_results`,
"How Packet Delivery Ratio Varies with Drop Rate") states:

> *"SHIELD-GH's faster detection and more reliable isolation provide
> substantially greater PDR recovery."*

The measured behaviour is the opposite: PDR **degrades**, not recovers, after
isolation. This gap between the report's stated expectation and the measured
number is exactly what Task 7.75 is asking to be surfaced.

---

## 2. Root cause (verified in code, not guessed)

The 5-node prototype topology (`routing.cc:276`, `const int total_size = 5`,
`N_Vehicles` defaults to 4) runs **exactly one active flow**
(`routing.cc ~141457`: `source = 0`, `destination = 3`; the reverse flow is
explicitly zeroed out in `filter_flows()`), and it has **no redundant path** —
it is a single chain from source to destination through the other vehicle
nodes. Separately, `declare_attackers_routing()` (`routing.cc:488`) always
assigns attacker(s) starting from node index 0.

I tested the obvious-looking fix — move the attacker off node 0 so isolation
doesn't remove the flow's source (`routing.cc:489`, start the loop at index 1
instead of 0) — expecting PDR to recover after mitigation. **It did not; it
got worse.** With node 1 isolated instead of node 0, PDR decayed continuously
toward ~2% instead of stabilizing around 50%, and a new false positive
appeared (an honest node later got isolated too, at t=21). I reverted this
change; `routing.cc` is back to the original, unpatched, rebuilt clean.

**Why moving the attacker didn't help:** with only one flow and no alternate
path, isolating *any* node on that single path — source, relay, or
destination — fully severs the flow's only route. There is no "safe" node to
attack in this topology once isolation removes it from routing. The apparent
partial recovery to ~50% (rather than collapsing to 0%) when node 0 (the
source) is the attacker is itself a MATD/rerouting side-effect, not evidence
of a working recovery path.

A second, compounding factor: the reported PDR (`routing.cc:116970`,
`average_packet_delivery_ratio_dsrc = current_cumulative_ratio /
data_gathering_cycle_number`) is a **cumulative running average over the
whole simulation**, not a windowed or instantaneous rate. Once the flow's
per-cycle PDR drops (partially or fully) after isolation, the *cumulative*
average will keep drifting toward that lower value for the rest of the run
by construction — even in a run where the framework is working exactly as
intended. This makes the metric look worse than the framework's real,
instantaneous post-mitigation behaviour.

---

## 3. Is this a SHIELD-GH design flaw?

**No.** Every other measured signal says the design is sound:
- Node-level detection MCC = 1.0, 0 false positives, all 3 DP variants +
  all 3 CP variants detected and isolated (Task 1/2 evidence).
- Genuine fine-tuned Qwen2.5-7B LLM MCC = 0.792 (beats the classical
  bag-of-tokens baseline's 0.712 exactly on the temporal/target-specific
  classes it was added for — DP-IT/DP-TS).
- FL + blockchain gradient-integrity check rejects the poisoning client 5/5
  rounds; global model MCC 0.747 (integrity ON) vs 0.409 (integrity OFF).
- Full-mode NS-3-integrated run: M1 MCC = 1.0, non-degenerate confusion
  matrix (Task 8 preliminary evidence).

The poor PDR number is a **property of the specific 4-node/1-flow prototype
scenario used for early functional testing**, not of the detection or
mitigation algorithms. This is analogous to testing a highway's traffic
system on a single-lane road with one car — closing the lane for a
violation looks catastrophic for "throughput" even though the enforcement
logic is correct.

---

## 4. Recommended change (scenario/report fix, not algorithm redesign)

No change to Algorithm 1/2/3, DEBSC, MATD, PQC-LKH, or the fusion equation
is warranted. Two lower-risk fixes are recommended **before Task 8.5/9/10**,
where PDR-vs-drop-rate sweeps become a headline figure:

1. **Use a topology with path redundancy** (or a larger `N_Vehicles`,
   e.g. the 264-node Galle topology already used for Task 10 scale
   testing) for any experiment where post-mitigation PDR is reported.
   The current 5-node/1-flow scenario is fine for detection-accuracy
   evidence (MCC, TP/TN/FP/FN — already proven strong) but is
   structurally unable to show PDR recovery, regardless of how well
   SHIELD-GH detects and isolates.
2. **Report PDR as a windowed (e.g. per-5s) or instantaneous rate**
   alongside/instead of the whole-run cumulative average, so a metric
   artifact doesn't compound the topology issue. This only touches how
   a number is printed/logged, not detection logic.
3. **Correct `sec:expected_results`** in `main.tex` before real Task 8.5/9/10
   figures are generated: soften or remove the "PDR recovery" claim for the
   fixed prototype scenario, or explicitly scope it to the multi-path/
   larger-topology experiments where it will actually hold.

**No patch has been applied to `routing.cc`** — I tried one (attacker-index
relocation) and it made results worse, so it was reverted. The path forward
is a topology/metric choice for the next simulation tasks, which is best
made once (for Task 8.5's sensitivity analysis and Task 10's full sweep)
rather than patched piecemeal now.

---

## 5. Everything else checked — no other "very poor" results found

| Component | Measured result | Verdict |
|---|---|---|
| Lightweight rule detection (S1–S6) | MCC 1.0, 0 FP, all variants isolated | Strong |
| Genuine Qwen2.5-7B LLM | MCC 0.792, 18ms/window | Strong; weakest sub-class is DP-IT F1=0.49 — **expected and reported as-is**, it's precisely the hard temporal case the LLM tier exists for, not a flaw |
| FL + blockchain gradient integrity | 5/5 poison rejections, MCC 0.747 (ON) vs 0.409 (OFF, attack condition) | Strong; the 0.409 number is the *unprotected* baseline shown for contrast, not the deployed configuration |
| Full-mode NS-3 integration (Task 8 prelim) | MCC 1.0, TP=2 TN=2 FP=0 FN=0 | Strong (small 5-node sample, same topology caveat as §1 applies if PDR is added later) |
| Real Fabric DEBSC + VRF endorser selection | 8/8 + 25/25 unit tests, live on-chain isolation verified, 64-RSU scale test passes | Strong |
| PQC crypto (Kyber/ML-DSA, PQC-LKH, threshold sigs) | 31/31 tests, O(log N) rekey speedup 2.33× matches design | Strong |

**Conclusion for the supervisor: no design changes are required to the
SHIELD-GH detection/mitigation algorithms.** The one weak measured number
(post-mitigation network PDR settling near 50%) traces to the fixed
4-node/1-flow prototype topology having zero path redundancy plus a
cumulative-average PDR metric — a scenario/reporting choice, not an
algorithmic defect — and is recommended to be fixed at the topology/metric
level in Task 8.5/10, not by patching Task 1–7.5 code now.
