# SHIELD-GH — 50 Simulation Diagnostic Questions: Answers with Evidence

**Purpose.** This document answers all 50 supervisor diagnostic questions with real
evidence pulled from this codebase — either (a) freshly-run simulations/scripts
captured during this investigation, or (b) existing evidence logs already in the
repo, cited exactly. No number in this document is invented. Where a question's
premise does not match what is actually implemented, or where the required
infrastructure/scale (200-vehicle runs, full Colombo map, full E1-E5 grid,
live multi-round FL) does not exist yet, that is stated explicitly rather than
papered over.

**Prototype topology, stated once for the whole document:** the current NS-3
scenario is hard-capped at `N_Vehicles = 4` (`routing.cc`, clamped to
`total_size = 5` array slots — see Q7-Q9, Q44, Q47). Task 9/9.5/10 (SOA
comparison, ablation, full 200-vehicle/264-node Galle experiment grid) are
**not yet run** per `scratch/tasks.md`. This one fact governs the honest
answer to a large fraction of the 50 questions and is not repeated in full
every time — see the individual answers for how it applies.

---

## Legend / Summary Table

| # | Status | One-line reason |
|---|--------|------------------|
| Q1 | ✅ Verified from live run | Fresh run, per-window Fwd/Rcv printed, drop rate computed by hand |
| Q2 | ⚠️ Partially answerable | DP-IT is a simple 5s on/off cycle in code, not "7.5s of 15s" — question's premise (T*=15s, 50/50 split) doesn't match the actual default; answered against real code/log behaviour |
| Q3 | ✅ Verified from live run | S3.log DP-TS per-node PDR; only target flow exercised in this topology |
| Q4 | ⚠️ Partially answerable | No literal "action=DROP,p_drop=ρ_a" flow-rule struct printed; CP-FR is a TAMPER-scale mechanism (scale=0.50), evidenced from S4.log |
| Q5 | ✅ Verified from existing evidence | S5.log CP-IT TAMPER timestamps confirm alternation, period ≈1s not toggling every T* |
| Q6 | ⚠️ Partially answerable | CP-TS conditions on target flow ID, not a documented "safety-critical class / whitelist W_BC" concept — that's a report abstraction; code confirmed |
| Q7 | ✅ Verified from live run | Fresh run, p=0%, drop_rate=0% → PDR=100.00% |
| Q8 | ✅ Verified from live run | Fresh run, p=100%, ρ_a=100% → PDR=0.00% |
| Q9 | ✅ Verified from live run | Fresh + existing run both show `round()`, not `floor()`, semantics |
| Q10 | ❌ Not executable as asked | No SUMO run at exactly v=10km/h exists; bridge script exists but untested at this speed |
| Q11 | ⚠️ Partially answerable | MATD is genuinely implemented but speed is hardcoded (13.9 m/s) in the live loop, not driven from SUMO/v=140 |
| Q12 | ⚠️ Partially answerable | Formula implemented; evaluated by hand from code constants (no run log does this) |
| Q13 | ⚠️ Partially answerable | τ_f=0.60 confirmed in code; no high-speed run exists (speed not varied) |
| Q14 | ⚠️ Partially answerable | 3 of 4 constants match main.tex exactly; R_RSU code default (500m) contradicts main.tex (270m) — real discrepancy |
| Q15 | ⚠️ Partially answerable | Variance/ε_f=0.20 implemented; only pass/fail boolean logged, not the raw σ² number |
| Q16 | ⚠️ Partially answerable | γ_it=1.30 implemented; fires in S4-S6 logs, not S2.log; raw ratio not logged |
| Q17 | ❌ Not executable with current evidence | τ_ts=0.50/KL-divergence implemented in code but never observed firing in any existing log |
| Q18 | ⚠️ Partially answerable | Reputation computed live every window; no persisted CSV found; update rule is a running mean, not guaranteed monotone |
| Q19 | ✅ Verified from existing evidence | S1.log shows `ZKP=FAIL` for the attacker |
| Q20 | ❌ Not executable — feature absent | Only a 2-state (PASS/FAIL) ZKP model is implemented; ABSENT state doesn't exist in code despite being specified in main.tex |
| Q21 | ❌ Not executable with current evidence | No 0%-attacker log exists; reasoned from code only |
| Q22 | ✅ Verified from live code read | Two isolation paths exist: DEBSC AND-gate (stat∧ZKP) and a separate OR-bypass (3 consecutive stat signatures alone) — no 3-way stat/ZKP/both counter exists |
| Q23 | ✅ Verified from existing evidence | S1.log confusion matrix quoted |
| Q24 | ✅ Verified from live computation | MCC/accuracy hand-computed and matches printed values exactly |
| Q25 | ❌ Not executable — structural limitation | M2/GHSR has never produced a real number in this topology (no redundant path) |
| Q26 | ⚠️ Partially answerable | No clamp in code; overshoot is possible by formula inspection, not observed (no real M2 value exists yet) |
| Q27 | ✅ Verified from existing evidence | M4=0.0, legit count matches N(1-p) coincidentally at this N |
| Q28 | ✅ Verified from existing evidence | ESRL=948ms vs (t_isolate-t_onset)=900ms; 48ms display-precision gap explained |
| Q29 | ❌ Not executable — feature absent | 4-stage decomposition not instrumented in code (only 2 timestamps exist) |
| Q30 | ✅ Verified from live run | Real liboqs ML-DSA-87/ML-KEM-1024 timings measured; note the checked-in M6 evidence actually uses ML-DSA-44/Kyber-768 |
| Q31 | ✅ Verified from existing evidence | PQC-LKH tests assert exact ⌈log2 N⌉ at N=4,8,16 |
| Q32 | ⚠️ Partially answerable | Formula/tests confirm O(log N) at tested N; N=128/200 specifically not in any test, only extrapolated |
| Q33 | ✅ Verified from live run | Fallback LLM backend run on synthetic FWD tokens, real softmax printed |
| Q34 | ✅ Verified from live run | Same, DRP tokens, DP-FR highest as expected |
| Q35 | ❌ Not executable with current evidence | ε_u=0.15 exists but escalation-rate statistic over 100 inputs never measured/logged |
| Q36 | ✅ Verified from existing evidence | SHA-256 commit/verify code confirmed, real hash path |
| Q37 | ✅ Verified from existing evidence | Poison rejection confirmed 5/5 (1 poisoner over 5 rounds) |
| Q38 | ❌ Not executable — feature absent | Only final-round MCC measured (0.747 vs 0.409); no per-round (1,3,5) progression logged |
| Q39 | ✅ Verified from existing evidence | S4.log Tc: 0.65→0.30→0.00 across CP-FR detections |
| Q40 | ⚠️ Partially answerable | A boolean sub-threshold flag exists; not a continuous accumulating Ψ_c(t) state variable |
| Q41 | ⚠️ Partially answerable | Failover triggers correctly (Tc<0.4); but it's single-controller RSU-quorum whitelist reinstall, not multi-controller "lowest-ranked ordered list" selection (that logic is main.tex-only, unimplemented in C++) |
| Q42 | ✅ Verified from existing evidence | Go VRF endorser code + explicit determinism unit test found in SHIELD-GH's own blockchain, not LORIS |
| Q43 | ✅ Verified from existing evidence | θ_RSU=0.5 trust filter confirmed in endorser_vrf.go |
| Q44 | ❌ Not executable — not yet run | Task 10 (E1 grid) not started; zero (p,ρ_a) sweep results exist |
| Q45 | ❌ Not executable — not yet run | E4/AEI equations exist in main.tex only; zero code implementation, zero runs |
| Q46 | ✅ Verified from existing evidence | B1 (Malik) confirmed data-plane-only by its own README; S4 vs B1 is a designed N/A, not a bug |
| Q47 | ⚠️ Partially answerable | Only Galle map exists (no Colombo anywhere in repo) — question's premise is wrong; Galle stats reported instead |
| Q48 | ❌ Not executable with current evidence | No dual-run comparison exists; ns-3 default fixed-seed behaviour makes determinism plausible but unverified |
| Q49 | ✅ Verified from live run | `results/blockchain_log.csv` located, size/first/last line printed |
| Q50 | ✅ Verified from existing evidence | Raw TP/TN/FP/FN confirmed printed alongside MCC in S1.log; same code path for S2-S6 |

---

# Category 1 — Attack Injection Correctness (Q1–Q9)

## Q1. S1 (DP-FR): per-slot n_i^fwd / n_i^rx for the attacker, actual drop rate

**Command run (fresh, this session):**
```
LD_LIBRARY_PATH=$PWD/build/lib:$PWD/build ./build/scratch/routing \
  --detection_mode=lightweight --routing_test=1 --attack_number=1 --drop_rate=50 \
  --attack_percentage=50 --simTime=15 --routing_algorithm=4 --architecture=0 --maxspeed=80
```
Per-window Node 0 (attacker) `Fwd/Rcv` across the first 10 windows (`LocalPDR=... (Fwd=x/Rcv=y)`):
```
(3,5) (3,3) (3,4) (3,7) (3,6) (2,9) (3,5) (2,9) (2,9) (3,4)
```
```
Σfwd = 27, Σrcv = 61
actual drop rate = 1 - 27/61 = 0.5574
```
Configured `drop_rate = 50` (i.e. ρ_a = 0.50).

**Answer:** NOT within ±0.01 of ρ_a for this single node/run — measured 0.5574 vs
expected 0.50 (Δ=0.057). This is a genuine per-packet Bernoulli process
(`rand()%100 < drop_rate` in `routing.cc`) over a small sample (61 packets);
at this n, a binomial 95% CI around p=0.5 is roughly ±0.13, so 0.557 is
statistically consistent with ρ_a=0.50, just not tight to ±0.01. A companion
node (Node 1, also forced attacker at 40%/50% sweep) measured 0.6786 over 56
packets (z≈2.7σ from 0.50) — still plausible under small-sample noise but a
visibly looser match. **Honest conclusion: the mean drop behaviour tracks
ρ_a correctly in expectation (code implements exactly `P(drop)=drop_rate/100`
per packet), but at N=4-node/short-window scale the empirical per-run drop
rate is not guaranteed to land within ±0.01 of ρ_a — that tolerance requires
many more packets than this prototype topology generates in 10 windows.**

---

## Q2. S2 (DP-IT) at d=0.5, T*=15s: malicious/benign epoch sequence

**Evidence:** `routing.cc` line 144, `double intermittent_period = 5.0;` (default,
**not 15s**), and the on/off logic at lines 973-974/1121-1122:
```cpp
double cycle = fmod(now - attack_start_time, 2.0 * intermittent_period);
bool attack_on = (cycle < intermittent_period);
```
This is a symmetric 50/50 on/off cycle of length `2*intermittent_period`, default
`2*5.0=10s` total period (5s malicious / 5s benign), not the T*=15s / 7.5s-of-15s
split the question assumes. Timestamped evidence from `shield_gh/evidence/S2.log`:
```
249:Attackers declared at t=1.1
276-285: DP-IT DROP (t≈1.10–1.127, malicious epoch)
287-313: DP-IT FORWARD (t≈1.129–1.207, benign epoch)
415:     DP-IT FORWARD (t=2.10, still benign — cycle wrapped)
420-441: DP-IT DROP (t≈2.13, malicious epoch resumes)
```
**Answer:** The attacker's malicious/benign epochs are real and timestamped, and
they do alternate — but under the code's actual default (`intermittent_period=5.0s`,
giving a 10s total cycle: 5s malicious + 5s benign), **not** the question's
assumed T*=15s/7.5s split. `intermittent_period` is a CLI-overridable parameter
(`--intermittent_period=7.5` would produce a 15s cycle with 7.5s malicious
epochs), but no run in this repo has been executed with that value — the
question's specific T*=15s/7.5s scenario has not been produced. This is
reported honestly rather than reinterpreting the default run to fit the
question.

---

## Q3. S3 (DP-TS): per-source PDR at the attacker

**Evidence:** `shield_gh/evidence/S3.log`, per-node PDR block (repeated per window),
e.g.:
```
Node 0 | LocalPDR=0.00% (Fwd=0/Rcv=12) | E2E_PDR=0.00% (0/3) | ... [DP-ATTACKER]
Node 1 | LocalPDR=100.00% (Fwd=1/Rcv=1) | E2E_PDR=0.00% (0/0) | RelayPDR=25.00% (Fwd=1/Rcv=4)
Node 2 | LocalPDR=100.00% (Fwd=1/Rcv=1) | E2E_PDR=0.00% (0/0) | RelayPDR=25.00% (Fwd=1/Rcv=4)
Node 3 | LocalPDR=100.00% (Fwd=1/Rcv=1) | E2E_PDR=100.00% (1/1)
```
DP-TS code (`routing.cc` line ~1148): only drops packets on `flow_id ==
grey_hole_target_flow` (default target flow=0); all other flows are
unconditionally forwarded (`DP-TS FORWARD (non-target)`). In this particular
run window, `grep -c "DP-TS FORWARD (non-target)"` on `S3.log` returns **0** —
only the target flow (flow 0) was exercised by this specific traffic pattern,
so no non-target-flow forwarding events appear in this log to independently
confirm the "all others ≈1.0" claim beyond the other 3 nodes' relay/local PDR.

**Answer:** Targeted-source (Node 0, flow 0) local PDR = 0.00% after isolation
(fully dropped, ≈1-ρ_a pre-isolation per the S1-style Bernoulli mechanism —
see Q1), and the three non-attacker nodes (1,2,3) show 100% local PDR —
consistent with "all others ≈1.0". The DP-TS-specific "only the target flow
is dropped" behaviour is confirmed in code, but this particular log has no
non-target-flow traffic through the attacker to directly demonstrate
selective forwarding by flow ID (only by node).

---

## Q4. S4 (CP-FR): flow rules from the compromised controller

**Evidence:** `shield_gh/evidence/S4.log`:
```
97: CP Attack state: CP-FR (Fixed Rate) ACTIVE
280-295: CP-FR TAMPER: node=0 flow=0 scale=0.50 t=2.04   (repeated for all node×flow pairs)
209: [SHIELD-GH][CP] Controller 0 grey-hole flow rule detected | S4=1 S5=0 S6=0 | Tc=0.65 | t=2.00
```
**Answer:** CP-FR is **not** implemented as a literal `{action: DROP, p_drop:
ρ_a}` flow-rule record printed per-rule — the actual mechanism is a
**tamper-scale multiplier** (`scale=0.50`) applied to all flow rules the
compromised controller issues to every node×flow pair, at a fixed cadence
(~every simulated second: t=2.04, t=3.04, ...). This scale factor plays the
same functional role as a drop probability (it degrades legitimate forwarding
by that factor) but the question's specific "print action/p_drop fields of a
flow-rule struct" does not correspond 1:1 to what's coded. `scale=0.50`
matches the CLI default `drop_rate=50` → ρ_a=0.50 by construction (both use
the same `drop_rate` global), so functionally action≈DROP with p_drop≈ρ_a
holds, just not via a printed struct with those exact field names.

---

## Q5. S5 (CP-IT): controller flow rule install timestamps, alternation

**Evidence:** `shield_gh/evidence/S5.log`:
```
97:  CP Attack state: CP-IT (Intermittent) ACTIVE
278-293: CP-IT TAMPER: node=X flow=Y t=2.04   (all 16 node×flow pairs)
412-...: CP-IT TAMPER: node=X flow=Y t=3.04   (repeats)
```
Grepping the full 60s of `S5.log` for `CP-IT TAMPER` timestamps shows tamper
events recurring roughly once per simulated second (t=2.04, 3.04, 4.04, ...),
not alternating DROP/FORWARD blocks at a period T* the way DP-IT does. There
is no `CP-IT FORWARD`/off-period counterpart logged — CP-IT in this code
tampers **every controller flow-rule-push cycle**, it does not toggle
malicious/benign in the same on/off sense as the data-plane DP-IT.

**Answer:** No — the controller-plane CP-IT does not alternate DROP/FORWARD
at period T* the way the question assumes (that's the DP-IT pattern). CP-IT
tampers continuously at every ~1s controller update in this implementation;
the "intermittent" naming reflects periodic controller *rule pushes*, not an
on/off attack duty cycle. This is a real discrepancy between the question's
assumed CP-IT semantics and the code's actual CP-IT semantics, reported
honestly.

---

## Q6. S6 (CP-TS): match fields of drop rules, whitelist W_BC

**Evidence:** `shield_gh/evidence/S6.log`:
```
97: CP Attack state: CP-TS (Target Specific) ACTIVE
280: CP-TS TAMPER (target flow=0): node=0 flow=0 t=2.04
281-283: CP-TS NO TAMPER (non-target flow): node=0 flow=1/2/3
346: [SHIELD-GH][CP-MIT] Controller 0 FAILOVER — Tc=0.30 < θc=0.40 | RSU threshold
     FlowMod 3/3 co-signed, quorum_ok=1 | whitelist-only rules reinstalled | t=3.00
```
Grep for `whitelist`/`W_BC` in the C++ source (`routing.cc`, `shield_gh/`)
finds exactly one code site — `shield_gh_integration.h` lines 521, 537 — the
**mitigation** side (a whitelist-only rule set is installed after failover),
not a detection-side "conditioned on safety-critical class, absent from
whitelist" match field on the tampered rules themselves.

**Answer:** The match field CP-TS actually conditions on is `flow_id ==
grey_hole_target_flow` (an integer flow ID, default 0) — a literal flow-ID
match, not a semantic "safety-critical message class" concept. The
"whitelist W_BC" idea does exist in code, but only on the *mitigation* side
(post-failover whitelist reinstall), not as a detection-time match-field
condition. The question's framing ("conditioned only on safety-critical
class, absent from whitelist W_BC") is a main.tex-level abstraction that
does not map directly onto the CP-TS implementation, which is simpler
(flow-ID targeting).

---

## Q7. p=0%, ρ_a=0%: network-wide avg PDR (200 vehicles)

**Command run (fresh, this session):**
```
LD_LIBRARY_PATH=$PWD/build/lib:$PWD/build ./build/scratch/routing \
  --detection_mode=lightweight --routing_test=1 --attack_number=1 --drop_rate=0 \
  --attack_percentage=0 --simTime=10 --routing_algorithm=4 --architecture=0 --maxspeed=80
```
```
average packet delivery ratio is 100.00
```
**Answer:** PDR = 100.00% ≥ 0.97 — **yes, condition satisfied**. Caveat (honest,
not fabricated): this is **not** a 200-vehicle run — `N_Vehicles` is
hard-capped at 4 in this prototype (`routing.cc`: `if (N_Vehicles >
(uint32_t)total_size) N_Vehicles = total_size;`, `total_size=5`). Also, even
at `attack_percentage=0`, the code forces a minimum of 1 "attacker" node
(`if(num_attackers==0) num_attackers=1`), but with `drop_rate=0` that
attacker never actually drops a packet, so the network-wide behaviour is
genuinely clean. The 200-vehicle scale this question asks for requires Task
10, not yet executed.

---

## Q8. p=100%, ρ_a=100%: network-wide PDR

**Command run (fresh, this session):**
```
LD_LIBRARY_PATH=$PWD/build/lib:$PWD/build ./build/scratch/routing \
  --detection_mode=lightweight --routing_test=1 --attack_number=1 --drop_rate=100 \
  --attack_percentage=100 --simTime=10 --routing_algorithm=4 --architecture=0 --maxspeed=80
```
```
Forcing exactly 4 attackers out of 4 vehicles
average packet delivery ratio is 0.00   (repeated every window, e.g. lines 226, 365, 493, ... 1328)
Node TP=2 TN=0 FP=0 FN=2   M1a Detection Accuracy: 50.00%   M1b MCC: 0.00
```
**Answer:** PDR = 0.00% ≤ 0.03 — **yes, condition satisfied.** Same N=4
topology caveat as Q7 applies. Side finding: at 100% attacker density, node
detection MCC degrades to 0.00 (TP=2,TN=0,FP=0,FN=2) because there are no
benign nodes left to form a non-degenerate confusion matrix and 2 of the 4
attacker nodes are FN (not flagged this window) — an honest, real artifact
of saturating the whole topology with attackers, not a detector bug.

---

## Q9. p=40%: exact attacker/legit counts at t=30s

**Evidence (existing):** `shield_gh_ml/logs/task9_t30s_ap40_run_postfix.log`:
```
Forcing exactly 2 attackers out of 4 vehicles
```
**Evidence (fresh, this session, `--attack_percentage=40 --simTime=30`):**
```
Forcing exactly 2 attackers out of 4 vehicles
Node 0 forced as ATTACKER
Node 1 forced as ATTACKER
Attackers declared at t=1.1
```
Code (`routing.cc` line 494): `num_attackers = (uint32_t)round((attack_percentage
/ 100.0) * N_Vehicles);` — this uses **`round()`, not `floor()`**.

```
floor(0.4 * 4) = 1        (question's assumed formula)
round(0.4 * 4) = round(1.6) = 2   (what the code actually computes)
```

**Answer:** Does **not** match `floor(0.4N)=1` and `N-floor(0.4N)=3` as the
question assumes. The code produces exactly **2 attackers, 2 legitimate
nodes** (confirmed identically in both a pre-existing evidence log and a
fresh run), because it rounds rather than floors. This is a genuine,
reproducible discrepancy between the question's assumed rounding convention
and the actual code — reported as found, not adjusted to match the
question.

---

# Category 2 — MATD and Mobility (Q10–Q14)

## Q10. E2 at v=10km/h: avg vehicle speed from sumo_ns3_bridge.py

**Evidence:** `scratch/sumo/sumo_ns3_bridge.py` is a real TraCI bridge script
(docstring: "Provides realistic vehicle speeds for MATD (Eq. 3.4, 3.17)"),
writing `results/sumo_speeds.csv` with `speed_kmh` columns. Its two configured
scenarios are `urban_scenario.sumocfg` ("Low-speed vehicles, 20-50 km/h") and
`highway_scenario.sumocfg` ("High-speed vehicles, 80-120 km/h").

**Answer:** ❌ Not executable as asked. **No SUMO scenario in this repo is
configured for v=10km/h** — the two existing scenarios cover 20-50 km/h
(urban) and 80-120 km/h (highway) bands only. No log shows this bridge
script having actually been run and printing an average speed for any
scenario. Producing a genuine 10±0.5 km/h data point would require either a
new low-speed SUMO route file or clamping vehicle max-speed in an existing
scenario — neither exists today.

---

## Q11. E2 at v=140km/h: raw vs MATD-corrected PDR for 3 legit nodes

**Evidence:** `shield_gh/detection/matd.h`/`matd.cc` implement a genuine
`MobilityAwareTrustDecay` class (`ComputeHandoffLoss` = Eq. 3.4,
`CorrectPDR` = Eq. 3.5, `ApplyMobilityDecay` = Eq. 3.17), instantiated at
`shield_gh_integration.h:88` and invoked every detection window
(`shield_gh_integration.h:638-644`, `g_sg_matd.CorrectPDR(obs_pdr, speed)`).
**However**, the `speed` variable fed into it is a hardcoded constant:
```cpp
double speed = 13.9; // m/s — override from SUMO bridge if available
```
This is **never actually overridden** by SUMO or by any per-node velocity in
any run this investigation found — `speed` is always 50 km/h (13.9 m/s)
regardless of the CLI `--maxspeed` flag used in the S1-S6/task8/task9 runs.

**Answer:** ⚠️ MATD's math is real and runs every window, but there is **no
run in this repo where speed is actually varied to 140 km/h** — the pipeline
always corrects against a fixed 50 km/h assumption. No raw-vs-corrected PDR
comparison at v=140 km/h exists. Producing one would require wiring the
hardcoded `speed = 13.9` to a live SUMO feed or CLI override, which is not
currently done.

---

## Q12. ρ_ho(v_i,t) at v=10 and v=140 km/h

**Evidence:** `matd.cc`: `ComputeHandoffLoss(speed_mps) = speed_mps *
m_delta_t_ho / m_R_RSU * m_rho_max`. Using the code's actual live constructor
values (`shield_gh_integration.h:88`: `R_RSU=500.0, delta_t_ho=0.5,
rho_max=0.3`):
```
v=10 km/h  = 2.778 m/s -> rho_ho = 2.778*0.5/500*0.3 = 0.000833
v=140 km/h = 38.89 m/s -> rho_ho = 38.89*0.5/500*0.3 = 0.011667
ratio = 0.011667 / 0.000833 = 14.0x
```
**Answer:** Computed by hand (no log evaluates this directly) using the code's
own formula and default constants — the ratio is **exactly 14.0x**, matching
the question's "≈14x" expectation (this is a linear formula in speed, so the
ratio is mathematically forced to equal the speed ratio, 140/10=14, regardless
of the other constants — it would hold true even with main.tex's stated
R_RSU=270m instead of the code's 500m). Note the code's R_RSU constant
(500m) contradicts main.tex's documented value (270m) — see Q14.

---

## Q13. No attackers at v=140km/h: legit nodes triggering S1 (PDR<τ_f=0.60)

**Evidence:** `shield_gh/detection/attack_signatures.h`: `S1_FixedRate(...,
double tau_f = 0.6, double epsilon_f = 0.20)`, confirmed default never
overridden anywhere in the codebase. Since speed is hardcoded (Q11), there is
no run that exercises v=140km/h specifically, and no clean no-attacker run
exists (see Q21) to check for legit-node false positives at that speed.

**Answer:** ❌ Not executable with current infrastructure. τ_f=0.60 is
confirmed correct in code, but the specific experiment (no attackers,
v=140km/h, count of legit nodes falsely triggering S1) cannot be produced
without (a) a clean/no-attacker run and (b) actual speed variation, neither
of which exist today (see Q10/Q11/Q21).

---

## Q14. λ_s, R_RSU, Δt_ho, ρ_max as used in sim

**Code (`shield_gh_integration.h:88`):**
```cpp
static MobilityAwareTrustDecay g_sg_matd(500.0, 0.5, 0.3, 0.01, 1.0);
// constructor order: R_RSU, delta_t_ho, rho_max, lambda_s, (5th param)
```
**main.tex (lines 3912-3915, 4044):**
```
R_RSU = 270m,  Delta t_ho = 0.5s,  rho_max = 0.30,  lambda_s = 0.01
```

| Constant | Code value | main.tex value | Match? |
|---|---|---|---|
| λ_s | 0.01 | 0.01 | ✅ |
| Δt_ho | 0.5 s | 0.5 s | ✅ |
| ρ_max | 0.3 | 0.30 | ✅ |
| R_RSU | **500.0 m** | **270 m** | ❌ |

**Answer:** 3 of 4 match exactly. **R_RSU does not match** — the running
code uses 500.0m as the MATD coverage radius, while main.tex (and the
separate RSU-deployment settings table, "$8\times8$ grid, 250m spacing,
R=270m coverage") documents 270m. This is a genuine, previously
unflagged code/report discrepancy, reported here as found.

---

# Category 3 — Signature Detection and DEBSC (Q15–Q22)

## Q15. σ²_i(W) for attacker at end of first window, vs ε_f=0.20

**Evidence:** `blockchain_ledger.cc` implements `ComputePDRVariance` (Eq. 3.3);
`attack_signatures.cc`: `return (corrected_pdr < tau_f) && (variance <
epsilon_f);` with `epsilon_f=0.20` default, confirmed never overridden.
`S1.log` shows the attacker's `corrPDR` values (e.g. `corrPDR=0.12`,
`corrPDR=0.50`) triggering S1 repeatedly — all below τ_f=0.60.

**Answer:** ⚠️ The variance computation and the ε_f=0.20 threshold are both
genuinely implemented and exercised (S1 fires on the attacker in every S1.log
window). **However, the raw σ² number itself is never printed to any log** —
only the pass/fail boolean (`S1:1`) and `corrPDR` are logged. No existing
evidence file contains a literal numeric σ²_i(W) value; producing one would
require adding a print statement to `attack_signatures.cc`, which was not
done as part of this investigation (out of scope — no source changes were
made).

---

## Q16. R_mi(T*) for attacker vs γ_it=1.30

**Evidence:** `attack_signatures.h`: `S2_Intermittent(..., double gamma_it =
1.3, ...)`, confirmed exact default. Implementation computes an
autocorrelation-based ratio compared against `gamma_it`. Grep across all six
evidence logs for `S2:1` (S2 firing) shows **zero hits in `S2.log` itself**
(despite the filename) — S2 actually fires in the controller-plane logs
instead, e.g. `S5.log:1053`: `S1:1 S2:1 S3:0`.

**Answer:** ⚠️ γ_it=1.30 confirmed exact in code, and S2 does genuinely fire
in some captured runs (just not the file literally named `S2.log`, which only
shows S1 firing on its DP-FR-style attacker). The raw R_mi ratio value is
never printed anywhere — only the boolean. No number to report for "print
R_mi(T*)"; the file naming (S2.log) does not correspond to "the run where S2
fires," which is a documentation/naming gap worth flagging.

---

## Q17. D_KL(P_PDR||U) for attacker vs τ_ts=0.50

**Evidence:** `attack_signatures.cc` computes a real KL-divergence:
`kl_div += pdr * log(pdr/uniform + 1e-9)`, compared against `tau_ts=0.5`
(confirmed exact default). Grep across **all** evidence logs
(`shield_gh/evidence/*.log`) for `S3:1` (the S3 rule firing) returns **zero
hits anywhere**, including in the file literally named `S3.log`.

**Answer:** ❌ Not executable with current evidence. The KL-divergence
formula and τ_ts=0.50 threshold are genuinely coded, but **S3 has never been
observed to fire in any log in this repository** — not even in the run
ostensibly demonstrating it. This signature appears implemented but
untested/unexercised in practice under the scenarios run so far — a real
limitation, not a fabricatable number.

---

## Q18. Blockchain reputation R_i(t) after 5/10/20 windows, monotonic?

**Evidence:** `blockchain_ledger.cc`: `ComputeReputation` (Eq. 3.18) — a
running mean of per-window trust values, invoked every window
(`shield_gh_integration.h:647`: `double R_i = g_sg_ledger.ComputeReputation(n,
t);`). A CSV write path exists (`results/blockchain_log.csv`, confirmed to
exist on disk — see Q49 for its actual header/content) with a `reputation`
column, but no run was found where reputation is tracked and printed at
exactly windows 5/10/20 for one node in isolation.

**Answer:** ⚠️ Reputation is genuinely computed and drives DEBSC every
window (real, wired code, real CSV output). But (a) no evidence isolates the
values at windows 5/10/20 specifically, and (b) the update rule is a running
*average*, not a rule designed to be strictly monotonically decreasing — it
can rise again if a node behaves well after a bad window. "Monotonically
decreasing" is not an accurate characterization of the implemented update
rule; it trends downward under sustained attack but is not guaranteed
monotone by construction.

---

## Q19. Π_ZKP for a dropping attacker — should be FAIL

**Evidence:** `shield_gh/evidence/S1.log`:
```
[LW-DP-Det] Node 0 SUSPECTED — S1:1 S2:0 S3:0 corrPDR=0.12
[SHIELD-GH-ISOLATE] Node 0 blocked, dropping flow 0 t=5.10
```
Full-mode evidence (`TASK8_EVIDENCE.md`): `ZKP=FAIL real_attacker=1` when the
dropping node's proof commitment fails to match its observed forward count
(`zkp_proofs.cc`: `GenerateProof` sets `valid=false` when `commit.n_fwd !=
observable_count`).

**Answer:** ✅ Confirmed — the dropping attacker's ZKP is genuinely computed
and evaluates to FAIL, matching the expectation exactly.

---

## Q20. Attacker withholds ZKP proof — should be ABSENT (3-state model)

**Evidence:** `zkp_proofs.h`/`zkp_proofs.cc` implement only a **binary**
`ZKPProof.valid` (true/false). `DEBSC::RecordZKPResult(node_id, t, bool
proof_valid)` also takes a plain bool. Grep of the entire `shield_gh/` tree
for `ABSENT`, `zkp_status`, or any 3-state enum: **zero hits**. Every
detection window unconditionally calls `CreateCommitment` + `GenerateProof`
for every node (`shield_gh_integration.h:566-568`) — a proof is never
withheld or missing in the current implementation.

By contrast, **main.tex explicitly specifies and requires** a three-state
model (`main.tex:2204`, "SUPERVISOR REVISION BLOCK 5: three-state ZKP";
`main.tex:2213-2236`: *"The original two-state ZKP model (PASS or FAIL)
contains a critical [flaw]... The complete three-state model... ABSENT...
the proof submission deadline per observation window"*).

**Answer:** ❌ Not executable — the feature does not exist. Only a 2-state
(PASS/FAIL) model is actually implemented in code, despite main.tex
documenting and mandating a 3-state PASS/FAIL/ABSENT model as a fix for a
flaw the report itself calls "critical." This is a genuine gap between the
approved report design and the shipped code — reported honestly rather than
simulating an ABSENT case that the code cannot actually produce.

---

## Q21. No attackers: total DEBSC isolation events over 300s

**Evidence:** No log with `attack_percentage=0` and a full detection pass
(clean run) was found anywhere in `shield_gh/evidence/` or
`shield_gh_ml/logs/`. Code logic (`shield_gh_integration.h:698-704`):
isolation requires either the DEBSC AND-gate (statistical + ZKP fail) or 3
consecutive statistical detections — with no attacker present and PDR
staying ≥τ_f, this logic predicts zero isolations, but that is an inference
from reading the code, not an observed result.

**Answer:** ❌ Not executable with current evidence. No genuinely
clean/no-attacker 300s run exists in the repo. Code-logic reasoning (not
verified execution) predicts 0 isolation events would occur, but this would
need an actual run — e.g. `--attack_number=1 --drop_rate=0
--attack_percentage=0` for 300s — to state as a measured fact rather than an
expectation. (The Q7 run above is a short version of this at 10s/PDR=100%,
which is consistent with, but not identical to, this specific 300s/0-isolation
claim.)

---

## Q22. p=40%: stat-gate-only / ZKP-gate-only / both-fired node counts

**Evidence:** Two distinct isolation-gating mechanisms exist in the code:
1. `debsc.cc` (`DEBSC::ShouldIsolate`): a genuine **AND-gate** —
   `return statistical_gate && zkp_failed;` (comment: "BOTH must be true to
   trigger isolation").
2. `shield_gh_integration.h:698-704` (the actual live wiring): `should_isolate
   = (response == IsolationDecision::ISOLATE || sustained) && !already_isolated`,
   where `sustained` = 3 consecutive statistical-signature detections **with
   no ZKP requirement at all** — an explicit OR-bypass, commented: *"Isolate
   if EITHER the DEBSC reputation gate fires... OR a signature has fired for
   N consecutive windows (stealthy attackers like DP-IT/DP-TS whose
   reputation stays high)."*

**Answer:** ⚠️ There is no distinct 3-way counter tracking "stat-only" vs
"ZKP-only" vs "both-fired" nodes anywhere in the code or logs — those
categories aren't instrumented as separate metrics. More importantly, the
question's premise ("only both-fired should be isolated") does **not** match
the live implementation: `shield_gh_integration.h` deliberately isolates on
statistical signatures ALONE after 3 consecutive windows, bypassing the ZKP
requirement entirely, specifically to catch stealthy attackers. This is a
documented design decision (not a bug), but it means a "ZKP-gate-only" or
"stat-gate-only" isolation *can* happen via the sustained-signature path,
contradicting the question's AND-only assumption.

---

# Category 4 — Metric Computation (Q23–Q32)

## Q23. TP/TN/FP/FN for one S1 run

**Evidence:** `shield_gh/evidence/S1.log`:
```
=== SHIELD-GH DETECTION METRICS (node-level) ===
  Node TP=1 TN=3 FP=0 FN=0
  M1a Detection Accuracy: 100.00%
  M1b MCC: 1.00
```
(An earlier window in the same log also shows a degenerate case: `Node TP=0
TN=3 FP=0 FN=1`, before the attacker is first correctly flagged.)

**Answer:** ✅ TP=1, TN=3, FP=0, FN=0 (steady-state, post-detection window).

---

## Q24. MCC and accuracy for the same run

```python
TP, TN, FP, FN = 1, 3, 0, 0
MCC = (TP*TN - FP*FN) / sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN))
    = (1*3 - 0*0) / sqrt(1*1*3*3) = 3/3 = 1.0
Accuracy = (TP+TN)/(TP+TN+FP+FN) = 4/4 = 1.0
```
Log prints: `M1a Detection Accuracy: 100.00%`, `M1b MCC: 1.00` — **exact
match** to hand computation.

For the earlier degenerate window (`TP=0 TN=3 FP=0 FN=1`): MCC numerator =
0, and the denominator includes a zero factor `(TP+FN)=1,(TP+FP)=0` →
denominator=0 → MCC is mathematically undefined and the code reports 0 by
convention, matching the printed `M1b MCC: 0`. Accuracy=(0+3)/4=75%, matches.

**Answer:** ✅ Both formulas verified correct and the two metrics genuinely
differ in the degenerate case (Accuracy=75% but MCC=0, correctly reflecting
that raw accuracy is misleading on an imbalanced/degenerate confusion
matrix) — MCC and accuracy do **not** always agree, exactly as the metric
choice is supposed to demonstrate.

---

## Q25. M2 (GHSR): PDR_baseline/attack/post

**Evidence:** `shield_gh_ml/logs/task9_t30s_ap40_run_postfix.log`, every
occurrence (11 total) of the M2 line reads identically:
```
[M2]  GHSR: NOT MEASURABLE this run -- no pre-attack baseline window exists
      (attackers active from t=1.1s, before the first full-mode evaluation
      window; needs a run with attack_number=0 for N windows first, or a
      delayed attack-onset run)
```
`TASK8_EVIDENCE.md` documents a follow-up attempt with `--attack_onset_delay=6.0`
where `PDR_baseline=1.0` was successfully sampled, but `ALT_ROUTE_EXISTS`
(the Task 7.75 route-availability gate) evaluated false for every attacker
node every window in this 4-node/1-flow topology — there is genuinely no
alternate path — so full isolation never completes and the "post-isolation"
phase never begins, leaving M2 "not yet computable" even with a working
baseline.

**Answer:** ❌ Not executable — structural limitation, not a bug. **No run in
this codebase has ever produced a real numeric M2 (GHSR) value.** This
matches the same limitation already documented in
`TASK7_75_DESIGN_REVIEW.md` and `TASK8_EVIDENCE.md`: the 4-node/1-flow
prototype has zero path redundancy, so the route-availability gate (correctly)
never allows full isolation, and GHSR — which requires a genuine
post-isolation PDR recovery phase — cannot be computed here regardless of
code correctness. A topology with at least one redundant path (Task 8.5/10)
is required.

---

## Q26. M2 clamp to [0,1]; can PDR_post > PDR_baseline?

**Evidence:** `shield_gh_integration.h`:
```cpp
double ghsr = (pdr_post - pdr_attack) / (pdr_base - pdr_attack);
```
No `min()`/`max()`/clamp call appears anywhere near this line or the
surrounding M2 block.

**Answer:** ⚠️ No clamp exists in code. By formula inspection, if
`pdr_post` overshoots `pdr_baseline` (e.g. post-mitigation load-balancing
happens to route traffic better than the original pre-attack baseline),
GHSR > 1.0 is mathematically possible and would print unclamped. This is a
code-review finding, not an observed run — since no run has ever produced a
real M2 value at all (Q25), there is no actual case in this repo where
PDR_post > PDR_baseline was observed; the clamp gap is a latent risk, not a
demonstrated bug.

---

## Q27. M4 (FIR): |V_legit| and isolated-legit count

**Evidence:** `shield_gh_ml/logs/task9_t30s_ap40_run_postfix.log`:
```
[M4] FIR: 0.0 (0/2 legitimate vehicles ever falsely isolated)
```
Code (`shield_gh_integration.h`): `fir = false_isolated.size() /
g_sg_legit_nodes.size()`, where `g_sg_legit_nodes` is populated by actually
*observing* non-attacker node IDs during the run, not by a closed-form
`N*(1-p)` computation.

```
N*(1-p) = 4*(1-0.5) = 2   (matches the observed |V_legit|=2 in this log)
```

**Answer:** ✅ |V_legit|=2 matches `N(1-p)=2` at this run's parameters
(N=4, p≈50%-equivalent — 2 attackers forced). Note this is agreement by
coincidence of the fixed small-N topology and the code's `round()`-based
attacker count (see Q9), not because the code literally computes `N*(1-p)`
— it counts observed legit nodes empirically. isolated-legit count = 0, so
FIR = 0/2 = 0.0, matching the printed value exactly.

---

## Q28. M5 (ESRL): t_onset, t_isolate, isolate>onset?

**Evidence:** `TASK8_EVIDENCE.md`:
```
[M5] ESRL: 948.0 ms (t_onset=1.1 t_response=2.0 -- onset to GRADUATED
     RESPONSE (rate-limit); full isolation withheld by the route-availability
     gate, no alternate path in this topology)
```
```
(2.0 - 1.1) * 1000 = 900 ms   vs printed 948.0 ms   -> 48 ms discrepancy
```
**Answer:** ✅ isolate/response (t=2.0) > onset (t=1.1) — confirmed. ESRL
formula `= t_response - t_onset` holds in principle, but the printed 948ms
does not exactly equal the naive (2.0-1.1)*1000=900ms computed from the
**displayed, rounded** timestamps. This is because the console print
truncates `t_onset`/`t_response` to 1 decimal for readability while the
internal computation uses full double precision (NS-3 event-scheduler
timestamps are not exactly on 0.1s boundaries) — the real underlying
`attack_start_time` and `response_time` doubles carry sub-decimal precision
that the display rounds away. This is a **display-precision gap, not a
computation error** — reported honestly as a minor reporting nit rather than
silently "fixed" by picking numbers that reconcile exactly.

---

## Q29. M5 decomposed into Δt_det/ZKP/sig/FM — sum = total ESRL?

**Evidence:** Grep of `shield_gh_integration.h` for stage-specific timestamps
(`detection_time`, `zkp_time`, `flowmod_time`, `sign_time` as **separate**
measured values) finds only: `attack_start_time`, `detection_time`,
`mitigation_time`, `graduated_response_time` — i.e. 2 effective endpoints
used for ESRL (onset → response), no separate ZKP-stage or
threshold-sign-stage or FlowMod-stage timestamp. Code comment (lines
416-421): *"The 4-stage decomposition (Eq. m5_esrl_decomp:
detection/ZKP/threshold-sign/FlowMod) is NOT fabricated here — it needs
per-stage std::chrono instrumentation... future work, not measured yet."*

**Answer:** ❌ Not executable — feature does not exist. The 4-way
decomposition is explicitly not instrumented in code (confirmed by the
code's own comment, matching what `TASK8_EVIDENCE.md` already states).
Producing a real decomposed sum would require adding per-stage timers, which
was out of scope for this investigation (no source changes made).

---

## Q30. M6 Ω_comp: real wall-clock ms, ML-DSA-87 sign + ML-KEM-1024 encap

**Command run (fresh, this session, venv `~/shield-crypto-venv/bin/python3`,
liboqs 0.15.0):**
```
ML-DSA-87 sign:    0.0818 ms/op (avg of 50 real liboqs calls)
ML-KEM-1024 encap: 0.0135 ms/op (avg of 50 real liboqs calls)
```
**Important caveat, found and reported honestly:** the checked-in M6 evidence
actually used in the Task 8 report (`shield_gh_ml/evidence/m6_overhead_benchmark.json`)
does **not** use these mechanisms — it deliberately selects
**ML-DSA-44** (Dilithium2-equivalent) and **Kyber-768**, not ML-DSA-87/ML-KEM-1024:
```json
"dilithium_mechanism": "ML-DSA-44",
"kyber_mechanisms": {"512":"Kyber512","768":"Kyber768","1024":"Kyber1024"},
"ops_ms": {"kyber_enc": 0.0185, "dilithium_sign": 0.0429, "zkp_prove": 25.55, "zkp_verify": 27.63}
```
**Answer:** ✅ Real numbers measured directly in this session for the exact
mechanism pair the question names (ML-DSA-87/ML-KEM-1024): sign≈0.082ms,
encap≈0.014ms. But note the report's actual M6 evidence uses different
(lower NIST-level) mechanisms (ML-DSA-44/Kyber-768: sign≈0.043ms,
enc≈0.019ms) — reported here so the discrepancy between "what M6.json says"
and "what this question asks about" is visible rather than silently
conflated.

---

## Q31/Q32. M9 η_rekey: Kyber op counts at N=200, N=16, N=128

**Evidence:** `shield_gh_crypto/pqc_lkh.py`:
```python
self.depth = max(1, math.ceil(math.log2(max(2, n))))
```
Test file `shield_gh_crypto/tests/test_crypto.py` (`test_lkh_isolation_cost_is_logN`)
asserts `kyber_ops == ceil(log2(N))` for `N ∈ {4, 8, 16}`:
```
N=4  -> 2 ops   N=8 -> 3 ops   N=16 -> 4 ops   (all asserted and passing)
```
A real run log (`vectors/ns3_crypto_events.log`) shows N=5: `kyber_ops=3 =
ceil(log2(5))=3` — consistent.

```
ceil(log2(200)) = 8    (question's expectation)
log2(128) = 7           (question's expectation)
log2(16) = 4             (already unit-tested, confirmed = 4)
```

**Answer:** ⚠️ Partially answerable. The O(log N) formula is genuinely
implemented (`math.ceil(math.log2(n))`) and **unit-tested and passing at
N∈{4,8,16}** — N=16 gives exactly 4, matching the question's expectation.
**N=200 and N=128 specifically are not exercised by any test or evidence log
in this repo** — `ceil(log2(200))=8` and `log2(128)=7` are correct by
formula extrapolation (the code would produce these values if called at
those N), but no actual test/run does so; this is stated as an
extrapolation, not a measured fact.

---

# Category 5 — LLM-FL Pipeline (Q33–Q38)

## Q33. 10 FWD tokens (benign) → LLM, 7-class softmax, BENIGN>0.90?

**Evidence:** `shield_gh_ml/llm_scorer.py`: `CLASSES = ["BENIGN", "DP-FR",
"DP-IT", "DP-TS", "CP-FR", "CP-IT", "CP-TS"]` (7-class taxonomy confirmed).
Ran the CPU fallback backend (fitted on the real `selection/dataset.jsonl`,
2800 rows) on 10 synthetic `FWD:s0` tokens:
```
softmax = [BENIGN 0.595, DP-FR 0.069, DP-IT 0.166, DP-TS 0.106,
           CP-FR 0.015, CP-IT 0.033, CP-TS 0.017]
argmax = BENIGN, Q_i = 0.405 (confidence)
```
**Answer:** ❌ BENIGN probability (0.595) is **not** >0.90 for this synthetic
input, though it is correctly the argmax class. This is an honest artifact
of testing with synthetic, repeated-token input rather than a real dataset
sample — the fallback featurizer relies on structural cues (drop-run
periodicity, source concentration) that a monotone repeated-FWD sequence
doesn't fully exercise the way genuine varied traffic would. The correct
class wins, but not with >0.90 confidence on this specific synthetic probe.

---

## Q34. 10 DRP tokens → LLM, S1 highest?

**Evidence:** Same fallback backend, 10 synthetic `DRP:s1` tokens:
```
softmax = [BENIGN 0.001, DP-FR 0.795, DP-IT 0.045, DP-TS 0.097,
           CP-FR 0.049, CP-IT 0.004, CP-TS 0.009]
argmax = DP-FR, Q_i = 0.999
```
**Answer:** ✅ DP-FR (the class corresponding to "S1"/fixed-rate dropping in
this taxonomy) is the highest-probability class at 0.795, and confidence
Q_i=0.999. Matches expectation.

---

## Q35. max_c(softmax) for 100 random inputs, fraction <ε_u=0.15

**Evidence:** `llm_scorer.py`: `EPS_U = 0.15  # Eq. 3.17 uncertainty
threshold`. But the actual escalation check `needs_tier2()` does **not**
threshold `max(softmax)<0.15` directly — it uses a confidence-margin form:
`conf < (1/7 + 0.15) ≈ 0.293`, with an explicit code comment: *"Using
max-prob directly is degenerate for 7 classes, so we use a confidence margin
that maps cleanly onto the eps_u threshold."* Both Q33/Q34 synthetic cases
returned `needs_tier2=False` (confidences 0.595, 0.999 ≫ 0.293).

**Answer:** ❌ Not executable with current evidence. No existing log or
evidence file records an aggregate escalation-rate statistic (fraction of
100 test inputs with low confidence) — this specific measurement was never
run/logged anywhere in the repo. Producing it would require a fresh
100-sample batch run against the fallback or genuine LLM backend, which was
not done here (out of scope for a single-question spot check within budget).

---

## Q36. SHA-256 of Δw_i locally vs on-chain, identical?

**Evidence:** `shield_gh_ml/federated.py`:
- `commit_hash()` (lines 39-45): computes `hashlib.sha256()` of the local
  gradient.
- `BlockchainCommitStore.verify()` (lines 62-68, Eq. 3.16/3.27):
  recomputes the hash of the **received** Δw and compares it against the
  on-chain commitment.

**Answer:** ✅ Confirmed real SHA-256 commit/verify code path exists and is
used to gate aggregation — for an honest (non-poisoned) vehicle, the locally
computed hash and the on-chain commitment are identical by construction
(the commit is computed once, from the same gradient that's later
transmitted, so any honest client's local/on-chain hashes match trivially;
a mismatch only occurs when the transmitted gradient is tampered post-commit,
which is exactly the poison case in Q37).

---

## Q37. Poison Δw_i after hash commit — aggregator must reject

**Evidence:** `federated.py` `VehicleClient.poison()` (lines 97-104):
transmits `15.0*garbage - delta_w` instead of the committed honest gradient.
The "5/5 poison rejections" claim traces to
`shield_gh_ml/evidence/evidence_transcript.txt` line 22:
```
integrity ON : rounds=5  poison rejections=5  global-model detection MCC=0.747
round 1 -> accepted=[0,1,2,3] rejected=[9] (V9 = poisoner, blocked)
```
**Answer:** ✅ Confirmed reject — the poisoning client (vehicle 9) is
rejected in every one of the 5 FL rounds (5/5), matching the "100%
poison-gradient rejection" figure cited elsewhere in project memory. Note
this is **1 poisoner rejected across 5 sequential rounds**, not 5 independent
poisoning trials — worth being precise about, since "5/5" could otherwise be
misread as 5 different poison attempts.

---

## Q38. Global model MCC at rounds 1, 3, 5 — improving?

**Evidence:** `shield_gh_ml/gen_evidence.py` (lines 112-126) calls
`agg.fit(rounds=5, ...)` then computes MCC **once**, only on the final
post-round-5 global model, for both integrity-ON and integrity-OFF:
```
evidence_transcript.txt:22-25
integrity ON:  MCC=0.747
integrity OFF: MCC=0.409
PASS: integrity check preserved the model (MCC 0.7473 vs poisoned 0.409)
```
**Answer:** ❌ Not executable — feature does not exist. No code path
snapshots MCC after round 1 or round 3 — only the final (round-5) MCC is
ever computed/logged. There is no per-round progression to show whether MCC
is "improving" round over round; only a single before/after (integrity ON
vs OFF) comparison exists. This is confirmed by reading `gen_evidence.py`
directly, not inferred.

---

# Category 6 — Controller Trust and Governance (Q39–Q43)

## Q39. T_c(t) at t=0, after 5 CP-FR, after 10 CP-FR — decreasing?

**Evidence:** `shield_gh_integration.h` (lines 139-143, 496-509):
`g_sg_ctrl_trust[CTRL_ID]` starts at 1.0, decremented by `SG_DELTA_SIG=0.35`
on any S4/S5/S6 trigger, floored at 0. `shield_gh/evidence/S4.log`:
```
t=2.00: Tc=0.65
t=3.00: Tc=0.30
t=4.00: Tc=0.00
```
**Answer:** ✅ Confirmed monotonically decreasing across repeated CP-FR
detections (1.0 → 0.65 → 0.30 → 0.00, i.e. reaching floor after just 3
detections in this run, not literally "5" and "10" as the question phrases
it — the trust decay is fast enough at Δ=0.35/hit that it saturates at 0
well before 5 detections in this scenario). The trend direction (strictly
decreasing) is verified real; the specific checkpoints "after 5" and "after
10" detections aren't separately observable because trust floors out
earlier.

---

## Q40. Sub-threshold accumulator Ψ_c(t) — accumulating >0?

**Evidence:** No variable literally named `Psi_c`/`psi_c` exists anywhere in
the codebase (confirmed by grep). The related concept is implemented as a
**per-window boolean flag**, not a continuous accumulator:
```cpp
// shield_gh_integration.h:504-508
bool psi_breach = (fr.action == "drop") && !s456;   // sub-threshold, applies SG_DELTA_AGG
```
**Answer:** ⚠️ Partially implemented. The distinction between a
full signature hit (S4-S6) and a sub-threshold drop-rule anomaly exists as a
boolean per-window flag that also decrements trust (`SG_DELTA_AGG=0.10`),
but there is **no genuine running accumulator variable Ψ_c(t) that
integrates sub-threshold breaches over time** the way the question's
notation implies. It is re-evaluated fresh each window, not accumulated.

---

## Q41. Force T_c(t)<θ_c — replacement controller: lowest-ranked eligible?

**Evidence:** Failover trigger confirmed real: `S4.log:346`:
```
[SHIELD-GH][CP-MIT] Controller 0 FAILOVER — Tc=0.30 < θc=0.40 | RSU threshold
FlowMod 3/3 co-signed, quorum_ok=1 | whitelist-only rules reinstalled | t=3.00
```
The topology has a **single hardcoded controller** (`CTRL_ID = 0`,
`shield_gh_integration.h:472`) — there is no second/third controller to fail
over *to*. The "mitigation" action taken is an RSU-quorum threshold-signed
whitelist-only FlowMod reinstall on the same controller, not selecting a
different controller from an ordered list.

The question's "lowest-ranked eligible in ordered list (not global-highest-
trust)" selection rule is fully specified in `main.tex` (Eq. eq:failover_select,
`c_new^z = argmin_j j` s.t. `c_j^z ≠ c_failed, T_{c_j^z}(t) > θ_c` — lines
2028-2060, and Algorithm 5) but grepping `shield_gh/blockchain/` and
`shield_gh/detection/` for `argmin`/`ordered list`/multi-controller selection
logic: **zero hits**.

**Answer:** ⚠️ The trust-threshold trigger (Tc<θc) genuinely fires and a
real mitigation action (whitelist reinstall) genuinely happens. But there is
no multi-controller replacement mechanism in code at all — the "lowest-ranked
eligible, not global-highest-trust" selection algorithm is fully specified
in main.tex/Algorithm 5 but is **design-document-only, not implemented in
C++**. This is a real gap between the approved report design and the
current code.

---

## Q42. VRF endorser selection twice, same seed — deterministic?

**Evidence:** Real Go chaincode: `shield_gh/blockchain_standalone/chaincode-debsc/endorser_vrf.go` —
a SHA-256-based verifiable-VRF surrogate (`vrfEval`/`vrfVerify`, lines
89-103), seeded per-transaction by `txID|txTimestamp|tSec` (line 141), with
eligibility filtering and NORMAL/RELAXED/DEFERRED/EMERGENCY modes.
Determinism is explicitly unit-tested: `endorser_vrf_test.go` lines 100-125,
`TestSelectEndorsers_Deterministic` — calls `SelectEndorsers` **twice with
the same transaction ID** ("sameTx") and asserts identical selected-set
ordering both times, and confirms a *different* tx ID yields a different
seed/selection.

Cross-check requested by the question ("is this SHIELD-GH's own code or
LORIS's?"): grepping the separate LORIS project directory (`scratch/Blockchain/`)
for "VRF" returns **zero hits** — LORIS's endorser mechanism (referenced in
project memory as "dynamic trust-ranked endorser selection") is a different,
simpler trust-rank scheme; SHIELD-GH has its own independent, genuine
VRF-based endorser selection with cryptographic proof/verify, not shared
code between the two projects.

**Answer:** ✅ Confirmed — VRF endorser selection is deterministic given the
same transaction ID/seed, verified by an existing passing unit test
(`TestSelectEndorsers_Deterministic`), and this is SHIELD-GH's own
implementation, distinct from the LORIS project's mechanism.

---

## Q43. 30% of RSUs' T_rj(t)<θ_RSU — VRF selection excludes them?

**Evidence:** `endorser_vrf.go` line 36: `thetaRSU = 0.5  // θ_RSU: min
trust for endorser candidacy`; `RSURecord.Trust` field (line 53, commented
"T_rj(t) — on-ledger trust score"); eligibility filter (line 125): `if
r.Trust >= thetaRSU && r.NumInter >= nMin && !r.Probation { eligible =
append(eligible, r) }`. `shield_gh_integration.h` (lines 294-326) registers
64 RSUs on-chain with a range of trust values, some deliberately below 0.5
to exercise this exclusion path.

**Answer:** ✅ Confirmed implemented — the θ_RSU=0.5 filter is real code
that excludes any RSU with `Trust < 0.5` from the eligible candidate pool
before VRF selection runs, matching the question's expectation that no
low-trust RSU should appear in the selected endorser set Ω(t). (This
investigation did not re-run a live 30%-injection scenario to produce a
fresh Ω(t) printout — relying on the existing filter-logic code and its
passing unit test as the evidence, per the earlier memory note "64-RSU scale
test passes.")

---

# Category 7 — Experiment Configuration (Q44–Q47)

## Q44. E1 2D grid: (p, ρ_a) pairs run — should be 36 (6×6)

**Evidence:** Grepped for "E1" and any multi-pair sweep script/results file
across `scratch/` (results CSVs, sweep scripts): no hits corresponding to a
genuine (p, ρ_a) grid sweep. `scratch/tasks.md` confirms Task 10 (full
research experiment grid) is **not yet started**.

**Answer:** ❌ Not executable — not yet run. Zero (p, ρ_a) pairs have been
swept as a grid; this requires Task 10, which has not started. No fabricated
count is given; the honest answer is 0 of 36.

---

## Q45. E4 (AEI): T*, d, k_t at ξ=0 and ξ=1

**Evidence:** `main.tex` (lines 5444-5496) fully specifies the AEI
equations: `ξ ∈ {0.0, 0.2, ..., 1.0}`, `T*(ξ)=ξ·T_max`,
`d(ξ)=d_max−ξ(d_max−d_min)`, `k_t(ξ)=⌊(1−ξ)·K⌋`. Grepped `shield_gh/*.cc`
and `*.h` for `xi`/`AEI`: **zero hits** — no code implementation exists.

**Answer:** ❌ Not executable — not implemented, not run. The AEI
parameterization is a main.tex design specification only; there is no code
path that varies T*/d/k_t as a function of ξ, and consequently no run has
produced ξ=0 or ξ=1 data points. The question's expected values (T*≈0 at
ξ=0, T*=30 at ξ=1, etc.) come directly from the report's own formulas and
are internally consistent with main.tex, but they have never been exercised
by simulation.

---

## Q46. E5: S4 vs baseline B1 (Malik) — should be N/A (no CP capability)

**Evidence:** `soa1_dpgha_malik/README.md`: *"This NS-3 setup is
**data-plane only** — it exposes no RREQ/RREP/DSN counters, only
data-packet forwarding."* The detector (`dpgha_detection.h`) implements only
PLR/RRR/μ(DSN) signals (Eq. 13-18) over data-plane forwarding/routing
behaviour — no flow-rule, controller-plane, or SDN-controller monitoring
logic exists anywhere in the directory.

**Answer:** ✅ Confirmed by design — running S4 (a controller-plane
flow-rule attack) against B1 would trivially show zero/N/A detection,
**because B1 has no mechanism to observe SDN controller flow rules at all**,
not because of a bug or unfair test. This matches the question's expected
outcome exactly, and the reason is verified from B1's own scope
documentation rather than assumed.

---

## Q47. Colombo map: edges/intersections/bbox — differs from Galle's 284?

**Evidence:** Searched `scratch/sumo/` exhaustively by filename and content
for "Colombo": **zero hits anywhere in the repository.** Only a Galle map
exists: `scratch/sumo/galle_scenario/galle.net.xml`.

Galle map stats (from the actual `.net.xml` and `bbox.txt`):
```
<edge> count:     3344
<junction> tags:   725 total (224 are the filtered "real" intersection subset)
bbox.txt:          6.044456282670429,80.21196651626431,6.062543717329571,80.2300334837357  (lat/lon)
net.xml location:  convBoundary="0.00,0.00,2097.40,2120.26" (i.e. ~2097m x 2120m, UTM)
```
main.tex (lines 3819, 3953) states: *"$2097\text{m}\times2120\text{m}$ with
$284$ real intersections"* — this **284** figure is the report's own stated
number, not directly reproduced by a naive tag-count grep (which gives 725
raw junction tags or 224 after filtering internal/unregulated types) —
main.tex's 284 likely comes from SUMO's own intersection-classification
tooling rather than a simple XML tag count.

**Answer:** ⚠️ The question's premise is factually wrong: **there is no
Colombo map anywhere in this repository** — only Galle. The "~2km×2km" and
"284 intersections" figures the question attributes to a separate Colombo
map are actually main.tex's own description of the **Galle** map. Reported
here as found: Galle is genuinely ~2097m×2120m per the SUMO net file, and
main.tex's 284-intersection figure is real (appears verbatim twice in
main.tex) but is not exactly reproducible from a naive junction-tag grep on
the XML (725 raw / 224 filtered vs the paper's 284) — a minor
counting-methodology gap, not a fabricated figure.

---

# Category 8 — Reproducibility (Q48–Q50)

## Q48. Same config twice (p=40,ρ_a=40,S1,N=200,seed=42) — identical to 4dp?

**Evidence:** Grepped `routing.cc` case-insensitively for `RngSeedManager`,
`SetSeed`, `::seed`: **zero hits** — no explicit seed is set anywhere in the
simulation driver. This means the run relies on ns-3's own default
deterministic RNG stream (ns-3 defaults to seed=1, run=1 unless explicitly
overridden), which — if genuinely relied upon — would make back-to-back runs
of the same binary/config deterministic by construction. However, `routing.cc`
also calls `srand()` seeded from `Simulator::Now().GetNanoSeconds() + node_id
* 1000 + dp_drop_counter[node_id]` for the DP-FR drop decision (see Q1) —
this reseeds the C-library `rand()` (not ns-3's RNG) on every packet using a
simulation-time-dependent value, which **is** deterministic given a fixed
simulation schedule, but is a different, layered randomness source from
ns-3's `RngSeedManager`.

**Answer:** ❌ Not executable with current evidence — no dual-run comparison
was found or performed. Also note the question's exact scenario (N=200) is
not producible at all in this topology (hard-capped at N=4, see Q7-Q9).
Determinism is plausible from the code's construction (fixed ns-3 seed +
time-derived-but-schedule-fixed `srand()` reseeding) but has **not been
empirically verified** by actually running the same config twice and diffing
outputs — stated honestly rather than assumed.

---

## Q49. Output results file: path, size, first/last line

**Evidence:** `shield_gh_integration.h:281` writes to `results/blockchain_log.csv`.
```
$ ls -la /home/sdvn_ssh/ns-allinone-3.35/ns-3.35/62/results/blockchain_log.csv
-rw-rw-r-- ... 6945 bytes ... Jul 29 18:20 blockchain_log.csv
```
First line (header):
```
window,node_id,timestamp,n_rx,n_fwd,pdr,zkp_valid,trust_mob,reputation,suspicion_level,s1,s2,s3,fused_score,decision,is_real_attacker
```
Last line:
```
27,3,28.998,3,3,1.0000,1,0.8605,0.7970,0,0,0,0,0.0812,BENIGN,0
```
**Answer:** ✅ File exists, non-empty (6945 bytes, 107 lines), with a
correctly structured header and a plausible final data row (node 3, benign,
PDR=1.0, correctly classified BENIGN).

---

## Q50. Raw TP/TN/FP/FN saved alongside metrics for every experiment?

**Evidence:** `shield_gh/evidence/S1.log` lines 207-209:
```
Node TP=0 TN=3 FP=0 FN=1
M1a Detection Accuracy: 75.00%
M1b MCC: 0.00
```
and lines 332-334:
```
Node TP=1 TN=3 FP=0 FN=0
M1a Detection Accuracy: 100.00%
M1b MCC: 1.00
```
Same print statement (`shield_gh_integration.h`) is shared by every
detection-mode run — S1-S6, and the task8/task9 full-mode logs (already
confirmed for `task9_t30s_ap40_run_postfix.log` above, e.g. `Node TP=2 TN=2
FP=0 FN=0` alongside M1 MCC=1.0).

**Answer:** ✅ Confirmed for S1.log and the task8/task9 logs directly
inspected — raw confusion-matrix counts are always printed immediately
adjacent to the derived MCC/accuracy metrics in the same log block, not
computed/reported in isolation. Since the print statement is shared code
across all S1-S6/attack_number combinations, the same pattern holds for
S2-S6 by construction (not each individually re-verified line-by-line in
this pass, but the shared code path guarantees it).

**Caveat that applies to this whole question:** the E1-E5/TX-E1-4
experiment *grid* itself has not been run (Q44/Q45/Q46's E5-variant
excepted) — so "for every experiment E1-E5/TX-E1-4" cannot be answered for
experiments that don't have any run data yet. What can be honestly confirmed
is that **the underlying logging mechanism** used by any run in this
codebase does save raw TP/TN/FP/FN alongside computed metrics, so *when*
those experiments are eventually run, the raw-counts requirement will
already be satisfied by the existing code path.

---

# Cross-cutting findings worth flagging to the supervisor

1. **N_Vehicles is hard-capped at 4** (`total_size=5` array). This single
   fact is the root cause of "not measurable"/"not executable" answers for
   Q7-Q9 (200-vehicle claim), Q10-Q13 (mobility sweep), Q25/Q26 (M2/GHSR),
   Q44 (E1 grid), Q47 (200-vehicle-scale topology), and Q48 (N=200
   reproducibility). It is a known, previously-documented limitation
   (`TASK7_75_DESIGN_REVIEW.md`), not new.
2. **ZKP is only a 2-state (PASS/FAIL) model in code**, despite main.tex
   explicitly mandating a 3-state PASS/FAIL/ABSENT model as a fix for a
   flaw the report calls "critical" (Q20). This is a real, previously
   unflagged implementation gap.
3. **R_RSU discrepancy**: code hardcodes 500.0m, main.tex specifies 270m
   (Q14). Doesn't affect the Q12 ratio (linear formula), but is a genuine
   code/report mismatch.
4. **MATD speed is hardcoded at 13.9 m/s (50km/h)** in the live detection
   loop — never actually driven by the SUMO bridge or CLI `--maxspeed` in
   any run found (Q11). The formula is real; the live wiring to variable
   speed is not.
5. **S3 (DP-TS KL-divergence rule) has never been observed firing in any
   log in this repository** (Q17), including the file named for it.
6. **Multi-controller failover selection ("lowest-ranked eligible in ordered
   list") is main.tex/Algorithm-5-only** — not implemented in C++ (Q41);
   the live code has exactly one controller and no selection logic to test.
7. **No Colombo SUMO map exists anywhere in this repository** — only Galle
   (Q47). Any question or report text referencing a Colombo map should be
   corrected or clarified.
8. **The build on disk was stale relative to source** at the start of this
   investigation (`--detection_mode`, `--attack_percentage` etc. were
   rejected by the installed binary until a forced clean rebuild was run
   during this session — `rm build/scratch/routing.cc.*.o build/scratch/routing
   && ./waf build --targets=routing`). Future evidence-gathering sessions
   should rebuild before trusting `./build/scratch/routing`'s flag set.

---

# Reproduction commands used in this document

```bash
cd /home/sdvn_ssh/ns-allinone-3.35/ns-3.35/62

# Rebuild (was required — binary was stale)
rm -f build/scratch/routing.cc.*.o build/scratch/routing
./waf build --targets=routing

# Q1 / Q9 (fresh evidence)
LD_LIBRARY_PATH=$PWD/build/lib:$PWD/build ./build/scratch/routing \
  --detection_mode=lightweight --routing_test=1 --attack_number=1 --drop_rate=50 \
  --attack_percentage=50 --simTime=15 --routing_algorithm=4 --architecture=0 --maxspeed=80

# Q7 (p=0%, rho_a=0%)
LD_LIBRARY_PATH=$PWD/build/lib:$PWD/build ./build/scratch/routing \
  --detection_mode=lightweight --routing_test=1 --attack_number=1 --drop_rate=0 \
  --attack_percentage=0 --simTime=10 --routing_algorithm=4 --architecture=0 --maxspeed=80

# Q8 (p=100%, rho_a=100%)
LD_LIBRARY_PATH=$PWD/build/lib:$PWD/build ./build/scratch/routing \
  --detection_mode=lightweight --routing_test=1 --attack_number=1 --drop_rate=100 \
  --attack_percentage=100 --simTime=10 --routing_algorithm=4 --architecture=0 --maxspeed=80

# Q9 (p=40%, confirming round() semantics), also cross-checked against
# the pre-existing scratch/shield_gh_ml/logs/task9_t30s_ap40_run_postfix.log
LD_LIBRARY_PATH=$PWD/build/lib:$PWD/build ./build/scratch/routing \
  --detection_mode=lightweight --routing_test=1 --attack_number=1 --drop_rate=50 \
  --attack_percentage=40 --simTime=30 --routing_algorithm=4 --architecture=0 --maxspeed=80

# Q30 (M6 ML-DSA-87 / ML-KEM-1024 real timing)
~/shield-crypto-venv/bin/python3   # liboqs micro-benchmark, ML-DSA-87 sign + ML-KEM-1024 encap, avg of 50 ops each

# Q33/Q34 (LLM fallback backend, synthetic FWD/DRP token softmax)
cd scratch/shield_gh_ml && python3 -c "import llm_scorer; ..."  # fallback backend fit on selection/dataset.jsonl
```

Existing evidence files cited throughout (already in repo, not generated by
this investigation):
- `scratch/shield_gh/evidence/S1.log` .. `S6.log`
- `scratch/shield_gh/evidence/route_availability_gate_run.log`
- `scratch/shield_gh_ml/TASK8_EVIDENCE.md`
- `scratch/shield_gh_ml/logs/task9_t30s_ap40_run_postfix.log`
- `scratch/shield_gh_ml/evidence/m6_overhead_benchmark.json`
- `scratch/shield_gh_ml/evidence/evidence_transcript.txt`
- `scratch/TASK7_75_DESIGN_REVIEW.md`
- `scratch/main.tex`
- `scratch/soa1_dpgha_malik/README.md`
- `scratch/sumo/galle_scenario/galle.net.xml`, `scratch/sumo/bbox.txt`
- `results/blockchain_log.csv`
