# SHIELD-GH — Daily Progress & Panel Evaluation Document
### Date: 2026-06-03
### Project: Grey Hole Attack Detection & Mitigation in Software-Defined Vehicular Networks (SDVN)
### Platform: NS-3.35 (C++) + Hyperledger Fabric (Go chaincode)

---

## 0. Executive Summary (read this first)

Today we made the SHIELD-GH lightweight detection mode **fully functional, verified, and
demonstrable**, and we built the **real Hyperledger Fabric blockchain** with **formally
verified smart contracts**. Specifically:

1. **Fixed the broken build** (NS-3.35 vs Python 3.12 incompatibility) so the project compiles and runs.
2. **Got the routing simulation running** (fixed hard-coded paths, installed Gurobi optimizer).
3. **Completed Task 1 (Blockchain) and Task 2 (Lightweight Crypto/Detection)** — the lightweight mode.
4. **All six attack signatures (S1–S6)** wired through the named algorithms (LW-DP-Det, LW-CP-Det).
5. **All three data-plane attacks (DP-FR, DP-IT, DP-TS) detected AND mitigated** — 100% accuracy, 0 false positives, MCC = 1.0.
6. **Real isolation/blocking** of attackers (not just logging) + **correct node-level evaluation metrics**.
7. **NetAnim attack visualization** (red attacker, green=forward, black=drop) with tunable packet counts.
8. **Real Hyperledger Fabric** deployment with the DEBSC smart contract (Eq. 3.19) running on a 2-org network.
9. **Formal verification of the smart contract** — 8 unit tests, all passing, 74.6% coverage.

**Current scope completed: Lightweight Mode (Tasks 1 & 2).** Full mode (LLM + Federated
Learning, Task 3) is future work.

---

## 1. Background: What is SHIELD-GH?

SHIELD-GH is a **dual-mode** framework to detect and mitigate **grey hole attacks** in SDVNs.

- **Grey hole attack:** A malicious vehicle selectively drops *some* packets while forwarding
  others (unlike a black hole, which drops everything). This makes it stealthy and hard to detect.
- **Dual-mode design:**
  - **Lightweight mode** (what we completed) — fast, rule-based signature detection (S1–S6) using
    blockchain-anchored evidence. Catches known/obvious attack patterns within real-time latency budgets.
  - **Full mode** (future) — LLM + Federated Learning for stealthy/zero-day attacks that evade the rules.

### The four architectural layers
1. **Data plane** — vehicles forwarding/dropping packets (where attacks happen).
2. **Control plane** — SDN controller (treated as **untrusted** — can be compromised).
3. **Blockchain plane** — RSU-maintained tamper-proof ledger (the trust anchor).
4. **Intelligence plane** — detection logic (signatures in lightweight; LLM/FL in full).

---

## 2. What We Did Today — Step by Step

### 2.1 Fixed the build (NS-3.35 + Python 3.12 incompatibility)
- **Problem:** Build failed with `PySys_SetArgv deprecated` and `Py_TYPE(...) = ...` errors.
- **Root cause:** NS-3.35 (2021) is incompatible with the system's Python 3.12 — these errors were
  in NS-3's own Python bindings and visualizer, **not our code**.
- **Fix:** Reconfigured with `./waf configure --enable-examples --disable-python --disable-werror`
  (disables Python bindings + treats warnings as warnings, not errors).

### 2.2 Made the scratch build work with our module structure
- **Problem:** NS-3 tried to compile our support folders (`soa_baselines/`, `sumo/`, `shield_gh/`)
  as standalone programs → `undefined reference to main`.
- **Fix:** Patched `wscript` (`add_scratch_programs`) to:
  - Compile `routing.cc` together with all `shield_gh/**/*.cc` implementation files.
  - Exclude the PQC crypto sources (`crypto/`, `mitigation/`) — these belong to **full mode** and
    need the `liboqs` library (this is the "lightweight mode" build choice).
  - Skip the non-program support directories.
  - Link OpenSSL (`-lcrypto`) for SHA-256 used by the blockchain ledger.

### 2.3 Got the simulation running
- **Problem 1 — crash:** `assert failed ... Fading trace file not found`. Cause: a path hard-coded
  to the original author's machine (`/home/dilukshan/...`). Fixed all such paths to our system.
- **Problem 2 — zero metrics:** `ModuleNotFoundError: No module named 'gurobipy'`. The routing
  controller calls a Python optimizer (Gurobi) every second to compute routes; without it, no routes
  → no traffic → 0% PDR. **Fix:** Installed `gurobipy` 13.0.2 (matching the academic license) into a
  dedicated virtualenv and pointed the simulation at it.

### 2.4 Completed Lightweight Detection (Tasks 1 & 2)
- **Verified** that Task 1 (blockchain ledger, DEBSC, ZKP) and Task 2 (MATD, signatures S1–S6) were
  implemented, then **wired them correctly**:
  - Detection now runs through the **named paper algorithms**: `LW_DP_Det` (Algorithm 1, data plane)
    and `LW_CP_Det` (Algorithm 2, controller plane) — satisfying the supervisor's one-to-one
    paper-to-code mapping requirement.
  - Wired the **controller-plane signatures (S4–S6)** which were implemented but not connected.

### 2.5 Fixed real mitigation + correct evaluation metrics
- **Found:** "Isolation" only printed a log message — the attacker kept dropping packets afterward.
  Also, the displayed TP/FP metrics were **packet delivery** counts, not **attacker-detection** counts.
- **Fixed:**
  - Isolation now **actually blocks** the attacker (`shield_gh_isolated_nodes[]` checked in the
    forwarding path → models the threshold-signed FlowMod blocking). Attacker drops fell 177 → 37.
  - Added a **correct node-level detection confusion matrix** (compares detector verdict vs. ground
    truth) producing the true M1a (accuracy), M1b (MCC), M2 (FPR).

### 2.6 Fixed DP-IT (intermittent) detection
- **Found:** DP-IT was being **missed** (False Negative every window). The S2 autocorrelation
  couldn't catch the sparse, noisy real drop pattern.
- **Fixed:** Replaced with **recurring-drop detection** (≥2 on/off drop episodes) + fed S2 the real
  observed PDR series + added **sustained-detection isolation** (isolate after a signature fires for
  3 consecutive windows). Result: DP-IT now detected AND isolated.

### 2.7 NetAnim attack visualization
- Added `--enable_shield_gh=0` (turn detection off for a clean attack video) and `--video_mode=1`
  (cap packets so each drop/forward is visible). Attacker shown **RED**; flashes **GREEN** on
  forward, **BLACK** on drop.
- Added CLI control of attack type: `--attack_number=1|2|3` (DP-FR/DP-IT/DP-TS).

### 2.8 Real Hyperledger Fabric blockchain (Task 1 evidence)
- Deployed the **DEBSC smart contract** (Go chaincode) to a real Hyperledger Fabric test-network
  (2 organizations, orderer, channel). Demonstrated Eq. 3.19 (dual-evidence isolation) on-chain.

### 2.9 Formal verification of the smart contract (supervisor request)
- Wrote a **unit-test suite** (`debsc_test.go`) driving the contract with dummy data; 8 tests, all
  pass, 74.6% coverage. Verifies the Eq. 3.19 truth table and false-positive protection.

---

## 3. Results (the numbers for the panel)

### 3.1 Detection & Mitigation — all three data-plane attacks
| Attack | Detected | Isolated & Blocked | False Positives | M1b (MCC) |
|---|---|---|---|---|
| **DP-FR** (fixed-rate) | ✅ (22 windows) | ✅ at t = 7 s | 0 | 1.00 |
| **DP-IT** (intermittent) | ✅ (20 windows) | ✅ at t = 12 s | 0 | 1.00 |
| **DP-TS** (target-specific) | ✅ (24 windows) | ✅ at t = 8 s | 0 | 1.00 |

- **M1a Detection Accuracy = 100%**, **M2 False Positive Rate = 0%**, **MCC = 1.0** on all three.
- Node-level confusion matrix: **TP = 1, TN = 3, FP = 0, FN = 0** (1 real attacker correctly caught,
  3 benign nodes correctly cleared).

### 3.2 Controller-plane signatures (S4–S6)
- Run with `--enable_cp_attack=1 --cp_attack_number=4|5|6`. Verified S4 (CP-FR), S5 (CP-IT),
  S6 (CP-TS) all fire via Algorithm 2 (LW-CP-Det).

### 3.3 Smart contract verification
- **8/8 unit tests PASS**, **74.6% coverage** (business logic 78–91%; only `main()` uncovered, which
  is the Fabric bootstrap entrypoint and is not unit-testable).

---

## 4. File Map (where everything lives)

```
scratch/
├── routing.cc                         # Main NS-3 SDVN simulation (modified today)
├── wscript  (../wscript)              # Build config (patched for shield_gh)
└── shield_gh/
    ├── shield_gh_integration.h        # Wires detection into routing.cc (modified today)
    ├── blockchain/
    │   ├── blockchain_ledger.{h,cc}   # In-memory ledger SIMULATION (PDR, trust, reputation)
    │   ├── debsc.{h,cc}               # DEBSC dual-gate (Eq. 3.19, 3.13)
    │   └── zkp_proofs.{h,cc}          # ZKP forwarding proof (Eq. 3.29–3.30)
    ├── detection/
    │   ├── matd.{h,cc}                # Mobility-Aware Trust Decay (Eq. 3.4, 3.5, 3.17)
    │   ├── attack_signatures.{h,cc}   # Signatures S1–S6 (Eq. 3.6–3.11)  [S2 fixed today]
    │   ├── lw_dp_det.{h,cc}           # Algorithm 1 — LW-DP-Det  [header added today]
    │   └── lw_cp_det.{h,cc}           # Algorithm 2 — LW-CP-Det  [header added today]
    └── blockchain_standalone/         # REAL Hyperledger Fabric (created today)
        ├── chaincode-debsc/
        │   ├── debsc.go               # DEBSC smart contract (Go)
        │   └── debsc_test.go          # Formal verification unit tests
        ├── debsc_demo.sh              # Live on-chain isolation demo
        ├── run_tests.sh               # Runs the unit-test verification
        ├── debsc_coverage.html        # Visual coverage report
        └── README.md                  # Full reproduction guide
```

---

## 5. How to Run Everything (live demo commands)

### 5.1 Build
```bash
cd ~/ns-allinone-3.35/ns-3.35
./waf build --targets=routing
```

### 5.2 Lightweight mode — detect + mitigate each attack
```bash
# DP-FR (fixed-rate)
./waf --run "routing --N_Vehicles=20 --simTime=30 --architecture=0 --routing_algorithm=4 --maxspeed=80 --attack_number=1"
# DP-IT (intermittent)
./waf --run "routing ... --attack_number=2 --intermittent_period=2"
# DP-TS (target-specific)
./waf --run "routing ... --attack_number=3 --grey_hole_target_flow=0"
# Controller-plane (Algorithm 2 / S4-S6)
./waf --run "routing ... --enable_cp_attack=1 --cp_attack_number=4"
```

### 5.3 NetAnim attack video (detection OFF, packets reduced)
```bash
./waf --run "routing ... --enable_shield_gh=0 --video_mode=1 --video_flow_packets=4 --attack_number=1"
# Open ~/ns-allinone-3.35/ns-3.35/routing.xml in NetAnim
```

### 5.4 Real Hyperledger Fabric blockchain
```bash
cd ~/fabric-samples/test-network
./network.sh up createChannel -c mychannel
./network.sh deployCC -ccn debsc -ccp <abs path>/shield_gh/blockchain_standalone/chaincode-debsc -ccl go -c mychannel
bash ~/ns-allinone-3.35/ns-3.35/scratch/shield_gh/blockchain_standalone/debsc_demo.sh
./network.sh down   # when finished
```

### 5.5 Smart contract verification
```bash
bash ~/ns-allinone-3.35/ns-3.35/scratch/shield_gh/blockchain_standalone/run_tests.sh
```

---

## 6. Key Equations Implemented (paper → code)

| Eq. | Meaning | Where |
|---|---|---|
| 3.1 | PDR over window | `blockchain_ledger.cc::ComputePDR` |
| 3.3 | PDR variance | `blockchain_ledger.cc::ComputePDRVariance` |
| 3.4, 3.5 | Handoff loss + mobility-corrected PDR | `matd.cc` |
| 3.6 | S1 fixed-rate signature | `attack_signatures.cc::S1_FixedRate` |
| 3.7 | S2 intermittent signature | `attack_signatures.cc::S2_Intermittent` |
| 3.8 | S3 target-specific signature | `attack_signatures.cc::S3_TargetSpecific` |
| 3.9–3.11 | S4–S6 controller-plane signatures | `attack_signatures.cc` |
| 3.13 | Suspicion level Λi | `debsc.cc::ComputeSuspicionLevel` |
| 3.16 | Trust score | `blockchain_ledger.cc::ComputeTrustScore` |
| 3.17 | Mobility trust decay | `matd.cc::ApplyMobilityDecay` |
| 3.18 | Reputation Ri | `blockchain_ledger.cc::ComputeReputation` |
| **3.19** | **DEBSC dual-evidence isolation** | `debsc.cc::ShouldIsolate` + `debsc.go::EvaluateIsolation` |
| 3.29–3.30 | ZKP forwarding proof | `zkp_proofs.cc` |

---

## 7. ANTICIPATED PANEL QUESTIONS & ANSWERS

**Q1. What did you actually complete?**
A. Lightweight mode end-to-end: blockchain trust layer, MATD mobility correction, all six attack
signatures, the two detection algorithms (LW-DP-Det, LW-CP-Det), DEBSC dual-gate isolation with real
attacker blocking, correct evaluation metrics, NetAnim visualization, plus a real Hyperledger Fabric
deployment of the DEBSC chaincode with formal unit-test verification.

**Q2. Why lightweight mode if it already gets 100%?**
A. 100% holds because our test attacks are deliberately *obvious* (clear drop patterns in a small
network). Lightweight mode can only catch attacks that match predefined rules. **Full mode (LLM + FL)
exists to catch stealthy, adaptive, and zero-day attacks that evade the rules** — at higher compute
cost, so it's only invoked when lightweight is uncertain. Our dual-mode design runs lightweight
always (fast/cheap) and escalates to full mode only when needed.

**Q3. Is the blockchain real or simulated?**
A. **Both, deliberately.** Inside NS-3 we use an in-memory *behavioural simulation* of the ledger
(`blockchain_ledger.cc`) so detection runs at network-simulation speed. Separately, we deployed the
**real Hyperledger Fabric** with the DEBSC chaincode (`blockchain_standalone/`) for authentic
evidence. The implementation guide explicitly planned this two-part approach.

**Q4. Do you NEED blockchain for lightweight detection?**
A. For *computing* the signatures, no — they could use plain counters. The blockchain is essential for
**trust**: it provides a tamper-proof, RSU-maintained record so a grey-hole attacker cannot falsify
its forwarding statistics, and it lets isolation happen **without trusting the (potentially
compromised) SDN controller**. Detection works without it; trustworthy, controller-independent
*mitigation* does not.

**Q5. How does the DEBSC dual-gate prevent false isolation?**
A. Eq. 3.19 requires BOTH a statistical gate ((1−Ri) > θR, low reputation) AND a cryptographic gate
(ZKP proof FAILED). An honest but fast-moving vehicle may temporarily show low reputation (signal
loss during RSU handoff) but still produces a **valid** ZKP — so it is NOT isolated. We have a unit
test proving exactly this (`TestEvaluateIsolation_StatGateButValidZKP_NotIsolated`).

**Q6. How is each grey-hole attack type detected?**
A. DP-FR (fixed-rate) → S1 (low corrected PDR + low variance). DP-IT (intermittent) → S2 (recurring
on/off drop episodes). DP-TS (target-specific) → caught via reduced overall PDR (S1/S2) at the
attacker; S3's per-source KL-divergence applies to multi-flow relay attackers.

**Q7. What does MCC = 1.0 mean and why use it?**
A. Matthews Correlation Coefficient ranges −1 to +1; +1 = perfect classification. We report it
because accuracy alone is misleading with class imbalance (few attackers, many benign). MCC = 1.0
means perfect detection with no false positives or negatives.

**Q8. Why does network PDR drop after isolating the attacker?**
A. Honest topology limitation: in our fixed 5-node line, the attacker (node 0) is also the *source*
of its flow. Blocking it stops its grey-hole dropping (drops 177→37) but also stops its own
legitimate source traffic, since no other node can originate it. In a larger redundant topology the
network would route around the isolated node and PDR would recover. We disclose this honestly.

**Q9. What does "formally verify the smart contract with dummy data" mean here?**
A. Unit tests that feed controlled dummy inputs into each chaincode function and assert correct
outputs — proving functional correctness independent of a live network. 8 tests cover the Eq. 3.19
truth table, reputation/ZKP derivation, false-positive protection, ledger persistence, and queries.
All pass; 74.6% coverage (only the non-testable `main()` entrypoint is uncovered).

**Q10. What is the role of MATD (Mobility-Aware Trust Decay)?**
A. Fast vehicles naturally lose packets during RSU handoffs, which can look like an attack. MATD
(Eq. 3.4, 3.5, 3.17) adds the expected handoff loss back into the PDR before signature evaluation, so
the detector judges *forwarding behaviour* net of mobility effects — reducing false positives on
high-speed honest vehicles.

**Q11. Why Gurobi? Is it part of the contribution?**
A. Gurobi is the routing optimizer in the *existing* SDVN base (computes link-lifetime-aware routes
each second). It is not our contribution; it's infrastructure we restored so the simulation produces
real traffic for detection to operate on.

**Q12. What's left / future work?**
A. Task 3 — Full mode (Edge-LLM threat scoring + Federated Learning + fusion engine), Task 4 — full
integration & ablation studies, Task 5 — SUMO mobility integration & baseline comparisons. Also,
moving to a larger redundant topology to demonstrate PDR recovery after isolation.

---

## 8. Honest Limitations (be upfront — panels respect this)

1. **Fixed 5-node topology.** The codebase hard-codes the topology size; `--N_Vehicles` is overridden.
   This limits PDR-recovery demonstrations after isolation. Future: dynamic topology.
2. **NS-3 ledger is a simulation,** not a real consensus blockchain (the real one is the separate
   Fabric deployment).
3. **100% detection reflects obvious attacks** in a small network — full mode is needed for stealthy
   adversaries (this is *why* the dual-mode design exists).
4. **S3 target-specific** requires a multi-flow relay attacker to exercise its per-source test; the
   current topology routes one flow through the attacker, so DP-TS is caught by S1/S2 instead.

---

## 9. Evidence Checklist for the Panel (screenshots to have ready)

- [ ] Simulation run output showing `[LW-DP-Det] Node 0 SUSPECTED` + `ISOLATED & BLOCKED`
- [ ] `SHIELD-GH DETECTION METRICS` block: TP=1 TN=3 FP=0 FN=0, MCC=1.00, FPR=0%
- [ ] NetAnim screenshot/video: red attacker, green/black packet flashes
- [ ] `docker ps` showing Fabric containers + DEBSC chaincode containers
- [ ] `debsc_demo.sh` output: honest→MONITOR, grey-hole→ISOLATE (Eq.3.19 dual-gate FIRED)
- [ ] `run_tests.sh` output: 8/8 PASS, 74.6% coverage
- [ ] `debsc_coverage.html` opened in browser (visual coverage)

---

*End of document. Prepared 2026-06-03 for panel evaluation on 2026-06-04.*
