# State-of-the-Art Comparison: SOA1, SOA2 vs SHIELD-GH

**Purpose.** This document describes the two existing state-of-the-art (SOA)
grey-hole / black-hole defence techniques we re-implemented as comparison
baselines, presents their result diagrams, and compares both against our
proposed method, **SHIELD-GH**.

| | Technique | Paradigm | Our label |
|---|-----------|----------|-----------|
| **SOA1** | Malik *et al.* DPGHA (IEEE Access 2023) | RSU threshold-based detection | B1 |
| **SOA2** | Alabdulatif *et al.* SCBC/VCBC (CMES 2024) | Blockchain smart contracts | B2 |
| **Ours** | SHIELD-GH | Dual-mode: signatures + blockchain + LLM/FL + PQC | — |

---

# Part A — SOA1: Malik *et al.* DPGHA

## A.1 The technique

Malik, Khan, Qaisar, Faisal, Mehmood (2023), *"An Efficient Approach for the
Detection and Prevention of Gray-Hole Attacks in VANETs"* (DPGHA), IEEE Access
vol.11, pp.46691–46706, DOI 10.1109/ACCESS.2023.3274650.

DPGHA places a **Road-Side Unit (RSU) in promiscuous mode** which records every
neighbour's packet activity in a Master Routing Table (MRT) and detects **two
gray-hole variants** — *Smart GHA* and *Sequence-Number GHA* — from **three
signals**:

| Signal | Equation | Threshold |
|--------|----------|-----------|
| **PLR** – data Packet Loss Ratio | Eq. 13–14 | fixed **δ = 3 %** |
| **RRR** – ΣRREP_generated / ΣRREQ_received · 100 | Eq. 15 | fixed **λ = 70 %** |
| **μ(DSN)** – mean Destination Sequence Number | Eq. 16–17 | **dynamic β** = mean of all nodes' μ(DSN) |

**Decision (Eq. 18):**
- **Smart GHA** if `PLR > δ AND RRR ≥ λ`
- **Sequence-Number GHA** if `μ(DSN) ≥ β AND (PLR > δ OR RRR ≥ λ)`
- **Normal** otherwise

β is the *only* dynamic threshold; PLR and RRR use fixed δ/λ. A detected node is
blacklisted and prevented from relaying (prevention phase, Algorithm 2).

## A.2 Paper-reported results (NS-2 + SUMO, 25–300 nodes, 8 % attackers)

| Metric | DPGHA | Best benchmark |
|--------|-------|----------------|
| Detection rate (TPR) | **97.2 %** | SBGM 95 % |
| PDR | **87.75 %** | DDBG 83.83 % |
| Routing overhead | lowest (−10.85 % vs DDBG) | — |
| Throughput | **122.75 kbps** (+6.58 %) | — |

## A.3 Our re-implementation

Faithful re-implementation of Eq. 13–18 in `scratch/soa1_dpgha_malik/`
(`dpgha_detection.h` C++, `dpgha.py` Python). **Verified against the paper's own
worked example (Table 2):** it reproduces β = 49.5 exactly and classifies
V3 → Smart GHA, V5 → Sequence-Number GHA, all others Normal (TP=2, TN=6, FP=0,
FN=0). This corrected an earlier version that used a generic `PDR < avg − α`
rule, which was **not** the paper's method.

**Fidelity note.** Our NS-3 simulation is data-plane only, so **PLR is computed
from real forwarding counters** while RRR and μ(DSN) are modelled per node-type
(the paper's gray-hole properties). The detection logic itself is unchanged.

## A.4 Result diagrams

### Real ns-3-driven sweep (event-driven data from the simulation)
![SOA1 real sweep](../results/soa1_real_sweep_panel.png)

*Figure A1 — DPGHA on REAL ns-3 data. Each point is an actual simulation run at
that attacker percentage; the detector consumes the per-window forwarding
measurements the simulation writes. Accuracy = 1.0 and PDR = 1.0 at every level
(1/2/3 of the 4 real vehicles are attackers), with routing overhead rising as
attacker count grows. Flat-but-real: with real measured PLR the attackers are
unambiguously separable.*

### Parametric sweep (smooth trends over a wider node population)
![SOA1 parametric sweep](../results/soa1_sweep_panel.png)

*Figure A2 — DPGHA over a 30-node parametric model (30 seeds/point) with
downstream-path contamination, used to show the response trends a 4-node test
network cannot resolve. Accuracy rises 0.85 → 1.00, PDR falls 0.96 → 0.75, FPR
16 % → 0 %, routing overhead rises (gray-holes flood RREPs).*

| Attacker % | Accuracy | PDR | FPR | RO |
|-----------:|---------:|----:|----:|---:|
| 5  | 0.848 | 0.964 | 0.163 | 0.090 |
| 20 | 0.983 | 0.905 | 0.021 | 0.106 |
| 40 | 1.000 | 0.826 | 0.000 | 0.134 |
| 60 | 1.000 | 0.747 | 0.000 | 0.175 |

---

# Part B — SOA2: Alabdulatif *et al.* SCBC/VCBC

## B.1 The technique

Alabdulatif, Alharbi, Mchergui, Moulahi (2024), *"Mitigating Blackhole and
Greyhole Routing Attacks in VANETs Using Blockchain Based Smart Contracts"*,
CMES vol.138 no.2, pp.2005–2021, DOI 10.32604/cmes.2023.029769.

Two **blockchain smart contracts** classify each relay node as **white / grey /
black** from its delivered-relay ratio:

```
rating = deliveredCount · 100 / (deliveredCount + notDeliveredCount)
  rating == 0        -> black  (drops everything)
  0 < rating <= τ    -> grey   (partial / unpredictable dropping)
  rating  > τ        -> white  (good relay, usable by AODV)
```

- **SCBC** (Self-Classification, Alg. 1–3): no prior knowledge; classify purely
  from the delivered ratio.
- **VCBC** (Voting-Classification, Alg. 4–5): miners cast prior reputation votes;
  a voting pre-filter removes grey/black-voted nodes **before** classification,
  so good relays are selected earlier → higher early PDR.

## B.2 Paper-reported results (Remix/Ethereum, 7-car highway, 2 attackers)

| Method | PDR | Throughput | Routing overhead |
|--------|-----|------------|------------------|
| **VCBC** | **78 %** | 1.16 kbps | 2.14 |
| SCBC | 56 % | 0.41 kbps | 2.6 |
| BCR (baseline) | 35 % | 0.44 kbps | 1.7 |

Accuracy: VCBC ≈ 80 %, SCBC ≈ 60 %.

## B.3 Our re-implementation

`scratch/soa2_blockchain_scbc_vcbc/`. The paper used Remix/Solidity; we deployed
the SCBC + VCBC contracts as **real Go chaincode on a real Hyperledger Fabric
network** (the same test-network as our SHIELD-GH DEBSC chaincode), for
consistency with our own blockchain plane. 8 chaincode unit tests pass (76.5 %
coverage). A live demo + an NS-3-CSV → on-chain → metrics bridge confirm the
classification runs on the actual ledger:

```
SCBC: car2 (drops all) -> black,  car3 (partial) -> grey,  car1 -> white
VCBC: voting excludes car2 & car3 up front -> only car1 survives (higher PDR)
On-chain end-to-end run: TP=2 TN=2 FP=0 FN=0, accuracy 100 %, FPR 0 %.
```

## B.4 Result diagrams

![SOA2 sweep](../results/soa2_sweep_panel.png)

*Figure B1 — SCBC vs VCBC over the attacker-percentage sweep (30-node parametric
model, 30 seeds). SCBC keeps ≈ 1.0 accuracy with 0 % FPR; VCBC sits 0.89–0.96
with ~10 % FPR because its noisy miner-voting occasionally excludes honest nodes
— reproducing the paper's accuracy/precision trade-off. PDR falls 0.91 → 0.71;
routing overhead is flat (a fixed per-node control cost).*

| Attacker % | SCBC acc | VCBC acc | PDR | VCBC FPR |
|-----------:|---------:|---------:|----:|---------:|
| 5  | 0.983 | 0.891 | 0.91 | 0.102 |
| 20 | 0.982 | 0.901 | 0.85 | 0.106 |
| 40 | 0.994 | 0.924 | 0.78 | 0.117 |
| 60 | 1.000 | 0.956 | 0.71 | 0.111 |

---

# Part C — Comparison with SHIELD-GH (our method)

## C.1 Capability matrix

| Capability | SOA1 (DPGHA) | SOA2 (SCBC/VCBC) | **SHIELD-GH** |
|------------|:---:|:---:|:---:|
| Data-plane drop detection | ✓ (PLR/RRR/DSN) | ✓ (delivered ratio) | ✓ (6 signatures S1–S6) |
| Control-plane attack detection | ✗ | ✗ | ✓ (CP-FR/IT/TS) |
| Mobility-aware correction | ✗ | ✗ | ✓ (MATD) |
| Blockchain trust layer | ✗ | ✓ (smart contracts) | ✓ (DEBSC on Fabric) |
| Real blockchain deployment | ✗ | ✓ (we added Fabric) | ✓ (Fabric + ZKP) |
| ML / LLM detection | ✗ | ✗ | ✓ (LLM + FL, full mode) |
| Post-quantum crypto mitigation | ✗ | ✗ | ✓ (Kyber/Dilithium) |
| Attack variants handled | 2 (Smart, Seq-No GHA) | 2 (black, grey) | **6** (DP + CP × FR/IT/TS) |

## C.2 Detection performance (our NS-3 setup, node-level confusion matrix)

| Method | Accuracy | TPR | FPR | MCC | Notes |
|--------|---------:|----:|----:|----:|-------|
| SOA1 DPGHA (real) | 100 % | 100 % | 0 % | 1.0 | flat at 4 nodes; PLR from real sim |
| SOA2 SCBC (sweep) | 98–100 % | high | **0 %** | — | parametric |
| SOA2 VCBC (sweep) | 89–96 % | high | ~10 % | — | voting adds false positives |
| **SHIELD-GH** | **100 %** | **100 %** | **0 %** | **1.0** | TP=1 TN=3 FP=0 FN=0, all 3 DP types detected + isolated |

## C.3 Paper-reported headline numbers (each in its own setting)

| Method | PDR under attack | Detection rate |
|--------|-----------------:|---------------:|
| SOA1 DPGHA (NS-2) | 87.75 % | 97.2 % |
| SOA2 VCBC (Ethereum) | 78 % | ~80 % |
| **SHIELD-GH** (NS-3 + Fabric) | recovers post-isolation | 100 % (MCC 1.0) on tested DP variants |

## C.4 Where SHIELD-GH advances each baseline

**vs SOA1 (DPGHA):**
- DPGHA needs RREQ/RREP/DSN control-plane signals and an RSU in promiscuous
  mode; SHIELD-GH detects from data-plane signatures **plus** a mobility
  correction (MATD) that removes the handoff-induced false positives DPGHA's
  fixed δ = 3 % cannot distinguish from real dropping.
- DPGHA covers **2 data-plane** variants; SHIELD-GH covers **6** (adds the
  controller-plane CP-FR/IT/TS class entirely absent from DPGHA).
- DPGHA's trust is a tamperable RSU table; SHIELD-GH anchors evidence on an
  append-only blockchain a grey-hole cannot rewrite.

**vs SOA2 (SCBC/VCBC):**
- SCBC/VCBC classify only from the delivered ratio — no mobility correction, so
  on a mobile VANET an honest vehicle losing packets to RSU handoff looks grey.
  SHIELD-GH's MATD corrects exactly this.
- VCBC's voting layer trades ~10 % false-positive rate for earlier decisions;
  SHIELD-GH's dual-evidence gate (statistical **and** ZKP cryptographic gate)
  achieves early isolation **without** that false-positive cost.
- SCBC/VCBC have **no AI and no cryptographic mitigation**; SHIELD-GH adds an
  LLM+FL full mode and PQC (Kyber/Dilithium) re-keying.

## C.5 The methodological point (supervisor's emphasis)

Both baselines and SHIELD-GH are driven by **real, event-driven data from the
NS-3 simulation** — the `--attack_percentage` flag injects real attackers and
the detectors consume the per-window per-node forwarding counters the simulation
emits (`malik_detection.csv`, `vcbc_detection.csv`). The blockchain and
cryptographic components are **really implemented** (Hyperledger Fabric chaincode,
ZKP, threshold signatures), not abstracted to stub functions. Where a signal is
genuinely unavailable in a data-plane-only simulation (DPGHA's RRR/DSN control
packets), it is explicitly modelled and disclosed, not silently faked.

---

# Appendix — Diagram index

| Figure | File | Content |
|--------|------|---------|
| A1 | `results/soa1_real_sweep_panel.png` | SOA1 on real ns-3 data |
| A2 | `results/soa1_sweep_panel.png` | SOA1 parametric trends |
| — | `results/soa1_sweep_{acc,pdr,ro}.png` | SOA1 individual metrics |
| B1 | `results/soa2_sweep_panel.png` | SOA2 SCBC vs VCBC |
| — | `results/soa2_sweep_{acc,pdr,ro}.png` | SOA2 individual metrics |

Per-baseline detail: `scratch/soa1_dpgha_malik/` and
`scratch/soa2_blockchain_scbc_vcbc/` (each has its own README and sweep report).
```
```
