# Technology Justification — SHIELD-GH

Why each technology was chosen for the SHIELD-GH grey-hole detection/mitigation
system, and what would be missing/weaker without it.

---

## NS-3 (Network Simulator 3)

**Why:** SHIELD-GH is a network-layer security mechanism (routing-layer attack
detection in an SDVN). It has to be evaluated where routing actually happens —
packet forwarding, drop behaviour, PDR, delay, jitter — under a realistic
wireless/vehicular MAC and PHY stack. NS-3 is the standard discrete-event
network simulator for this: it gives an accurate 802.11p/LTE PHY, routing,
and mobility integration, and is what nearly every SDN/SDV routing-security
paper in this space (including the state-of-the-art baselines we compare
against) uses, so results are directly comparable.

**What it replaces:** a custom packet-level simulator would need to
reimplement MAC contention, propagation loss, and mobility from scratch and
would not be trusted/comparable to prior work; a pure analytical/queueing
model can't reproduce the packet-level events (forwarding records, drop
signatures S1–S6) that the detection algorithm actually consumes.

---

## SUMO (Simulation of Urban Mobility)

**Why:** grey-hole and control-plane attacks in a Software-Defined Vehicular
Network are only meaningful under realistic vehicle mobility — topology
changes, link lifetime, and traffic density all affect detection accuracy
(false positives from mobility-induced link breaks vs. genuine attacks).
SUMO generates microscopic, road-network-accurate vehicle traces (used via
the NS-3/SUMO bridge) so the SDVN topology evolves the way real traffic
would, instead of a synthetic random-waypoint model that can hide or
exaggerate the attack's effect.

**What it replaces:** NS-3's built-in mobility models (random waypoint,
constant velocity) are not representative of road-constrained vehicular
movement; using them would make the link-lifetime and routing-stability
results (and the SOA comparisons that also use SUMO) scientifically weaker.

---

## Blockchain (Hyperledger Fabric + DEBSC)

**Why:** the detection/mitigation decision (isolate a suspected grey-hole
node) has to be **tamper-proof, auditable, and trusted by multiple
controllers/RSUs** that don't fully trust each other — a single controller
unilaterally blacklisting a node is a single point of failure and a single
point of compromise (a compromised controller could frame or protect an
attacker). A permissioned blockchain (Hyperledger Fabric, DEBSC = Decentralised
Evidence-Based Smart Contract) gives:
- **Higher security / integrity** — isolation verdicts are endorsed by
  multiple peers (Org1+Org2) and written to an immutable ledger, so no single
  node can forge or erase a verdict.
- **Auditability** — every reputation update and isolation decision is
  queryable on-chain evidence (used directly in Task 1's evidence).
- **Decentralised trust** — matches the SDVN's multi-controller/RSU
  architecture; no single RSU is a trust bottleneck.

**What it replaces:** a plain in-memory blacklist/database on one controller
would be faster but trivially spoofable or single-point-of-failure; it
couldn't provide the cryptographic endorsement + immutability the report's
"trust dual-gate" (Eq. 3.19) design assumes.

---

## Post-Quantum Cryptography + Threshold Signatures (Kyber/ML-KEM, Dilithium/ML-DSA)

**Why:** SDVN control messages (FlowMod isolation commands) and node identity
have to stay secure even against a **future quantum adversary** — a vehicular
network deployed today needs a multi-decade security horizon, and classical
ECC/RSA are broken by Shor's algorithm once large quantum computers exist.
NIST-standardised PQC (ML-KEM-1024 / ML-DSA-87, Level 5) future-proofs key
exchange and signatures. Threshold signatures (k-of-n RSU co-sign) additionally
mean **no single RSU can unilaterally isolate a node** — an extra Byzantine-
fault-tolerance layer on top of blockchain endorsement.

**What it replaces:** classical ECDSA/RSA would be simpler and faster today
but has no quantum-resistance story; a single-signer authorization would
reintroduce the single-point-of-compromise problem blockchain was chosen to
avoid.

---

## LLM (Qwen2.5-7B)

**Why:** the rule-based signatures (S1–S6, threshold/statistical detectors)
work well for simple, high-volume drop patterns but **fail on sequence-order
and intermittent/targeted attack variants** — the project's own evidence
(`selection/run_selection.py`) shows a classical bag-of-tokens/ML baseline
tops out at MCC≈0.76 and specifically **fails DP-IT (F1=0.51) and DP-TS
(F1=0.58)**, the attacks defined by *when* and *which flow* packets are
dropped, not just *how many*. An LLM, fed tokenised forwarding-window
sequences, can model that temporal/targeted structure the way a fixed
threshold rule or a bag-of-words classifier cannot. Qwen2.5-7B was picked
after a measured 4-model comparison (vs Mistral-7B, Nemo-12B, Qwen2.5-14B) as
the best accuracy/latency trade-off (MCC 0.80 tied with the 14B model at
roughly half the latency, 17.8ms/window on RTX 5090).

**What it replaces:** without an LLM, the system is limited to hand-crafted
statistical signatures — brittle to attack variants the designer didn't
anticipate, and this exact gap (sequence-order attacks) is what the ML
selection evidence was built to demonstrate.

---

## Federated Learning (FL)

**Why:** the forwarding-behaviour data an LLM/scorer needs to train on lives
on individual RSUs/controllers across the vehicular network, and **that
traffic data is privacy- and operator-sensitive** — pooling raw logs from
every RSU into one central trainer is both a privacy liability and a
realistic deployment blocker (different road operators won't share raw
traffic). FL (FedAvg, Eq. 3.25/3.26) lets each RSU train locally and only
share model updates, which are then aggregated — combined with a blockchain
hash-commit integrity check (Eq. 3.16/3.27) so a malicious RSU can't poison
the global model with a bad gradient update.

**What it replaces:** centralised training would require shipping raw
per-vehicle traffic logs to one server — worse privacy, a single data
honeypot, and no defence against a poisoned central dataset; FL's
gradient-integrity check is also what lets the blockchain's trust model
extend from "who gets isolated" to "whose model updates are trusted."

---

## Why these combine (not independently optional)

Each piece covers a gap the others leave open:

| Technology | Covers |
|---|---|
| NS-3 + SUMO | realistic network + mobility ground-truth to detect against |
| Rule-based signatures (S1–S6) | fast, cheap detection of simple/high-volume attacks |
| LLM | detection of sequence-order/targeted attacks rules miss |
| FL | trains the LLM/scorer without centralising sensitive traffic data |
| Blockchain (DEBSC) | tamper-proof, multi-party-auditable isolation verdicts + FL update integrity |
| PQC + threshold sigs | long-horizon (quantum-safe) + Byzantine-safe authorization of isolation commands |

Removing any one leaves a specific, evidenced weakness: no NS-3/SUMO → no
credible network-layer evaluation; no LLM → misses DP-IT/DP-TS attacks
(measured F1 0.51/0.58); no FL → central privacy risk; no blockchain →
spoofable/single-point-of-failure verdicts; no PQC/threshold → verdicts are
quantum-vulnerable and single-signer.
