# Task 9 — SOTA verification, corrections, and a decision I need from you

**Date:** 2026-08-12
**Scope:** Verification of all 3 SOTA baselines against their source papers;
two defects found and fixed; re-run results; one open decision.

---

## 1. Summary (read this first)

You asked me to confirm whether SHIELD-GH is superior to all 3 state-of-the-art
baselines. **The answer is yes**, and that verdict has survived every
correction round below.

But two problems surfaced during verification that you should know about
before signing off, and one of them **conflicts with your earlier "one seed is
enough" instruction**. I have not silently changed the protocol — I am
bringing it to you.

| | Result |
|---|---|
| **SHIELD-GH** | **MCC = +0.94** (TP=15, TN=16, FP=0, FN=1) |
| SOA1 / SOA2 / SOA3 | 0.00 (absolute suppression) **or** 0.34 / 0.27 / 0.24 (probabilistic) |

The choice between those two baseline columns is the decision I need from you
(Section 6).

---

## 2. Paper verification — all 3 SOTA checked against their sources

I obtained and read all three papers in full and audited each implementation
line-by-line against them.

### SOA1 — Malik et al., *"An Efficient Approach for the Detection and
Prevention of Gray-Hole Attacks in VANETs"*, IEEE Access vol.11 (2023),
pp.46691–46706, DOI 10.1109/ACCESS.2023.3274650

**Paper's method:** RSU in promiscuous mode maintains a Master Routing Table,
then applies three thresholds — PLR (Eq.13–14, δ=3%), RRR =
RREP_generated/RREQ_received (Eq.15, λ=70%), and μ(DSN) against a dynamic
β (Eq.16–17). Eq.18 decides: *SmartGHA* if `PLR>δ AND RRR≥λ`; *SeqNoGHA* if
`μ(DSN)≥β AND (PLR>δ OR RRR≥λ)`.

**Status: FAITHFUL — verified by executable test.** Our `dpgha.py` self-test
reproduces the paper's Table 2 exactly:

```
β = 49.5 (paper: 49.5)
  V3: PLR=4.706% RRR=92.000% DSN=23  -> SmartGHA
  V5: PLR=2.143% RRR=93.750% DSN=200 -> SeqNoGHA
  (all six other vehicles -> Normal)
OK — Python port matches paper Table 2.
```

**No mismatch against the paper.**

### SOA2 — Alabdulatif, Alharbi, Mchergui, Moulahi, *"Mitigating Blackhole and
Greyhole Routing Attacks in VANETs Using Blockchain Based Smart Contracts"*,
CMES vol.138 no.2 (2024), pp.2005–2021, DOI 10.32604/cmes.2023.029769

**Paper's method:** Smart contracts classify relays. Alg.3:
`rate = delivered×100/(delivered+notDelivered)`; rating==0 → black,
rating>τ → white, else grey. Alg.4–5 (VCBC) add a voting pre-filter removing
grey/black-reputation nodes before the same classification.

**Status: FAITHFUL, and genuinely on-chain.** `scbcvcbc.go:classify()` matches
Alg.3 exactly; `makeVoting()` matches Alg.4 line-for-line; `RunVCBC()` matches
Alg.5. Classification executes on a real Hyperledger Fabric deployment, not a
stub.

**No mismatch against the paper.** One judgement call to note: the paper never
fixes τ numerically, so we chose τ=50%.

### SOA3 — Arízaga-Silva, Medina-Santiago, Espinosa-Tlaxcaltecatl,
Muñiz-Montero, *"Machine Learning-Powered IDS for Gray Hole Attack Detection
in VANETs"*, World Electric Vehicle Journal 2025, 16, 526,
DOI 10.3390/wevj16090526

**Paper's method:** 20 flow features (time-/packet-/protocol-based) from NS-3,
Random Forest with **15 estimators, max_depth 15**, 10-fold stratified CV.
Reports F1 = 0.9927.

**Status: FAITHFUL.** Correct hyperparameters, real scikit-learn RF, real
repeated stratified CV.

**No mismatch against the paper's algorithm.**

### Verification verdict

**No SOTA implementation contradicts its source paper.** All three reproduce
their published detection logic. The problems found were elsewhere.

---

## 3. Defect 1 — SOA1 was scored on an easier ground truth than SOA2/SOA3

**This one is a direct consequence of how your round-6 instruction was scoped,
so I want to be explicit about it.**

Your instruction was *"Correct SOA2 and SOA3 to report a value."* We did
exactly that — and only that. It named two baselines, so **SOA1 never received
the same controller-plane ground-truth extension**:

| Baseline | Ground truth before this fix |
|---|---|
| SOA2 | `DP* \|\| (CP* && cp_drop_counter>0)` |
| SOA3 | `DP* \|\| (CP* && cp_drop>0)` |
| **SOA1** | **`DP*` only** ← defect |

A node compromised *only* via the controller plane was therefore labelled
BENIGN for SOA1 but ATTACKER for SOA2/SOA3. SOA1 was being scored against a
**different, easier problem** — the exact defect you identified in SOA2,
left unfixed in SOA1 purely because the instruction named two baselines.

This is what produced SOA1's non-comparable MCC = 1.00 in the round-6
intermediate numbers.

**Fixed** in `routing.cc` at both SOA1 ground-truth sites (`write_malik_csv()`
and `malik_monitor_window()`), using the identical rule and the same
`cp_drop_counter > 0` observability cap already applied to SOA2/SOA3. All three
baselines are now scored on one common ground truth.

**Also found and fixed:** `results/vcbc_detection.csv` and
`soa3_rf_features.csv` had accumulated **41 appended headers** from past runs
at differing topology sizes (up to 20 nodes). The Python bridges read the last
row, so they would silently score whichever run happened to be last in the
file. Both cleared before re-running. Flagged as a re-run hygiene issue for
Tasks 9.5 and 10.

---

## 4. Defect 2 — the suppression model produced MCC = 0.00 for all baselines

After fixing Defect 1, all three baselines returned **exactly 0.00**. That is
not a credible result, so I investigated rather than reporting it.

### The 0.00 was not a detection failure

Every baseline detected correctly and was then overruled:

| Baseline | Raw MCC (its own verdict) | After suppression |
|---|---|---|
| SOA1 | **+1.000** (TP=2 TN=2 FP=0 FN=0) | 0.00 |
| SOA2 | **+1.000** | 0.00 |
| SOA3 | **+0.891** | 0.00 |

SOA2's console output shows the mechanism most clearly — the chaincode
classified both attackers correctly as `grey` (ratings 23.8% and 7.5%), and
the compromised controller then converted both correct findings into false
negatives.

**The baselines are not failing to detect. They are detecting correctly and
being overruled.** That is a stronger and more accurate statement of your
threat model than "the SOTAs scored zero" — but the bare 0.00 does not
communicate it.

### Three problems caused the 0.00

1. **Suppression was absolute (p = 1.0)** — the gate deleted *every* correct
   verdict. Your description (falsified OpenFlow counters, sub-threshold rule
   injection, deceiving voting/reputation systems) describes *degradation* of
   the evidence channel, not a perfectly reliable 100% censor. Absolute
   suppression is stronger than your threat model requires.
2. **MCC = 0 is ambiguous** — it is the identical value a randomly-guessing
   detector produces. Reporting it alone destroys the distinction between
   "detected correctly, overruled" and "failed to detect". A reviewer will
   read it as "the baselines are broken", which is wrong and unfair to them.
3. **At N=4, MCC has almost no resolution** — with 2 attackers and 2 benign
   nodes the only reachable values are ≈ {0.00, 0.577, 1.00}. There is no
   "low but nonzero" available at a single seed.

### Fix

New shared module `soa_suppression.py`, used identically by all three
baselines. Suppression is now **probabilistic** (default p = 0.75: the
controller hides *most* correct detections, not all), deterministic in
`(salt, rng_run, node)` so results reproduce exactly, and **both raw and
post-suppression scores are now reported**.

**p = 0.75 is an explicit modelling assumption, not a measurement.** It is
labelled as such in the code, and the sensitivity sweep below is provided so
it is never presented as an empirical constant.

---

## 5. Results

Scenario: DP-FR + CP-TS jointly, N=4, t=10s, attack_percentage=40%.

### SHIELD-GH (unaffected by suppression — architecturally not
controller-mediated)

```
MCC = +0.94   (TP=15, TN=16, FP=0, FN=1)
[SHIELD-GH][CP] Controller 0 grey-hole flow rule detected | S4=1 S5=1 S6=1
```

Its LW-CP-Det flagged the compromised controller directly. SHIELD-GH's
LLM/Fusion verdicts reach the DEBSC RSU-consensus ledger without passing
through the controller, so it has no equivalent single point of falsification.
This is an architectural property, not a scoring advantage granted to it.

### Baselines — suppression sensitivity sweep

Mean actionable MCC (SOA1/SOA2: 20 seeds; SOA3: 5 seeds):

| p | SOA1 | SOA2 | SOA3 | SHIELD-GH |
|---|---|---|---|---|
| 0.50 | 0.652 ± 0.376 | 0.575 ± 0.293 | 0.403 ± 0.123 | **0.94** |
| **0.75** | **0.344 ± 0.406** | **0.273 ± 0.354** | **0.236 ± 0.095** | **0.94** |
| 1.00 | 0.000 ± 0.000 | 0.000 ± 0.000 | 0.000 ± 0.000 | **0.94** |
| *raw* | *+1.000* | *+1.000* | *+0.891* | *0.94* |

**SHIELD-GH outperforms all three baselines at every suppression level.**

---

## 6. THE DECISION I NEED FROM YOU

Probabilistic suppression conflicts with your earlier *"one seed is enough"*
instruction, and I did not want to overrule that unilaterally.

**The problem:** at p=0.75 with only 2 attacker nodes, the standard deviation
exceeds the mean for SOA1 (0.406 vs 0.344) and approaches it for SOA2
(0.354 vs 0.273). A single seed can only land on 0.00, 0.577 or 1.00 — that is
a coin flip, not a result.

**Concretely: `rng_run=1` — the seed our signed-off result uses — happens to
draw no suppression at all**, which would report SOA1 at 1.00. That is luck,
not signal.

You cannot simultaneously have: single-seed reporting, probabilistic
suppression, and N=4. One must give.

### Option A — keep absolute suppression (p=1.0), single seed

> SHIELD-GH 0.94 vs SOA1/SOA2/SOA3 all 0.00, with raw scores
> (+1.00 / +1.00 / +0.891) reported alongside.

- Preserves your "one seed is enough" protocol exactly.
- The raw column prevents 0.00 being misread as a broken baseline.
- But 0.00 remains an extreme claim, and models the controller as a perfect
  censor.

### Option B — probabilistic suppression (p=0.75), multi-seed mean

> SHIELD-GH 0.94 vs SOA1 0.34, SOA2 0.27, SOA3 0.24.

- Most defensible under peer review; cannot be dismissed as "you zeroed the
  baselines".
- Closer to your actual threat description (degradation, not deletion).
- But requires multi-seed reporting, i.e. reopening the single-seed protocol.

**My recommendation: Option B**, because single-seed reporting under
probabilistic suppression at N=4 is not statistically meaningful. Option A is
entirely reasonable if you prefer to keep the protocol fixed — in which case
the raw-vs-actionable pair must be reported together.

I will implement whichever you choose.

---

## 7. Two limitations that must be disclosed in the report (not bugs)

These are properties of our simulation scenario, not implementation errors,
but a reviewer will find them if we do not state them first.

1. **SOA1 runs at reduced strength.** Our scenario is data-plane only and
   exposes no RREQ/RREP/DSN control-plane counters (documented at
   `routing.cc:364-365`), so two of DPGHA's three gates (RRR, μ(DSN)) are
   unavailable and it degrades to the PLR-only sub-rule. This is the honest
   handling — the earlier alternative synthesised those signals from the
   ground-truth label, which was the data leak removed on 2026-08-09 — but
   the report must state that a **weakened DPGHA** was evaluated.

2. **SOA3 uses 12 of the paper's 20 features**, missing the protocol-based
   ones (hop count mean/std, dest_seq mean/std) and byte-level forward/backward
   statistics, for the same reason. Mitigating factor: the paper's own Table 4
   ranks transmission rate and packet/byte counts as the *most* influential
   features, and we do have those.

3. **SOA2 is unaffected** — it only ever required delivered/not-delivered
   relay counts, which we have in full.

If you want SOA1 and SOA3 at full paper strength, that requires adding AODV
control-plane counters to the simulation. That is real work and I would
suggest scheduling it with Task 10 rather than bolting it on now — but it is
your call.

---

## 8. Caveat on scope

The N=4 / t=10s operating point is a smoke test, as you specified. SOA3's
variance is much tighter (±0.095) than SOA1/SOA2's because it evaluates 32
windowed rows rather than 4 nodes — which confirms the variance problem is a
small-N artefact that resolves at Task 10's larger scale.

The claim I am comfortable defending from Task 9 is: **on the complete DP+CP
threat model, SHIELD-GH detects the compromised controller and retains
MCC 0.94, while all three baselines — despite each computing correct verdicts
— are overruled by the controller they depend on.** Broader superiority claims
across the full attack space belong to Task 10's E1–E5 grid.

---

## 9. Files changed

| File | Change |
|---|---|
| `routing.cc` | SOA1 ground truth extended to CP plane at both sites (Defect 1) |
| `soa_suppression.py` | **New** — shared probabilistic suppression model (Defect 2) |
| `soa1_dpgha_malik/dpgha_sweep_real.py` | Uses shared suppression; reports raw + actionable |
| `soa2_blockchain_scbc_vcbc/scbcvcbc_bridge.py` | Same |
| `State_of_Art_3/soa3_rf_sweep_real.py` | Same, applied per-prediction inside CV |
| `Task9_Evidence/TASK9_EVIDENCE.md` | Both corrections documented in full |
| `tasks.md` | Task 9 entry updated |

Papers archived at `State_of_Art_3/papers/`.
