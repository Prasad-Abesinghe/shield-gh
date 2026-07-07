# SOA1 — Malik et al. DPGHA (faithful re-implementation)

First state-of-the-art baseline for the SHIELD-GH comparison (report B1).

**Paper:** Malik, Khan, Qaisar, Faisal, Mehmood (2023), *"An Efficient Approach
for the Detection and Prevention of Gray-Hole Attacks in VANETs"* (DPGHA),
IEEE Access vol.11, pp.46691–46706. DOI 10.1109/ACCESS.2023.3274650.

## Why this directory exists (correctness fix)

The previous SOA1 (`scratch/soa_baselines/malik_detection.h`, and the in-sim
`malik_monitor_window` in `routing.cc`) flagged a node when its PDR fell below
`network_average − α`. **That is not the paper's method.** The DPGHA paper
detects two gray-hole variants from **three** signals computed by an RSU over
its Master Routing Table (Eq. 13–18):

| Signal | Equation | Threshold |
|--------|----------|-----------|
| **PLR** – data Packet Loss Ratio | Eq. 13–14 | fixed **δ = 3 %** |
| **RRR** – ΣRREP_generated / ΣRREQ_received · 100 | Eq. 15 | fixed **λ = 70 %** |
| **μ(DSN)** – mean Destination Sequence Number | Eq. 16–17 | **dynamic β** = mean of all nodes' μ(DSN) |

**Decision (Eq. 18):**
- **Smart GHA** if `PLR > δ AND RRR ≥ λ`
- **Sequence-Number GHA** if `μ(DSN) ≥ β AND (PLR > δ OR RRR ≥ λ)`
- **Normal** otherwise

β (sequence numbers) is the *only* dynamic threshold; PLR and RRR use the fixed
δ/λ from the paper. The old code mislabelled a PDR margin as "the dynamic
threshold", which was the core error.

## Faithfulness vs the simulator

This NS-3 setup is **data-plane only** — it exposes no RREQ/RREP/DSN counters,
only data-packet forwarding. So:
- **PLR** is computed from the **real** forwarding counters.
- **RRR** and **μ(DSN)** are **modelled per node-type** (Smart-GHA / Seq-No-GHA /
  honest) following the paper's stated gray-hole properties (§II, §V).
- The **detection logic itself is the paper's, unchanged** — see the self-test
  below, which reproduces the paper's Table 2 worked example exactly.

The in-sim detector in `routing.cc` was corrected to apply the genuine **PLR > δ
= 3 %** gate (the signal the simulation truly has), instead of `avg − α`.

## Layout

```
soa1_dpgha_malik/
├── dpgha_detection.h     # faithful Eq.13-18 detector (C++ header)
├── dpgha_selftest.cc     # reproduces paper Table 2 (β=49.5, V3=Smart, V5=SeqNo)
├── dpgha.py              # Python port of Eq.13-18 (identical results)
├── dpgha_sweep.py        # attacker-% sweep + plots (mirrors SOA2)
├── run_tests.sh          # runs both self-tests
├── malik_detection_OLD_incorrect.h.bak   # archived wrong version, for diff
└── README.md
```

## Verify (reproduces the paper's worked example)

```bash
bash run_tests.sh
```
Expected: β = 49.5; V3 → SmartGHA, V5 → SeqNoGHA, all others Normal; TP=2 TN=6
FP=0 FN=0 (matches paper Table 2 exactly), for both the C++ and Python versions.

## Attacker-percentage sweep + plots

```bash
python3 dpgha_sweep.py --N 30 --seeds 30 \
        --fracs 0.05,0.1,0.15,0.2,0.3,0.4,0.5,0.6
```
Outputs to `results/`:
- `soa1_sweep_panel.png` — accuracy, PDR, TPR/FPR, routing overhead
- `soa1_sweep_{acc,pdr,ro}.png` — individual figures
- `soa1_sweep_results.csv` — raw per-seed rows

Node types follow the paper: Smart GHA and Seq-No GHA each get half the
attackers; both drop data packets and flood RREPs (high RRR); Seq-No GHA also
inflates DSN. Honest nodes' observed loss rises with attacker density
(path contamination), so the curves move instead of sitting flat.

**What the curves show:**
- **Detection accuracy** rises 0.85 → 1.00 as attacker % grows (denser attacks
  separate more cleanly; the dynamic β stabilises and FPR → 0).
- **Network PDR** (Eq. 20) falls 0.96 → 0.75 — the headline trend.
- **Routing overhead** (Eq. 19) *rises* with attacker % — gray-holes flood
  RREPs, matching the paper's stated overhead mechanism (§V.A).
- **TPR** stays ≈ 1.0; **FPR** drops from ~16 % to 0 %.

## Metrics (paper §V)
- PLR Eq.14 · RRR Eq.15 · μ(DSN)/β Eq.16-17 · decision Eq.18
- PDR Eq.20 · Routing overhead Eq.19 · Detection rate (TPR) Eq.24
```
```
