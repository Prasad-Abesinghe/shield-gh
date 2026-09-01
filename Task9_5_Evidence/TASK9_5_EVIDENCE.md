# Task 9.5 — Internal Ablation Study (Pass 1)

**Date:** 2026-08-13
**Status:** Pass 1 complete — 5 ablation arms run, 38 real NS-3 runs, 6 figures.
**Scope decision (user, 2026-08-13):** run the ablations that have real wired
code knobs today; build the missing ones in pass 2.

---

## 1. Headline results

| Ablation | Component removed | Effect on M1 (MCC) | Verdict |
|---|---|---|---|
| **SIG** | All signatures S1–S6 | **0.84 → 0.00** at every ρ | **Decisive** — the signature layer performs essentially all node-level detection |
| **A12** | Multi-controller (M=1) | CP MCC **1.00 → 0.00** | **Decisive** — controller-compromise detection is impossible with a single controller |
| A7 | DEBSC ZKP gate | 0.00 (no change in M1) | **Null on M1** — but changes isolation behaviour (see §4) |
| A1 | MATD handoff correction | ≤ 0.05, non-monotonic | **Null** — explained by design (see §3) |
| A4 | LLM semantic scorer (μ₂=0) | ≤ 0.04, non-monotonic | **Null** — caused by the stand-in LLM (see §3) |

The two decisive results are the citable ones. **The three nulls are reported
as nulls.** They are not presented as evidence of component value.

---

## 2. Configuration (reproduces Task 9's signed-off control exactly)

```
--routing_test=true --simTime=10 --routing_algorithm=4
--N_Vehicles=16 --N_Controllers=4
--attack_number=1                            (DP-FR, data plane)
--attack_percentage=40
--enable_cp_attack=1 --cp_attack_number=6    (CP-TS, controller plane)
--cp_attack_percentage=40                    -> 2 of 4 controllers malicious
--rng_run=1
```

**Verified baseline:** this config reproduces Task 9's FINAL RESULT
bit-for-bit — `TP=38 TN=80 FP=0 FN=10`, **M1 MCC = 0.84**, **CP MCC = 1.00**.
Every ablation delta is measured against this same control, so a delta is
attributable to the single removed component.

> **Config warning for whoever runs this next.** An earlier draft of the driver
> used `simTime=30` with `attack_onset_delay=6.0` and scored MCC=0.22. That is
> not a regression — a 6 s onset on a short sim leaves almost no attack window.
> Do not change `simTime` or `attack_onset_delay` without re-verifying the
> control reproduces 0.84 first.

---

## 3. The three null results — why, honestly

### A1 (MATD) — null by deliberate design, not a broken toggle

The toggle **is** live: logs show `enable_matd=0` vs `=1` reaching the sim
(`[RQ3] node=… enable_matd=…`, 61–62 occurrences per run). But
[`lw_dp_det.cc:78-92`](../shield_gh/detection/lw_dp_det.cc#L78) applies

```
tau_f_effective = (tau_f_tuned − rho_ho(v_tuned)) + rho_ho(v_now)
```

which was added in Task 8.5 so the S1 decision boundary keeps the same
physical margin at any speed. That compensation **deliberately cancels MATD's
effect on the S1 threshold**, so the control and ablated arms converge. The
only point where a gap appears (90 km/h, 0.80 vs 0.85) is where the
compensation and the correction do not fully cancel.

**Consequence for the paper:** A1's contribution cannot be demonstrated
through M1 at a fixed speed. It needs **M4 (FIR)** — the metric main.tex
actually assigns to A1 — which is not implemented. Reporting A1 on M1 alone
would understate a component that is working as designed.

### A4 (LLM scorer) — null because the LLM is a stand-in

The toggle is live and the arms genuinely differ: the control arm invokes
`ns3_infer` (9 calls) and emits Q_i values; the ablated arm emits none.

But the emitted Q_i values are **0.860–0.878** — near-constant. This is the
known hashing stand-in, not Qwen. A near-constant score carries almost no
discriminative information, so removing it barely moves MCC.

**Consequence:** this measures the *stand-in's* contribution, which is
approximately zero by construction. It is **not** a measurement of the LLM
component's value and must not be reported as one. A real A4 needs the
genuine Qwen path (rebuild + `shield-ml-venv` + the inference-caching fix).

### A7 (ZKP gate) — null on M1, but the gate is demonstrably active

Log comparison at ρ=50 shows the ablated arm producing **19 additional
`ISOLATE`/`isolation` events** that the control arm suppresses. The gate is
working; it changes *who gets isolated*, not *who gets detected*.

**Consequence:** A7's effect lands on **M2/M4** (attack-impact reversal and
false-isolation rate), exactly as main.tex assigns it — not on M1. Neither
metric is implemented, so A7 cannot currently be scored on its own terms.

---

## 4. Coverage against main.tex's 17 ablations

main.tex `sec:ablation` defines **A1–A17**. An audit of `routing.cc` and
`shield_gh/` found only these with an implemented, wired CLI toggle:

| Ablation | Flag | Ran? |
|---|---|---|
| A1 | `--enable_matd=0` | ✅ |
| A4 | `--enable_full_mode_ai=0` | ✅ |
| A7 | `--enable_zkp_gate=0` | ✅ |
| A12 | `--N_Controllers=1…8` | ✅ |
| (SIG) | `--enable_signatures=0` | ✅ (not a main.tex ID; blanket reference bound) |
| **A2, A3** | — | ❌ **no per-signature / no CP-detector toggle exists** |
| **A5, A6, A8–A11, A13–A17** | — | ❌ no flags at all |

**13 of 17 ablations have no implementation.** They were not run and no
numbers are reported for them.

### Metric coverage is the deeper gap

Only **M1 (MCC)** is implemented, plus the controller-plane MCC added in
Task 9. M2/M3/M4/M5 exist only as comments in `routing.cc`; M7–M12 do not
exist at all. But main.tex assigns A1→{M1,M4}, A7→{M2,M4}, A8–A11→{M7,M8},
etc. **Most ablations are scored on metrics that do not exist**, which is
precisely why A1 and A7 come back null here: they are being measured on the
one metric that does not capture what they do.

---

## 5. Files

| File | What it is |
|---|---|
| `ablation_driver.py` | Sweep driver — 38 runs, checkpointed, Gurobi thread-pinned |
| `ablation_results.csv` | Raw results, one row per run |
| `make_ablation_figures.py` | Figure generator |
| `ablation_{A1,A4,A7,A12,SIG}.png` | Per-ablation figures |
| `ablation_summary.png` | Component-contribution bar chart |
| `logs/` | Full stdout for all 38 runs |
| `sweep_run.log` | Driver progress log |

Runtime: 4.3 min wall-clock for all 38 runs at 8 workers.

---

## 6. What pass 2 needs

Ordered by value to the paper:

1. **A2 + A3** — the two SOTA-comparable ablations. Need a per-signature
   enable mask (S1 / S1+S2 / S1+S2+S3) and a CP-detector toggle. These reuse
   the Task 9 baseline-comparison harness directly and are what reviewers
   scrutinise hardest.
2. **M2 and M4** — without them A1 and A7 cannot be scored on the metrics
   main.tex assigns them, and both will keep reading as false nulls.
3. **Genuine LLM path for A4** — otherwise A4 measures a constant.
4. Decide the fate of A5/A6/A8–A11/A13–A17: implement, or cut from main.tex
   before submission. Leaving 17 promised ablations with 4 evaluated is the
   one outcome that will not survive review.

**main.tex was deliberately not edited.** Trimming the table now would delete
ablations intended for pass 2; the honest coverage record lives here instead.
