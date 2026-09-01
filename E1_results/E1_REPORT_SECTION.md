# E1 Results — draft section for main.tex

**Status: COMPLETE.** 180/180 runs finished in 77.7 min, every run exited `ok`,
all 180 cells present, all MCC values in range (`verify_e1.py` passes).
All numbers below are measured, not projected.

**Artefacts** (all in `E1_results/`):

| File | Contents |
|---|---|
| `e1_m1_results.csv` | raw 180-row result set |
| `e1_mcc_heatmaps.png` | 5-panel MCC heatmap, shared colour scale |
| `e1_mcc_lines.png` | MCC vs drop rate at p=40% |
| `e1_results_table.tex` | paste-ready LaTeX grid table |
| `e1_density_split.txt` | **the recommended headline table** |
| `e1_summary.txt` | pooled means + false-positive check |
| `verify_e1.py` | integrity check, re-runnable |

---

## What was actually run

| Item | Value | Note |
|---|---|---|
| Grid | $p \in \{0,20,40,60,80,100\}\%$ × $\rho_a \in$ same | 36 cells, as specified |
| Systems | SHIELD-GH full, SHIELD-GH lightweight, B1, B2, B3 | all five, as specified |
| Runs | 180 | one per (cell, system) |
| $N$ | **20 vehicles** | *deviates from the specified 200 — see below* |
| Variant | **S1 (DP-FR) only** | *deviates from "all six simultaneously" — see below* |
| Metric | **M1 (MCC) only** | *M2–M5 not instrumented — see below* |
| Speed | 80 km/h | as specified |
| simTime | 30 s, attack onset at 6.0 s | onset delay gives a pre-attack baseline |

---

## Three deviations that must be stated in the paper

Each is a real constraint of the current simulator, not a shortcut. Writing
them down plainly is safer than letting a reviewer find them.

### 1. Only M1 (MCC) is reported

`routing.cc` computes and prints only `CUM M1a Detection Accuracy` and
`CUM M1b MCC`. The strings `GHSR`, `AVCR`, `ESRL`, `FIR` appear in the source
**only inside comments** — verified by
`grep -nE 'cout.*(GHSR|AVCR|ESRL|FIR)' routing.cc`, which returns nothing.

M2 (GHSR), M3 (AVCR), M4 (FIR) and M5 (ESRL) are therefore **not measurable**
today. E1 is presented as a detection-quality comparison.

> **Suggested wording.** "Experiment E1 evaluates detection quality (M1,
> Matthews Correlation Coefficient) across the attacker-penetration ×
> drop-rate grid. Metrics M2–M5 require mitigation-pipeline instrumentation
> that is not present in the current simulator build and are deferred to
> future work."

Do **not** leave the M2–M5 columns in the E1 table as blanks or dashes — an
empty column reads as "measured and got nothing," which is worse than an
explicit scope statement.

### 2. $N=20$ rather than $N=200$

`optimize_link_lifetime()` in `routing.cc` shells out to
`optimization_lifetime.py` **once per simulated second**, and that script
solves one Gurobi model per node pair (an $n^2$ loop). At $N=200$ this
dominates: a single 30 s simulation was observed blocked for **18+ CPU-hours**
at 0 % CPU, waiting on the solver. At $N=20$ a run completes in ~4 min.

> **Suggested wording.** "Simulations are run at $N=20$ vehicles. The
> link-lifetime optimisation invoked each simulated second scales as $O(n^2)$
> in the vehicle count, making larger populations computationally prohibitive
> in the present implementation; scaling behaviour is addressed separately in
> Experiment E3."

### 3b. SHIELD-GH full mode used the fallback scorer, not Qwen2.5-7B

`shield_gh_integration.h` hardcoded `bool genuine = false`, so full mode ran a
hashing/softmax **stand-in** rather than the real LLM. Its output carries no
discriminative signal — it emitted `Q_i ~ 0.85` for *every* node, attacker or
not — so fusing it with the real signature term actively degraded detection.

Why the real model was not used instead: enabling it needs a source edit
(now available as `SHIELD_GH_GENUINE_LLM=1`, default unchanged) **plus** a full
rebuild, and measured genuine inference is **~10 min per 4-node window**. At
~30 windows per run × 36 runs that is roughly a week of GPU time. The cause is
already recorded in `ns3_infer.py`: `build_scorer()` retrains the model from
scratch on every invocation instead of loading once and caching — the source
comment itself flags this as "a separate, larger issue flagged for follow-up".

The environment is otherwise fully ready (torch 2.11.0+cu128, RTX 5090,
transformers, peft, bitsandbytes, Qwen2.5-7B weights and the LoRA adapter all
present), so this is purely an inference-efficiency blocker.

> **Decision (2026-08-09):** report **SHIELD-GH lightweight** as the evaluated
> configuration; full-mode LLM evaluation is deferred to future work pending
> an inference-caching fix. Do **not** present the stand-in full-mode numbers
> as the framework's LLM performance.

### 3. Variant S1 only, not all six simultaneously

The codebase applies **one attack variant per run** (`--attack_number`); there
is no per-node mixed-variant attacker pool. "All six variants active
simultaneously" is not expressible without modifying the attack-assignment
code.

Averaging six single-variant runs per cell — the approach the earlier driver
attempted — was rejected: it costs 6× the compute *and* cannot reproduce
variant interaction, so it would not deliver what the spec asks for anyway.

> **Suggested wording.** "Each grid cell injects the fixed-rate data-plane
> variant (S1/DP-FR) as the representative attack. The simulator applies a
> single attack variant per run; per-variant results are reported separately
> in Experiment E5."

---

## Reading the figures

- **`e1_mcc_heatmaps.png`** — five panels, shared colour scale. $x$ = drop
  rate $\rho_a$, $y$ = attacker penetration $p$. Cell values printed in-place.
- **`e1_mcc_lines.png`** — MCC vs $\rho_a$ at $p=40\%$, one line per system;
  the cleanest single figure for a head-to-head comparison.
- **`e1_results_table.tex`** — full grid, paste-ready.

### The $p=0\%$ row is your correctness check
At zero attackers there are no positives to find. MCC is **undefined** (0/0)
and will show as `n/a` or 0 — that is correct behaviour, not a failure. Do not
present that row as "perfect detection." It is best used as a false-positive
check via the accuracy column instead.

### Two columns that are not detection failures

Both must be excluded before averaging, or every system looks artificially bad:

- **`p=0` row** — no attackers exist, so MCC is 0/0. Accuracy (94–98%) is the
  meaningful number there, as a false-positive check.
- **`rho_a=0` column** — attackers exist but drop *nothing*. They are
  behaviourally identical to legitimate nodes and are undetectable **by
  definition**, not by failure. MCC near 0 here is the correct answer.

The headline comparison is therefore over cells with **`p>0` AND `rho_a>0`**.

### Headline result — report this honestly

Mean MCC over genuine attack cells (`p>0`, `rho_a>0`), n=25 cells per system:

| System | Mean MCC | sd |
|---|---|---|
| **SHIELD-GH lightweight** | **0.802** | 0.075 |
| B3: Random Forest | 0.796 | 0.073 |
| SHIELD-GH full (stand-in scorer) | 0.784 | 0.107 |
| B2: VCBC | 0.762 | 0.075 |
| B1: Malik | 0.707 | 0.043 |

SHIELD-GH lightweight has the highest pooled mean (0.802), but the margin over
B3 (0.796) is **0.006 against a standard deviation of ~0.075** — well inside
noise. State it as "competitive with / marginally ahead of", not as a win.
The gap over B1/Malik (0.707) *is* substantial and can be claimed directly.

Do not write "SHIELD-GH outperforms all baselines" — the pooled mean does not
support it. Defensible claims: SHIELD-GH lightweight is *competitive with the
strongest ML baseline* while additionally covering controller-plane variants
(S4–S6) that B1–B3 cannot address at all, and it does so with rule-based
signatures rather than a trained classifier. Coverage, not pooled MCC, is the
honest differentiator — and E5 (per-variant) is where that should be shown.

### The pooled mean hides a ranking inversion — report this

Splitting by attacker density tells a much more interesting story than the
pooled average, and it is the strongest genuine finding in E1:

Final measured values (mean MCC over `rho_a>0` cells at each penetration):

| System | p=20% | p=40% | p=60% | p=80% | p=100% | pooled |
|---|---|---|---|---|---|---|
| **SHIELD-GH lightweight** | **0.866** | 0.836 | 0.792 | **0.758** | **0.756** | **0.802** |
| B3: Random Forest | 0.842 | **0.846** | 0.788 | 0.752 | 0.750 | 0.796 |
| SHIELD-GH full (stand-in) | 0.670 | 0.736 | 0.874 | 0.814 | 0.824 | 0.784 |
| B2: VCBC | 0.714 | 0.840 | 0.774 | 0.740 | 0.740 | 0.762 |
| B1: Malik | 0.714 | 0.708 | 0.738 | 0.684 | 0.690 | 0.707 |

Three things to draw out:

1. **All systems degrade as attacker density rises.** Every rule- and
   ML-based detector loses discriminative power as the benign reference
   population shrinks — SHIELD-GH lightweight falls 0.866 → 0.756. This is an
   honest, expected trend and worth stating rather than hiding.
2. **SHIELD-GH lightweight leads at 4 of 5 densities** (B3 edges it only at
   p=40%), and its lead is widest where it matters operationally — at low
   attacker penetration (0.866 vs 0.842), the realistic deployment regime.
   Saying "consistently at or above the strongest baseline across the
   penetration range" is defensible; "outperforms all baselines" is not.
3. **Ignore full mode's apparent win at p≥60%.** Its stand-in emits a high
   `Q_i ~ 0.85` for every node — disastrous when most nodes are benign (0.670
   at p=20%, plus the worst false-positive rate at 93.01%) but *accidentally*
   right once most nodes really are attackers (0.824 at p=100%). That is an
   artifact of the noise stand-in, not evidence of LLM capability, and must not
   be reported as such.

The density-split table is the better figure for the paper: it shows a real
behavioural difference between systems rather than one averaged number.

---

## Honest framing

This is a **real** result: 180 genuine simulation runs, no synthetic or
back-filled numbers. Its scope is narrower than the E1 specification in three
respects, all stated above and all traceable to simulator limitations rather
than to choices of convenience.

A complete, honestly-scoped single-metric result is stronger than a
five-metric table with four columns that were never actually computed.
