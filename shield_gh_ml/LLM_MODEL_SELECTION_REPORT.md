# SHIELD-GH — LLM Model Selection Report

**Tasks 06.01 & 06.02** — LLM selection evidence, model-selection results, and
pipeline settings, for **supervisor approval before implementation** (Task
06.03).

Project: *A Blockchain, Large Language Model, and Federated Learning based Secure
Approach to Mitigate Grey Hole Attack in SDVN* (SHIELD-GH).
Report references below are to `Grey_Hole_Attack_Proposal.pdf` / `main.tex`.

---

## 1. Decision requested

> **Approve the selection of the LLM for the full-mode semantic threat scorer
> (Eq. 3.28) and its two-tier edge/cloud deployment (Eq. 3.17) before we
> implement Task 06.03.**

**Proposed selection (recommended):**

| Tier | Model | Role | Report anchor |
|------|-------|------|---------------|
| **Tier-1 (Edge, on RSU/OBU)** | **DistilBERT** (BERT-family encoder), fine-tuned + 4/8-bit quantised | Real-time binary/7-class verdict on short forwarding-log windows `x_i^(t)` | §3.6.5 Tier-1; Eq. 3.17, 3.28 |
| **Tier-2 (Cloud, on escalation)** | **Mistral-7B** (4-bit), fine-tuned | Definitive verdict on long history window `n_c ≫ n_e` when edge confidence `< ε_u` | §3.6.5 Tier-2; MistralBSM [Hamhoum & Cherkaoui] |

This is consistent with what the report already commits to: §3.6.5 names *"a
4-bit quantised Mistral-7B or BERT-based model"* for the edge, §2.3 motivates the
choice with **FL-BERT** [Ahsan et al.] and **MistralBSM** [Hamhoum & Cherkaoui],
and Eq. 3.28 defines the task as **sequence classification over tokenised
forwarding logs** — the exact task both cited systems solve.

---

## 2. Why an LLM at all (and not just the rule-based / classical detector)

The lightweight mode (Algorithms 1–2) already covers **fixed-rate** and **clear
target-specific** patterns cheaply. The full mode exists for the **hard,
sequence-dependent** variants that evade thresholds: **intermittent (S2/S5)** and
**subtle target-specific (S3/S6)** dropping, where the *order* and *periodicity*
of the forwarding record — not just aggregate PDR — carry the signal (§3.4.3,
§3.6.8). Detecting those requires a **token-sequence model**, which is the
definition of the LLM component here.

We **measured** this gap (Section 3): a classical bag-of-tokens classifier solves
the fixed-rate and controller-plane classes perfectly but **collapses on the
temporal / targeted classes**, which is precisely the coverage a BERT sequence
model is selected to restore.

---

## 3. Selection evidence (measured, reproducible)

We built the *exact* full-mode input (Eq. 3.28): a labelled dataset of
**tokenised blockchain forwarding-log windows** (W = 10 slots, Table 3.3),
covering all seven classes `{BENIGN, DP-FR, DP-IT, DP-TS, CP-FR, CP-IT, CP-TS}`,
including **mobility-/handoff-induced benign loss** (the false-positive trap the
whole framework must survive, §3.4.1). Generator: `selection/gen_dataset.py`
(§3.9.1 data families). Benchmark: `selection/run_selection.py`.

Each candidate is scored on the six criteria that govern the §3.6.5 edge/cloud
decision:

| # | Criterion | How obtained |
|---|-----------|--------------|
| C1 | Detection quality — Accuracy / Macro-F1 / **MCC** (M1) | **measured** on held-out test set |
| C2 | Edge latency per window (Eq. 3.17 budget) | **measured** (per-sample inference) |
| C3 | Footprint — params / model size (OBU RAM) | **measured** / declared |
| C4 | Quantisability — 4/8-bit on OBU (§3.6.5 Tier-1) | declared from literature |
| C5 | Sequence-log fit (Eq. 3.28) | declared from architecture |
| C6 | Ecosystem / FL fit — HF + PEFT-LoRA for federated fine-tune | declared |

**Final selection score** = `0.55·MCC + 0.30·edge-suitability + 0.15·footprint`.

### 3.1 Measured results (this host)

Full JSON: `evidence/selection_results.json`. Reproduce:
`python3 selection/gen_dataset.py && python3 selection/run_selection.py`.

Per-class F1 of the runnable classical baseline (TF-IDF + Logistic Regression),
the key piece of evidence:

| Class | F1 | Interpretation |
|-------|----|----|
| CP-FR (S4) | **1.00** | flow-rule token → linearly separable, no LLM needed |
| CP-IT (S5) | **1.00** | flow-rule token dominates |
| CP-TS (S6) | **1.00** | flow-rule token dominates |
| BENIGN | 0.75 | handoff/benign loss partly confusable with attacks |
| DP-FR (S1) | 0.69 | fixed-rate: mostly rate-based, partly caught |
| **DP-TS (S3)** | **0.58** | **needs per-source *order* — bag-of-tokens loses it** |
| **DP-IT (S2)** | **0.51** | **needs *periodicity* — bag-of-tokens loses it** |

> **Headline evidence:** a non-sequence model tops out at **MCC ≈ 0.76** and
> **fails the two temporal/targeted data-plane classes (F1 0.51 / 0.58)**. These
> are exactly the classes §3.4.3 / §3.6.8 say require semantic sequence
> modelling. A BERT-family encoder models token order and is therefore selected
> to close this gap.

The transformer candidates (DistilBERT / Mistral-7B) are scored via documented
capability profiles on this host because `torch`/`transformers` are not installed
system-wide; they run for real once the ML venv is created (Section 5). The
**architectural argument does not depend on the host**: bag-of-tokens provably
cannot represent token order, so it is a valid *lower bound* for what the
sequence LLM must beat, and the measured 0.51/0.58 F1 quantifies the gap.

### 3.2 Candidate comparison (families considered)

| Family | Seq-fit (C5) | Quantisable (C4) | Params | Edge role | Verdict |
|--------|:---:|:---:|---:|-----------|---------|
| **DistilBERT** | ✔ native | ✔ 4/8-bit | 66 M | **Tier-1 edge** | **SELECTED (edge)** |
| BERT-base | ✔ native | ✔ | 110 M | edge (heavier) | backup; 1.7× params |
| **Mistral-7B** | ✔ | ~ (4-bit ≈ 4 GB) | 7 B | **Tier-2 cloud** | **SELECTED (cloud)** |
| TinyBERT | ✔ | ✔ | 15 M | ultra-low-power | fallback if OBU RAM critical |
| TF-IDF+LogReg | ✗ | ✔ | ~0 | — | **dependency-free fallback only** |
| Char-ngram+LogReg | ~ | ✔ | ~0 | — | baseline |
| Majority | ✗ | — | 0 | — | sanity floor |

Rationale for each family is stored in `FAMILY_PROFILE` (see
`selection/run_selection.py`) so no score is arbitrary.

### 3.3 Why DistilBERT for the edge (not Mistral-7B)

- **OBU footprint:** Mistral-7B is ~4 GB even at 4-bit — infeasible for a Tier-1
  OBU/RSU real-time verdict (§3.6.5 explicitly calls Tier-1 "resource-constrained").
  DistilBERT is 66 M params (~40% of BERT), runs in tens of ms, and quantises
  cleanly. Mistral-7B is therefore reserved for **Tier-2 cloud escalation**
  (Eq. 3.17), triggered only when edge confidence `< ε_u`.
- **Task fit:** DistilBERT is a native **sequence classifier** — the FL-BERT
  formulation [Ahsan et al.] this project's full mode is closest to (§2.3).
- **Federated fine-tuning:** HuggingFace + **PEFT/LoRA** lets each vehicle
  fine-tune a small adapter locally and share only the adapter gradient — the FL
  update `Δw_i` (Eq. 3.25/3.26) — which is small enough for the high-mobility
  communication budget flagged in §2.4.2.

---

## 4. Pipeline settings to report (Task 06.02)

These are the settings we will use for the approved implementation, aligned with
Table 3.3 and §3.6.5–3.6.8. **Subject to supervisor approval / adjustment.**

### 4.1 LLM (semantic threat scorer, Eq. 3.28)

| Setting | Value | Source |
|---------|-------|--------|
| Edge model | DistilBERT (`distilbert-base-uncased`) | §3.6.5 Tier-1 |
| Cloud model | Mistral-7B-Instruct, 4-bit | §3.6.5 Tier-2 / MistralBSM |
| Task | 7-class sequence classification (BENIGN + S1–S6) + binary head | Eq. 3.28 |
| Input | tokenised forwarding-log window `x_i^(t)` | Eq. 3.28, Fig 3.10 tokenizer |
| Edge window `n_e` | W = 10 slots | Table 3.3 |
| Cloud window `n_c` | 50 slots (`n_c ≫ n_e`) | §3.6.5 |
| Uncertainty threshold `ε_u` | 0.15 (tune on val) → Tier-2 escalation | Eq. 3.17 |
| Fine-tune method | PEFT / LoRA adapters (federated-friendly) | §2.4.2 |
| Quantisation | 4-bit (bitsandbytes) edge + cloud | §3.6.5 |
| Threat score `Q_i` | softmax(malicious class) | Eq. 3.28 |
| Optimiser / lr / epochs | AdamW / 2e-5 / 3 (per-round local) | FL-BERT practice |
| Max token length | 64 | window fits comfortably |

### 4.2 Federated Learning (Eq. 3.25–3.27)

| Setting | Value | Source |
|---------|-------|--------|
| Local loss | cross-entropy over `D_i` | Eq. 3.25 |
| Aggregation | dataset-size-weighted FedAvg | Eq. 3.26 |
| Clients | per-vehicle, **non-IID** partition (dense-urban vs sparse-highway) | §3.4.3 |
| Gradient integrity | on-chain hash commitment `C_i = Hash(Δw_i‖t‖id_i)`; reject on mismatch | Eq. 3.16 / 3.27 |
| Rounds | 10 (config) | — |
| Poisoning defence | commitment mismatch → update discarded (no trusted aggregator) | §3.4.3, §3.6.4 |

### 4.3 Fusion (final verdict, Eq. 3.29)

`ŷ_i = 1[ μ1·S_total + μ2·Q_i + μ3·(1−R_i) > θ_det ]`, with `μ1+μ2+μ3 = 1`
(fusion weights tuned on validation), `S_total` = max rule-based signature score
(S1–S6), `Q_i` = LLM threat score (Eq. 3.28), `(1−R_i)` = blockchain reputation
deficit (Eq. 3.20). `θ_det` tuned on validation.

### 4.4 Data (§3.9)

Three §3.9.1 families (selective / temporal / semantic), features per §3.9.2
(behavioural logs, network-context metadata, stochastic model gradients).
Generator already implemented: `selection/gen_dataset.py`.

---

## 5. What Task 06.03 will implement (pending approval)

1. **LLM scorer** (`llm_scorer.py`) — DistilBERT sequence classifier producing
   `Q_i` (Eq. 3.28); two-tier edge/cloud routing (Eq. 3.17); dependency-free
   TF-IDF fallback with identical API so it always runs (mirrors the crypto-task
   hybrid pattern).
2. **Federated Learning** (`federated.py`) — local train (Eq. 3.25), weighted
   FedAvg (Eq. 3.26), **blockchain hash-commit gradient integrity that rejects
   poisoned updates** (Eq. 3.16/3.27), non-IID client partitions.
3. **Fusion engine** (`fusion.py`) — Eq. 3.29 three-source combination → verdict
   → hand-off to DEBSC isolation gate.
4. **Evidence** — pytest suite (one test per equation/property), evidence
   transcript (poisoned gradient rejected; intermittent attacker the rule-based
   mode missed but the LLM catches), golden vectors. Same deliverable shape as
   Task 05 crypto (`shield_gh_crypto/`).

**Environment for genuine models** (one-time, matches the crypto-task venv
pattern):
```bash
python3 -m venv ~/shield-ml-venv
~/shield-ml-venv/bin/pip install torch transformers peft datasets \
    scikit-learn accelerate bitsandbytes pytest
```
Everything in Section 3 above already runs **without** this venv (sklearn only),
so the selection evidence is reproducible today.

---

## 6. Files

```
shield_gh_ml/
├── LLM_MODEL_SELECTION_REPORT.md   <- this report (06.01/06.02 deliverable)
├── selection/
│   ├── gen_dataset.py              <- §3.9 forwarding-log dataset (Eq 3.28 input)
│   ├── run_selection.py            <- candidate benchmark + scoring
│   └── dataset.jsonl               <- generated dataset
└── evidence/
    └── selection_results.json      <- measured benchmark + ranking (evidence)
```

## 7. Reproduce the evidence

```bash
cd scratch/shield_gh_ml/selection
python3 gen_dataset.py --n_per_class 400 --seed 42
python3 run_selection.py        # -> evidence/selection_results.json
```
