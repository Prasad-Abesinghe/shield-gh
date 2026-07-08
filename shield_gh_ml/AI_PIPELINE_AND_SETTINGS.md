# SHIELD-GH — AI Pipeline & Settings (for supervisor review / approval)

**Task 06.02** — the full AI/LLM/FL pipeline and every setting used, so the
modeling can be reviewed **before** approval. Cross-referenced to the paper
(`Grey_Hole_Attack_Proposal.pdf` / `main.tex`) equation numbers, and to the exact
code that implements each step.

Selected LLM: **Qwen2.5-7B-Instruct** (see `LLM_MODEL_SELECTION_REPORT.md`).

---

## 1. End-to-end pipeline (full detection mode, Algorithm 3 / FV-Det)

```
 forwarding logs (NS-3 / blockchain)
        │
        ▼
 (1) Blockchain Log Tokenizer  ─────────────►  tokenised window x_i^(t)   [§3.9, Fig 3.10]
        │   W = 10 slots; each slot = "ACTION:src" token (FWD/DRP/HOF),
        │   CP variants prepend a RULE token
        ▼
 (2) LLM semantic scorer  (Qwen2.5-7B, LoRA)  ─►  Q_i(t) = softmax(...)_malicious   [Eq. 3.28]
        │        two-tier: edge verdict; escalate to cloud if conf < ε_u  [Eq. 3.17]
        ▼
 (3) Federated Learning  ────────────────────►  global model w^(r+1)      [Eq. 3.25/3.26]
        │        local train → hash-commit Δw on-chain → verify → FedAvg
        │        poisoned (uncommitted) gradients rejected                [Eq. 3.16/3.27]
        ▼
 (4) Fusion engine  ─────────────────────────►  ŷ_i = 1[μ1·S_total + μ2·Q_i + μ3·(1−R_i) > θ_det]  [Eq. 3.29]
        │        S_total = rule-based signature (S1–S6), R_i = blockchain reputation [Eq. 3.20]
        ▼
 (5) verdict → DEBSC isolation gate (Task-05 crypto, Eq. 3.23)  — detection only here
```

Code map: (1) `selection/gen_dataset.py` · (2) `llm_scorer.py` + `finetune_qwen.py`
· (3) `federated.py` · (4) `fusion.py` · driver `gen_evidence.py`.

---

## 2. LLM settings (Eq. 3.28 / 3.17)  — `finetune_qwen.py`

| Setting | Value | Rationale / source |
|---|---|---|
| Base model | **Qwen2.5-7B-Instruct** (7.6B) | Selection basis, §3.6.5 (moderately-large >4B, <15B) |
| Task head | Sequence classification, **7 classes** (BENIGN + S1–S6) | Eq. 3.28; FL-BERT / MistralBSM formulation |
| Threat score `Q_i` | softmax probability mass on the 6 malicious classes | Eq. 3.28 |
| Fine-tune method | **LoRA / PEFT** (adapters only) | Federated-friendly small Δw, §2.4.2 |
| LoRA rank `r` | 16 | standard for 7B seq-cls |
| LoRA `alpha` | 32 | 2× rank |
| LoRA dropout | 0.05 | regularisation |
| LoRA target modules | `q_proj, k_proj, v_proj, o_proj` | attention projections |
| Quantisation | **4-bit NF4**, double-quant, bf16 compute | fits RTX 5090 / OBU footprint, §3.6.5 |
| Optimiser | AdamW | — |
| Learning rate | 2e-4 (LoRA) | typical LoRA lr |
| Epochs (local) | 3 | matches FL round budget |
| Batch size | 16 | — |
| Max token length | 96 | covers W=10 window + RULE token |
| Two-tier escalation `ε_u` | 0.15 → escalate to cloud when max-class conf below floor | Eq. 3.17 |
| Hardware | NVIDIA RTX 5090 (32 GB), CUDA 12.8, torch 2.11 | — |

> The `llm_scorer.py` genuine backend uses the same recipe with `r=8` for the
> real-time edge inference path; `finetune_qwen.py` (`r=16`) is the training/
> benchmark run that produces the measured numbers.

---

## 3. Federated Learning settings (Eq. 3.16 / 3.25 / 3.26 / 3.27)  — `federated.py`

| Setting | Value | Source |
|---|---|---|
| Local objective | cross-entropy over local set `D_i` | Eq. 3.25 |
| Aggregation | **dataset-size-weighted FedAvg** `Σ (|D_i|/|D_A|)·Δw_i` | Eq. 3.26 |
| Clients | per-vehicle, **non-IID** class partitions (dense-urban vs sparse-highway skew) | §3.4.3 |
| Rounds | 5 (config; `fit(rounds=...)`) | — |
| Local epochs / round | 150–200 (fallback) / 3 (Qwen LoRA) | — |
| **Gradient integrity** | on-chain commitment `C_i = SHA256(Δw_i ‖ t ‖ id_i)` submitted **before** transmit | Eq. 3.16 |
| Accept rule | `Accept(Δw_i)=1[Hash(received)=C_i^BC]` — mismatch ⇒ discard | Eq. 3.27 |
| Trusted aggregator | **none required** (integrity is cryptographic, not reputational) | §3.6.4 novelty |
| Poison model (for evidence) | attacker commits honest hash, transmits different (destructive) gradient | §3.4.3 threat |

**Verified behaviour:** with a poisoner present, global-model detection MCC =
**0.75 (integrity ON)** vs **0.41 (integrity OFF)** — the check demonstrably
blocks poisoning. Transcript: `evidence/evidence_transcript.txt`.

---

## 4. Fusion settings (Eq. 3.29)  — `fusion.py`

| Setting | Value | Source |
|---|---|---|
| Decision rule | `ŷ_i = 1[μ1·S_total + μ2·Q_i + μ3·(1−R_i) > θ_det]` | Eq. 3.29 |
| `S_total` | max rule-based signature score over S1–S6 | Alg. 1/2 |
| `Q_i` | LLM threat score | Eq. 3.28 |
| `1 − R_i` | blockchain reputation deficit | Eq. 3.20 |
| Fusion weights `μ1,μ2,μ3` | **tuned on validation** by grid search (sum = 1) | Eq. 3.29 ("optimised on validation set") |
| `θ_det` | tuned on validation (grid 0.2–0.8) | Eq. 3.29 |
| Tuned result (current run) | μ = (0.2, 0.8, 0.0), θ_det = 0.3 | maximises val MCC |

**Verified behaviour:** fusion recovers the intermittent (DP-IT) and
target-specific (DP-TS) variants the rule-based mode misses (detection 0.00 →
0.79 via the LLM), confirming the §3.6.8 claim that no single evidence source
suffices.

---

## 5. Data settings (§3.9)  — `selection/gen_dataset.py`

| Setting | Value | Source |
|---|---|---|
| Input unit | tokenised forwarding-log window | Eq. 3.28 |
| Window `W` | 10 slots | Table 3.3 |
| Classes | BENIGN + DP-FR, DP-IT, DP-TS, CP-FR, CP-IT, CP-TS | S1–S6, §3.3 |
| Attacker drop `ρ_a` | 0.40 | Table 3.3 (sweep 20–80%) |
| Handoff/benign loss `ρ_ho` | 0.30 (tagged HOF, benign) | Table 3.3; §3.4.1 FP trap |
| Data families | selective / temporal / semantic dropping | §3.9.1 |
| Samples | 400 / class × 7 = 2800; split 2240 train / 280 val / 280 test | — |
| Seed | 42 (fully reproducible) | — |

---

## 6. Reproduce

```bash
# fallback (any host, no install):
python3 selection/gen_dataset.py --n_per_class 400 --seed 42
python3 gen_evidence.py
python3 -m unittest tests.test_pipeline -v     # 20 tests

# genuine Qwen2.5-7B (GPU):
~/shield-ml-venv/bin/python finetune_qwen.py   # measured accuracy/MCC/latency
```

Evidence: `evidence/evidence_transcript.txt`, `evidence/golden_vector.json`,
`evidence/qwen_finetune_results.json` (measured, produced by the genuine run).

---

## 7. Note on §3.6.5 modeling update

The paper §3.6.5 currently names a two-tier DistilBERT(edge)/Mistral-7B(cloud)
setup. Per the supervisor requirement for a single moderately-large (>4B) model,
we standardise on **Qwen2.5-7B-Instruct** as the full-mode LLM and will update
§3.6.5 to match. All other modeling (Eq. 3.17/3.28/3.25/3.26/3.29) is unchanged.
```
