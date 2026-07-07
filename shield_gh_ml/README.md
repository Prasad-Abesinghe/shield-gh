# SHIELD-GH — Task 06: ML / LLM / Federated Learning

Runnable implementation of the full-mode AI detection pipeline specified in the
proposal (`main.tex`, `Grey_Hole_Attack_Proposal.pdf`): the **LLM semantic threat
scorer** (Eq. 3.28), **Federated Learning with blockchain-verified gradient
integrity** (Eq. 3.16/3.25/3.26/3.27), and the **three-source fusion verdict**
(Eq. 3.29) — i.e. Algorithm 3 (FV-Det + FL-AGGREGATE).

Standalone Python module (like `scratch/shield_gh_crypto/`): proven with a test
suite and reproducible evidence, decoupled from the NS-3 data-plane simulation.

## Task 06.01 / 06.02 — LLM selection (supervisor-approved basis)

Selection is documented in **`LLM_MODEL_SELECTION_REPORT.md`**. Per supervisor
requirement (moderately large LLM, **>4B and <15B params**, chosen from a
recorded comparison of several models):

| Model | Params | Acc | TPR | TNR | Lat(s) |
|-------|-------:|----:|----:|----:|-------:|
| Mistral-7B-Instruct-v0.3 | 7.3B | 100% | 100% | 100% | 1.43 |
| **Qwen2.5-7B-Instruct** | **7.6B** | **100%** | **100%** | **100%** | **0.85** |
| Mistral-Nemo-12B-Instruct | 12.0B | 100% | 100% | 100% | 2.03 |
| Qwen2.5-14B-Instruct | 14.0B | 100% | 100% | 100% | 1.44 |

**Selected: Qwen2.5-7B-Instruct** — equal detection quality, **lowest latency
(0.85 s, 41% faster than nearest)**, mid-band size. Basis: `selection/model_candidates.py`.

## Task 06.03 — implementation

| File | Report | What it implements |
|------|--------|--------------------|
| `llm_scorer.py` | Eq. 3.17, 3.28 | LLM threat score `Q_i` (sequence classification over forwarding logs); two-tier edge/cloud escalation; **genuine Qwen2.5-7B + LoRA backend** OR dependency-free fallback (identical API) |
| `federated.py` | Eq. 3.16/3.25/3.26/3.27 | Per-vehicle local train, weighted FedAvg, **blockchain hash-commit gradient integrity** that rejects poisoned updates without a trusted aggregator |
| `fusion.py` | Eq. 3.29 | `ŷ_i = 1[μ1·S_total + μ2·Q_i + μ3·(1−R_i) > θ_det]`; validation-tuned weights |
| `finetune_qwen.py` | Eq. 3.25/3.28 | Genuine Qwen2.5-7B 4-bit LoRA fine-tune + measured accuracy/MCC/latency |
| `gen_evidence.py` | Alg. 3 | End-to-end evidence transcript + golden vectors |
| `selection/gen_dataset.py` | §3.9 | Forwarding-log dataset (Eq. 3.28 input), all 6 variants + benign handoff loss |
| `tests/test_pipeline.py` | all | 20 tests, one per equation/property |

## Backends (hybrid, like the crypto task)

The LLM scorer uses the **genuine Qwen2.5-7B-Instruct** (via `torch`+`transformers`
+`peft`, LoRA fine-tuned) when the ML venv is present, otherwise a **documented
dependency-free fallback** (`hashing+struct+softmax`) with an identical API so the
FL/fusion/tests run on any host. The fallback is a runnable *proxy* — clearly
flagged, NOT the selected LLM. Active backend is printed by every entry point and
recorded in the evidence.

## Run

### A. No-install path (fallback backend — reproduces on any host)
```bash
cd scratch/shield_gh_ml
python3 selection/gen_dataset.py --n_per_class 400 --seed 42   # dataset
python3 selection/model_candidates.py                          # selection table
python3 gen_evidence.py                                        # LLM+FL+fusion evidence
python3 -m unittest tests.test_pipeline -v                     # 20 tests
```

### B. Genuine Qwen2.5-7B path (measured LLM evidence; needs GPU)
```bash
python3 -m venv ~/shield-ml-venv
~/shield-ml-venv/bin/pip install torch --index-url https://download.pytorch.org/whl/cu128
~/shield-ml-venv/bin/pip install transformers peft accelerate bitsandbytes datasets scikit-learn
~/shield-ml-venv/bin/python finetune_qwen.py     # downloads + LoRA fine-tunes Qwen2.5-7B
# then gen_evidence.py automatically uses the genuine backend
~/shield-ml-venv/bin/python gen_evidence.py
```

## Evidence

- `evidence/selection_results.json` — selection benchmark (06.01/06.02)
- `evidence/qwen_finetune_results.json` — **measured** Qwen2.5-7B accuracy/MCC/latency
- `evidence/evidence_transcript.txt` — LLM + FL + fusion transcript
- `evidence/golden_vector.json` — golden metrics

**Key evidence claims (in the transcript):**
1. **LLM (Eq. 3.28)** separates benign vs attacker forwarding logs (`Q_i`).
2. **FL gradient integrity (Eq. 3.16/3.27)** blocks a poisoner: global-model MCC
   stays healthy with the check ON and collapses with it OFF.
3. **Fusion (Eq. 3.29)** recovers the intermittent/target-specific variants
   (DP-IT/DP-TS) that the rule-based mode misses — the §3.6.8 coverage claim.
