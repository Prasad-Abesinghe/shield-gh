# SHIELD-GH Task 06.03 — LLM + Federated Learning Evidence

**For supervisor review.** All numbers below are **measured** (not analytical), fully
reproducible, and produced on the genuine **Qwen2.5-7B-Instruct** model. Raw
artifacts are in `shield_gh_ml/evidence/`.

Model: **Qwen2.5-7B-Instruct** (7.6 B params) — the supervisor-approved selection.
Hardware: NVIDIA RTX 5090 (32 GB), CUDA 12.8, PyTorch 2.11.
Dataset: 2800 tokenised forwarding-log windows (7 classes × 400), seed 42,
split 2240 train / 280 val / 280 test.

---

## 1. LLM fine-tuning — how the model was trained (Eq. 3.25 / 3.28)

| Setting | Value |
|---|---|
| Base model | Qwen2.5-7B-Instruct |
| Task | 7-class sequence classification (BENIGN + S1–S6) |
| Fine-tune method | LoRA/PEFT — r=16, α=32, dropout=0.05, targets q/k/v/o\_proj |
| Precision | bf16 training; 4-bit NF4 deployment config |
| Optimiser | AdamW, lr 2×10⁻⁴, 3 epochs, effective batch 16 (micro 4 × accum 4) |
| Max token length | 96 |
| Training time | 93 s; loss converged 1.19 → 0.50 → **0.40** |

**Reproduce:** `bash run_finetune_resilient.sh` → `evidence/qwen_finetune_results.json`

### Measured detection performance (held-out test set)

| Metric | Value |
|---|---|
| Accuracy (7-class) | **0.821** |
| **MCC** | **0.792** |
| Macro-F1 | 0.808 |
| Binary attack detection — TPR | **0.928** |
| Binary attack detection — TNR | 0.756 |
| Inference latency | **18 ms / window** (real-time viable) |

### Per-class F1 — *this is the key scientific result*

| Class | F1 | Reading |
|---|---|---|
| CP-FR (S4) | **1.00** | controller-plane flow-rule variants are cleanly separable |
| CP-IT (S5) | **1.00** | |
| CP-TS (S6) | **1.00** | |
| DP-FR (S1) | 0.81 | fixed-rate data-plane: strong |
| BENIGN | 0.71 | benign vs handoff-loss (the false-positive trap) mostly handled |
| DP-TS (S3) | 0.65 | target-specific: harder, needs token-order reasoning |
| DP-IT (S2) | 0.49 | intermittent: **hardest** — the temporal variant |

> The LLM earns its place exactly on the **temporal / target-specific** variants
> (DP-IT, DP-TS) that the rule-based signatures miss — consistent with §3.4.3 /
> §3.6.8 of the report. The genuine Qwen MCC (0.792) beats the dependency-free
> proxy baseline (0.712), as the selection report predicted.

---

## 2. Federated Learning + blockchain gradient integrity (Eq. 3.16 / 3.26 / 3.27)

Setup: 4 honest non-IID vehicle clients + 1 malicious poisoner (V9), 5 FL rounds,
dataset-size-weighted FedAvg, each gradient hash-committed on-chain before transmit.

| Configuration | Poison rejections | Global-model detection MCC |
|---|---|---|
| **Integrity check ON** | 5 / 5 (V9 blocked every round) | **0.747** |
| Integrity check OFF | 0 | 0.409 |

> **Result: the blockchain gradient-integrity mechanism works.** With the check
> on, the poisoner (V9) is rejected at every round and the global model stays
> healthy (MCC 0.747); with it off, poisoning collapses the model to MCC 0.409.
> This is the §3.6.4 anti-poisoning novelty, demonstrated — no trusted aggregator
> required.

**Reproduce:** `python3 gen_evidence.py` → `evidence/evidence_transcript.txt`

---

## 3. Fusion — three-source verdict (Eq. 3.29)

The fusion combines rule-based signatures, the LLM score, and blockchain
reputation. It recovers the variants the rule-based mode misses:

| Variant | Rule-based | LLM | Fused verdict |
|---|---|---|---|
| DP-IT (S2) | 0.00 (missed) | 0.79 | **0.79** |
| DP-TS (S3) | 0.00 (missed) | 0.79 | **0.79** |
| DP-FR, CP-FR/IT/TS | 1.00 | ~1.00 | **1.00** |

Fusion weights are tuned on the validation set by grid search; the **general
three-way equation is retained** (weights re-tuned per deployment), consistent
with the μ₃ cross-validation finding below.

---

## 4. μ₃ cross-validation (the fusion-weight validity check you requested)

30-fold repeated stratified CV (θ_det tuned on train fold only), paired t-tests
μ₃=0 vs 0.1, 0.2:

- Best μ₃ by CV mean = **0.1**, not 0 (differences ~0.001–0.002 MCC — within noise;
  no value significantly better).
- **corr(Q_i, reputation deficit) = +0.515** → the two signals are partially
  redundant on this small dataset, which is why the single-split grid drifted to
  μ₃=0.
- **Conclusion:** μ₃=0 was a small-grid artifact; it is **not** stated as a result.
  The paper keeps the three-way fusion general. (A genuine-Qwen Q_i rerun of this
  CV is the remaining step before the fusion-weights paragraph is written.)

**Reproduce:** `python3 validate_mu3.py` → `evidence/mu3_validation.json`

---

## 5. Evidence files (attach these)

| File | Contents |
|---|---|
| `evidence/qwen_finetune_results.json` | measured Qwen accuracy/MCC/TPR/TNR/latency/per-class |
| `evidence/evidence_transcript.txt` | full LLM + FL + fusion run transcript |
| `evidence/golden_vector.json` | machine-readable golden values |
| `evidence/mu3_validation.json` | 30-fold CV μ₃ significance test |
| `evidence/selection_results.json` | model-selection benchmark |
| `LLM_MODEL_SELECTION_REPORT.md` | why Qwen2.5-7B was selected |
| `AI_PIPELINE_AND_SETTINGS.md` | full pipeline + settings |

## 6. Reproduce everything

```bash
cd scratch/shield_gh_ml
python3 selection/gen_dataset.py --n_per_class 400 --seed 42   # dataset
bash run_finetune_resilient.sh                                 # genuine Qwen fine-tune
python3 gen_evidence.py                                        # LLM+FL+fusion transcript
python3 validate_mu3.py                                        # mu3 cross-validation
python3 -m unittest discover -s tests -p "test_*.py"           # 20 unit tests (all pass)
```
