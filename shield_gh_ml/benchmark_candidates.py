"""
SHIELD-GH LLM candidate re-benchmark (supervisor-requested re-run).

Supervisor feedback on the first selection table:
  * "Still MCC is 1?"  -> the binary screening task saturated all models.
  * "Re-run the experiment." -> benchmark the candidates on the HARD 7-class
    per-variant task so MCC genuinely discriminates between them.
  * "estimated from parameter count" is unacceptable -> measure real latency
    for EVERY candidate, not just the selected one.

This script fine-tunes each candidate with an identical LoRA recipe on the same
7-class SHIELD-GH forwarding-log dataset, then measures on the held-out test set:
  * 7-class MCC (paper's M1 primary metric) -- now differs across models
  * accuracy, macro-F1
  * mean single-window classification forward-pass latency (ms) on this GPU

Crash-resilient for the RTX 5090 (Blackwell): per-candidate results are written
incrementally to evidence/candidate_benchmark.json, so a GPU fault only loses the
current candidate, and re-running skips already-completed candidates.

Run:  bash run_benchmark_all.sh     (wrapper: relaunches on CUDA fault)
  or  ~/shield-ml-venv/bin/python benchmark_candidates.py --only <hf_id>
"""
from __future__ import annotations
import argparse
import json
import time
import platform
from pathlib import Path

import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from peft import LoraConfig, get_peft_model, TaskType
from sklearn.metrics import accuracy_score, matthews_corrcoef, f1_score

HERE = Path(__file__).parent
EVID = HERE / "evidence"; EVID.mkdir(exist_ok=True)
OUT = EVID / "candidate_benchmark.json"
CLASSES = ["BENIGN", "DP-FR", "DP-IT", "DP-TS", "CP-FR", "CP-IT", "CP-TS"]
MAXLEN = 96
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
BS = 4                      # small batch: less Blackwell kernel pressure
MAX_RETRY = 3

# The four candidates in the >4B, <15B band (two families, full size range).
CANDIDATES = [
    ("Mistral-7B-Instruct-v0.3", "mistralai/Mistral-7B-Instruct-v0.3", 7.3),
    ("Qwen2.5-7B-Instruct",      "Qwen/Qwen2.5-7B-Instruct",           7.6),
    ("Mistral-Nemo-12B-Instruct","mistralai/Mistral-Nemo-Instruct-2407",12.0),
    ("Qwen2.5-14B-Instruct",     "Qwen/Qwen2.5-14B-Instruct",          14.0),
]


def load():
    data = [json.loads(l) for l in open(HERE / "selection" / "dataset.jsonl")]
    return data[:2240], data[2240:2520], data[2520:]


def batched(seq, bs):
    for i in range(0, len(seq), bs):
        yield seq[i:i + bs]


def _cuda_fault(e):
    s = str(e).lower()
    return "cuda" in s and ("launch failure" in s or "unspecified" in s
                            or "illegal" in s or "out of memory" in s)


def build(hf_id):
    tok = AutoTokenizer.from_pretrained(hf_id)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForSequenceClassification.from_pretrained(
        hf_id, num_labels=len(CLASSES), dtype=torch.bfloat16)  # bf16: Blackwell-safe
    model.config.pad_token_id = tok.pad_token_id
    cfg = LoraConfig(task_type=TaskType.SEQ_CLS, r=16, lora_alpha=32,
                     lora_dropout=0.05,
                     target_modules=["q_proj", "k_proj", "v_proj", "o_proj"])
    model = get_peft_model(model, cfg)
    if DEVICE == "cuda":
        model = model.to(DEVICE)
    return tok, model


def enc(tok, texts):
    return tok(list(texts), return_tensors="pt", padding=True,
              truncation=True, max_length=MAXLEN)


def train(tok, model, tr, epochs=3, lr=2e-4):
    dev = next(model.parameters()).device
    opt = torch.optim.AdamW((p for p in model.parameters() if p.requires_grad), lr=lr)
    texts = [d["text"] for d in tr]; labels = [d["label"] for d in tr]
    idx = np.arange(len(texts))
    for ep in range(epochs):
        model.train(); np.random.RandomState(ep).shuffle(idx); tot = 0.0
        for b in batched(idx, BS):
            for attempt in range(MAX_RETRY):
                try:
                    e = {k: v.to(dev) for k, v in
                         enc(tok, [texts[i] for i in b]).items()}
                    y = torch.tensor([labels[i] for i in b]).to(dev)
                    out = model(**e, labels=y); out.loss.backward()
                    opt.step(); opt.zero_grad(); tot += out.loss.item(); break
                except RuntimeError as ex:
                    if _cuda_fault(ex) and attempt < MAX_RETRY - 1:
                        opt.zero_grad(set_to_none=True)
                        torch.cuda.synchronize(); torch.cuda.empty_cache(); continue
                    raise
        print(f"    epoch {ep+1}/{epochs} loss={tot/max(1,len(idx)//BS):.4f}",
              flush=True)


@torch.no_grad()
def predict(tok, model, texts, bs=8):
    dev = next(model.parameters()).device
    model.eval(); probs = []
    for b in batched(list(texts), bs):
        e = {k: v.to(dev) for k, v in enc(tok, b).items()}
        probs.append(torch.softmax(model(**e).logits.float(), -1).cpu().numpy())
    return np.concatenate(probs)


@torch.no_grad()
def latency_ms(tok, model, texts, n=64):
    dev = next(model.parameters()).device
    model.eval()
    for x in texts[:4]:                                   # warmup
        model(**{k: v.to(dev) for k, v in enc(tok, [x]).items()})
    torch.cuda.synchronize()
    t0 = time.perf_counter()
    for x in texts[:n]:
        model(**{k: v.to(dev) for k, v in enc(tok, [x]).items()})
    torch.cuda.synchronize()
    return 1000.0 * (time.perf_counter() - t0) / min(n, len(texts))


def load_done():
    if OUT.exists():
        return json.loads(OUT.read_text())
    return dict(task="SHIELD-GH 7-class candidate benchmark (re-run)",
                gpu=torch.cuda.get_device_name(0) if DEVICE == "cuda" else None,
                host=platform.node(), classes=CLASSES, results={})


def run_one(name, hf_id, params_b, tr, te):
    print(f"\n=== {name} ({params_b}B) : {hf_id} ===", flush=True)
    tok, model = build(hf_id)
    print("  fine-tuning (7-class LoRA) ...", flush=True)
    train(tok, model, tr, epochs=3)
    print("  evaluating ...", flush=True)
    P = predict(tok, model, [d["text"] for d in te]); pred = P.argmax(1)
    yte = np.array([d["label"] for d in te])
    lat = latency_ms(tok, model, [d["text"] for d in te])
    res = dict(
        params_b=params_b, hf_id=hf_id,
        mcc=round(float(matthews_corrcoef(yte, pred)), 4),
        accuracy=round(float(accuracy_score(yte, pred)), 4),
        macro_f1=round(float(f1_score(yte, pred, average="macro")), 4),
        latency_ms=round(float(lat), 2),
        per_class_f1={CLASSES[i]: round(float(v), 4) for i, v in
                      enumerate(f1_score(yte, pred, average=None,
                                         labels=list(range(7))))},
    )
    # free GPU before next model
    del model; torch.cuda.empty_cache()
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None, help="run a single hf_id")
    args = ap.parse_args()
    tr, va, te = load()
    out = load_done()
    todo = [c for c in CANDIDATES if (args.only in (None, c[1]))
            and c[0] not in out["results"]]
    if not todo:
        print("all candidates already benchmarked; nothing to do.")
    for name, hf_id, pb in todo:
        res = run_one(name, hf_id, pb, tr, te)
        out["results"][name] = res
        OUT.write_text(json.dumps(out, indent=2))   # incremental save
        print(f"  -> {name}: MCC={res['mcc']} acc={res['accuracy']} "
              f"lat={res['latency_ms']}ms  (saved)", flush=True)

    # final ranking print
    print("\n=== 7-CLASS BENCHMARK (measured) ===")
    print(f"{'Model':<28}{'Params':>7}{'MCC':>7}{'Acc':>7}{'Lat(ms)':>9}")
    for name, _, pb in CANDIDATES:
        r = out["results"].get(name)
        if r:
            print(f"{name:<28}{pb:>6}B{r['mcc']:>7.3f}{r['accuracy']:>7.3f}"
                  f"{r['latency_ms']:>9.1f}")
    print(f"\nevidence -> {OUT}")


if __name__ == "__main__":
    main()
