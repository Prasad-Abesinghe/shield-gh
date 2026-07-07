"""
Genuine Qwen2.5-7B-Instruct LoRA fine-tune + benchmark on the SHIELD-GH
forwarding-log dataset (Task 06.03 / 06.02 measured evidence).

Requires the ML venv:
    ~/shield-ml-venv/bin/pip install torch transformers peft accelerate \
        bitsandbytes datasets scikit-learn
Run:
    ~/shield-ml-venv/bin/python finetune_qwen.py

Produces:
    evidence/qwen_finetune_results.json   — REAL accuracy / MCC / latency
    ~/shield-ml-venv adapters saved under  models/qwen2.5-7b-shieldgh-lora/

This is the model the paper selects (Eq. 3.28). It fine-tunes a LoRA adapter on
top of 4-bit Qwen2.5-7B (the federated-friendly small update, §2.4.2) as a
7-class sequence classifier over tokenised forwarding-log windows.
"""
from __future__ import annotations
import json
import time
import platform
from pathlib import Path

import numpy as np
import torch
from transformers import (AutoTokenizer, AutoModelForSequenceClassification,
                          BitsAndBytesConfig)
from peft import LoraConfig, get_peft_model, TaskType, prepare_model_for_kbit_training
from sklearn.metrics import accuracy_score, matthews_corrcoef, f1_score

HERE = Path(__file__).parent
EVID = HERE / "evidence"; EVID.mkdir(exist_ok=True)
MODEL_DIR = HERE / "models" / "qwen2.5-7b-shieldgh-lora"
HF_ID = "Qwen/Qwen2.5-7B-Instruct"
CLASSES = ["BENIGN", "DP-FR", "DP-IT", "DP-TS", "CP-FR", "CP-IT", "CP-TS"]
MALICIOUS = list(range(1, 7))
MAXLEN = 96
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


def load():
    data = [json.loads(l) for l in open(HERE / "selection" / "dataset.jsonl")]
    return data[:2240], data[2240:2520], data[2520:]


def batched(seq, bs):
    for i in range(0, len(seq), bs):
        yield seq[i:i + bs]


def build_model(quantise=True):
    tok = AutoTokenizer.from_pretrained(HF_ID)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    kw = dict(num_labels=len(CLASSES))
    if quantise and DEVICE == "cuda":
        kw["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True)
        kw["torch_dtype"] = torch.bfloat16
    else:
        kw["torch_dtype"] = torch.float32
    model = AutoModelForSequenceClassification.from_pretrained(HF_ID, **kw)
    model.config.pad_token_id = tok.pad_token_id
    if quantise and DEVICE == "cuda":
        model = prepare_model_for_kbit_training(model)
    cfg = LoraConfig(task_type=TaskType.SEQ_CLS, r=16, lora_alpha=32,
                     lora_dropout=0.05,
                     target_modules=["q_proj", "k_proj", "v_proj", "o_proj"])
    model = get_peft_model(model, cfg)
    if DEVICE == "cuda":
        model = model.to(DEVICE)
    return tok, model


def encode(tok, texts):
    return tok(list(texts), return_tensors="pt", padding=True,
               truncation=True, max_length=MAXLEN)


def train(tok, model, tr, epochs=3, bs=16, lr=2e-4):
    opt = torch.optim.AdamW((p for p in model.parameters() if p.requires_grad),
                            lr=lr)
    model.train()
    texts = [d["text"] for d in tr]
    labels = [d["label"] for d in tr]
    idx = np.arange(len(texts))
    for ep in range(epochs):
        np.random.RandomState(ep).shuffle(idx)
        tot = 0.0
        for b in batched(idx, bs):
            enc = encode(tok, [texts[i] for i in b]).to(DEVICE)
            y = torch.tensor([labels[i] for i in b]).to(DEVICE)
            out = model(**enc, labels=y)
            out.loss.backward()
            opt.step(); opt.zero_grad()
            tot += out.loss.item()
        print(f"  epoch {ep+1}/{epochs}  loss={tot/max(1,len(idx)//bs):.4f}")


@torch.no_grad()
def predict(tok, model, texts, bs=32):
    model.eval()
    probs = []
    for b in batched(list(texts), bs):
        enc = encode(tok, b).to(DEVICE)
        logits = model(**enc).logits.float()
        probs.append(torch.softmax(logits, -1).cpu().numpy())
    return np.concatenate(probs)


@torch.no_grad()
def latency(tok, model, texts, n=64):
    model.eval()
    # warmup
    for x in texts[:4]:
        model(**encode(tok, [x]).to(DEVICE))
    if DEVICE == "cuda":
        torch.cuda.synchronize()
    t0 = time.perf_counter()
    for x in texts[:n]:
        model(**encode(tok, [x]).to(DEVICE))
    if DEVICE == "cuda":
        torch.cuda.synchronize()
    return (time.perf_counter() - t0) / min(n, len(texts))


def main():
    print(f"device={DEVICE}  gpu={torch.cuda.get_device_name(0) if DEVICE=='cuda' else '-'}")
    tr, va, te = load()
    print(f"loading + quantising {HF_ID} ...")
    tok, model = build_model(quantise=True)
    model.print_trainable_parameters()

    print("fine-tuning LoRA adapter (Eq. 3.25 local objective) ...")
    t0 = time.time()
    train(tok, model, tr, epochs=3, bs=16)
    train_s = time.time() - t0

    print("evaluating ...")
    P = predict(tok, model, [d["text"] for d in te])
    pred = P.argmax(1)
    yte = np.array([d["label"] for d in te])
    acc = accuracy_score(yte, pred)
    mcc = matthews_corrcoef(yte, pred)
    f1 = f1_score(yte, pred, average="macro")
    # binary (attack vs benign) for TPR/TNR
    yb = (yte != 0).astype(int); pb = (pred != 0).astype(int)
    tp = int(((pb == 1) & (yb == 1)).sum()); tn = int(((pb == 0) & (yb == 0)).sum())
    fp = int(((pb == 1) & (yb == 0)).sum()); fn = int(((pb == 0) & (yb == 1)).sum())
    tpr = tp / max(1, tp + fn); tnr = tn / max(1, tn + fp)
    lat = latency(tok, model, [d["text"] for d in te])

    res = dict(
        model=HF_ID, device=DEVICE,
        gpu=torch.cuda.get_device_name(0) if DEVICE == "cuda" else None,
        host=platform.node(), python=platform.python_version(),
        n_train=len(tr), n_test=len(te), classes=CLASSES,
        accuracy=round(float(acc), 4), mcc=round(float(mcc), 4),
        macro_f1=round(float(f1), 4),
        binary=dict(tpr=round(tpr, 4), tnr=round(tnr, 4),
                    tp=tp, tn=tn, fp=fp, fn=fn),
        latency_s_per_window=round(float(lat), 4),
        train_seconds=round(train_s, 1),
        per_class_f1={CLASSES[i]: round(float(v), 4)
                      for i, v in enumerate(
                          f1_score(yte, pred, average=None,
                                   labels=list(range(7))))},
    )
    (EVID / "qwen_finetune_results.json").write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2))

    MODEL_DIR.parent.mkdir(exist_ok=True)
    model.save_pretrained(str(MODEL_DIR))
    tok.save_pretrained(str(MODEL_DIR))
    print(f"\nadapter saved -> {MODEL_DIR}")
    print(f"evidence -> {EVID/'qwen_finetune_results.json'}")


if __name__ == "__main__":
    main()
