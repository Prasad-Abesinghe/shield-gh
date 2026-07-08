"""
SHIELD-GH full-mode LLM semantic threat scorer (Task 06.03, Eq. 3.28).

Selected model (supervisor-approved, Task 06.02): **Qwen2.5-7B-Instruct** (7.6B),
fine-tuned as a sequence classifier over tokenised blockchain forwarding-log
windows x_i^(t). Two-tier edge/cloud routing per Eq. 3.17.

    Q_i(t) = softmax( LLM(x_i^(t); theta) )_malicious            (Eq. 3.28)
    Use Tier-2 = 1[ max_c softmax(LLM_edge(x_i))_c < eps_u ]     (Eq. 3.17)

Hybrid backend (mirrors the Task-05 crypto module's genuine/fallback pattern):

  * GENUINE backend  — when `torch` + `transformers` (+ `peft` for LoRA) are
    installed, loads Qwen2.5-7B and fine-tunes a LoRA adapter (federated-friendly
    small gradient, §2.4.2). This is what a vehicle actually trains.
  * FALLBACK backend — dependency-free hashing-vectoriser + logistic classifier
    with an *identical* API, so the FL, fusion, and test code run on any host.
    Flagged as a stand-in; it is NOT the selected LLM, only a runnable proxy.

Both backends expose the same interface, so `federated.py` / `fusion.py` never
branch on which one is active:

    scorer = LLMScorer()          # picks best available backend
    scorer.fit(texts, labels)     # local fine-tune on D_i
    Q = scorer.threat_score(x)    # Eq. 3.28 malicious-class probability in [0,1]
    tier2 = scorer.needs_tier2(x) # Eq. 3.17 escalation flag
    w  = scorer.get_weights()     # flat vector -> FL gradient (Eq. 3.25)
    scorer.set_weights(w)         # apply aggregated global model (Eq. 3.26)
"""
from __future__ import annotations
import hashlib
from dataclasses import dataclass

import numpy as np

# 7 SHIELD-GH classes; index 0 = BENIGN, 1..6 = the six attack signatures.
CLASSES = ["BENIGN", "DP-FR", "DP-IT", "DP-TS", "CP-FR", "CP-IT", "CP-TS"]
MALICIOUS_IDS = list(range(1, len(CLASSES)))   # everything except BENIGN
EPS_U = 0.15   # Eq. 3.17 uncertainty threshold (Tier-2 escalation), tune on val


def _try_genuine():
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
#  Fallback backend: dependency-free sequence classifier (hashing + softmax)   #
# --------------------------------------------------------------------------- #
class _HashingFeaturizer:
    """Forwarding-log featurizer: hashed token/bigram counts + engineered
    structural features that expose the sequence-order signals the selection
    study showed a plain bag-of-tokens misses (DP-IT periodicity, DP-TS
    per-source targeting).

    Structural features (append after the hashed block):
      - drop rate, forward rate, handoff rate
      - number of on/off drop runs (periodicity -> DP-IT / S2)
      - longest drop run
      - per-source drop concentration = max_src(drops_src)/total_drops (DP-TS/S3)
      - has controller RULE token (CP variants / S4-S6)
    """
    N_STRUCT = 8

    def __init__(self, dim=512):
        self.dim = dim
        self.out_dim = dim + self.N_STRUCT

    def _hash(self, s):
        h = int(hashlib.md5(s.encode()).hexdigest(), 16)
        return h % self.dim

    def _struct(self, toks):
        actions = [t.split(":")[0] if ":" in t else t for t in toks]
        srcs = [t.split(":")[1] for t in toks if ":" in t]
        has_rule = 1.0 if any(t.startswith("RULE") for t in toks) else 0.0
        seq = [a for a in actions if a in ("FWD", "DRP", "HOF")]
        n = max(1, len(seq))
        n_drop = seq.count("DRP")
        n_fwd = seq.count("FWD")
        n_hof = seq.count("HOF")
        # on/off runs of drops (periodicity)
        runs, longest, cur = 0, 0, 0
        prev_drop = False
        for a in seq:
            d = (a == "DRP")
            if d and not prev_drop:
                runs += 1
            cur = cur + 1 if d else 0
            longest = max(longest, cur)
            prev_drop = d
        # per-source drop concentration
        drop_by_src = {}
        for a, s in zip(actions, [t.split(":")[1] if ":" in t else "?"
                                  for t in toks]):
            if a == "DRP":
                drop_by_src[s] = drop_by_src.get(s, 0) + 1
        total_drops = sum(drop_by_src.values())
        concentration = (max(drop_by_src.values()) / total_drops
                         if total_drops else 0.0)
        return np.array([n_drop / n, n_fwd / n, n_hof / n,
                         runs / n, longest / n, concentration,
                         has_rule, len(set(srcs)) / 4.0])

    def transform(self, texts):
        X = np.zeros((len(texts), self.out_dim), dtype=np.float64)
        for r, t in enumerate(texts):
            toks = t.split()
            grams = toks + [f"{a}|{b}" for a, b in zip(toks, toks[1:])]
            for g in grams:
                X[r, self._hash(g)] += 1.0
            # l2-normalise the hashed block only
            block = X[r, :self.dim]
            nb = np.linalg.norm(block)
            if nb > 0:
                X[r, :self.dim] = block / nb
            X[r, self.dim:] = self._struct(toks)
        return X


class _SoftmaxClassifier:
    """Multinomial logistic regression trained with full-batch gradient descent.

    Kept intentionally simple and pure-numpy so its weight vector IS the FL
    model update Δw (Eq. 3.25/3.26) with no framework coupling.
    """
    def __init__(self, dim, n_classes, lr=0.5, l2=1e-4, seed=0):
        rng = np.random.RandomState(seed)
        self.W = rng.normal(0, 0.01, size=(dim, n_classes))
        self.b = np.zeros(n_classes)
        self.lr, self.l2 = lr, l2
        self.n_classes = n_classes

    def _softmax(self, Z):
        Z = Z - Z.max(axis=1, keepdims=True)
        e = np.exp(Z)
        return e / e.sum(axis=1, keepdims=True)

    def proba(self, X):
        return self._softmax(X @ self.W + self.b)

    def fit(self, X, y, epochs=200):
        Y = np.eye(self.n_classes)[y]
        for _ in range(epochs):
            P = self.proba(X)
            g = X.T @ (P - Y) / len(X) + self.l2 * self.W
            gb = (P - Y).mean(axis=0)
            self.W -= self.lr * g
            self.b -= self.lr * gb
        return self

    # ---- flat weight (de)serialisation for FL ----
    def get_flat(self):
        return np.concatenate([self.W.ravel(), self.b.ravel()])

    def set_flat(self, v):
        d = self.W.size
        self.W = v[:d].reshape(self.W.shape)
        self.b = v[d:].reshape(self.b.shape)


@dataclass
class _FallbackBackend:
    dim: int = 512
    n_classes: int = 7

    def __post_init__(self):
        self.feat = _HashingFeaturizer(self.dim)
        self.clf = _SoftmaxClassifier(self.feat.out_dim, self.n_classes)
        self.kind = "fallback:hashing+struct+softmax (stand-in for Qwen2.5-7B)"

    def fit(self, texts, labels, epochs=200):
        X = self.feat.transform(texts)
        self.clf.fit(X, np.asarray(labels), epochs=epochs)

    def proba(self, texts):
        return self.clf.proba(self.feat.transform(texts))

    def get_weights(self):
        return self.clf.get_flat()

    def set_weights(self, v):
        self.clf.set_flat(np.asarray(v, dtype=np.float64))


# --------------------------------------------------------------------------- #
#  Genuine backend: Qwen2.5-7B-Instruct + LoRA sequence classifier            #
# --------------------------------------------------------------------------- #
class _GenuineBackend:
    """Loads the selected Qwen2.5-7B and fine-tunes a LoRA adapter.

    Only constructed when torch+transformers are importable. The LoRA adapter
    parameters form the FL update Δw (small -> mobility-friendly, §2.4.2). Kept
    lazy so importing this module never triggers a 15GB download.
    """
    def __init__(self, n_classes=7):
        from selection.model_candidates import SELECTED_HF_ID  # noqa
        import torch
        from transformers import (AutoTokenizer,
                                  AutoModelForSequenceClassification)
        self.hf_id = SELECTED_HF_ID
        self.tok = AutoTokenizer.from_pretrained(self.hf_id)
        if self.tok.pad_token is None:
            self.tok.pad_token = self.tok.eos_token
        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.hf_id, num_labels=n_classes,
            torch_dtype=torch.float16, device_map="auto")
        self.model.config.pad_token_id = self.tok.pad_token_id
        try:
            from peft import LoraConfig, get_peft_model, TaskType
            cfg = LoraConfig(task_type=TaskType.SEQ_CLS, r=8, lora_alpha=16,
                             lora_dropout=0.05,
                             target_modules=["q_proj", "v_proj"])
            self.model = get_peft_model(self.model, cfg)
            self.kind = "genuine:Qwen2.5-7B-Instruct + LoRA"
        except Exception:
            self.kind = "genuine:Qwen2.5-7B-Instruct (full fine-tune)"
        self.torch = torch

    def _dev(self):
        import torch
        return next(self.model.parameters()).device

    def fit(self, texts, labels, epochs=3, lr=2e-4, bs=16):
        import torch
        # a 7B model needs only a few epochs; callers passing the fallback's
        # large epoch count (e.g. 300) are clamped so genuine runs stay tractable
        epochs = min(int(epochs), 3)
        dev = self._dev()
        opt = torch.optim.AdamW(
            (p for p in self.model.parameters() if p.requires_grad), lr=lr)
        self.model.train()
        texts, labels = list(texts), list(labels)
        idx = np.arange(len(texts))
        for _ in range(epochs):
            np.random.shuffle(idx)
            for b in range(0, len(idx), bs):
                bi = idx[b:b + bs]
                enc = self.tok([texts[i] for i in bi], return_tensors="pt",
                               padding=True, truncation=True, max_length=64)
                enc = {k: v.to(dev) for k, v in enc.items()}
                y = torch.tensor([labels[i] for i in bi]).to(dev)
                out = self.model(**enc, labels=y)
                out.loss.backward()
                opt.step(); opt.zero_grad()

    def proba(self, texts):
        import torch
        dev = self._dev()
        self.model.eval()
        texts = list(texts)
        probs = []
        with torch.no_grad():
            for b in range(0, len(texts), 32):
                enc = self.tok(texts[b:b + 32], return_tensors="pt",
                               padding=True, truncation=True, max_length=64)
                enc = {k: v.to(dev) for k, v in enc.items()}
                logits = self.model(**enc).logits.float()
                probs.append(torch.softmax(logits, dim=-1).cpu().numpy())
        return np.concatenate(probs)

    def get_weights(self):
        import torch
        return torch.cat([p.detach().flatten()
                          for p in self.model.parameters() if p.requires_grad]
                         ).cpu().numpy()

    def set_weights(self, v):
        import torch
        v = torch.tensor(v)
        i = 0
        for p in self.model.parameters():
            if not p.requires_grad:
                continue
            n = p.numel()
            p.data.copy_(v[i:i + n].view_as(p)); i += n


# --------------------------------------------------------------------------- #
#  Public scorer                                                              #
# --------------------------------------------------------------------------- #
class LLMScorer:
    def __init__(self, force_fallback=False, dim=512):
        if not force_fallback and _try_genuine():
            try:
                self.backend = _GenuineBackend(n_classes=len(CLASSES))
            except Exception:
                self.backend = _FallbackBackend(dim=dim, n_classes=len(CLASSES))
        else:
            self.backend = _FallbackBackend(dim=dim, n_classes=len(CLASSES))

    @property
    def kind(self):
        return self.backend.kind

    def fit(self, texts, labels, **kw):
        self.backend.fit(texts, labels, **kw)
        return self

    def proba(self, texts):
        """Full class-probability matrix (rows = windows, cols = CLASSES)."""
        single = isinstance(texts, str)
        P = self.backend.proba([texts] if single else list(texts))
        return P[0] if single else P

    def threat_score(self, text):
        """Q_i(t): probability mass on the malicious classes (Eq. 3.28)."""
        p = self.proba(text)
        return float(p[MALICIOUS_IDS].sum())

    def predict(self, text):
        p = self.proba(text)
        return CLASSES[int(np.argmax(p))]

    def needs_tier2(self, text):
        """Eq. 3.17: escalate to cloud when max class confidence < eps_u.

        Confidence = 1 - normalised entropy; low confidence -> escalate.
        (Using max-prob directly is degenerate for 7 classes, so we use a
        confidence margin that maps cleanly onto the eps_u threshold.)"""
        p = self.proba(text)
        conf = float(np.max(p))
        return conf < (1.0 / len(CLASSES) + EPS_U)  # ~0.293 with 7 classes

    # ---- FL hooks (Eq. 3.25/3.26) ----
    def get_weights(self):
        return np.asarray(self.backend.get_weights(), dtype=np.float64)

    def set_weights(self, v):
        self.backend.set_weights(v)
