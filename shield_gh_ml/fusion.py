"""
SHIELD-GH full-mode fusion engine (Task 06.03, Eq. 3.28 / 3.29 / Algorithm 3).

The final full-mode verdict fuses three independent evidence sources — because
§3.6.8 shows no single source is sufficient across all six variants:

  ŷ_i(t) = 1[ μ1·S_total(v_i) + μ2·Q_i(t) + μ3·(1 − R_i(t)) > θ_det ]   (Eq. 3.29)

    S_total(v_i)  = max binary rule-based signature score across S1–S6
    Q_i(t)        = LLM semantic threat score (Eq. 3.28), from llm_scorer
    (1 − R_i(t))  = blockchain reputation deficit (Eq. 3.20)
    μ1+μ2+μ3 = 1  = fusion weights tuned on the validation set

A positive verdict ŷ_i = 1 triggers the PQC mitigation / DEBSC isolation gate
(the crypto module, Task 05). This module produces the DETECTION decision only;
it does not isolate (that is Eq. 3.23, handled by shield_gh_crypto).

This is the fusion step of Algorithm 3 (FV-Det) lines 3–7.
"""
from __future__ import annotations
from dataclasses import dataclass

import numpy as np

from llm_scorer import LLMScorer


@dataclass
class FusionWeights:
    mu1: float = 0.34   # rule-based signature
    mu2: float = 0.33   # LLM semantic score
    mu3: float = 0.33   # blockchain reputation deficit

    def __post_init__(self):
        s = self.mu1 + self.mu2 + self.mu3
        assert abs(s - 1.0) < 1e-6, f"fusion weights must sum to 1 (got {s})"


@dataclass
class Evidence:
    """The three evidence inputs for one vehicle window."""
    s_total: float      # max rule-based signature score S1–S6 in {0,1} (or graded)
    q_i: float          # LLM threat score Q_i in [0,1] (Eq. 3.28)
    reputation: float   # R_i in [0,1] (Eq. 3.20); deficit = 1 − R_i


class FusionEngine:
    def __init__(self, scorer: LLMScorer, weights: FusionWeights = None,
                 theta_det: float = 0.5):
        self.scorer = scorer
        self.w = weights or FusionWeights()
        self.theta_det = theta_det

    def fuse(self, ev: Evidence) -> dict:
        """Eq. 3.29: weighted linear combination -> binary verdict."""
        score = (self.w.mu1 * ev.s_total
                 + self.w.mu2 * ev.q_i
                 + self.w.mu3 * (1.0 - ev.reputation))
        verdict = int(score > self.theta_det)
        return dict(score=round(float(score), 4), verdict=verdict,
                    s_total=ev.s_total, q_i=round(ev.q_i, 4),
                    rep_deficit=round(1.0 - ev.reputation, 4))

    def evaluate_window(self, text, s_total, reputation) -> dict:
        """Compute Q_i from the LLM (Eq. 3.28) and fuse (Eq. 3.29)."""
        q = self.scorer.threat_score(text)
        tier2 = self.scorer.needs_tier2(text)     # Eq. 3.17 escalation flag
        out = self.fuse(Evidence(s_total=s_total, q_i=q, reputation=reputation))
        out["tier2_escalate"] = bool(tier2)
        out["llm_pred"] = self.scorer.predict(text)
        return out


def tune_weights(scorer, val_texts, val_s_total, val_reputation, val_y,
                 grid=None):
    """Grid-search μ1,μ2,μ3 (sum=1) + θ_det to maximise validation MCC.

    Returns the best (FusionWeights, theta_det, mcc). Fusion weights are 'tuned
    on the validation set' exactly as Eq. 3.29 requires — not hand-picked."""
    from sklearn.metrics import matthews_corrcoef
    if grid is None:
        grid = np.linspace(0, 1, 6)
    q = np.array([scorer.threat_score(t) for t in val_texts])
    s = np.asarray(val_s_total, dtype=float)
    d = 1.0 - np.asarray(val_reputation, dtype=float)
    y = np.asarray(val_y)
    best = (None, None, -2.0)
    for m1 in grid:
        for m2 in grid:
            m3 = 1.0 - m1 - m2
            if m3 < -1e-9 or m3 > 1 + 1e-9:
                continue
            score = m1 * s + m2 * q + m3 * d
            for th in np.linspace(0.2, 0.8, 13):
                pred = (score > th).astype(int)
                mcc = matthews_corrcoef(y, pred) if len(set(pred)) > 1 else 0.0
                if mcc > best[2]:
                    best = (FusionWeights(round(m1, 3), round(m2, 3),
                                          round(max(0.0, m3), 3)),
                            round(float(th), 3), round(float(mcc), 4))
    return best
