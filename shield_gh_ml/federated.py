"""
SHIELD-GH Federated Learning with blockchain-verified gradient integrity
(Task 06.03, §3.6.4 / §3.6.7).

Each vehicle v_i trains a local detector on its own labelled forwarding-log
dataset D_i and shares only the model update Δw_i — never raw traffic
(privacy-preserving, §1.8). The global model is FedAvg-aggregated, and a
blockchain hash commitment blocks gradient-poisoning without a trusted
aggregator.

Equations implemented:

  L_i(w)     = (1/|D_i|) Σ ℓ(f(x;w), y)                          (Eq. 3.25)
  w^(r+1)    = Σ_{i∈A} (|D_i|/|D_A|) w_i^(r)                       (Eq. 3.26)
  C_i        = Hash(Δw_i ‖ t ‖ id_i)   committed on-chain          (Eq. 3.16)
  Accept(Δw_i) = 1[ Hash(Δw_i) == C_i^BC ]                         (Eq. 3.27)
  Valid_i    = 1[ Hash(Δw_i ‖ t ‖ id_i) == C_i^BC ]               (Eq. 3.16)

Design insight (§3.6.4): a vehicle commits the hash of its update BEFORE it
transmits the update. A poisoner that submits a *different* (manipulated)
gradient than the one it committed produces a hash mismatch and is rejected —
so poisoning requires breaking a cryptographic hash, not just out-voting honest
clients. This needs no trusted aggregator and no gradient-norm heuristics, and
is auditable (the on-chain commitment traces the responsible round/vehicle).
"""
from __future__ import annotations
import hashlib
import time
from dataclasses import dataclass, field

import numpy as np

from llm_scorer import LLMScorer


# --------------------------------------------------------------------------- #
#  Minimal in-memory blockchain commitment store (Eq. 3.16)                   #
# --------------------------------------------------------------------------- #
def commit_hash(delta_w, t, vehicle_id) -> str:
    """C_i = Hash(Δw_i ‖ t ‖ id_i)  — the on-chain commitment (Eq. 3.16)."""
    h = hashlib.sha256()
    h.update(np.asarray(delta_w, dtype=np.float64).tobytes())
    h.update(str(t).encode())
    h.update(str(vehicle_id).encode())
    return h.hexdigest()


class BlockchainCommitStore:
    """Append-only commitment ledger. Mirrors the real DEBSC ledger used in the
    NS-3 side; here it is the in-memory prototype form (Table 3.3)."""
    def __init__(self):
        self._commits = {}   # (vehicle_id, round) -> C_i

    def submit_commitment(self, vehicle_id, rnd, delta_w, t):
        c = commit_hash(delta_w, t, vehicle_id)
        self._commits[(vehicle_id, rnd)] = c
        return c

    def get(self, vehicle_id, rnd):
        return self._commits.get((vehicle_id, rnd))

    def verify(self, vehicle_id, rnd, received_delta_w, t) -> bool:
        """Valid_i (Eq. 3.16/3.27): recompute hash of the RECEIVED gradient and
        compare to the pre-committed on-chain hash."""
        onchain = self._commits.get((vehicle_id, rnd))
        if onchain is None:
            return False
        return commit_hash(received_delta_w, t, vehicle_id) == onchain


# --------------------------------------------------------------------------- #
#  Vehicle client                                                             #
# --------------------------------------------------------------------------- #
@dataclass
class VehicleClient:
    vehicle_id: int
    texts: list
    labels: list
    poisoner: bool = False        # if True, transmits a gradient ≠ committed one
    scorer: LLMScorer = field(default=None, repr=False)

    def __post_init__(self):
        if self.scorer is None:
            self.scorer = LLMScorer()

    @property
    def n(self):
        return len(self.texts)

    def local_train(self, global_w, epochs=200):
        """Eq. 3.25: set global weights, minimise local CE loss, return Δw."""
        self.scorer.set_weights(global_w)
        self.scorer.fit(self.texts, self.labels, epochs=epochs)
        new_w = self.scorer.get_weights()
        return new_w - global_w      # Δw_i

    def poison(self, delta_w):
        """Model-destruction poison: instead of the honest Δw it committed, the
        attacker transmits a large update that drives the global weights toward a
        fixed garbage target, collapsing the detector. Deterministic so the
        evidence is reproducible."""
        rng = np.random.RandomState(1234)
        garbage = rng.normal(0, 1.0, size=delta_w.shape)
        return 15.0 * garbage - delta_w


# --------------------------------------------------------------------------- #
#  Federated aggregator                                                       #
# --------------------------------------------------------------------------- #
class FederatedAggregator:
    def __init__(self, clients, ledger: BlockchainCommitStore,
                 integrity_check=True):
        self.clients = clients
        self.ledger = ledger
        self.integrity_check = integrity_check
        dim = clients[0].scorer.get_weights().shape[0]
        self.global_w = np.zeros(dim)
        self.round = 0
        self.audit_log = []          # rejections, for evidence

    def run_round(self, epochs=200):
        """One FL round: local train -> commit -> (poison?) -> verify -> FedAvg."""
        self.round += 1
        t = time.time()
        accepted = []       # (client, delta_w, weight)
        for c in self.clients:
            delta = c.local_train(self.global_w, epochs=epochs)
            # commit the HONEST gradient hash on-chain BEFORE transmit (Eq. 3.16)
            self.ledger.submit_commitment(c.vehicle_id, self.round, delta, t)
            # a poisoner then transmits a DIFFERENT gradient than it committed
            transmitted = c.poison(delta) if c.poisoner else delta
            if self.integrity_check:
                ok = self.ledger.verify(c.vehicle_id, self.round,
                                        transmitted, t)     # Eq. 3.27
            else:
                ok = True
            if ok:
                accepted.append((c, transmitted, c.n))
            else:
                self.audit_log.append(
                    dict(round=self.round, vehicle=c.vehicle_id,
                         reason="gradient hash mismatch (poisoning blocked)",
                         poisoner=c.poisoner))
        # weighted FedAvg over accepted set A (Eq. 3.26)
        if accepted:
            total = sum(w for _, _, w in accepted)
            agg = np.zeros_like(self.global_w)
            for _, delta, w in accepted:
                agg += (w / total) * delta
            self.global_w = self.global_w + agg
        return dict(round=self.round,
                    accepted=[c.vehicle_id for c, _, _ in accepted],
                    rejected=[e["vehicle"] for e in self.audit_log
                              if e["round"] == self.round])

    def fit(self, rounds=5, epochs=200):
        history = [self.run_round(epochs=epochs) for _ in range(rounds)]
        return history

    def global_scorer(self):
        """A scorer carrying the aggregated global model (for evaluation/fusion)."""
        s = LLMScorer()
        s.set_weights(self.global_w)
        return s
