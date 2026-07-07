# ============================================================
# IMPLEMENTS: Eq. 3.20 — Local loss Li(w)
#             Eq. 3.21 — Global FedAvg w^(r+1) = Σ (|Di|/|DA|) wi
#             Eq. 3.22 — Accept(Δwi) = 1[H_BC(Δwi) == Hash(Δwi)]
# SECTION 3.6.6 — Federated Learning with Blockchain-Verified Gradient Integrity
# ============================================================
import hashlib
import json
import numpy as np


class BlockchainVerifiedFLAggregator:
    """
    Implements Eq. 3.21–3.22: Blockchain-verified FedAvg aggregator.
    Malicious vehicles cannot tamper with gradients because the
    pre-committed hash on blockchain blocks poisoned updates.
    """

    def __init__(self, blockchain_ledger):
        self.ledger = blockchain_ledger  # dict: node_id → round → committed_hash
        self.accepted_updates = {}

    def compute_gradient_hash(self, gradient: np.ndarray,
                               round_num: int, node_id: int) -> str:
        """
        Eq. 3.14: Ci = Hash(Δwi || t || idi)
        Pre-commitment: vehicle sends this hash to blockchain BEFORE
        transmitting the actual gradient update.
        """
        data = {
            'gradient': gradient.tolist(),
            'round': round_num,
            'node_id': node_id
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def verify_and_aggregate(self, updates: dict, round_num: int) -> np.ndarray:
        """
        Eq. 3.21 + 3.22:
        w^(r+1) = Σ_{i∈A} (|Di|/|DA|) * w_i^(r)
        A = {i : Accept(Δwi) == 1}

        Accept(Δwi) = 1[ H_BC(Δwi) == Hash(Δwi) ]
        """
        accepted = {}
        total_data_volume = 0

        for node_id, (gradient, dataset_size) in updates.items():
            # Eq. 3.22: verify against blockchain pre-committed hash
            computed_hash = self.compute_gradient_hash(gradient, round_num, node_id)
            blockchain_hash = self.ledger.get(node_id, {}).get(round_num, None)

            if blockchain_hash is None:
                print(f"Node {node_id}: No pre-committed hash found — REJECTED")
                continue

            # Eq. 3.22: Accept(Δwi) = 1[ H_BC(Δwi) == Hash(Δwi) ]
            if computed_hash == blockchain_hash:
                accepted[node_id] = (gradient, dataset_size)
                total_data_volume += dataset_size
                print(f"Node {node_id}: gradient hash VERIFIED — ACCEPTED")
            else:
                print(f"Node {node_id}: hash mismatch — POISONED gradient REJECTED")

        if not accepted:
            raise ValueError("No verified gradient updates in this round")

        # Eq. 3.21: Weighted FedAvg
        aggregated = None
        for node_id, (gradient, dataset_size) in accepted.items():
            weight = dataset_size / total_data_volume
            if aggregated is None:
                aggregated = weight * gradient
            else:
                aggregated += weight * gradient

        self.accepted_updates[round_num] = list(accepted.keys())
        return aggregated
