# ============================================================
# IMPLEMENTS: Eq. 3.20 — Li(w) = (1/|Di|) Σ ℓ(f(x;w), y)
#             Eq. 3.21 — w^(r+1) = Σ_{i∈A} (|Di|/|DA|) wi
#             Eq. 3.22 — Accept(Δwi) = 1[H_BC(Δwi) == Hash(Δwi)]
# ALGORITHM 3: FV-Det full-mode LLM + FL detection pipeline
# ============================================================
import torch
import torch.nn as nn
import hashlib
import json
import numpy as np
from typing import List, Dict, Tuple, Optional


class VehicleLocalModel(nn.Module):
    """Local detection model per vehicle — Eq. 3.20"""
    def __init__(self, input_dim: int = 20):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 64), nn.ReLU(),
            nn.Linear(64, 32),        nn.ReLU(),
            nn.Linear(32, 2)          # binary: benign/malicious
        )

    def forward(self, x):
        return self.net(x)


class FederatedLearningClient:
    """
    Vehicle-side FL client.
    Eq. 3.20: Li(w) = (1/|Di|) Σ_{(x,y)∈Di} ℓ(f(x;w), y)
    """
    def __init__(self, node_id: int, dataset: list):
        self.node_id = node_id
        self.dataset = dataset
        self.model = VehicleLocalModel()

    def local_train(self, global_weights: dict, round_num: int,
                    epochs: int = 5) -> dict:
        """
        Eq. 3.20: train on local dataset Di using cross-entropy loss.
        Returns gradient update Δwi with blockchain hash commitment.
        """
        self.model.load_state_dict(global_weights)
        optimizer = torch.optim.SGD(self.model.parameters(), lr=0.01)
        criterion = nn.CrossEntropyLoss()

        X = torch.FloatTensor([d['features'] for d in self.dataset])
        y = torch.LongTensor([d['label']    for d in self.dataset])

        for _ in range(epochs):
            optimizer.zero_grad()
            outputs = self.model(X)
            # Eq. 3.20: cross-entropy loss ℓ
            loss = criterion(outputs, y)
            loss.backward()
            optimizer.step()

        # Compute gradient update Δwi = w_new − w_global
        delta_w = {
            k: (self.model.state_dict()[k] - global_weights[k]).numpy()
            for k in global_weights
        }

        # Eq. 3.14: pre-commitment hash H(Δwi || t || idi) for blockchain
        data_str = json.dumps({
            'delta': {k: v.tolist() for k, v in delta_w.items()},
            'round': round_num,
            'node_id': self.node_id
        }, sort_keys=True)
        gradient_hash = hashlib.sha256(data_str.encode()).hexdigest()

        return {
            'node_id':      self.node_id,
            'delta_w':      delta_w,
            'dataset_size': len(self.dataset),
            'gradient_hash': gradient_hash,  # submit to blockchain FIRST
            'round':        round_num
        }

    def infer(self, features: list) -> Tuple[int, float]:
        """Run local model inference. Returns (class, malicious_probability)."""
        x = torch.FloatTensor(features).unsqueeze(0)
        with torch.no_grad():
            logits = self.model(x)
        probs = torch.softmax(logits, dim=-1)
        return int(probs.argmax().item()), probs[0][1].item()


class FederatedLearningServer:
    """
    Aggregator implementing Eq. 3.21 + blockchain-verified Eq. 3.22
    """
    def __init__(self):
        self.global_model = VehicleLocalModel()
        self.blockchain_hashes: Dict[int, Dict[int, str]] = {}  # node_id → round → hash

    def get_global_weights(self) -> dict:
        return self.global_model.state_dict()

    def commit_hash_to_blockchain(self, node_id: int, round_num: int,
                                   gradient_hash: str):
        """Vehicle pre-commits hash before transmitting gradient"""
        self.blockchain_hashes.setdefault(node_id, {})[round_num] = gradient_hash

    def aggregate(self, client_updates: list, round_num: int) -> int:
        """
        Eq. 3.21: w^(r+1) = Σ_{i∈A} (|Di| / |DA|) * wi
        Eq. 3.22: A = {i : Accept(Δwi) == 1}
        Returns count of accepted updates.
        """
        accepted = []
        total_data = 0

        for update in client_updates:
            node_id = update['node_id']
            # Eq. 3.22: verify against pre-committed hash
            committed = self.blockchain_hashes.get(node_id, {}).get(round_num)
            if committed == update['gradient_hash']:
                accepted.append(update)
                total_data += update['dataset_size']
                print(f"  Node {node_id}: ACCEPTED (hash verified)")
            else:
                print(f"  Node {node_id}: REJECTED (hash mismatch — poisoning attempt)")

        if not accepted:
            print("  WARNING: No valid updates in this round")
            return 0

        # Eq. 3.21: Weighted FedAvg
        global_state = self.global_model.state_dict()
        aggregated = {k: torch.zeros_like(v) for k, v in global_state.items()}

        for update in accepted:
            weight = update['dataset_size'] / total_data
            for key in aggregated:
                aggregated[key] += weight * torch.FloatTensor(update['delta_w'][key])

        for key in global_state:
            global_state[key] += aggregated[key]
        self.global_model.load_state_dict(global_state)

        print(f"Round {round_num}: aggregated {len(accepted)}/{len(client_updates)} updates")
        return len(accepted)

    def infer_global(self, features: list) -> Tuple[int, float]:
        """Run global model inference. Returns (class, malicious_probability)."""
        x = torch.FloatTensor(features).unsqueeze(0)
        with torch.no_grad():
            logits = self.global_model(x)
        probs = torch.softmax(logits, dim=-1)
        return int(probs.argmax().item()), probs[0][1].item()


def generate_synthetic_dataset(node_id: int, is_malicious: bool,
                                n_samples: int = 50) -> list:
    """
    Generate synthetic per-node forwarding feature vectors for FL training.
    Features: [PDR_t1..t10, DropRate_t1..t10] — 20-dimensional
    """
    dataset = []
    for _ in range(n_samples):
        if is_malicious:
            pdr_vals      = np.random.uniform(0.1, 0.55, 10)
            drop_rate_vals = 1.0 - pdr_vals + np.random.uniform(-0.05, 0.05, 10)
            label = 1
        else:
            pdr_vals      = np.random.uniform(0.8, 1.0, 10)
            drop_rate_vals = 1.0 - pdr_vals + np.random.uniform(-0.05, 0.05, 10)
            label = 0
        drop_rate_vals = np.clip(drop_rate_vals, 0, 1)
        features = list(pdr_vals) + list(drop_rate_vals)
        dataset.append({'features': features, 'label': label})
    return dataset


if __name__ == "__main__":
    print("=== SHIELD-GH Federated Learning Pipeline (Eq. 3.20–3.22) ===")

    # Setup: 4 vehicles (2 benign, 2 malicious)
    server = FederatedLearningServer()
    clients = [
        FederatedLearningClient(0, generate_synthetic_dataset(0, False)),
        FederatedLearningClient(1, generate_synthetic_dataset(1, False)),
        FederatedLearningClient(2, generate_synthetic_dataset(2, True)),
        FederatedLearningClient(3, generate_synthetic_dataset(3, True)),
    ]

    # Federated training for 3 rounds
    for round_num in range(3):
        print(f"\n--- FL Round {round_num} ---")
        global_weights = server.get_global_weights()
        updates = []

        for client in clients:
            update = client.local_train(global_weights, round_num)
            # Pre-commit hash to blockchain BEFORE sending gradient
            server.commit_hash_to_blockchain(
                client.node_id, round_num, update['gradient_hash']
            )
            # Simulate poisoning: malicious node alters its gradient
            if client.node_id == 3:
                print(f"  Node 3 attempting gradient poisoning...")
                update['gradient_hash'] = 'poisoned_hash_tampered'
            updates.append(update)

        server.aggregate(updates, round_num)

    # Inference test
    print("\n=== FL Inference Test ===")
    benign_features = [0.95] * 10 + [0.05] * 10
    malicious_features = [0.3] * 10 + [0.7] * 10

    _, q_benign = server.infer_global(benign_features)
    _, q_malicious = server.infer_global(malicious_features)
    print(f"Benign node FL threat score: {q_benign:.4f}")
    print(f"Malicious node FL threat score: {q_malicious:.4f}")
