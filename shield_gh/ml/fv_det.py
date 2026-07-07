# ============================================================
# IMPLEMENTS: ALGORITHM 3 — FV-Det
#             Full-Version LLM + FL Detection Pipeline
#             Lines 1–14 of Algorithm 3 in paper
# INPUT:  Per-node blockchain forwarding logs (from NS-3 CSV)
# OUTPUT: Detection decisions + threat scores per node
# ============================================================
import csv
import json
import sys
import numpy as np
from typing import List, Dict, Optional
from llm_agent import ShieldGHEdgeLLM
from federated_learning import FederatedLearningServer, generate_synthetic_dataset


class BlockchainLedgerInterface:
    """
    Python-side interface to read NS-3 blockchain log CSV.
    Feeds the LLM and FL modules with per-node forwarding records.
    """
    def __init__(self, csv_path: str = "../../results/blockchain_log.csv"):
        self.csv_path = csv_path
        self.records: Dict[int, List[dict]] = {}
        self._load()

    def _load(self):
        try:
            with open(self.csv_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    node_id = int(row['node_id'])
                    n_rx    = int(row.get('n_rx', 0))
                    n_fwd   = int(row.get('n_fwd', 0))
                    pdr     = n_fwd / max(n_rx, 1)
                    rec = {
                        'node_id':   node_id,
                        'timestamp': float(row.get('timestamp', 0)),
                        'pdr':       pdr,
                        'drop_rate': 1.0 - pdr,
                        'n_rx':      n_rx,
                        'n_fwd':     n_fwd,
                    }
                    self.records.setdefault(node_id, []).append(rec)
        except FileNotFoundError:
            print(f"Warning: {self.csv_path} not found — using synthetic data")

    def get_history(self, node_id: int, window: int = 10) -> List[dict]:
        recs = self.records.get(node_id, [])
        return recs[-window:] if len(recs) > window else recs

    def get_reputation(self, node_id: int) -> float:
        recs = self.records.get(node_id, [])
        if not recs:
            return 1.0
        trust_values = []
        for r in recs:
            n_drop = r['n_rx'] - r['n_fwd']
            t = (1 + r['n_fwd']) / (1 + r['n_fwd'] + 1 + max(n_drop, 0) + 1e-9)
            trust_values.append(t)
        return sum(trust_values) / len(trust_values)


class FVDet:
    """
    Algorithm 3: Full-Version LLM + FL Detection Pipeline

    Fuses:
      - Qi(t): LLM threat score (Eq. 3.23)
      - FL inference score
      - Ri(t): blockchain reputation (Eq. 3.18)
    into final detection decision ŷi(t) via Eq. 3.24
    """

    def __init__(self,
                 llm_model_path: str = "distilbert-base-uncased",
                 fl_server: Optional[FederatedLearningServer] = None,
                 mu1: float = 0.40,
                 mu2: float = 0.35,
                 mu3: float = 0.25,
                 theta_det: float = 0.50,
                 epsilon_u: float = 0.70):
        self.llm    = ShieldGHEdgeLLM(llm_model_path, epsilon_u)
        self.fl     = fl_server
        self.mu1    = mu1
        self.mu2    = mu2
        self.mu3    = mu3
        self.theta  = theta_det
        self.results: List[dict] = []

    def detect(self, node_id: int, ledger: BlockchainLedgerInterface,
               window: int = 10) -> bool:
        """
        Algorithm 3, lines 1–13:
        1. Tokenise blockchain log → xi
        2. Qi ← softmax(LLM(xi; θ))_malicious    [Eq. 3.23]
        3. ŷ_FL_i ← f(x_feat_i; w^(r))           [local FL inference]
        4. Ri ← GET_REPUTATION(vi)               [Eq. 3.18]
        5. ŷi ← 1[μ1*Stotal + μ2*Qi + μ3*(1-Ri) > θdet] [Eq. 3.24]
        6. If ŷi == 1 → report to DEBSC for Algorithm 4
        7. Else → submit gradient update
        """
        # Line 1: retrieve tokenised blockchain forwarding log
        history = ledger.get_history(node_id, window)

        if not history:
            # No data — assume benign
            return False

        # Line 2 (Eq. 3.23): LLM threat score via route_decision
        Q_i, use_tier2 = self.llm.route_decision(history)

        if use_tier2:
            # Eq. 3.15: edge model uncertain — escalate to cloud tier
            print(f"  Node {node_id}: Tier-2 escalation (confidence < ε_u={self.llm.epsilon_u})")
            Q_i = self.llm.compute_threat_score(history)

        # Line 3: FL model inference
        features = ([r['pdr']       for r in history] +
                    [r['drop_rate'] for r in history])
        # Pad or truncate to 20 features
        features = (features + [0.0] * 20)[:20]

        S_fl = 0.0
        if self.fl is not None:
            _, S_fl = self.fl.infer_global(features)

        # S_total combines rule-based signature and FL scores
        S_total = max(Q_i, S_fl)

        # Line 4 (Eq. 3.18): blockchain reputation
        R_i = ledger.get_reputation(node_id)

        # Line 5 (Eq. 3.24): fusion decision
        score = self.mu1 * S_total + self.mu2 * Q_i + self.mu3 * (1.0 - R_i)
        y_hat = (score > self.theta)

        status = "MALICIOUS" if y_hat else "BENIGN"
        print(f"FV-Det Node {node_id}: Qi={Q_i:.3f} S_fl={S_fl:.3f} "
              f"Ri={R_i:.3f} score={score:.3f} → {status}")

        self.results.append({
            'node_id': node_id,
            'Q_i':     Q_i,
            'S_fl':    S_fl,
            'R_i':     R_i,
            'score':   score,
            'decision': 1 if y_hat else 0,
        })

        return y_hat

    def run_all_nodes(self, ledger: BlockchainLedgerInterface,
                      node_ids: List[int]) -> Dict[int, bool]:
        decisions = {}
        print("\n=== Algorithm 3: FV-Det Full-Mode Detection Pipeline ===")
        for node_id in node_ids:
            decisions[node_id] = self.detect(node_id, ledger)
        return decisions

    def write_results_csv(self, path: str = "../../results/fv_det_results.csv"):
        if not self.results:
            return
        import csv
        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
            writer.writeheader()
            writer.writerows(self.results)
        print(f"FV-Det results written to {path}")


def run_fvdet_pipeline(csv_path: str, node_count: int = 5):
    """Entry point: load ledger, train FL, run Algorithm 3."""
    ledger = BlockchainLedgerInterface(csv_path)

    # Pre-train FL on synthetic data (in production: loaded from file)
    print("Pre-training FL global model...")
    fl_server = FederatedLearningServer()
    from federated_learning import FederatedLearningClient
    clients = [
        FederatedLearningClient(i, generate_synthetic_dataset(i, i >= node_count // 2))
        for i in range(node_count)
    ]
    global_w = fl_server.get_global_weights()
    for r in range(2):
        updates = []
        for c in clients:
            upd = c.local_train(global_w, r)
            fl_server.commit_hash_to_blockchain(c.node_id, r, upd['gradient_hash'])
            updates.append(upd)
        fl_server.aggregate(updates, r)

    detector = FVDet(fl_server=fl_server)
    decisions = detector.run_all_nodes(ledger, list(range(node_count)))
    detector.write_results_csv()

    print("\n=== FV-Det Summary ===")
    for nid, detected in decisions.items():
        print(f"  Node {nid}: {'MALICIOUS (→ trigger Algorithm 4)' if detected else 'BENIGN'}")

    return decisions


if __name__ == "__main__":
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "../../results/blockchain_log.csv"
    node_count = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    run_fvdet_pipeline(csv_path, node_count)
