# ============================================================
# IMPLEMENTS: Eq. 3.15 — Use_Tier2 = 1[max_c softmax(LLM_edge(xi))_c < ε_u]
#             Eq. 3.23 — Qi(t) = softmax(LLM(xi^(t); θ))_malicious
# SECTION 3.6.4: Edge-LLM Architecture for Real-Time Grey Hole Detection
# Two-tier: RSU edge LLM (quantised DistilBERT) + cloud LLM fallback
# INPUT: Tokenised blockchain forwarding logs
# OUTPUT: Threat score Qi(t) ∈ [0, 1]
# ============================================================
import torch
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
import numpy as np
import os


class ShieldGHEdgeLLM:
    """
    Implements Eq. 3.23: Qi(t) = softmax(LLM(x_i^(t); θ))_malicious

    Fine-tuned DistilBERT on tokenised blockchain forwarding log sequences.
    Quantised to 4-bit for RSU edge deployment (Tier 1).
    """

    def __init__(self, model_path: str = "distilbert-base-uncased",
                 epsilon_u: float = 0.7):
        self.epsilon_u = epsilon_u  # uncertainty threshold for Tier 2 escalation
        self.tokenizer = DistilBertTokenizer.from_pretrained(model_path)
        self.model = DistilBertForSequenceClassification.from_pretrained(
            model_path, num_labels=2  # binary: benign / malicious
        )
        self.model.eval()

    def tokenize_forwarding_log(self, log_records: list) -> dict:
        """
        Convert blockchain forwarding log records into token sequence x_i^(t).
        Format: "NodeID PDR_slot1 PDR_slot2 ... DROP_RATE_slot_n"
        """
        log_text = " ".join([
            f"NODE{r['node_id']} PDR{r['pdr']:.2f} DROP{r['drop_rate']:.2f}"
            for r in log_records
        ])
        return self.tokenizer(log_text, return_tensors='pt',
                              max_length=128, truncation=True, padding=True)

    def compute_threat_score(self, log_records: list) -> float:
        """
        Eq. 3.23: Qi(t) = softmax(LLM(xi^(t); θ))_malicious
        Returns probability assigned to malicious class.
        """
        inputs = self.tokenize_forwarding_log(log_records)
        with torch.no_grad():
            logits = self.model(**inputs).logits
        probabilities = torch.softmax(logits, dim=-1)
        # Index 1 = malicious class
        return probabilities[0][1].item()

    def route_decision(self, log_records: list) -> tuple:
        """
        Eq. 3.15: Use_Tier2 = 1[max_c softmax(LLM_edge(xi))_c < ε_u]
        Returns (threat_score, use_tier2)
        """
        inputs = self.tokenize_forwarding_log(log_records)
        with torch.no_grad():
            logits = self.model(**inputs).logits
        probabilities = torch.softmax(logits, dim=-1)

        max_confidence = probabilities.max().item()
        threat_score = probabilities[0][1].item()

        # Eq. 3.15: escalate to cloud LLM if edge confidence < ε_u
        use_tier2 = (max_confidence < self.epsilon_u)
        return threat_score, use_tier2

    def fine_tune(self, training_data: list, labels: list, epochs: int = 3,
                  save_path: str = "shield_gh_llm_model"):
        """
        Fine-tune on simulation-generated forwarding log sequences.
        Labels: 0=benign, 1=malicious (grey hole attacker)
        """
        from torch.optim import AdamW
        optimizer = AdamW(self.model.parameters(), lr=2e-5)
        self.model.train()

        for epoch in range(epochs):
            total_loss = 0
            for log_records, label in zip(training_data, labels):
                inputs = self.tokenize_forwarding_log(log_records)
                labels_tensor = torch.tensor([label])
                outputs = self.model(**inputs, labels=labels_tensor)
                loss = outputs.loss
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            print(f"Epoch {epoch+1}/{epochs} — Loss: {total_loss/len(training_data):.4f}")

        self.model.eval()
        self.model.save_pretrained(save_path)
        self.tokenizer.save_pretrained(save_path)
        print(f"Model saved to {save_path}")


def generate_training_data(n_samples: int = 200):
    """
    Generate synthetic training data from simulation-style forwarding logs.
    Benign nodes: PDR > 0.85; Malicious: PDR < 0.55
    """
    training_data = []
    labels = []

    for _ in range(n_samples // 2):
        # Benign node: consistent high forwarding
        records = [
            {'node_id': 0,
             'pdr': 0.85 + np.random.uniform(0, 0.15),
             'drop_rate': np.random.uniform(0, 0.15)}
            for _ in range(10)
        ]
        training_data.append(records)
        labels.append(0)

    for _ in range(n_samples // 2):
        # Malicious node: grey hole (low PDR)
        records = [
            {'node_id': 0,
             'pdr': np.random.uniform(0.1, 0.55),
             'drop_rate': np.random.uniform(0.45, 0.9)}
            for _ in range(10)
        ]
        training_data.append(records)
        labels.append(1)

    return training_data, labels


if __name__ == "__main__":
    print("=== SHIELD-GH Edge LLM Training ===")
    llm = ShieldGHEdgeLLM()

    training_data, labels = generate_training_data(100)
    llm.fine_tune(training_data, labels, epochs=2)

    # Test threat scoring
    benign_log = [{'node_id': 0, 'pdr': 0.95, 'drop_rate': 0.05}] * 5
    malicious_log = [{'node_id': 1, 'pdr': 0.3, 'drop_rate': 0.7}] * 5

    q_benign, _ = llm.route_decision(benign_log)
    q_malicious, _ = llm.route_decision(malicious_log)

    print(f"Benign node threat score Qi: {q_benign:.4f}")
    print(f"Malicious node threat score Qi: {q_malicious:.4f}")
