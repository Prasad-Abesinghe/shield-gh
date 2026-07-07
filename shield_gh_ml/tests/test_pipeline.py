"""
SHIELD-GH Task 06.03 test suite — one test per equation / property.

Runs with pytest (`pytest tests/ -v`) or stdlib unittest
(`python3 -m unittest tests.test_pipeline -v`) so it needs no install.
Uses the dependency-free fallback backend, so every assertion holds on any host;
the genuine Qwen2.5-7B backend satisfies the same contracts.
"""
import json
import sys
import unittest
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from llm_scorer import LLMScorer, CLASSES, MALICIOUS_IDS          # noqa: E402
from federated import (VehicleClient, FederatedAggregator,        # noqa: E402
                       BlockchainCommitStore, commit_hash)
from fusion import (FusionEngine, FusionWeights, Evidence,        # noqa: E402
                    tune_weights)


def _load():
    data = [json.loads(l) for l in open(ROOT / "selection" / "dataset.jsonl")]
    return data


# shared fitted scorer (fitting once keeps the suite fast)
_DATA = _load()
_SCORER = LLMScorer()
_SCORER.fit([d["text"] for d in _DATA[:2240]],
            [d["label"] for d in _DATA[:2240]], epochs=300)


class TestLLMScorer(unittest.TestCase):
    def test_threat_score_in_unit_interval(self):
        # Eq. 3.28: Q_i is a probability in [0,1]
        q = _SCORER.threat_score(_DATA[0]["text"])
        self.assertGreaterEqual(q, 0.0)
        self.assertLessEqual(q, 1.0)

    def test_proba_is_distribution(self):
        p = _SCORER.proba(_DATA[0]["text"])
        self.assertEqual(len(p), len(CLASSES))
        self.assertAlmostEqual(float(p.sum()), 1.0, places=5)

    def test_benign_below_attacker_threat(self):
        # Eq. 3.28 must separate benign from attacker on average
        te = _DATA[2520:]
        q_ben = np.mean([_SCORER.threat_score(d["text"])
                         for d in te if d["label"] == 0])
        q_att = np.mean([_SCORER.threat_score(d["text"])
                         for d in te if d["label"] != 0])
        self.assertGreater(q_att, q_ben + 0.2)

    def test_threat_score_is_malicious_mass(self):
        # Q_i == sum of malicious-class probs
        p = _SCORER.proba(_DATA[0]["text"])
        self.assertAlmostEqual(_SCORER.threat_score(_DATA[0]["text"]),
                               float(p[MALICIOUS_IDS].sum()), places=6)

    def test_tier2_flag_is_bool(self):
        # Eq. 3.17 escalation flag
        self.assertIn(_SCORER.needs_tier2(_DATA[0]["text"]), (True, False))

    def test_weight_roundtrip(self):
        w = _SCORER.get_weights()
        s2 = LLMScorer()
        s2.set_weights(w)
        np.testing.assert_allclose(s2.get_weights(), w)


class TestBlockchainIntegrity(unittest.TestCase):
    def test_commit_hash_deterministic(self):
        d = np.arange(10.0)
        self.assertEqual(commit_hash(d, 1.0, 7), commit_hash(d, 1.0, 7))

    def test_commit_hash_sensitive(self):
        # Eq. 3.16: any change to the gradient changes the commitment
        d = np.arange(10.0)
        d2 = d.copy(); d2[3] += 1e-6
        self.assertNotEqual(commit_hash(d, 1.0, 7), commit_hash(d2, 1.0, 7))

    def test_honest_update_accepted(self):
        # Eq. 3.27: Hash(received) == on-chain commitment -> accept
        led = BlockchainCommitStore()
        d = np.random.RandomState(0).normal(size=50)
        led.submit_commitment(1, 1, d, 123.0)
        self.assertTrue(led.verify(1, 1, d, 123.0))

    def test_poisoned_update_rejected(self):
        # Eq. 3.27: transmitted gradient != committed -> reject
        led = BlockchainCommitStore()
        d = np.random.RandomState(0).normal(size=50)
        led.submit_commitment(1, 1, d, 123.0)      # commit honest
        poisoned = -8.0 * d                          # transmit different
        self.assertFalse(led.verify(1, 1, poisoned, 123.0))

    def test_missing_commitment_rejected(self):
        led = BlockchainCommitStore()
        self.assertFalse(led.verify(99, 1, np.zeros(5), 1.0))


class TestFederatedLearning(unittest.TestCase):
    def _clients(self, poison_v9=True):
        rng = np.random.RandomState(42)
        tr = _DATA[:2240]

        def mk(vid, labs, cap, poison=False):
            keep = [d for d in tr if d["label"] in labs]
            rng.shuffle(keep); keep = keep[:cap]
            return VehicleClient(vid, [d["text"] for d in keep],
                                 [d["label"] for d in keep], poison)
        return [mk(0, [0, 1, 4], 200), mk(1, [0, 2, 5], 200),
                mk(2, [0, 3, 6], 200), mk(3, list(range(7)), 200),
                mk(9, list(range(7)), 200, poison=poison_v9)]

    def test_fedavg_weight_conservation(self):
        # Eq. 3.26: FedAvg weights sum to 1 over accepted clients
        led = BlockchainCommitStore()
        agg = FederatedAggregator(self._clients(), led, integrity_check=True)
        r = agg.run_round(epochs=50)
        self.assertNotIn(9, r["accepted"])   # poisoner excluded

    def test_poisoner_rejected_every_round(self):
        led = BlockchainCommitStore()
        agg = FederatedAggregator(self._clients(), led, integrity_check=True)
        hist = agg.fit(rounds=3, epochs=50)
        for h in hist:
            self.assertIn(9, h["rejected"])
            self.assertNotIn(9, h["accepted"])

    def test_integrity_preserves_model(self):
        # the headline claim: integrity ON >> integrity OFF under poisoning
        from sklearn.metrics import matthews_corrcoef
        te = _DATA[2520:]
        yte = np.array([0 if d["label"] == 0 else 1 for d in te])

        def run(on):
            led = BlockchainCommitStore()
            agg = FederatedAggregator(self._clients(), led, integrity_check=on)
            agg.fit(rounds=4, epochs=80)
            pred = agg.global_scorer().proba([d["text"] for d in te]).argmax(1)
            return matthews_corrcoef(yte, (pred != 0).astype(int))
        mcc_on, mcc_off = run(True), run(False)
        self.assertGreater(mcc_on, mcc_off + 0.15)   # integrity clearly helps


class TestFusion(unittest.TestCase):
    def test_weights_sum_to_one(self):
        with self.assertRaises(AssertionError):
            FusionWeights(0.5, 0.5, 0.5)   # sums to 1.5 -> invalid
        FusionWeights(0.34, 0.33, 0.33)    # ok

    def test_fusion_monotone_in_each_source(self):
        # Eq. 3.29 is a positive linear combination -> monotone in each input
        fe = FusionEngine(_SCORER, FusionWeights(0.34, 0.33, 0.33), theta_det=0.5)
        base = fe.fuse(Evidence(s_total=0.0, q_i=0.0, reputation=1.0))["score"]
        more_s = fe.fuse(Evidence(s_total=1.0, q_i=0.0, reputation=1.0))["score"]
        more_q = fe.fuse(Evidence(s_total=0.0, q_i=1.0, reputation=1.0))["score"]
        more_d = fe.fuse(Evidence(s_total=0.0, q_i=0.0, reputation=0.0))["score"]
        self.assertGreater(more_s, base)
        self.assertGreater(more_q, base)
        self.assertGreater(more_d, base)

    def test_high_all_sources_triggers(self):
        fe = FusionEngine(_SCORER, FusionWeights(0.34, 0.33, 0.33), theta_det=0.5)
        v = fe.fuse(Evidence(s_total=1.0, q_i=1.0, reputation=0.0))
        self.assertEqual(v["verdict"], 1)

    def test_all_clear_no_trigger(self):
        fe = FusionEngine(_SCORER, FusionWeights(0.34, 0.33, 0.33), theta_det=0.5)
        v = fe.fuse(Evidence(s_total=0.0, q_i=0.0, reputation=1.0))
        self.assertEqual(v["verdict"], 0)

    def test_llm_recovers_variant_rules_miss(self):
        # the coverage claim: for a DP-IT the rules miss (S_total=0), a
        # high LLM Q_i still yields an attack verdict via fusion (Eq. 3.29)
        te = _DATA[2520:]
        dpit = next(d for d in te if d["label"] == 2
                    and _SCORER.threat_score(d["text"]) > 0.5)
        fe = FusionEngine(_SCORER, FusionWeights(0.2, 0.8, 0.0), theta_det=0.3)
        v = fe.evaluate_window(dpit["text"], s_total=0.0, reputation=0.85)
        self.assertEqual(v["verdict"], 1)

    def test_tune_weights_returns_valid(self):
        va = _DATA[2240:2400]
        def st(d): return 0.0 if d["label"] in (0, 2, 3) else 1.0
        def rp(d): return 0.85 if d["label"] == 0 else 0.6
        w, th, mcc = tune_weights(
            _SCORER, [d["text"] for d in va], [st(d) for d in va],
            [rp(d) for d in va], [0 if d["label"] == 0 else 1 for d in va])
        self.assertAlmostEqual(w.mu1 + w.mu2 + w.mu3, 1.0, places=2)
        self.assertGreater(mcc, 0.5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
