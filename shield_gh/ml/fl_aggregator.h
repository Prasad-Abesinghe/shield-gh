// ============================================================
// IMPLEMENTS: NS-3 side FL interface
//             Eq. 3.21 — FedAvg global model (C++ representation)
//             Eq. 3.22 — Accept(Δwi) gradient integrity check
// SECTION 3.6.6: Federated Learning with Blockchain-Verified Gradient Integrity
// This header provides the NS-3 simulation-side FL stub.
// Actual training runs in federated_learning.py (PyTorch).
// The C++ side stores gradient hashes and provides inference scores.
// ============================================================
#pragma once
#include <cstdint>
#include <string>
#include <map>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

// Per-node FL model performance record (from Python training side)
struct FLInferenceRecord {
    uint32_t node_id;
    double   malicious_probability;  // Qi from FL model (Eq. 3.23 proxy)
    uint32_t round;
    bool     gradient_accepted;      // Eq. 3.22 result
};

class FLAggregatorStub {
public:
    // Pre-commit gradient hash to blockchain (Eq. 3.14 + 3.22)
    // Vehicle calls this BEFORE transmitting gradient to aggregator
    void CommitGradientHash(uint32_t node_id, uint32_t round,
                             const std::string& hash) {
        m_committed_hashes[node_id][round] = hash;
    }

    // ── Eq. 3.22: Accept(Δwi) = 1[ H_BC(Δwi) == Hash(Δwi) ] ──────────
    bool AcceptGradient(uint32_t node_id, uint32_t round,
                        const std::string& received_hash) const {
        auto it = m_committed_hashes.find(node_id);
        if (it == m_committed_hashes.end()) return false;
        auto jt = it->second.find(round);
        if (jt == it->second.end()) return false;
        return (jt->second == received_hash);
    }

    // Store FL inference result from Python side (written to shared CSV)
    void RecordFLInference(const FLInferenceRecord& rec) {
        m_fl_scores[rec.node_id] = rec;
    }

    // Retrieve latest FL-based malicious probability for a node
    double GetFLThreatScore(uint32_t node_id) const {
        auto it = m_fl_scores.find(node_id);
        return (it != m_fl_scores.end()) ? it->second.malicious_probability : 0.0;
    }

    // Compute SHA-256 hash of a gradient representation (Eq. 3.14)
    static std::string ComputeHash(const std::string& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(data.c_str()),
               data.size(), hash);
        std::ostringstream oss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        return oss.str();
    }

private:
    std::map<uint32_t, std::map<uint32_t, std::string>> m_committed_hashes;
    std::map<uint32_t, FLInferenceRecord> m_fl_scores;
};
