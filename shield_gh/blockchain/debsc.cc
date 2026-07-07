#include "debsc.h"

DEBSC::DEBSC(BlockchainLedger* ledger,
             double theta_R,
             double lambda1,
             double lambda2)
    : m_ledger(ledger),
      m_zkp_store(nullptr),
      m_theta_R(theta_R),
      m_lambda1(static_cast<uint32_t>(lambda1)),
      m_lambda2(static_cast<uint32_t>(lambda2)) {}

// Register ZKP result from the ZKP module into the local cache
void DEBSC::RecordZKPResult(uint32_t node_id, double t, bool proof_valid) {
    m_zkp_cache[node_id] = {t, proof_valid};
}

// ── Eq. 3.19 ─────────────────────────────────────────────────────────────────
// Statistical gate: (1 − Ri(t)) > θR
// Cryptographic gate: Π_ZKP(vi, t) == FAIL
// BOTH must be true to trigger isolation
bool DEBSC::ShouldIsolate(uint32_t node_id, double t) const {
    double Ri = m_ledger->ComputeReputation(node_id, t);
    bool statistical_gate = ((1.0 - Ri) > m_theta_R);

    // ZKP gate: check if the node failed ZKP proof verification
    bool zkp_failed = false;
    if (m_zkp_cache.count(node_id)) {
        zkp_failed = !m_zkp_cache.at(node_id).second;
    }

    // Dual-evidence: both gates must fire
    return statistical_gate && zkp_failed;
}

// ── Eq. 3.13 ─────────────────────────────────────────────────────────────────
// Λi(t) = Σ_{τ=t−Ws}^{t} 1[(1 − Ri(τ)) > θR]
uint32_t DEBSC::ComputeSuspicionLevel(uint32_t node_id, double t,
                                       uint32_t Ws) const {
    uint32_t count = 0;
    for (uint32_t tau = 0; tau <= Ws; tau++) {
        double Ri = m_ledger->ComputeReputation(node_id, t - tau);
        if ((1.0 - Ri) > m_theta_R) count++;
    }
    return count;
}

// Graduated response (Section 3.6.2)
IsolationDecision DEBSC::GetGraduatedResponse(uint32_t node_id, double t) const {
    uint32_t lambda = ComputeSuspicionLevel(node_id, t);

    if (lambda < m_lambda1) {
        return IsolationDecision::MONITOR;          // Case 0
    } else if (lambda < m_lambda2) {
        return IsolationDecision::RATE_LIMIT;       // Case 1 (rate-limit)
    } else {
        if (ShouldIsolate(node_id, t)) {
            return IsolationDecision::ISOLATE;      // Case 3 (full isolation)
        }
        return IsolationDecision::REQUIRE_ZKP;     // Case 2 (require ZKP)
    }
}
