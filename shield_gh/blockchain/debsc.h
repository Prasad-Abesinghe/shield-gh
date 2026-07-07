// ============================================================
// IMPLEMENTS: Eq. 3.12 / Eq. 3.19 (DEBSC isolation gate)
//             Eq. 3.13 (Suspicion level Λi)
// FIGURE 3.14: Cryptographic Mitigation Flowchart
// ============================================================
#pragma once
#include "blockchain_ledger.h"
#include "zkp_proofs.h"
#include <map>
#include <utility>

enum class IsolationDecision { ISOLATE, RATE_LIMIT, REQUIRE_ZKP, MONITOR };

class DEBSC {
public:
    explicit DEBSC(BlockchainLedger* ledger,
                   double theta_R = 0.4,   // reputation isolation threshold
                   double lambda1 = 2,     // rate-limit threshold
                   double lambda2 = 5);    // full isolation threshold

    // ── Eq. 3.19 ────────────────────────────────────────────────────────
    // Isolate(vi) = 1[(1 − Ri(t)) > θR  AND  Π_ZKP(vi, t) == FAIL]
    bool ShouldIsolate(uint32_t node_id, double t) const;

    // ── Eq. 3.13 ────────────────────────────────────────────────────────
    // Λi(t) = Σ_{τ=t−Ws}^{t} 1[(1 − Ri(τ)) > θR]
    uint32_t ComputeSuspicionLevel(uint32_t node_id, double t,
                                   uint32_t Ws = 10) const;

    // Graduated response (Section 3.6.2)
    IsolationDecision GetGraduatedResponse(uint32_t node_id, double t) const;

    // Register ZKP proof verification result from ZKP module
    void RecordZKPResult(uint32_t node_id, double t, bool proof_valid);

private:
    BlockchainLedger* m_ledger;
    ZKPProofStore*    m_zkp_store;
    double            m_theta_R;
    uint32_t          m_lambda1, m_lambda2;

    // ZKP result cache: node_id → (timestamp, valid)
    std::map<uint32_t, std::pair<double, bool>> m_zkp_cache;
};
