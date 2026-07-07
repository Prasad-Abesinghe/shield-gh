// ============================================================
// IMPLEMENTS: ALGORITHM 4 — PQC-Mit
//             Post-Quantum Cryptographic Mitigation Pipeline
// Steps:
//   1. DEBSC decides ISOLATE (Eq. 3.19)
//   2. RSU signs FlowMod with Dilithium (Eq. 3.27)
//   3. k RSUs co-sign via threshold (Eq. 3.31–3.33)
//   4. Open Flow switch verifies & installs block rule (Eq. 3.28)
//   5. PQC-LKH refreshes group key (Eq. 3.36) — O(log N)
//   6. Isolated vehicle denied decapsulation (Eq. 3.26)
// FIGURE 3.14: Cryptographic Mitigation Flowchart
// ============================================================
#pragma once
#include "../blockchain/debsc.h"
#include "../crypto/kyber_kem.h"
#include "../crypto/dilithium_sig.h"
#include "../crypto/threshold_sig.h"
#include "../crypto/pqc_lkh.h"
#include <vector>
#include <string>
#include <set>
#include <iostream>

struct RSUKeyStore {
    uint32_t rsu_id;
    DilithiumKeyPair dil_key;
    KyberKeyPair     kyber_key;
};

class PQCMitigation {
public:
    PQCMitigation(DEBSC* debsc,
                  PQCLogicalKeyHierarchy* lkh,
                  uint32_t required_k    = 2,   // k-of-n threshold for isolation
                  double   theta_R       = 0.4); // reputation threshold

    // ── Algorithm 4 entry point ──────────────────────────────────────────
    // Called when DEBSC returns IsolationDecision::ISOLATE
    // Returns true if mitigation was successfully applied
    bool Trigger(uint32_t node_id, double t);

    // Register RSU key stores (called during simulation setup)
    void AddRSU(const RSUKeyStore& rsu);

    // Check if a node is currently isolated
    bool IsIsolated(uint32_t node_id) const;

    // Get isolation FlowMod message for a node
    static std::string BuildFlowModMessage(uint32_t node_id, double t);

    // Get count of isolated nodes (for metrics)
    uint32_t GetIsolatedCount() const { return static_cast<uint32_t>(m_isolated.size()); }

private:
    DEBSC*                        m_debsc;
    PQCLogicalKeyHierarchy*       m_lkh;
    std::vector<RSUKeyStore>      m_rsus;
    std::set<uint32_t>            m_isolated;
    uint32_t                      m_required_k;
    double                        m_theta_R;

    // Step 2–3: collect partial Dilithium signatures from k RSUs, combine
    AggregateSignature CollectThresholdSignatures(const std::string& flowmod_msg) const;

    // Step 4: verify aggregate signature and "install" block rule
    bool VerifyAndInstallBlockRule(const std::string& flowmod_msg,
                                   const AggregateSignature& agg) const;

    // Step 5: rekey the group excluding the isolated node
    void RekeyGroup(uint32_t isolated_node_id);
};
