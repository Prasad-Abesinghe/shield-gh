// ============================================================
// IMPLEMENTS: ALGORITHM 4 — PQC-Mit
//             Post-Quantum Cryptographic Mitigation Pipeline
// FIGURE 3.14: Cryptographic Mitigation Flowchart
// ============================================================
#include "pqc_mit.h"
#include <sstream>

PQCMitigation::PQCMitigation(DEBSC* debsc,
                               PQCLogicalKeyHierarchy* lkh,
                               uint32_t required_k,
                               double   theta_R)
    : m_debsc(debsc),
      m_lkh(lkh),
      m_required_k(required_k),
      m_theta_R(theta_R) {}

void PQCMitigation::AddRSU(const RSUKeyStore& rsu) {
    m_rsus.push_back(rsu);
}

std::string PQCMitigation::BuildFlowModMessage(uint32_t node_id, double t) {
    // FlowMod command: "BLOCK:node_id:timestamp"
    // M = isolation command signed by controller (Eq. 3.27)
    std::ostringstream oss;
    oss << "FLOWMOD:BLOCK:NODE=" << node_id << ":T=" << t;
    return oss.str();
}

bool PQCMitigation::IsIsolated(uint32_t node_id) const {
    return m_isolated.count(node_id) > 0;
}

// ── Algorithm 4, Steps 2–3 ───────────────────────────────────────────────────
// Eq. 3.31: σj = TS.PartialSign(skj, B(vi))
// Eq. 3.32: σ* = TS.Combine({σj}^k_{j=1})
AggregateSignature PQCMitigation::CollectThresholdSignatures(
    const std::string& flowmod_msg) const {

    std::vector<ThresholdPartialSig> partials;
    uint32_t k = std::min(m_required_k,
                          static_cast<uint32_t>(m_rsus.size()));

    for (uint32_t i = 0; i < k; i++) {
        // Eq. 3.31: each RSU signs with its Dilithium secret key
        ThresholdPartialSig sig = ThresholdSig::PartialSign(
            m_rsus[i].rsu_id,
            flowmod_msg,
            m_rsus[i].dil_key.sk.data()
        );
        partials.push_back(sig);
        std::cout << "[PQC-Mit] RSU " << m_rsus[i].rsu_id
                  << " partial signature added" << std::endl;
    }

    // Eq. 3.32: combine k partial signatures
    return ThresholdSig::Combine(partials);
}

// ── Algorithm 4, Step 4 ──────────────────────────────────────────────────────
// Eq. 3.33: b = TS.Verify(pkgroup, B(vi), σ*)
// b = 1 → OpenFlow switch installs block rule
bool PQCMitigation::VerifyAndInstallBlockRule(
    const std::string& flowmod_msg,
    const AggregateSignature& agg) const {

    // Collect RSU public keys for verification
    std::vector<uint8_t*> rsu_pubkeys;
    for (auto& rsu : m_rsus) {
        rsu_pubkeys.push_back(
            const_cast<uint8_t*>(rsu.dil_key.pk.data())
        );
    }

    // Eq. 3.33: threshold verification
    bool verified = ThresholdSig::Verify(agg, flowmod_msg,
                                          m_required_k, rsu_pubkeys);

    if (verified) {
        std::cout << "[PQC-Mit] FlowMod VERIFIED by " << agg.k_signers
                  << " RSUs — BLOCK RULE INSTALLED" << std::endl;
    } else {
        std::cout << "[PQC-Mit] FlowMod verification FAILED — rule rejected" << std::endl;
    }
    return verified;
}

// ── Algorithm 4, Step 5 ──────────────────────────────────────────────────────
// Eq. 3.36: rekey path(ℓi → root) — O(log N) Kyber operations
// Isolated vehicle cannot derive new Kgrp (Eq. 3.26)
void PQCMitigation::RekeyGroup(uint32_t isolated_node_id) {
    std::cout << "[PQC-Mit] Rekeying group — excluding node " << isolated_node_id
              << " | Cost: O(log N) = " << m_lkh->GetRekeyingCost()
              << " Kyber.Enc operations" << std::endl;

    // Eq. 3.36: refresh keys along path from leaf to root
    std::vector<KyberCiphertext> new_keys = m_lkh->IsolateAndRekey(isolated_node_id);

    // Eq. 3.35: re-encapsulate group session key at root
    auto [new_kgrp, c_root] = m_lkh->EncapsulateGroupKey();

    std::cout << "[PQC-Mit] New group key Kgrp encapsulated — "
              << new_keys.size() << " path updates broadcast" << std::endl;
    // Isolated vehicle has no sk for any refreshed node on its path
    // → it cannot call Kyber.Dec(sk, c) to recover Kgrp (Eq. 3.26)
}

// ── Algorithm 4 — Main Entry Point ───────────────────────────────────────────
bool PQCMitigation::Trigger(uint32_t node_id, double t) {
    // Guard: already isolated
    if (IsIsolated(node_id)) {
        std::cout << "[PQC-Mit] Node " << node_id << " already isolated" << std::endl;
        return true;
    }

    // Step 1: DEBSC dual-evidence gate (Eq. 3.19)
    // Caller (DEBSC) already confirmed ISOLATE decision before calling Trigger
    std::cout << "[PQC-Mit] Algorithm 4 triggered for node " << node_id
              << " at t=" << t << std::endl;

    if (m_rsus.empty()) {
        std::cout << "[PQC-Mit] WARNING: No RSU keys registered — using demo mode" << std::endl;
        m_isolated.insert(node_id);
        return true;
    }

    // Step 2: build FlowMod isolation command
    std::string flowmod_msg = BuildFlowModMessage(node_id, t);
    std::cout << "[PQC-Mit] FlowMod: " << flowmod_msg << std::endl;

    // Steps 2–3: collect k-of-n Dilithium partial signatures (Eq. 3.31–3.32)
    AggregateSignature agg = CollectThresholdSignatures(flowmod_msg);

    // Step 4: verify and install block rule (Eq. 3.33 + Eq. 3.28)
    bool rule_installed = VerifyAndInstallBlockRule(flowmod_msg, agg);

    if (!rule_installed) {
        std::cout << "[PQC-Mit] ABORT: signature threshold not met" << std::endl;
        return false;
    }

    // Mark node as isolated
    m_isolated.insert(node_id);
    std::cout << "[PQC-Mit] Node " << node_id << " ISOLATED at t=" << t << std::endl;

    // Step 5: O(log N) group re-keying (Eq. 3.36)
    RekeyGroup(node_id);

    return true;
}
