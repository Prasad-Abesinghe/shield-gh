// ============================================================
// IMPLEMENTS: Eq. 3.1 (PDRi), Eq. 3.16 (Ti), Eq. 3.18 (Ri),
//             Eq. 3.14 (gradient hash), Eq. 3.22 (Accept)
// FIGURE 3.10: Blockchain Trust Layer (RSU-maintained)
// ============================================================
#pragma once
#include <map>
#include <vector>
#include <string>
#include <cmath>
#include <openssl/sha.h>  // SHA-256 for hash commitments

// Per-slot forwarding record committed to the ledger
struct ForwardingRecord {
    uint32_t node_id;
    double   timestamp;
    uint32_t n_rx;      // packets received (nᵢʳˣ)
    uint32_t n_fwd;     // packets forwarded (nᵢᶠʷᵈ)
    std::string zkp_proof;    // π_i (Eq. 3.30)
    std::string commitment;   // C_i (Eq. 3.29)
};

// FL gradient update record
struct GradientRecord {
    uint32_t node_id;
    uint32_t round;
    std::string gradient_hash;  // H_BC(Δwᵢ) pre-submitted commitment
};

// Flow rule record (for CP signatures S4–S6)
struct FlowRuleRecord {
    uint32_t controller_id;
    double   timestamp;
    std::string action;      // "drop" or "forward"
    double   drop_prob;      // p_drop(f) for Eq. 3.9
    bool     is_wildcard;    // match(f) == WILDCARD for Eq. 3.11
    uint32_t match_src;      // non-wildcard source for Eq. 3.11
};

class BlockchainLedger {
public:
    // Append-only ledger — RSU consensus only
    void CommitForwardingRecord(const ForwardingRecord& rec);
    void CommitFlowRule(const FlowRuleRecord& rule);
    void CommitGradientHash(const GradientRecord& grad);

    // ── Eq. 3.1: PDRi(t, W) = Σ n_fwd / Σ n_rx over window W ──────
    double ComputePDR(uint32_t node_id, double t, uint32_t W) const;

    // ── Eq. 3.2: δi(t) = 1 − PDRi(t, 1) ───────────────────────────
    double ComputeDropRate(uint32_t node_id, double t) const;

    // ── Eq. 3.3: σ²i(W) = (1/W) Σ (PDRi(τ,1) − mean)² ────────────
    double ComputePDRVariance(uint32_t node_id, double t, uint32_t W) const;

    // ── Eq. 3.16: Ti(t) = (α + n_fwd) / (α + n_fwd + β + n_drop) ──
    double ComputeTrustScore(uint32_t node_id, double t,
                             double alpha = 1.0, double beta = 1.0) const;

    // ── Eq. 3.18: Ri(t) = (1/|Hi|) Σ T_mob_i(h) over Hi ───────────
    double ComputeReputation(uint32_t node_id, double t) const;

    // ── Eq. 3.14: Validi = 1[ Hash(Δwi||t||idi) == C_BC_i ] ────────
    bool VerifyGradientHash(uint32_t node_id, uint32_t round,
                            const std::string& received_gradient_hash) const;

    // ── Eq. 3.22: Accept(Δwi) = 1[ H_BC(Δwi) == Hash(Δwi) ] ───────
    bool AcceptGradient(uint32_t node_id, uint32_t round,
                        const std::string& computed_hash) const;

    // Get historical records for a node
    std::vector<ForwardingRecord> GetHistory(uint32_t node_id) const;
    std::vector<FlowRuleRecord>   GetFlowHistory(uint32_t ctrl_id,
                                                  double t, uint32_t W) const;

private:
    // Append-only storage (simulate immutable ledger)
    std::vector<ForwardingRecord> m_forwarding_log;
    std::vector<FlowRuleRecord>   m_flow_rule_log;
    std::vector<GradientRecord>   m_gradient_log;

    // SHA-256 helper
    std::string SHA256Hash(const std::string& data) const;
};
