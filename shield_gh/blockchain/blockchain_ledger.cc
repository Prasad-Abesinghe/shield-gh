#include "blockchain_ledger.h"
#include <numeric>
#include <algorithm>
#include <sstream>
#include <iomanip>

// Append-only commit operations

void BlockchainLedger::CommitForwardingRecord(const ForwardingRecord& rec) {
    m_forwarding_log.push_back(rec);
}

void BlockchainLedger::CommitFlowRule(const FlowRuleRecord& rule) {
    m_flow_rule_log.push_back(rule);
}

void BlockchainLedger::CommitGradientHash(const GradientRecord& grad) {
    m_gradient_log.push_back(grad);
}

// ── Eq. 3.1 ─────────────────────────────────────────────────────────────────
// PDRi(t, W) = [Σ_{τ=t-W}^{t} nᵢᶠʷᵈ(τ)] / [Σ_{τ=t-W}^{t} nᵢʳˣ(τ)]
double BlockchainLedger::ComputePDR(uint32_t node_id, double t, uint32_t W) const {
    uint32_t total_fwd = 0, total_rx = 0;
    for (const auto& rec : m_forwarding_log) {
        if (rec.node_id == node_id && rec.timestamp >= (t - W) && rec.timestamp <= t) {
            total_fwd += rec.n_fwd;
            total_rx  += rec.n_rx;
        }
    }
    return (total_rx > 0) ? (double)total_fwd / total_rx : 1.0;
}

// ── Eq. 3.2 ─────────────────────────────────────────────────────────────────
// δi(t) = 1 − PDRi(t, 1)
double BlockchainLedger::ComputeDropRate(uint32_t node_id, double t) const {
    return 1.0 - ComputePDR(node_id, t, 1);
}

// ── Eq. 3.3 ─────────────────────────────────────────────────────────────────
// σ²i(W) = (1/W) Σ (PDRi(τ,1) − PDRi(W))²
double BlockchainLedger::ComputePDRVariance(uint32_t node_id,
                                            double t, uint32_t W) const {
    double mean_pdr = ComputePDR(node_id, t, W);
    double variance = 0.0;
    uint32_t count = 0;
    for (const auto& rec : m_forwarding_log) {
        if (rec.node_id == node_id && rec.timestamp >= (t-W) && rec.timestamp <= t) {
            double slot_pdr = (rec.n_rx > 0) ? (double)rec.n_fwd / rec.n_rx : 1.0;
            variance += (slot_pdr - mean_pdr) * (slot_pdr - mean_pdr);
            count++;
        }
    }
    return (count > 0) ? variance / count : 0.0;
}

// ── Eq. 3.16 ────────────────────────────────────────────────────────────────
// Ti(t) = (α + nᵢᶠʷᵈ) / (α + nᵢᶠʷᵈ + β + nᵢᵈʳᵒᵖ)
double BlockchainLedger::ComputeTrustScore(uint32_t node_id, double t,
                                           double alpha, double beta) const {
    uint32_t n_fwd = 0, n_rx = 0;
    for (const auto& rec : m_forwarding_log) {
        if (rec.node_id == node_id && rec.timestamp <= t) {
            n_fwd += rec.n_fwd;
            n_rx  += rec.n_rx;
        }
    }
    uint32_t n_drop = (n_rx > n_fwd) ? (n_rx - n_fwd) : 0;
    return (alpha + n_fwd) / (alpha + n_fwd + beta + n_drop + 1e-9);
}

// ── Eq. 3.18 ────────────────────────────────────────────────────────────────
// Ri(t) = (1/|Hi|) Σ_{h∈Hi} T_mob_i(h)
// NOTE: T_mob values are committed to ledger after MATD correction (Eq. 3.17)
double BlockchainLedger::ComputeReputation(uint32_t node_id, double t) const {
    // In practice, the MATD-corrected trust values are stored in the ledger
    // Here we compute from raw records; MATD correction applied by caller
    std::vector<double> trust_values;
    for (const auto& rec : m_forwarding_log) {
        if (rec.node_id == node_id && rec.timestamp <= t) {
            uint32_t n_drop = (rec.n_rx > rec.n_fwd) ? (rec.n_rx - rec.n_fwd) : 0;
            double trust = (1.0 + rec.n_fwd) / (1.0 + rec.n_fwd + 1.0 + n_drop + 1e-9);
            trust_values.push_back(trust);
        }
    }
    if (trust_values.empty()) return 1.0;
    double sum = 0;
    for (double v : trust_values) sum += v;
    return sum / trust_values.size();
}

// ── Eq. 3.14 & 3.22 ─────────────────────────────────────────────────────────
// Validi = 1[ Hash(Δwi||t||idi) == C_BC_i ]
bool BlockchainLedger::VerifyGradientHash(uint32_t node_id, uint32_t round,
                                          const std::string& received_hash) const {
    for (const auto& g : m_gradient_log) {
        if (g.node_id == node_id && g.round == round) {
            return (g.gradient_hash == received_hash);
        }
    }
    return false;  // No pre-committed hash found — reject
}

bool BlockchainLedger::AcceptGradient(uint32_t node_id, uint32_t round,
                                      const std::string& computed_hash) const {
    return VerifyGradientHash(node_id, round, computed_hash);
}

// Retrieve all forwarding records for a node
std::vector<ForwardingRecord> BlockchainLedger::GetHistory(uint32_t node_id) const {
    std::vector<ForwardingRecord> history;
    for (const auto& rec : m_forwarding_log) {
        if (rec.node_id == node_id) {
            history.push_back(rec);
        }
    }
    return history;
}

// Retrieve flow rule records for a controller within time window W
std::vector<FlowRuleRecord> BlockchainLedger::GetFlowHistory(uint32_t ctrl_id,
                                                              double t,
                                                              uint32_t W) const {
    std::vector<FlowRuleRecord> history;
    for (const auto& rule : m_flow_rule_log) {
        if (rule.controller_id == ctrl_id &&
            rule.timestamp >= (t - W) && rule.timestamp <= t) {
            history.push_back(rule);
        }
    }
    return history;
}

// SHA-256 helper using OpenSSL
std::string BlockchainLedger::SHA256Hash(const std::string& data) const {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()),
           data.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}
