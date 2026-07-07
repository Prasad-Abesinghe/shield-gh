// ============================================================
// IMPLEMENTS: Eq. 3.6  — S_DP-FR (Signature S1: fixed-rate data-plane)
//             Eq. 3.7  — S_DP-IT (Signature S2: intermittent data-plane)
//             Eq. 3.8  — S_DP-TS (Signature S3: target-specific data-plane)
//             Eq. 3.9  — S_CP-FR (Signature S4: fixed-rate controller-plane)
//             Eq. 3.10 — S_CP-IT (Signature S5: intermittent controller-plane)
//             Eq. 3.11 — S_CP-TS (Signature S6: target-specific controller-plane)
// ALGORITHM 1 & 2: LW-DP-Det and LW-CP-Det
// ============================================================
#include "attack_signatures.h"
#include <cmath>
#include <algorithm>
#include <iostream>

// ── Eq. 3.6 ──────────────────────────────────────────────────────────────────
// S_DP-FR(vi) = 1[ PDR̂i(t,W) < τf  AND  σ²i(W) < εf ]
bool AttackSignatureEngine::S1_FixedRate(uint32_t node_id, double t,
                                          double corrected_pdr, double variance,
                                          double tau_f, double epsilon_f) {
    (void)node_id; (void)t;
    // From Algorithm 1, lines 5–6: fixed-rate test
    return (corrected_pdr < tau_f) && (variance < epsilon_f);
}

// ── Eq. 3.7 ──────────────────────────────────────────────────────────────────
// S_DP-IT(vi) = 1[ ∃T* ∈ [Tmin, Tmax] : Rm_i(T*) > γit ]
bool AttackSignatureEngine::S2_Intermittent(const std::vector<double>& pdr_history,
                                             double tau_it, double gamma_it,
                                             uint32_t T_min, uint32_t T_max) {
    // Binary malicious indicator: mi(τ) = 1[PDRi(τ,1) < τit]   (Eq. 3.7)
    std::vector<int> m;
    for (double pdr : pdr_history) m.push_back(pdr < tau_it ? 1 : 0);

    uint32_t W = m.size();
    if (W < T_min + 1) return false;

    uint32_t n_mal = 0;
    for (int v : m) n_mal += v;
    if (n_mal < 2) return false;   // not enough drops to be "intermittent"

    // ── Intermittency requires BOTH drop windows AND recovery windows ─────────
    // DP-IT is on/off: it drops in some windows and forwards normally in others.
    // A FIXED-RATE attacker (DP-FR) drops in EVERY window (all 1s) — that is
    // S1's job, not S2's. So S2 must NOT fire when there are no recovery (0)
    // windows. This cleanly separates S2 (intermittent) from S1 (fixed-rate).
    uint32_t n_benign = W - n_mal;
    if (n_benign == 0) return false;   // continuous dropping -> not intermittent (DP-FR)

    // ── Recurring-drop (on/off) detection ────────────────────────────────────
    // Count "drop episodes" = rising edges (0→1). A genuine on/off attacker has
    // ≥2 separate drop episodes (drop, recover, drop again).
    uint32_t episodes = 0;
    for (uint32_t i = 0; i < W; i++) {
        bool rising = (m[i] == 1) && (i == 0 || m[i - 1] == 0);
        if (rising) episodes++;
    }
    if (episodes >= 2) return true;   // recurring on/off dropping → DP-IT

    // ── Fallback: classic autocorrelation (Eq. 3.7) for clean periodic cases ─
    double mean_activity = (double)n_mal / W;
    if (mean_activity > 0.0) {
        for (uint32_t T = T_min; T <= T_max && T < W; T++) {
            double sum = 0.0; uint32_t terms = 0;
            for (uint32_t tau = T; tau < W; tau++) { sum += (double)(m[tau]*m[tau-T]); terms++; }
            if (terms == 0) continue;
            double autocorr = (sum / terms) / mean_activity;
            if (autocorr > gamma_it) return true;
        }
    }
    return false;
}

// ── Eq. 3.8 ──────────────────────────────────────────────────────────────────
// S_DP-TS(vi) = 1[ D_KL(P^(s)_PDRi || U) > τts ]
bool AttackSignatureEngine::S3_TargetSpecific(
    const std::map<uint32_t, double>& per_source_pdr,
    double tau_ts) {
    if (per_source_pdr.empty()) return false;

    // Uniform reference distribution U
    double uniform = 1.0 / per_source_pdr.size();

    // KL divergence D_KL(P || U) = Σ P(s) * log(P(s) / U)
    double kl_div = 0.0;
    for (const auto& [src, pdr] : per_source_pdr) {
        if (pdr > 0.0) {
            kl_div += pdr * std::log(pdr / uniform + 1e-9);
        }
    }
    return kl_div > tau_ts;
}

// ── Eq. 3.9 ──────────────────────────────────────────────────────────────────
// S_CP-FR(c) = 1[ ∃f ∈ Fc(t) : action(f) == drop  AND  p_drop(f) > τc ]
bool AttackSignatureEngine::S4_CPFixedRate(
    const std::vector<FlowRule>& flow_rules, double tau_c) {
    // Algorithm 2, lines 3–5
    for (const auto& rule : flow_rules) {
        if (rule.action == "drop" && rule.drop_prob > tau_c) {
            return true;
        }
    }
    return false;
}

// ── Eq. 3.10 ─────────────────────────────────────────────────────────────────
// S_CP-IT(c) = 1[ R_Fmal_c(T*) > γc  AND  Fmal_c(W) > 0 ]
bool AttackSignatureEngine::S5_CPIntermittent(
    const std::vector<uint32_t>& malicious_rule_counts,
    double gamma_c) {
    // Algorithm 2, lines 11–14
    uint32_t W = malicious_rule_counts.size();
    bool any_malicious = false;
    for (auto c : malicious_rule_counts) if (c > 0) { any_malicious = true; break; }
    if (!any_malicious) return false;

    // Autocorrelation of malicious flow-rule count time series
    for (uint32_t T = 1; T < W; T++) {
        double autocorr = 0.0;
        for (uint32_t tau = T; tau < W; tau++) {
            autocorr += malicious_rule_counts[tau] * malicious_rule_counts[tau - T];
        }
        autocorr /= W;
        if (autocorr > gamma_c) return true;
    }
    return false;
}

// ── Eq. 3.11 ─────────────────────────────────────────────────────────────────
// S_CP-TS(c) = 1[ ∃f ∈ Fc(t) : action(f) == drop  AND  match(f) ≠ WILDCARD ]
bool AttackSignatureEngine::S6_CPTargetSpecific(
    const std::vector<FlowRule>& flow_rules) {
    // Algorithm 2, lines 7–9
    for (const auto& rule : flow_rules) {
        if (rule.action == "drop" && !rule.is_wildcard) {
            return true;  // drop conditioned on specific source/priority
        }
    }
    return false;
}
