// ============================================================
// IMPLEMENTS: Eq. 3.6  — S_DP-FR (Signature S1: fixed-rate data-plane)
//             Eq. 3.7  — S_DP-IT (Signature S2: intermittent data-plane)
//             Eq. 3.8  — S_DP-TS (Signature S3: target-specific data-plane)
//             Eq. 3.9  — S_CP-FR (Signature S4: fixed-rate controller-plane)
//             Eq. 3.10 — S_CP-IT (Signature S5: intermittent controller-plane)
//             Eq. 3.11 — S_CP-TS (Signature S6: target-specific controller-plane)
// ALGORITHM 1 & 2: LW-DP-Det and LW-CP-Det
// ============================================================
#pragma once
#include <cstdint>
#include <vector>
#include <map>
#include <string>

struct FlowRule {
    uint32_t    rule_id;
    std::string action;      // "drop" or "forward"
    double      drop_prob;   // p_drop(f) for Eq. 3.9
    bool        is_wildcard; // match(f) == WILDCARD for Eq. 3.11
    uint32_t    match_src;   // non-wildcard source for Eq. 3.11
};

class AttackSignatureEngine {
public:
    // ── Eq. 3.6: S_DP-FR ──────────────────────────────────────────────────
    // S_DP-FR(vi) = 1[ PDR̂i(t,W) < τf  AND  σ²i(W) < εf ]
    // epsilon_f tolerates per-window sampling noise: a fixed-rate attacker has
    // consistently LOW PDR; random per-packet dropping still keeps variance
    // moderate (~0.15), so we set epsilon_f=0.20 to fire S1 on steady low PDR.
    static bool S1_FixedRate(uint32_t node_id, double t,
                              double corrected_pdr, double variance,
                              double tau_f = 0.6, double epsilon_f = 0.20);

    // ── Eq. 3.7: S_DP-IT ──────────────────────────────────────────────────
    // S_DP-IT(vi) = 1[ ∃T* ∈ [Tmin, Tmax] : Rm_i(T*) > γit ]
    // gamma_it is a NORMALISED autocorrelation threshold (baseline≈1.0;
    // a true periodic drop pattern exceeds it). T_min=1 so a 1-slot period
    // (the common on/off cadence) is detectable in short windows.
    static bool S2_Intermittent(const std::vector<double>& pdr_history,
                                 double tau_it = 0.7, double gamma_it = 1.3,
                                 uint32_t T_min = 1, uint32_t T_max = 10);

    // ── Eq. 3.8: S_DP-TS ──────────────────────────────────────────────────
    // S_DP-TS(vi) = 1[ D_KL(P^(s)_PDRi || U) > τts ]
    static bool S3_TargetSpecific(const std::map<uint32_t, double>& per_source_pdr,
                                   double tau_ts = 0.5);

    // ── Eq. 3.9: S_CP-FR ──────────────────────────────────────────────────
    // S_CP-FR(c) = 1[ ∃f ∈ Fc(t) : action(f) == drop  AND  p_drop(f) > τc ]
    static bool S4_CPFixedRate(const std::vector<FlowRule>& flow_rules,
                                double tau_c = 0.5);

    // ── Eq. 3.10: S_CP-IT ─────────────────────────────────────────────────
    // S_CP-IT(c) = 1[ R_Fmal_c(T*) > γc  AND  Fmal_c(W) > 0 ]
    static bool S5_CPIntermittent(const std::vector<uint32_t>& malicious_rule_counts,
                                   double gamma_c = 0.3);

    // ── Eq. 3.11: S_CP-TS ─────────────────────────────────────────────────
    // S_CP-TS(c) = 1[ ∃f ∈ Fc(t) : action(f) == drop  AND  match(f) ≠ WILDCARD ]
    static bool S6_CPTargetSpecific(const std::vector<FlowRule>& flow_rules);
};
