// ============================================================
// IMPLEMENTS: Eq. 3.4  — ρ_ho(vi, t) = si(t) * Δt_ho / R_RSU * ρ_max
//             Eq. 3.5  — PDR̂i(t, W) = PDRi(t, W) + ρ_ho(vi, t)
//             Eq. 3.17 — T_mob_i(t) = Ti(t) * exp(−λs * si(t) * Δt)
// SECTION 3.4.1, 3.4.2: RSU handoff attack enabler & trust volatility
// ============================================================
#pragma once

class MobilityAwareTrustDecay {
public:
    MobilityAwareTrustDecay(double rsu_radius   = 500.0,  // RRSU in meters
                             double delta_t_ho   = 0.5,   // avg handoff duration (s)
                             double rho_max      = 0.3,   // worst-case handoff loss rate
                             double lambda_s     = 0.01,  // mobility decay coefficient
                             double delta_t      = 1.0);  // observation slot duration

    // ── Eq. 3.4 ───────────────────────────────────────────────────────────
    // ρ_ho(vi, t) = si(t) * Δt_ho / RRSU * ρ_max
    double ComputeHandoffLoss(double speed_mps) const;

    // ── Eq. 3.5 ───────────────────────────────────────────────────────────
    // PDR̂i(t, W) = PDRi(t, W) + ρ_ho(vi, t)
    double CorrectPDR(double observed_pdr, double speed_mps) const;

    // ── Eq. 3.17 ──────────────────────────────────────────────────────────
    // T_mob_i(t) = Ti(t) * exp(−λs * si(t) * Δt)
    double ApplyMobilityDecay(double trust_score, double speed_mps) const;

private:
    double m_R_RSU;
    double m_delta_t_ho;
    double m_rho_max;
    double m_lambda_s;
    double m_delta_t;
};
