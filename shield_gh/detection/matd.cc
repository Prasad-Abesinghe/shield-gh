#include "matd.h"
#include <cmath>

MobilityAwareTrustDecay::MobilityAwareTrustDecay(double rsu_radius,
                                                   double delta_t_ho,
                                                   double rho_max,
                                                   double lambda_s,
                                                   double delta_t)
    : m_R_RSU(rsu_radius),
      m_delta_t_ho(delta_t_ho),
      m_rho_max(rho_max),
      m_lambda_s(lambda_s),
      m_delta_t(delta_t) {}

// ── Eq. 3.4 ──────────────────────────────────────────────────────────────────
// ρ_ho(vi, t) = si(t) · Δt_ho / RRSU · ρ_max
double MobilityAwareTrustDecay::ComputeHandoffLoss(double speed_mps) const {
    return speed_mps * m_delta_t_ho / m_R_RSU * m_rho_max;
}

// ── Eq. 3.5 ──────────────────────────────────────────────────────────────────
// PDR̂i(t, W) = PDRi(t, W) + ρ_ho(vi, t)
// Correction adds expected handoff loss back so signature engine
// evaluates forwarding behaviour NET of topology effects.
double MobilityAwareTrustDecay::CorrectPDR(double observed_pdr,
                                            double speed_mps) const {
    double rho_ho = ComputeHandoffLoss(speed_mps);
    double corrected = observed_pdr + rho_ho;
    return (corrected > 1.0) ? 1.0 : corrected;  // cap at 1.0
}

// ── Eq. 3.17 ─────────────────────────────────────────────────────────────────
// T_mob_i(t) = Ti(t) · exp(−λs · si(t) · Δt)
// Penalises high-speed vehicles with shallow per-RSU observation window.
// A fast-moving attacker's short observations carry lower weight in Ri(t).
double MobilityAwareTrustDecay::ApplyMobilityDecay(double trust_score,
                                                    double speed_mps) const {
    return trust_score * std::exp(-m_lambda_s * speed_mps * m_delta_t);
}
