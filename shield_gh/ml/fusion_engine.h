// ============================================================
// IMPLEMENTS: Eq. 3.24 — ŷi(t) = 1[μ1*Stotal + μ2*Qi + μ3*(1-Ri) > θdet]
// SECTION 3.6.7: LLM-Based Semantic Threat Scoring and Fusion
// Fuses three evidence sources:
//   Stotal: rule-based aggregate signature score (max of S1–S6)
//   Qi(t):  LLM semantic threat score (Eq. 3.23)
//   1-Ri:  blockchain reputation deficit (Eq. 3.18)
// ============================================================
#pragma once
#include <utility>
#include <cstdint>

class FusionEngine {
public:
    explicit FusionEngine(double mu1     = 0.40,  // signature weight
                          double mu2     = 0.35,  // LLM weight
                          double mu3     = 0.25,  // reputation deficit weight
                          double theta_det = 0.50) // detection threshold
        : m_mu1(mu1), m_mu2(mu2), m_mu3(mu3), m_theta(theta_det) {}

    // ── Eq. 3.24 ──────────────────────────────────────────────────────────
    // ŷi(t) = 1[μ1*Stotal + μ2*Qi + μ3*(1-Ri) > θdet]
    // Returns {decision: true=malicious, fused_score}
    std::pair<bool, double> Fuse(double S_total,  // ∈ [0,1] — sig engine score
                                  double Q_i,      // ∈ [0,1] — LLM threat score
                                  double R_i) const // ∈ [0,1] — blockchain reputation
    {
        // Eq. 3.24 weighted combination
        double score = m_mu1 * S_total + m_mu2 * Q_i + m_mu3 * (1.0 - R_i);
        bool decision = (score > m_theta);
        return {decision, score};
    }

    // Lightweight version: no LLM score (lightweight mode only uses S_total + reputation)
    std::pair<bool, double> FuseLightweight(double S_total, double R_i) const {
        double score = 0.60 * S_total + 0.40 * (1.0 - R_i);
        return {score > m_theta, score};
    }

    double GetThreshold() const { return m_theta; }
    void   SetThreshold(double t) { m_theta = t; }

private:
    double m_mu1, m_mu2, m_mu3, m_theta;
};
