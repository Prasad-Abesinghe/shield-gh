// ============================================================
// SOA1 — Malik et al. (IEEE Access 2023, vol.11, pp.46691-46706)
// "An Efficient Approach for the Detection and Prevention of
//  Gray-Hole Attacks in VANETs"  (DPGHA)
// DOI 10.1109/ACCESS.2023.3274650
//
// FAITHFUL re-implementation of the paper's RSU-based detection
// (Eq. 13-18), replacing the earlier generic "PDR < avg - alpha"
// detector which did NOT match the paper.
//
// The paper detects two GHA variants from THREE signals computed
// by an RSU in promiscuous mode over its Master Routing Table (MRT):
//
//   PLR  (Eq.13-14)  data Packet Loss Ratio,  fixed threshold δ = 3%
//   RRR  (Eq.15)     Σ RREP_generated / Σ RREQ_received · 100,
//                    fixed threshold λ = 70%
//   μ(DSN)/β (Eq.16-17)  mean Destination Sequence Number of a node's
//                    RREPs vs the DYNAMIC threshold β = mean of all
//                    nodes' μ(DSN). β is the *only* dynamic threshold.
//
// Decision (Eq.18):
//   Smart GHA          if  PLR > δ      AND  RRR ≥ λ
//   Seq-No-based GHA   if  μ(DSN) ≥ β   AND (PLR > δ  OR  RRR ≥ λ)
//   Normal             otherwise
//
// NOTE ON SIGNALS: this NS-3 setup is data-plane only and exposes no
// RREQ/RREP/DSN counters. PLR is computed from the REAL forwarding
// counters; RRR and DSN are supplied by the caller (modelled per
// node-type in the sweep harness, or wired to real counters if the
// AODV path is later instrumented). The DETECTION LOGIC below is the
// paper's, unchanged, regardless of where the signals come from.
// ============================================================
#pragma once
#include <cstdint>
#include <iostream>
#include <cmath>
#include <vector>

namespace dpgha {

// Fixed thresholds from the paper (§IV.B).
struct DpghaConfig {
    double delta = 3.0;   // δ — PLR threshold (%). Paper: normal AODV PDR 97-98%.
    double lambda = 70.0; // λ — RRR threshold (%). Paper: abnormal RREP flooding.
    // β is dynamic (Eq.17), computed each detection round; not a constant.
};

// Per-node signals fed to the detector for one detection round.
// All counts are cumulative as stored in the MRT (Table 2).
struct DpghaNodeSignals {
    uint32_t dp_received  = 0;  // ΣDPR — data packets received (Eq.13)
    uint32_t dp_forwarded = 0;  // ΣDPF — data packets forwarded (Eq.13)
    uint32_t rreq_received  = 0; // ΣRREQ_R (Eq.15 denominator)
    uint32_t rrep_generated = 0; // ΣRREP_G (Eq.15 numerator)
    double   mean_dsn = 0.0;     // μ(DSN_i) — mean DSN of this node's RREPs (Eq.16)
    bool     is_attacker = false; // ground truth (evaluation only)
};

enum class Verdict { Normal, SmartGHA, SeqNoGHA };

// Eq.13-14: Packet Loss Ratio for one node, as a percentage.
inline double PLR(const DpghaNodeSignals& s) {
    if (s.dp_received == 0) return 0.0;               // no traffic → no loss
    int32_t dpd = (int32_t)s.dp_received - (int32_t)s.dp_forwarded; // DPD (Eq.13)
    if (dpd < 0) dpd = 0;
    return 100.0 * (double)dpd / (double)s.dp_received;             // Eq.14
}

// Eq.15: Ratio of RREP generated to RREQ received, as a percentage.
// RREQ_R must be > 0 (paper's guard); else treated as 0 (not suspicious).
inline double RRR(const DpghaNodeSignals& s) {
    if (s.rreq_received == 0) return 0.0;
    return 100.0 * (double)s.rrep_generated / (double)s.rreq_received;
}

// Eq.17: dynamic β = mean of all nodes' μ(DSN). Recomputed every round.
inline double ComputeBeta(const std::vector<DpghaNodeSignals>& nodes) {
    if (nodes.empty()) return 0.0;
    double sum = 0.0;
    for (const auto& n : nodes) sum += n.mean_dsn;
    return sum / (double)nodes.size();
}

// Eq.18: classify one node given the round's dynamic β.
inline Verdict Classify(const DpghaNodeSignals& s, double beta,
                        const DpghaConfig& cfg = DpghaConfig{}) {
    const bool plr_gate = PLR(s) > cfg.delta;        // PLR > δ
    const bool rrr_gate = RRR(s) >= cfg.lambda;      // RRR ≥ λ
    const bool dsn_gate = s.mean_dsn >= beta;        // μ(DSN) ≥ β

    // Smart GHA (Eq.18 line 1): PLR > δ AND RRR ≥ λ
    if (plr_gate && rrr_gate) return Verdict::SmartGHA;
    // Seq-No-based GHA (Eq.18 line 2): μ(DSN) ≥ β AND (PLR > δ OR RRR ≥ λ)
    if (dsn_gate && (plr_gate || rrr_gate)) return Verdict::SeqNoGHA;
    return Verdict::Normal;
}

inline const char* VerdictName(Verdict v) {
    switch (v) {
        case Verdict::SmartGHA: return "SmartGHA";
        case Verdict::SeqNoGHA: return "SeqNoGHA";
        default:                return "Normal";
    }
}

// ── Full detection round over all nodes (Algorithm 1) ──────────────────────
// Returns per-node verdict; a node is blacklisted (detected) iff verdict != Normal.
// Accumulates TP/TN/FP/FN against ground truth for metrics.
struct DpghaResult {
    std::vector<Verdict> verdicts;
    uint32_t TP = 0, TN = 0, FP = 0, FN = 0;
    double beta = 0.0;
    double accuracy() const {
        uint32_t n = TP + TN + FP + FN;
        return n ? 100.0 * (TP + TN) / n : 0.0;
    }
    double tpr() const { return (TP + FN) ? 100.0 * TP / (TP + FN) : 0.0; }
    double fpr() const { return (FP + TN) ? 100.0 * FP / (FP + TN) : 0.0; }
};

inline DpghaResult DetectAll(const std::vector<DpghaNodeSignals>& nodes,
                             const DpghaConfig& cfg = DpghaConfig{}) {
    DpghaResult r;
    r.beta = ComputeBeta(nodes);                     // Eq.17 (dynamic, this round)
    r.verdicts.reserve(nodes.size());
    for (const auto& s : nodes) {
        Verdict v = Classify(s, r.beta, cfg);        // Eq.18
        r.verdicts.push_back(v);
        bool detected = (v != Verdict::Normal);
        if      ( detected &&  s.is_attacker) r.TP++;
        else if ( detected && !s.is_attacker) r.FP++;
        else if (!detected &&  s.is_attacker) r.FN++;
        else                                  r.TN++;
    }
    return r;
}

} // namespace dpgha
