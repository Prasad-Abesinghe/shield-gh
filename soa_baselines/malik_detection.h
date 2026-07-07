// ============================================================
// Baseline B1: Malik et al. [7]
// Dynamic-threshold grey hole detector
// NO mobility correction, NO blockchain, NO cryptography
// Reference: "Grey Hole Attack Detection Using Dynamic Thresholds"
// ============================================================
#pragma once
#include <cstdint>
#include <iostream>
#include <cmath>

// Malik B1 detection configuration
struct MalikConfig {
    double alpha          = 0.15;   // dynamic threshold offset below network avg
    uint32_t consec_win   = 2;      // consecutive low-PDR windows before flagging
};

// Per-node state for Malik detector
struct MalikNodeState {
    bool     flagged         = false;
    uint32_t consecutive_low = 0;
    double   window_pdr      = 1.0;
};

// ── Baseline B1: MalikDetect ──────────────────────────────────────────────────
// Simple threshold — no MATD correction, no ZKP, no blockchain trust
// Flags node if PDR < (network_average - alpha) for consec_win windows
inline bool MalikDetect(uint32_t node_id,
                         double   node_pdr,
                         double   network_avg_pdr,
                         MalikNodeState& state,
                         const MalikConfig& cfg = MalikConfig{}) {
    double threshold = network_avg_pdr - cfg.alpha;
    if (threshold < 0.0) threshold = 0.0;

    if (node_pdr < threshold) {
        state.consecutive_low++;
    } else {
        state.consecutive_low = 0;
    }

    if (state.consecutive_low >= cfg.consec_win && !state.flagged) {
        state.flagged = true;
        std::cout << "[Malik-B1] Node " << node_id
                  << " FLAGGED — PDR=" << node_pdr
                  << " < threshold=" << threshold << std::endl;
    }

    return state.flagged;
}

// ── Network-wide Malik scan ───────────────────────────────────────────────────
// Scans all N vehicles using existing per-node forwarding counters
// Returns detection accuracy for this window
inline double MalikScanAllNodes(uint32_t N_vehicles,
                                 const uint32_t* n_rx,
                                 const uint32_t* n_fwd,
                                 const bool* is_real_attacker,
                                 MalikNodeState* states,
                                 const MalikConfig& cfg = MalikConfig{}) {
    // Step 1: compute network average PDR
    double sum_pdr = 0.0;
    uint32_t active = 0;
    for (uint32_t n = 0; n < N_vehicles; n++) {
        if (n_rx[n] > 0) {
            double pdr = (double)n_fwd[n] / n_rx[n];
            states[n].window_pdr = pdr;
            sum_pdr += pdr;
            active++;
        } else {
            states[n].window_pdr = 1.0;
        }
    }
    double net_avg = (active > 0) ? sum_pdr / active : 1.0;

    // Step 2: flag nodes below threshold
    for (uint32_t n = 0; n < N_vehicles; n++) {
        MalikDetect(n, states[n].window_pdr, net_avg, states[n], cfg);
    }

    // Step 3: compute detection accuracy
    uint32_t TP = 0, TN = 0, FP = 0, FN = 0;
    for (uint32_t n = 0; n < N_vehicles; n++) {
        bool flagged = states[n].flagged;
        bool real    = is_real_attacker[n];
        if ( flagged &&  real) TP++;
        if ( flagged && !real) FP++;
        if (!flagged &&  real) FN++;
        if (!flagged && !real) TN++;
    }
    double accuracy = (N_vehicles > 0)
        ? 100.0 * (TP + TN) / N_vehicles
        : 0.0;
    double fpr = ((FP + TN) > 0)
        ? 100.0 * FP / (FP + TN)
        : 0.0;

    std::cout << "[Malik-B1] Accuracy=" << accuracy << "% FPR=" << fpr << "%" << std::endl;
    return accuracy;
}
