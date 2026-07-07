// ============================================================
// IMPLEMENTS: ALGORITHM 1 — LW-DP-Det (declaration)
//             Lightweight Data-Plane Grey Hole Detection
// Paper: Algorithm 1 (LW-DP-Det), Eqs. 3.1, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.17
// ============================================================
#pragma once
#include <cstdint>
#include <map>
#include "matd.h"
#include "../blockchain/blockchain_ledger.h"

// Result of one LW-DP-Det evaluation (Algorithm 1 output tuple)
struct DPDetResult {
    uint32_t node_id;
    bool     s1_fired;   // S_DP-FR  (Eq. 3.6)
    bool     s2_fired;   // S_DP-IT  (Eq. 3.7)
    bool     s3_fired;   // S_DP-TS  (Eq. 3.8)
    bool     detected;   // S1 OR S2 OR S3
    double   corrected_pdr;
    double   trust_mob;
};

// Algorithm 1: LW-DP-Det(vi, t, W, ...)
// pdr_history = actual observed per-window PDR series for this node (newest last),
// used by the S2 intermittent autocorrelation test (Eq. 3.7).
DPDetResult LW_DP_Det(uint32_t node_id,
                      double   t,
                      uint32_t W,
                      const BlockchainLedger& ledger,
                      const MobilityAwareTrustDecay& matd,
                      double speed_mps,
                      const std::map<uint32_t, double>& per_source_pdr,
                      const std::vector<double>& pdr_history);
