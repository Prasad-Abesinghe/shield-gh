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
// matd_enabled (ablation DA1/DA3, supervisor): when false, S1_FixedRate is
// evaluated on the RAW pdr (no MATD correction) instead of matd.CorrectPDR().
// Defaults to true so existing callers are unaffected.
// Task 8.5 (supervisor sensitivity-analysis instruction): tau_f/epsilon_f/
// tau_it/gamma_it/tau_ts are exposed here (default = AttackSignatureEngine's
// own defaults, so existing callers are unaffected) so routing.cc's CLI
// surface (sg_tau_f etc.) can drive the tab:gh_sensitivity grid search
// without recompiling per value.
DPDetResult LW_DP_Det(uint32_t node_id,
                      double   t,
                      uint32_t W,
                      const BlockchainLedger& ledger,
                      const MobilityAwareTrustDecay& matd,
                      double speed_mps,
                      const std::map<uint32_t, double>& per_source_pdr,
                      const std::vector<double>& pdr_history,
                      bool matd_enabled = true,
                      double tau_f = 0.75,
                      double epsilon_f = 0.20,
                      double tau_it = 0.7,
                      double gamma_it = 1.3,
                      double tau_ts = 0.5);
