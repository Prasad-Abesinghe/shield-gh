// ============================================================
// IMPLEMENTS: ALGORITHM 1 — LW-DP-Det
//             Lightweight Data-Plane Grey Hole Detection
//             Lines 1–15 of Algorithm 1 in paper
// INPUT:  Per-node blockchain forwarding records
// OUTPUT: Binary detection decision (S1 OR S2 OR S3)
// ============================================================
#include "lw_dp_det.h"
#include "attack_signatures.h"
#include "matd.h"
#include "../blockchain/blockchain_ledger.h"
#include <iostream>
#include <vector>

// Algorithm 1: LW-DP-Det
// For each vehicle vi ∈ V at time t with observation window W:
//   1. PDRi      ← ComputePDR(vi, t, W)          [Eq. 3.1]
//   2. ρ_ho      ← ComputeHandoffLoss(si(t))      [Eq. 3.4]
//   3. PDR̂i     ← CorrectPDR(PDRi, si(t))        [Eq. 3.5]
//   4. σ²i       ← ComputePDRVariance(vi, t, W)   [Eq. 3.3]
//   5. T_mob_i   ← ApplyMobilityDecay(Ti, si(t))  [Eq. 3.17]
//   6. S1 ← S_DP-FR(vi, PDR̂i, σ²i)               [Eq. 3.6]
//   7. S2 ← S_DP-IT(vi, pdr_history)              [Eq. 3.7]
//   8. S3 ← S_DP-TS(vi, per_source_pdr)           [Eq. 3.8]
//   9. If (S1 OR S2 OR S3): flag as suspected grey hole
// (DPDetResult struct declared in lw_dp_det.h)

DPDetResult LW_DP_Det(uint32_t node_id,
                       double   t,
                       uint32_t W,
                       const BlockchainLedger& ledger,
                       const MobilityAwareTrustDecay& matd,
                       double speed_mps,
                       const std::map<uint32_t, double>& per_source_pdr,
                       const std::vector<double>& pdr_history) {
    DPDetResult result;
    result.node_id = node_id;

    // Algorithm 1, line 2: PDRi (Eq. 3.1)
    double pdr = ledger.ComputePDR(node_id, t, W);

    // Algorithm 1, line 3: corrected PDR (Eq. 3.4, 3.5)
    result.corrected_pdr = matd.CorrectPDR(pdr, speed_mps);

    // Algorithm 1, line 4: variance σ²i (Eq. 3.3)
    double variance = ledger.ComputePDRVariance(node_id, t, W);

    // Algorithm 1, line 5: mobility-decayed trust (Eq. 3.16, 3.17)
    double trust = ledger.ComputeTrustScore(node_id, t);
    result.trust_mob = matd.ApplyMobilityDecay(trust, speed_mps);

    // pdr_history is the ACTUAL observed per-window PDR series (passed in),
    // used directly by the S2 autocorrelation test (Eq. 3.7).

    // Algorithm 1, lines 6–8: evaluate signatures S1, S2, S3
    result.s1_fired = AttackSignatureEngine::S1_FixedRate(
        node_id, t, result.corrected_pdr, variance);
    result.s2_fired = AttackSignatureEngine::S2_Intermittent(pdr_history);
    result.s3_fired = AttackSignatureEngine::S3_TargetSpecific(per_source_pdr);

    // Algorithm 1, line 9: detection decision (disjunction)
    result.detected = result.s1_fired || result.s2_fired || result.s3_fired;

    if (result.detected) {
        std::cout << "[LW-DP-Det] Node " << node_id
                  << " SUSPECTED — S1:" << result.s1_fired
                  << " S2:" << result.s2_fired
                  << " S3:" << result.s3_fired
                  << " corrPDR=" << result.corrected_pdr
                  << std::endl;
    }

    return result;
}
