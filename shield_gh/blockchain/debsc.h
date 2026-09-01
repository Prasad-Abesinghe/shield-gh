// ============================================================
// IMPLEMENTS: Eq. 3.12 / Eq. 3.19 (DEBSC isolation gate)
//             Eq. 3.13 (Suspicion level Λi)
// FIGURE 3.14: Cryptographic Mitigation Flowchart
// ============================================================
#pragma once
#include "blockchain_ledger.h"
#include "zkp_proofs.h"
#include <map>
#include <utility>

enum class IsolationDecision { ISOLATE, RATE_LIMIT, REQUIRE_ZKP, MONITOR };

class DEBSC {
public:
    explicit DEBSC(BlockchainLedger* ledger,
                   double theta_R = 0.4,   // reputation isolation threshold
                   double lambda1 = 2,     // rate-limit threshold
                   double lambda2 = 5);    // full isolation threshold

    // ── Eq. 3.19 ────────────────────────────────────────────────────────
    // Isolate(vi) = 1[(1 − Ri(t)) > θR  AND  Π_ZKP(vi, t) == FAIL]
    bool ShouldIsolate(uint32_t node_id, double t) const;

    // ── Eq. 3.13 ────────────────────────────────────────────────────────
    // Λi(t) = Σ_{τ=t−Ws}^{t} 1[(1 − Ri(τ)) > θR]
    uint32_t ComputeSuspicionLevel(uint32_t node_id, double t,
                                   uint32_t Ws = 10) const;

    // Graduated response (Section 3.6.2)
    IsolationDecision GetGraduatedResponse(uint32_t node_id, double t) const;

    // Register ZKP proof verification result from ZKP module
    void RecordZKPResult(uint32_t node_id, double t, bool proof_valid);

    // Ablation toggle (supervisor DA1/DA2 diagnostics): when false, the
    // dual-evidence gate in ShouldIsolate() degrades to the statistical gate
    // alone (ZKP requirement dropped). Defaults to true (dual-gate, as
    // specified by Eq. 3.19) so existing behaviour is unchanged unless
    // explicitly disabled.
    void SetZkpGateEnabled(bool enabled) { m_zkp_gate_enabled = enabled; }

    // Task 8.5 (supervisor sensitivity-analysis instruction): theta_R must be
    // settable from CLI post-construction, same reason as SetZkpGateEnabled
    // above (g_sg_debsc is a static global built before main() parses argv).
    void SetThetaR(double theta_R) { m_theta_R = theta_R; }

    // BUG FIX (supervisor-reported: DA1==DA2==DA3==DA4, MCC not monotonic
    // across ablation components): ComputeReputation() in BlockchainLedger
    // computes Ri(t) purely from raw forwarding-log counts -- the report's
    // own Eq. 3.18 specifies Ri(t) should average T_mob_i (the MATD-decayed
    // trust, Eq. 3.17), but no caller ever applied that decay before this
    // fix, so MATD's correction never reached the isolation decision
    // (ShouldIsolate/ComputeSuspicionLevel below), only the separate
    // S_total/flagged confusion-matrix path. Caller (shield_gh_integration.h,
    // which has per-node speed and the MATD instance) computes and records
    // the decay ratio T_mob_i(t)/Ti(t) here each window; ShouldIsolate/
    // ComputeSuspicionLevel apply it to whatever ComputeReputation() returns
    // instead of using the raw ledger value directly. Ablation DA1/DA3
    // (--enable_matd=0): caller simply doesn't call this, ratio stays 1.0
    // (no decay applied), matching the "MATD off" semantics used elsewhere.
    void RecordMobilityDecay(uint32_t node_id, double decay_ratio) {
        m_matd_decay[node_id] = decay_ratio;
    }

    // NQ7/NQ12/RQ4 debug accessor (supervisor-requested): expose the internal
    // gate state that GetGraduatedResponse()/ShouldIsolate() compute but
    // don't otherwise surface, so a caller can print WHY a given tier was
    // selected (suspicion level vs thresholds, statistical gate value, ZKP
    // proof result) instead of just the final tier name.
    struct DebugState {
        uint32_t lambda;
        uint32_t lambda1, lambda2;
        double   Ri_decayed;
        bool     statistical_gate;   // (1-Ri) > theta_R
        bool     zkp_cached;         // was a ZKP result ever recorded for this node
        bool     zkp_proof_valid;    // true=PASS, false=FAIL (only meaningful if zkp_cached)
        bool     zkp_gate_enabled;
    };
    DebugState GetDebugState(uint32_t node_id, double t) const {
        double Ri = DecayedReputation(node_id, t);
        bool stat_gate = ((1.0 - Ri) > EffectiveThetaR(node_id));
        bool cached = m_zkp_cache.count(node_id) > 0;
        bool valid  = cached ? m_zkp_cache.at(node_id).second : false;
        return DebugState{ ComputeSuspicionLevel(node_id, t), m_lambda1, m_lambda2,
                            Ri, stat_gate, cached, valid, m_zkp_gate_enabled };
    }

private:
    double DecayedReputation(uint32_t node_id, double t) const;

    // See .cc for full derivation: keeps theta_R anchored to the RAW-
    // reputation boundary the Task 8.5 sweep validated at v=80 km/h,
    // scaling with THIS node's current MATD decay ratio so the same
    // physical margin holds at any speed (supervisor-requested MATD
    // monotonicity fix).
    double EffectiveThetaR(uint32_t node_id) const;

    BlockchainLedger* m_ledger;
    ZKPProofStore*    m_zkp_store;
    double            m_theta_R;
    uint32_t          m_lambda1, m_lambda2;
    bool              m_zkp_gate_enabled = true;

    // ZKP result cache: node_id → (timestamp, valid)
    std::map<uint32_t, std::pair<double, bool>> m_zkp_cache;
    // Per-node MATD decay ratio (T_mob_i/Ti), most recent window. Defaults
    // to 1.0 (no decay) for any node never recorded via RecordMobilityDecay.
    std::map<uint32_t, double> m_matd_decay;
};
