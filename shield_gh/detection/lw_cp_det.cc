// ============================================================
// IMPLEMENTS: ALGORITHM 2 — LW-CP-Det
//             Lightweight Controller-Plane Grey Hole Detection
//             Lines 1–16 of Algorithm 2 in paper
// INPUT:  Flow rule records from blockchain ledger
// OUTPUT: Binary detection decision (S4 OR S5 OR S6)
// ============================================================
#include "lw_cp_det.h"
#include "attack_signatures.h"
#include "../blockchain/blockchain_ledger.h"
#include <iostream>
#include <vector>

// Algorithm 2: LW-CP-Det
// For each SDN controller c at time t with observation window W:
//   1. Fc(t) ← GetFlowHistory(c, t, W)           [ledger query]
//   2. Extract malicious rule count time series Fmal_c
//   3. S4 ← S_CP-FR(c, Fc(t))                    [Eq. 3.9]
//   4. S6 ← S_CP-TS(c, Fc(t))                    [Eq. 3.11]
//   5. S5 ← S_CP-IT(c, Fmal_c)                   [Eq. 3.10]
//   6. If (S4 OR S5 OR S6): flag controller as suspected
// (CPDetResult struct declared in lw_cp_det.h)

CPDetResult LW_CP_Det(uint32_t ctrl_id,
                       double   t,
                       uint32_t W,
                       const BlockchainLedger& ledger) {
    CPDetResult result;
    result.ctrl_id = ctrl_id;

    // Algorithm 2, line 1: retrieve flow rule history from blockchain
    std::vector<FlowRuleRecord> raw_history = ledger.GetFlowHistory(ctrl_id, t, W);

    // Convert to FlowRule structs for signature engine
    std::vector<FlowRule> flow_rules;
    for (const auto& rec : raw_history) {
        FlowRule fr;
        fr.action      = rec.action;
        fr.drop_prob   = rec.drop_prob;
        fr.is_wildcard = rec.is_wildcard;
        fr.match_src   = rec.match_src;
        flow_rules.push_back(fr);
    }

    // Algorithm 2, line 2: build malicious rule count time series for S5
    // Count drop rules per unit-time slot within window W
    std::vector<uint32_t> malicious_counts;
    for (uint32_t tau = 0; tau < W; tau++) {
        auto slot_rules = ledger.GetFlowHistory(ctrl_id, t - tau, 1);
        uint32_t count = 0;
        for (const auto& rec : slot_rules) {
            if (rec.action == "drop") count++;
        }
        malicious_counts.push_back(count);
    }

    // Algorithm 2, lines 3–5: evaluate signatures S4, S5, S6
    result.s4_fired = AttackSignatureEngine::S4_CPFixedRate(flow_rules);
    result.s5_fired = AttackSignatureEngine::S5_CPIntermittent(malicious_counts);
    result.s6_fired = AttackSignatureEngine::S6_CPTargetSpecific(flow_rules);

    // Algorithm 2, line 6: detection decision (disjunction)
    result.detected = result.s4_fired || result.s5_fired || result.s6_fired;

    if (result.detected) {
        std::cout << "[LW-CP-Det] Controller " << ctrl_id
                  << " SUSPECTED — S4:" << result.s4_fired
                  << " S5:" << result.s5_fired
                  << " S6:" << result.s6_fired
                  << std::endl;
    }

    return result;
}
