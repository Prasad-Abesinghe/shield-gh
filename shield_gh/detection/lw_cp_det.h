// ============================================================
// IMPLEMENTS: ALGORITHM 2 — LW-CP-Det (declaration)
//             Lightweight Controller-Plane Grey Hole Detection
// Paper: Algorithm 2 (LW-CP-Det), Eqs. 3.9, 3.10, 3.11
// ============================================================
#pragma once
#include <cstdint>
#include "../blockchain/blockchain_ledger.h"

// Result of one LW-CP-Det evaluation (Algorithm 2 output tuple)
struct CPDetResult {
    uint32_t ctrl_id;
    bool     s4_fired;   // S_CP-FR  (Eq. 3.9)
    bool     s5_fired;   // S_CP-IT  (Eq. 3.10)
    bool     s6_fired;   // S_CP-TS  (Eq. 3.11)
    bool     detected;   // S4 OR S5 OR S6
};

// Algorithm 2: LW-CP-Det(c, t, W)
CPDetResult LW_CP_Det(uint32_t ctrl_id,
                      double   t,
                      uint32_t W,
                      const BlockchainLedger& ledger);
