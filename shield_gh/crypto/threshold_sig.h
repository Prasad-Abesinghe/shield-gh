// ============================================================
// IMPLEMENTS: Eq. 3.31 — σj = TS.PartialSign(skj, B(vi))
//             Eq. 3.32 — σ* = TS.Combine({σj}^k_{j=1})
//             Eq. 3.33 — b = TS.Verify(pkgroup, B(vi), σ*)
// SECTION 3.6.8: Threshold signatures for collective blacklisting.
// Prevents any single compromised RSU from unilaterally isolating a vehicle.
// Isolation requires k independent RSU co-signatures.
// ============================================================
#pragma once
#include "dilithium_sig.h"
#include <cstdint>
#include <vector>
#include <string>

struct ThresholdPartialSig {
    uint32_t             rsu_id;
    std::vector<uint8_t> signature;   // Dilithium signature from one RSU
};

struct AggregateSignature {
    uint32_t             k_signers;        // number of partial signatures combined
    std::vector<uint32_t> signer_ids;     // RSU identifiers that co-signed
    std::vector<uint8_t> signature;       // combined aggregate signature
};

class ThresholdSig {
public:
    // ── Eq. 3.31 ──────────────────────────────────────────────────────
    // σj = TS.PartialSign(skj, B(vi))
    static ThresholdPartialSig PartialSign(uint32_t rsu_id,
                                            const std::string& blacklist_msg,
                                            const uint8_t* rsu_sk);

    // ── Eq. 3.32 ──────────────────────────────────────────────────────
    // σ* = TS.Combine({σj}^k_{j=1})
    static AggregateSignature Combine(
        const std::vector<ThresholdPartialSig>& partials);

    // ── Eq. 3.33 ──────────────────────────────────────────────────────
    // b = TS.Verify(pkgroup, B(vi), σ*)
    // b = 1 confirms ≥k independent RSUs endorsed the blacklisting decision
    static bool Verify(const AggregateSignature& agg,
                       const std::string& blacklist_msg,
                       uint32_t required_k,
                       const std::vector<uint8_t*>& rsu_public_keys);
};
