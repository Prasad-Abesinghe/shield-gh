// ============================================================
// IMPLEMENTS: Eq. 3.27 — σ = Dilithium.Sign(skc, M)
//             Eq. 3.28 — b = Dilithium.Verify(pkc, M, σ)
// SECTION 3.6.8: CRYSTALS-Dilithium for flow modification authentication
// Prevents compromised/spoofed controller from injecting false block rules
// ============================================================
#pragma once
#include <vector>
#include <string>
#ifdef USE_LIBOQS
#include <oqs/oqs.h>
#endif

struct DilithiumKeyPair {
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
};

class DilithiumSig {
public:
    // Generate a Dilithium-2 key pair
    static DilithiumKeyPair GenerateKeyPair();

    // ── Eq. 3.27 ──────────────────────────────────────────────────────
    // σ = Dilithium.Sign(skc, M)
    // M = isolation FlowMod command; skc = controller signing key
    static std::vector<uint8_t> Sign(const std::string& message,
                                     const uint8_t* secret_key);

    // ── Eq. 3.28 ──────────────────────────────────────────────────────
    // b = Dilithium.Verify(pkc, M, σ)
    // b = 1 → install block rule; b = 0 → reject command
    static bool Verify(const std::string& message,
                       const std::vector<uint8_t>& signature,
                       const uint8_t* public_key);
};
