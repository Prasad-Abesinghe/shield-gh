// ============================================================
// IMPLEMENTS: Eq. 3.27 — σ = Dilithium.Sign(skc, M)
//             Eq. 3.28 — b = Dilithium.Verify(pkc, M, σ)
// SECTION 3.6.8: CRYSTALS-Dilithium for flow modification authentication
// Prevents compromised/spoofed controller from injecting false block rules
// ============================================================
#include "dilithium_sig.h"
#include <oqs/oqs.h>

DilithiumKeyPair DilithiumSig::GenerateKeyPair() {
    DilithiumKeyPair kp;
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    kp.pk.resize(sig->length_public_key);
    kp.sk.resize(sig->length_secret_key);
    OQS_SIG_keypair(sig, kp.pk.data(), kp.sk.data());
    OQS_SIG_free(sig);
    return kp;
}

// ── Eq. 3.27 ─────────────────────────────────────────────────────────────────
// σ = Dilithium.Sign(skc, M)
// M = isolation FlowMod command; skc = controller signing key
std::vector<uint8_t> DilithiumSig::Sign(const std::string& message,
                                         const uint8_t* secret_key) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    size_t sig_len;
    std::vector<uint8_t> signature(sig->length_signature);
    OQS_SIG_sign(sig, signature.data(), &sig_len,
                 (uint8_t*)message.data(), message.size(), secret_key);
    OQS_SIG_free(sig);
    signature.resize(sig_len);
    return signature;
}

// ── Eq. 3.28 ─────────────────────────────────────────────────────────────────
// b = Dilithium.Verify(pkc, M, σ)
// b = 1 → install block rule; b = 0 → reject command
bool DilithiumSig::Verify(const std::string& message,
                           const std::vector<uint8_t>& signature,
                           const uint8_t* public_key) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    OQS_STATUS result = OQS_SIG_verify(sig,
        (uint8_t*)message.data(), message.size(),
        signature.data(), signature.size(), public_key);
    OQS_SIG_free(sig);
    return (result == OQS_SUCCESS);
}
