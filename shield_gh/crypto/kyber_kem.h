// ============================================================
// IMPLEMENTS: Eq. 3.25 — (K, c) = Kyber.Enc(pk, m)
//             Eq. 3.26 — K = Kyber.Dec(sk, c)
// SECTION 3.6.8: CRYSTALS-Kyber Key Encapsulation
// Uses liboqs (Open Quantum Safe) for actual CRYSTALS-Kyber-768
// ============================================================
#pragma once
#include <vector>
#include <utility>
#ifdef USE_LIBOQS
#include <oqs/oqs.h>
#endif

struct KyberKeyPair {
    uint8_t pk[OQS_KEM_kyber_768_length_public_key];
    uint8_t sk[OQS_KEM_kyber_768_length_secret_key];
};

struct KyberCiphertext {
    uint8_t data[OQS_KEM_kyber_768_length_ciphertext];
};

class KyberKEM {
public:
    // Generate a Kyber-768 key pair
    KyberKeyPair GenerateKeyPair();

    // ── Eq. 3.25 ──────────────────────────────────────────────────────
    // (K, c) = Kyber.Enc(pk, m),  m ←$ {0,1}^256
    // Returns {shared_secret K, ciphertext c}
    std::pair<std::vector<uint8_t>, KyberCiphertext>
    Encapsulate(const uint8_t* pk);

    // ── Eq. 3.26 ──────────────────────────────────────────────────────
    // K = Kyber.Dec(sk, c)
    // Only holder of correct sk can recover K.
    std::vector<uint8_t> Decapsulate(const uint8_t* sk,
                                     const KyberCiphertext& ct);
};
