// ============================================================
// IMPLEMENTS: Eq. 3.25 — (K, c) = Kyber.Enc(pk, m)
//             Eq. 3.26 — K = Kyber.Dec(sk, c)
// SECTION 3.6.8: CRYSTALS-Kyber Key Encapsulation
// Uses liboqs (Open Quantum Safe) for actual CRYSTALS-Kyber-768
// ============================================================
#include "kyber_kem.h"

KyberKeyPair KyberKEM::GenerateKeyPair() {
    KyberKeyPair kp;
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    OQS_KEM_keypair(kem, kp.pk, kp.sk);
    OQS_KEM_free(kem);
    return kp;
}

// ── Eq. 3.25 ─────────────────────────────────────────────────────────────────
// (K, c) = Kyber.Enc(pk, m),  m ←$ {0,1}^256
// Used for: session key encapsulation after node isolation (group re-keying)
// Also: PQC-LKH tree node key encapsulation (Eq. 3.35, 3.36)
std::pair<std::vector<uint8_t>, KyberCiphertext>
KyberKEM::Encapsulate(const uint8_t* pk) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    std::vector<uint8_t> shared_secret(OQS_KEM_kyber_768_length_shared_secret);
    KyberCiphertext ct;
    OQS_KEM_encaps(kem, ct.data, shared_secret.data(), pk);
    OQS_KEM_free(kem);
    return {shared_secret, ct};  // (K, c) as in Eq. 3.25
}

// ── Eq. 3.26 ─────────────────────────────────────────────────────────────────
// K = Kyber.Dec(sk, c)
// Only holder of correct sk can recover K.
// Isolated vehicle excluded from key refresh cannot derive new Kgrp.
std::vector<uint8_t> KyberKEM::Decapsulate(const uint8_t* sk,
                                            const KyberCiphertext& ct) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    std::vector<uint8_t> shared_secret(OQS_KEM_kyber_768_length_shared_secret);
    OQS_KEM_decaps(kem, shared_secret.data(), ct.data, sk);
    OQS_KEM_free(kem);
    return shared_secret;
}
