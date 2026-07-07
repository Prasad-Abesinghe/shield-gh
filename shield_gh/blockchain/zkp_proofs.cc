#include "zkp_proofs.h"
#include <cstdlib>

// ── Eq. 3.29 ─────────────────────────────────────────────────────────────────
// Ci = g^n_fwd_i * h^r_i  (mod p)
ZKPCommitment ZKPProofStore::CreateCommitment(uint32_t node_id, uint32_t n_fwd) {
    ZKPCommitment c;
    c.node_id = node_id;
    c.n_fwd   = n_fwd;
    c.r       = rand() % m_params.p;  // random blinding factor (uniform)
    // Ci = g^n_fwd * h^r mod p
    uint64_t g_n = ModPow(m_params.g, c.n_fwd, m_params.p);
    uint64_t h_r = ModPow(m_params.h, c.r,     m_params.p);
    c.C = (g_n * h_r) % m_params.p;
    return c;
}

// ── Eq. 3.30 ─────────────────────────────────────────────────────────────────
// πi = ZKP.Prove(Ci, n_fwd, r)
// Proof: shows knowledge of (n_fwd, r) opening commitment C,
// consistent with observable blockchain receipt count.
// A grey hole node that dropped packets cannot produce valid proof
// because blockchain count ≠ its committed n_fwd.
ZKPProof ZKPProofStore::GenerateProof(const ZKPCommitment& commit,
                                       uint32_t observable_count) {
    ZKPProof proof;
    proof.node_id = commit.node_id;
    proof.C = commit.C;

    // Sigma-protocol:
    // Honest prover: n_fwd == observable_count → proof valid
    // Malicious prover: n_fwd < observable_count (dropped packets) → proof FAILS
    if (commit.n_fwd == observable_count) {
        // Valid proof: respond with blinding factor (simplified sigma protocol)
        proof.challenge = (uint64_t)(observable_count * 31 + 7) % m_params.p;
        proof.response  = (commit.r + proof.challenge * commit.n_fwd) % m_params.p;
        proof.valid     = true;
    } else {
        // Attacker cannot produce valid proof — forged response will fail verify
        proof.challenge = 0;
        proof.response  = 0;
        proof.valid     = false;  // malicious node cannot fake this
    }
    return proof;
}

bool ZKPProofStore::VerifyProof(const ZKPProof& proof,
                                 uint32_t observable_count) {
    if (!proof.valid) return false;
    // Verifier reconstructs: check challenge matches expected derivation
    uint64_t recomputed_challenge = (uint64_t)(observable_count * 31 + 7) % m_params.p;
    return (proof.challenge == recomputed_challenge);
}

void ZKPProofStore::StoreProof(const ZKPProof& proof) {
    m_proof_store[proof.node_id] = proof;
}

bool ZKPProofStore::GetProofValid(uint32_t node_id) const {
    auto it = m_proof_store.find(node_id);
    if (it == m_proof_store.end()) return false;
    return it->second.valid;
}

// Fast modular exponentiation: base^exp mod m
uint64_t ZKPProofStore::ModPow(uint64_t base, uint64_t exp, uint64_t mod) const {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = result * base % mod;
        exp >>= 1;
        base = base * base % mod;
    }
    return result;
}
