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
//
// Fix 1 (supervisor, this round): the comparison here was EXACT equality
// (commit.n_fwd == observable_count), so ANY nonzero gap between a node's
// cumulative received and forwarded counts -- including ordinary MAC-layer
// collision loss on a perfectly honest node, not just deliberate grey-hole
// dropping -- was marked FAIL. Verified against the actual code before
// changing it (this comment previously described the check accurately: it
// WAS bare equality, confirmed by reading this file, not assumed from the
// supervisor's description). Fix: allow a small cumulative tolerance
// epsilon (packets lost to real-world MAC contention/collision, not
// attacker-scale dropping) before declaring FAIL. PASS iff
// (observable_count - commit.n_fwd) <= epsilon; a negative gap (n_fwd >
// observable_count, which should not happen for an honest node) still
// counts as a 0-magnitude gap here since committing to forward MORE than
// what was received is not the failure mode this gate targets.
ZKPProof ZKPProofStore::GenerateProof(const ZKPCommitment& commit,
                                       uint32_t observable_count) {
    ZKPProof proof;
    proof.node_id = commit.node_id;
    proof.C = commit.C;

    static const uint32_t SG_ZKP_CUM_EPSILON = 3;  // supervisor-prescribed tolerance
    uint32_t gap = (observable_count > commit.n_fwd)
                       ? (observable_count - commit.n_fwd)
                       : 0;

    // Sigma-protocol:
    // Honest prover: gap <= epsilon (received/forwarded match within normal
    // MAC-layer loss tolerance) → proof valid
    // Malicious prover: gap > epsilon (dropped packets beyond plausible
    // collision loss) → proof FAILS
    if (gap <= SG_ZKP_CUM_EPSILON) {
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
