// ============================================================
// IMPLEMENTS: Eq. 3.34 — Kj = {(pku, sku) : u ∈ path(vj→root)}
//             Eq. 3.35 — (Kgrp, croot) = Kyber.Enc(pkroot, m)
//             Eq. 3.36 — (K^new_u, cu) = Kyber.Enc(pk^sib_u, k^new_u)
//                         ∀u ∈ path(ℓi → root)
// FIGURE 3.11: PQC-LKH Binary Tree for Post-Quantum Group Re-Keying
// SECTION 3.6.9: Reduces re-keying cost from O(N) to O(log N) KEM ops
// ============================================================
#pragma once
#include "kyber_kem.h"
#include <cstdint>
#include <vector>
#include <climits>
#include <cmath>

struct LKHNode {
    uint32_t     id;
    KyberKeyPair key_pair;
    int32_t      left_child  = -1;
    int32_t      right_child = -1;
    int32_t      parent      = -1;
    uint32_t     leaf_vehicle = UINT32_MAX;  // set if leaf node
};

class PQCLogicalKeyHierarchy {
public:
    // Build binary tree for N vehicles (Figure 3.11)
    void Build(uint32_t N);

    // ── Eq. 3.34 ──────────────────────────────────────────────────────
    // Kj = {(pku, sku) : u ∈ path(vj→root)}
    std::vector<uint32_t> GetPathToRoot(uint32_t vehicle_id) const;

    // ── Eq. 3.35 ──────────────────────────────────────────────────────
    // (Kgrp, croot) = Kyber.Enc(pkroot, m),  m ←$ {0,1}^256
    std::pair<std::vector<uint8_t>, KyberCiphertext> EncapsulateGroupKey();

    // ── Eq. 3.36 ──────────────────────────────────────────────────────
    // When vehicle vi (leaf ℓi) is isolated:
    // Refresh only path(ℓi → root): ⌈log2 N⌉ Kyber operations
    // For each u ∈ path: (K^new_u, cu) = Kyber.Enc(pk^sib_u, k^new_u)
    std::vector<KyberCiphertext> IsolateAndRekey(uint32_t isolated_vehicle_id);

    // Complexity: O(log N) vs O(N) for naive unicast (Figure 3.11 table)
    uint32_t GetRekeyingCost() const {
        return (uint32_t)std::ceil(std::log2((double)m_N));
    }

private:
    uint32_t             m_N;
    std::vector<LKHNode> m_tree;
    KyberKEM             m_kyber;

    uint32_t GetLeafIndex(uint32_t vehicle_id) const;
    uint32_t GetSibling(uint32_t node_idx) const;
};
