// ============================================================
// IMPLEMENTS: Eq. 3.34 — Kj = {(pku, sku) : u ∈ path(vj→root)}
//             Eq. 3.35 — (Kgrp, croot) = Kyber.Enc(pkroot, m)
//             Eq. 3.36 — (K^new_u, cu) = Kyber.Enc(pk^sib_u, k^new_u)
//                         ∀u ∈ path(ℓi → root)
// FIGURE 3.11: PQC-LKH Binary Tree for Post-Quantum Group Re-Keying
// ============================================================
#include "pqc_lkh.h"
#include <stdexcept>

// Build a complete binary tree for N vehicles.
// Leaf nodes correspond to individual vehicles.
// Internal nodes hold KEMs used for subgroup key encapsulation.
void PQCLogicalKeyHierarchy::Build(uint32_t N) {
    m_N = N;
    // Number of nodes in a complete binary tree with N leaves = 2N - 1
    uint32_t total_nodes = 2 * N - 1;
    m_tree.resize(total_nodes);

    // Generate key pairs for every node in the tree
    for (uint32_t i = 0; i < total_nodes; i++) {
        m_tree[i].id       = i;
        m_tree[i].key_pair = m_kyber.GenerateKeyPair();

        // Wire children and parent pointers (1-indexed complete binary tree)
        if (i > 0) {
            m_tree[i].parent = (i - 1) / 2;
        }
        uint32_t left  = 2 * i + 1;
        uint32_t right = 2 * i + 2;
        if (left  < total_nodes) m_tree[i].left_child  = left;
        if (right < total_nodes) m_tree[i].right_child = right;
    }

    // Assign vehicle IDs to leaf nodes (nodes N-1 ... 2N-2)
    for (uint32_t leaf = 0; leaf < N; leaf++) {
        uint32_t node_idx = (N - 1) + leaf;
        m_tree[node_idx].leaf_vehicle = leaf;
    }
}

// Find the tree node index for a given vehicle id (leaf lookup)
uint32_t PQCLogicalKeyHierarchy::GetLeafIndex(uint32_t vehicle_id) const {
    for (uint32_t i = 0; i < m_tree.size(); i++) {
        if (m_tree[i].leaf_vehicle == vehicle_id) return i;
    }
    throw std::runtime_error("Vehicle not found in LKH tree");
}

// Get the sibling of a given node index
uint32_t PQCLogicalKeyHierarchy::GetSibling(uint32_t node_idx) const {
    if (node_idx == 0) return 0;  // root has no sibling
    int32_t parent = m_tree[node_idx].parent;
    uint32_t left  = m_tree[parent].left_child;
    uint32_t right = m_tree[parent].right_child;
    return (node_idx == (uint32_t)left) ? right : left;
}

// ── Eq. 3.34 ─────────────────────────────────────────────────────────────────
// Kj = {(pku, sku) : u ∈ path(vj→root)}
// Returns node indices along the path from vehicle leaf to root
std::vector<uint32_t> PQCLogicalKeyHierarchy::GetPathToRoot(uint32_t vehicle_id) const {
    std::vector<uint32_t> path;
    uint32_t current = GetLeafIndex(vehicle_id);
    while (true) {
        path.push_back(current);
        if (m_tree[current].parent < 0) break;
        current = m_tree[current].parent;
    }
    return path;  // leaf → root order
}

// ── Eq. 3.35 ─────────────────────────────────────────────────────────────────
// (Kgrp, croot) = Kyber.Enc(pkroot, m),  m ←$ {0,1}^256
// Encapsulates the group session key under the root public key
std::pair<std::vector<uint8_t>, KyberCiphertext>
PQCLogicalKeyHierarchy::EncapsulateGroupKey() {
    // Root is always node 0
    return m_kyber.Encapsulate(m_tree[0].key_pair.pk);
}

// ── Eq. 3.36 ─────────────────────────────────────────────────────────────────
// When vehicle vi (leaf ℓi) is isolated:
// For each u ∈ path(ℓi → root): regenerate ku, encapsulate under sibling pk
// Cost: ⌈log2 N⌉ Kyber.Enc operations (vs O(N) unicast)
std::vector<KyberCiphertext>
PQCLogicalKeyHierarchy::IsolateAndRekey(uint32_t isolated_vehicle_id) {
    std::vector<KyberCiphertext> new_ciphertexts;

    std::vector<uint32_t> path = GetPathToRoot(isolated_vehicle_id);

    // Walk path from leaf to root, refreshing keys at each node u
    // Encrypt new key under the sibling's public key (sibling can then update)
    for (uint32_t node_idx : path) {
        // Regenerate key pair for this node (Eq. 3.36: K^new_u)
        m_tree[node_idx].key_pair = m_kyber.GenerateKeyPair();

        // Encapsulate new key under sibling's current public key
        uint32_t sib = GetSibling(node_idx);
        if (sib != node_idx) {
            auto [shared_secret, ct] = m_kyber.Encapsulate(m_tree[sib].key_pair.pk);
            new_ciphertexts.push_back(ct);
        }
    }

    return new_ciphertexts;  // |path| = ⌈log2 N⌉ ciphertexts
}
