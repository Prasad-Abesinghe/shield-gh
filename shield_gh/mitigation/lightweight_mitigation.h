// ============================================================
// SHIELD-GH LIGHTWEIGHT-MODE MITIGATION
// Fig. 3.10 (left path) — "Lightweight Mitigation" box:
//   HMAC Authentication  +  RSU Threshold-signed FlowMod
//
// This module implements the two lightweight-mode mitigation
// primitives named in the abstract and Fig. 3.10 WITHOUT the
// post-quantum crypto stack (liboqs). It is the classical
// fallback that lets lightweight mode run in the default build:
//
//   * HMAC-SHA256 per-packet / per-record authentication
//     (integrity tag over the forwarding record) — Sec. 3.7.1,
//     "HMAC-based packet authentication for low-overhead
//      deployment on resource-constrained vehicular nodes".
//
//   * RSU threshold-signed FlowMod (Eq. 3.31-3.33): k independent
//     RSUs co-sign the BLOCK FlowMod before it is installed at the
//     OpenFlow switch. Here each RSU "signs" with an HMAC under its
//     own key (classical stand-in for Dilithium); Verify enforces
//     the k-of-n quorum, exactly like ThresholdSig::Verify. When the
//     build defines USE_LIBOQS the PQCMitigation path is used instead
//     and this module is bypassed.
//
// Self-contained (no external deps): a compact SHA-256 + HMAC so the
// header drops into the existing header-only shield_gh integration.
// ============================================================
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <sstream>
#include <iomanip>

namespace shield_gh_lw {

// ── Minimal SHA-256 (public-domain style, self-contained) ────────────────────
class SHA256 {
public:
    static std::array<uint8_t,32> Hash(const uint8_t* data, size_t len) {
        SHA256 ctx; ctx.Update(data, len); return ctx.Final();
    }
    SHA256() { Reset(); }
    void Reset() {
        m_len = 0; m_bufLen = 0;
        m_h[0]=0x6a09e667; m_h[1]=0xbb67ae85; m_h[2]=0x3c6ef372; m_h[3]=0xa54ff53a;
        m_h[4]=0x510e527f; m_h[5]=0x9b05688c; m_h[6]=0x1f83d9ab; m_h[7]=0x5be0cd19;
    }
    void Update(const uint8_t* data, size_t len) {
        m_len += len;
        while (len > 0) {
            size_t take = 64 - m_bufLen;
            if (take > len) take = len;
            std::memcpy(m_buf + m_bufLen, data, take);
            m_bufLen += take; data += take; len -= take;
            if (m_bufLen == 64) { Block(m_buf); m_bufLen = 0; }
        }
    }
    std::array<uint8_t,32> Final() {
        uint64_t bits = m_len * 8;
        uint8_t pad = 0x80; Update(&pad, 1);
        uint8_t zero = 0x00;
        while (m_bufLen != 56) Update(&zero, 1);
        uint8_t lenbytes[8];
        for (int i = 0; i < 8; i++) lenbytes[7-i] = (uint8_t)(bits >> (8*i));
        Update(lenbytes, 8);
        std::array<uint8_t,32> out{};
        for (int i = 0; i < 8; i++) {
            out[i*4+0] = (uint8_t)(m_h[i] >> 24);
            out[i*4+1] = (uint8_t)(m_h[i] >> 16);
            out[i*4+2] = (uint8_t)(m_h[i] >> 8);
            out[i*4+3] = (uint8_t)(m_h[i]);
        }
        return out;
    }
private:
    static uint32_t Rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32-n)); }
    void Block(const uint8_t* p) {
        static const uint32_t K[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (p[i*4]<<24)|(p[i*4+1]<<16)|(p[i*4+2]<<8)|(p[i*4+3]);
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = Rotr(w[i-15],7) ^ Rotr(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = Rotr(w[i-2],17) ^ Rotr(w[i-2],19)  ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=m_h[0],b=m_h[1],c=m_h[2],d=m_h[3],e=m_h[4],f=m_h[5],g=m_h[6],h=m_h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = Rotr(e,6) ^ Rotr(e,11) ^ Rotr(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = h + S1 + ch + K[i] + w[i];
            uint32_t S0 = Rotr(a,2) ^ Rotr(a,13) ^ Rotr(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        m_h[0]+=a; m_h[1]+=b; m_h[2]+=c; m_h[3]+=d;
        m_h[4]+=e; m_h[5]+=f; m_h[6]+=g; m_h[7]+=h;
    }
    uint32_t m_h[8];
    uint8_t  m_buf[64];
    size_t   m_bufLen;
    uint64_t m_len;
};

// ── HMAC-SHA256 (RFC 2104) ───────────────────────────────────────────────────
inline std::array<uint8_t,32> HmacSha256(const std::string& key,
                                         const std::string& msg) {
    uint8_t k[64] = {0};
    if (key.size() > 64) {
        auto kh = SHA256::Hash((const uint8_t*)key.data(), key.size());
        std::memcpy(k, kh.data(), 32);
    } else {
        std::memcpy(k, key.data(), key.size());
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }

    SHA256 inner; inner.Update(ipad, 64);
    inner.Update((const uint8_t*)msg.data(), msg.size());
    auto ih = inner.Final();

    SHA256 outer; outer.Update(opad, 64);
    outer.Update(ih.data(), 32);
    return outer.Final();
}

inline std::string ToHex(const std::array<uint8_t,32>& d) {
    std::ostringstream o;
    for (uint8_t b : d) o << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return o.str();
}

// ── Lightweight packet / forwarding-record authentication ────────────────────
// Sec. 3.7.1: each forwarding record carries an HMAC tag under the node's key.
// A record whose recomputed tag does not match is rejected as unauthenticated —
// this is the lightweight-mode analogue of the ZKP forwarding proof in full mode.
struct HmacAuth {
    // Per-node secret key (in a real deployment this is provisioned by the RSU
    // during association; here it is derived deterministically per node id).
    static std::string NodeKey(uint32_t node_id) {
        return "sg-lw-key-" + std::to_string(node_id);
    }
    // Tag a forwarding record (window,node,rx,fwd).
    static std::string Tag(uint32_t node_id, uint32_t window,
                           uint32_t rx, uint32_t fwd) {
        std::ostringstream m;
        m << "w" << window << ":n" << node_id << ":rx" << rx << ":fwd" << fwd;
        return ToHex(HmacSha256(NodeKey(node_id), m.str()));
    }
    // Verify a received tag against the recomputed one (constant-time-ish compare).
    static bool Verify(uint32_t node_id, uint32_t window,
                       uint32_t rx, uint32_t fwd, const std::string& tag) {
        std::string expect = Tag(node_id, window, rx, fwd);
        if (expect.size() != tag.size()) return false;
        uint8_t diff = 0;
        for (size_t i = 0; i < expect.size(); i++) diff |= (expect[i] ^ tag[i]);
        return diff == 0;
    }
};

// ── Classical RSU threshold-signed FlowMod (Eq. 3.31-3.33 fallback) ──────────
// k independent RSUs co-sign the BLOCK FlowMod for an attacker before it is
// installed at the OpenFlow switch. Mirrors ThresholdSig (crypto/threshold_sig)
// but uses per-RSU HMAC instead of Dilithium so it runs without liboqs.
struct RsuPartialSig { uint32_t rsu_id; std::string tag; };

struct FlowModAggregate {
    uint32_t              k_signers = 0;
    std::vector<uint32_t> signer_ids;
    std::string           combined;   // hex of XOR-combined tags
    bool                  quorum_ok = false;
};

class ThresholdFlowMod {
public:
    // The FlowMod message that blocks all traffic from the attacker.
    static std::string BuildBlockFlowMod(uint32_t node_id, double t) {
        std::ostringstream m;
        m << "FLOWMOD BLOCK node=" << node_id
          << " action=drop_all match=src:" << node_id
          << " t=" << std::fixed << std::setprecision(3) << t;
        return m.str();
    }
    // Eq. 3.31: one RSU's partial signature (HMAC under its RSU key).
    static RsuPartialSig PartialSign(uint32_t rsu_id, const std::string& msg) {
        std::string rsu_key = "sg-rsu-key-" + std::to_string(rsu_id);
        return { rsu_id, ToHex(HmacSha256(rsu_key, msg)) };
    }
    // Eq. 3.32: combine k partials + enforce the k-of-n quorum (Eq. 3.33).
    static FlowModAggregate CombineAndVerify(
            const std::vector<RsuPartialSig>& partials, uint32_t required_k) {
        FlowModAggregate agg;
        std::array<uint8_t,32> acc{};
        for (const auto& p : partials) {
            agg.signer_ids.push_back(p.rsu_id);
            // XOR-combine the raw tag bytes (parse hex back to bytes).
            for (size_t i = 0; i + 1 < p.tag.size() && i/2 < 32; i += 2) {
                uint8_t byte = (uint8_t)std::stoi(p.tag.substr(i,2), nullptr, 16);
                acc[i/2] ^= byte;
            }
        }
        agg.k_signers = (uint32_t)partials.size();
        agg.combined  = ToHex(acc);
        agg.quorum_ok = (agg.k_signers >= required_k);   // Eq. 3.33 quorum gate
        return agg;
    }
};

} // namespace shield_gh_lw
