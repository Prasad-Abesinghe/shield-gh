// ─────────────────────────────────────────────────────────────────────────────
//  SHIELD-GH full-mode AI bridge (Task 8: NS-3 <-> LLM+FL integration)
//
//  File-based bridge between the running NS-3 simulation and the Python full-mode
//  detection pipeline (shield_gh_ml/ns3_infer.py), using the SAME system() pattern
//  proven by the Gurobi optimisation calls in routing.cc.
//
//  Flow (per evaluation window, in FULL mode):
//    1. NS-3 collects each vehicle's forwarding window  -> SgAiWindow
//    2. sg_ai_dump_window()  writes /tmp/shieldgh_window.jsonl
//    3. sg_ai_run_bridge()   system()-calls ns3_infer.py (LLM Q_i + rule S_total
//                            + reputation -> fused verdict ŷ_i, Eq. 3.29)
//    4. sg_ai_read_verdicts() parses /tmp/shieldgh_verdict.json -> ŷ_i per node
//    5. the caller drives sg_node_TP/TN/FP/FN from ŷ_i vs ground truth (M1 MCC)
//
//  No modeling is bypassed: real NS-3 window data in, genuine three-way fusion
//  verdict out, real MCC measured. Latency of the system() call is timed with
//  std::chrono so the per-window inference cost is reported inside the sim.
// ─────────────────────────────────────────────────────────────────────────────
#ifndef SHIELD_GH_AI_BRIDGE_H
#define SHIELD_GH_AI_BRIDGE_H

#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <chrono>
#include <iostream>

// One vehicle's forwarding window, as the NS-3 side sees it.
struct SgAiWindow {
    uint32_t node;
    bool     gt_attacker;             // ground truth (for the confusion matrix)
    uint32_t rcv;
    uint32_t fwd;
    double   reputation;              // R_i (proxy = long-run forwarding ratio)
    double   speed;                   // m/s (from SUMO bridge if available)
    bool     rule_drop;               // controller installed a drop rule (CP)
    double   s_total;                 // rule signature already computed by NS-3
    // per-source forwarded/dropped counts (for DP-TS targeting in the tokeniser)
    std::map<uint32_t, std::pair<uint32_t,uint32_t>> per_src; // src -> (fwd,drp)
};

// One AI verdict for a node.
struct SgAiVerdict {
    uint32_t node   = 0;
    int      y_hat  = 0;      // fused binary verdict (Eq. 3.29)
    double   q_i    = 0.0;    // LLM semantic score
    double   score  = 0.0;    // fused score
};

// ── Write the per-node windows to the jsonl the bridge consumes ──────────────
inline bool sg_ai_dump_window(const std::vector<SgAiWindow>& wins,
                              const std::string& path) {
    std::ofstream f(path.c_str());
    if (!f.is_open()) {
        std::cout << "[SHIELD-GH][AI] ERROR: cannot open " << path << std::endl;
        return false;
    }
    for (const auto& w : wins) {
        f << "{\"node\":" << w.node
          << ",\"is_attacker\":" << (w.gt_attacker ? 1 : 0)
          << ",\"rcv\":" << w.rcv
          << ",\"fwd\":" << w.fwd
          << ",\"reputation\":" << w.reputation
          << ",\"speed\":" << w.speed
          << ",\"rule\":" << (w.rule_drop ? 1 : 0)
          << ",\"s_total\":" << w.s_total
          << ",\"per_src\":{";
        bool first = true;
        for (const auto& kv : w.per_src) {
            if (!first) f << ",";
            first = false;
            f << "\"" << kv.first << "\":{\"fwd\":" << kv.second.first
              << ",\"drp\":" << kv.second.second << "}";
        }
        f << "}}" << "\n";
    }
    f.close();
    return true;
}

// ── Call the Python full-mode scorer (same pattern as the Gurobi system() calls)
// Returns the wall-clock latency of the call in milliseconds (-1 on failure).
inline double sg_ai_run_bridge(const std::string& python,
                               const std::string& script,
                               const std::string& in_file,
                               const std::string& out_file,
                               bool genuine) {
    std::ostringstream cmd;
    cmd << python << " " << script
        << " --in " << in_file << " --out " << out_file;
    if (genuine) cmd << " --genuine";
    // route the bridge's stderr evidence line into the NS-3 console
    cmd << " 2>&1";
    auto t0 = std::chrono::steady_clock::now();
    int rc = system(cmd.str().c_str());
    auto t1 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    if (rc != 0) {
        std::cout << "[SHIELD-GH][AI] bridge exited rc=" << rc << std::endl;
        return -1.0;
    }
    return ms;
}

// ── Minimal parser for /tmp/shieldgh_verdict.json (only the fields we need) ───
// Avoids adding a JSON dependency to the ns-3 build; the verdict file is written
// by our own ns3_infer.py so the shape is fixed and known.
// pure model inference time (ms) reported by the bridge in the verdict json;
// separates the per-window detection cost from the one-off model-load cost.
inline double sg_ai_read_inference_ms(const std::string& path) {
    std::ifstream f(path.c_str());
    if (!f.is_open()) return -1.0;
    std::stringstream ss; ss << f.rdbuf();
    std::string s = ss.str();
    size_t p = s.find("\"inference_ms\":");
    if (p == std::string::npos) return -1.0;
    return std::strtod(s.c_str() + p + 15, nullptr);
}

inline std::vector<SgAiVerdict> sg_ai_read_verdicts(const std::string& path) {
    std::vector<SgAiVerdict> out;
    std::ifstream f(path.c_str());
    if (!f.is_open()) return out;
    std::stringstream ss; ss << f.rdbuf();
    std::string s = ss.str();
    // Walk each "node": ... object inside the "verdicts" array.
    size_t pos = 0;
    const std::string key = "\"node\":";
    while ((pos = s.find(key, pos)) != std::string::npos) {
        SgAiVerdict v;
        auto grab = [&](const std::string& k, size_t from) -> double {
            size_t p = s.find("\"" + k + "\":", from);
            if (p == std::string::npos) return 0.0;
            p += k.size() + 3;
            return std::strtod(s.c_str() + p, nullptr);
        };
        size_t np = pos + key.size();
        v.node  = (uint32_t) std::strtoul(s.c_str() + np, nullptr, 10);
        // scope the following lookups to this object (until the next "node":)
        size_t next = s.find(key, np);
        // y_hat / q_i / score all appear after node within the same object
        v.y_hat = (int) grab("y_hat", np);
        v.q_i   = grab("q_i", np);
        v.score = grab("score", np);
        out.push_back(v);
        pos = (next == std::string::npos) ? s.size() : next;
    }
    return out;
}

#endif // SHIELD_GH_AI_BRIDGE_H
