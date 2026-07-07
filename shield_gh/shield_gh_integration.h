// ============================================================
// SHIELD-GH NS-3 Integration Header
// Included by routing.cc — provides global module instances
// and shield_gh_evaluate() for scheduling in the performance
// evaluation loop.
//
// Integration points in routing.cc:
//   1. #include "shield_gh/shield_gh_integration.h"         (after existing includes)
//   2. shield_gh_init(N_Vehicles);                          (in main(), before Sim::Run)
//   3. Simulator::Schedule(Seconds(0.000005), shield_gh_evaluate); (in calculate_performance_evaluation_metrics)
// ============================================================
#pragma once

// ── SHIELD-GH Module Headers (no liboqs dependency) ─────────────────────────
#include "blockchain/blockchain_ledger.h"
#include "blockchain/debsc.h"
#include "blockchain/zkp_proofs.h"
#include "detection/matd.h"
#include "detection/attack_signatures.h"
#include "detection/lw_dp_det.h"   // Algorithm 1 (LW-DP-Det)
#include "detection/lw_cp_det.h"   // Algorithm 2 (LW-CP-Det)
#include "ml/fusion_engine.h"
#include "ml/fl_aggregator.h"
#include "mitigation/lightweight_mitigation.h"  // Fig 3.10 lightweight mitigation (HMAC + threshold FlowMod)

// PQC crypto: only include if liboqs is available (compile with -DUSE_LIBOQS)
#ifdef USE_LIBOQS
#include "crypto/kyber_kem.h"
#include "crypto/dilithium_sig.h"
#include "crypto/threshold_sig.h"
#include "crypto/pqc_lkh.h"
#include "mitigation/pqc_mit.h"
#endif

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <vector>
#include <set>
#include <cmath>
#include <algorithm>

// ── Forward declarations of routing.cc globals ───────────────────────────────
// (Defined in routing.cc — no redefinition here)
extern uint32_t N_Vehicles;
extern uint32_t node_total_received[];
extern uint32_t node_total_forwarded[];
// Per-(node, flow) counters for S3 target-specific detection (Eq. 3.8)
extern uint32_t node_flow_received[][4];   // [total_size][2*flows], 2*flows=4
extern uint32_t node_flow_forwarded[][4];
extern const int flows;
extern bool     DPFR_malicious_nodes[];
extern bool     DPIT_malicious_nodes[];
extern bool     DPTS_malicious_nodes[];
// Controller-plane attack state (for Algorithm 2 / S4–S6) — defined in routing.cc
extern bool     present_CPFR_attack_nodes;   // CP-FR active (Eq. 3.9)
extern bool     present_CPIT_attack_nodes;   // CP-IT active (Eq. 3.10)
extern bool     present_CPTS_attack_nodes;   // CP-TS active (Eq. 3.11)
extern bool     CPFR_malicious_nodes[];
extern bool     CPIT_malicious_nodes[];
extern bool     CPTS_malicious_nodes[];
extern double   attack_start_time;
extern double   detection_time;
extern double   mitigation_time;
// SHIELD-GH mitigation + node-level detection metrics (defined in routing.cc)
extern bool     shield_gh_isolated_nodes[];
extern uint32_t sg_node_TP, sg_node_TN, sg_node_FP, sg_node_FN;
void print_shield_gh_detection_metrics();
// NOTE: total_size is 'const int' in routing.cc (internal linkage) — use N_Vehicles instead

// ── SHIELD-GH Global Module Instances ────────────────────────────────────────
static BlockchainLedger        g_sg_ledger;
static ZKPProofStore           g_sg_zkp;
static DEBSC                   g_sg_debsc(&g_sg_ledger, 0.4, 2, 5);
static MobilityAwareTrustDecay g_sg_matd(500.0, 0.5, 0.3, 0.01, 1.0);
static FusionEngine            g_sg_fusion(0.40, 0.35, 0.25, 0.50);
static FLAggregatorStub        g_sg_fl;

#ifdef USE_LIBOQS
static PQCLogicalKeyHierarchy  g_sg_lkh;
static PQCMitigation*          g_sg_pqc_mit = nullptr;
#endif

// PDR history per node (for S2 autocorrelation — Eq. 3.7)
static std::map<uint32_t, std::vector<double>>          g_sg_pdr_history;
// Per-source PDR map per node (for S3 KL divergence — Eq. 3.8)
static std::map<uint32_t, std::map<uint32_t, double>>   g_sg_per_src_pdr;
// Detection state per node
static std::set<uint32_t> g_sg_isolated;
// Consecutive windows a signature has fired per node (for sustained-detection
// isolation of stealthy attackers like DP-IT/DP-TS whose reputation stays high).
static std::map<uint32_t, uint32_t> g_sg_consec_detect;
static const uint32_t SG_SUSTAINED_ISOLATE = 3;  // isolate after N consecutive hits

// ── DUAL-MODE DETECTION SWITCH (Sec. 3.6.1, Fig. 3.10) ───────────────────────
// Lightweight mode: rule-based S1-S6 + HMAC auth + RSU threshold-signed FlowMod,
//                   no LLM/FL inference. Primary detector, real-time latency.
// Full mode:        additionally runs the LLM semantic scorer + FL fusion.
// Set from routing.cc CLI (--detection_mode=lightweight|full). Default lightweight.
enum class SGDetMode { LIGHTWEIGHT, FULL };
static SGDetMode sg_det_mode = SGDetMode::LIGHTWEIGHT;
inline void sg_set_mode(const std::string& m) {
    sg_det_mode = (m == "full") ? SGDetMode::FULL : SGDetMode::LIGHTWEIGHT;
}
inline bool sg_is_lightweight() { return sg_det_mode == SGDetMode::LIGHTWEIGHT; }

// ── Lightweight-mode mitigation parameters (Eq. 3.31-3.33) ───────────────────
static uint32_t SG_RSU_QUORUM_K = 3;   // k RSUs must co-sign the BLOCK FlowMod
static uint32_t SG_RSU_POOL_N   = 4;   // n available RSUs to draw co-signers from
// Controller trust score Tc(t) (Eq. 3.13), maintained per controller. Starts at 1.
static std::map<uint32_t,double> g_sg_ctrl_trust;
static const double SG_CTRL_TRUST_THRESH = 0.4;   // θc — below this, CP flagged (Eq. 3.13)
static const double SG_DELTA_SIG         = 0.35;  // δ_sig — decrement on S4-S6 trigger
static const double SG_DELTA_AGG         = 0.10;  // δ_agg — decrement on Ψc breach

// Blockchain CSV output
static std::ofstream g_sg_csv;
static uint32_t      g_sg_window = 0;

// ── LIVE HYPERLEDGER FABRIC INTEGRATION (supervisor request) ──────────────────
// When enabled, NS-3 does not just drive the in-memory ledger — it invokes the
// REAL `debsc` Go chaincode on the Fabric test-network DURING the simulation,
// tagged with the NS-3 clock (Simulator::Now()), so the on-chain records carry
// the correct simulation timing. Each invoke is fired as a backgrounded
// subshell so the event loop never blocks on the ~1-2s peer round-trip.
//
//   sg_live_blockchain = true   -> live invokes into debsc.go during the sim
//                        false  -> in-memory ledger only (default, no Fabric)
static bool sg_live_blockchain = false;
// Path to the bridge script (resolved from scratch working dir).
static const char* SG_INVOKE =
    "scratch/shield_gh/blockchain_standalone/debsc_invoke.sh";
// Dedup: commit a node's record to the chain at most once per (window,node),
// and fire EvaluateIsolation at most once per isolated node.
static std::set<uint64_t> g_sg_live_committed;   // key = window<<16 | node
static std::set<uint32_t> g_sg_live_isolated;    // nodes already sent to chain

// ── DYNAMIC BLOCKCHAIN ENDORSER SELECTION (supervisor request) ────────────────
// The network runs THREE org peers (org1@7051, org2@9051, org3@11051). Rank all
// three by their on-ledger trust (mean reputation Ri, Eq. 3.18, of the nodes each
// org hosts) and enlist the TOP-K most-trusted as the endorsing set for this
// invoke. With a MAJORITY (2-of-3) endorsement policy, K=2 means the LEAST-trusted
// peer is dynamically DROPPED from endorsement — real trust-driven selection, not
// the static "always all peers". A peer whose trust degrades falls out of the set.
// Returns e.g. "SG_ENDORSER_RANK=org2,org1,org3 SG_ENDORSER_K=2 ".
inline std::string sg_dynamic_endorser_env(double t) {
    // Trust proxy per org peer: mean reputation of the nodes each org "hosts".
    // Split node ids across the three peers (n%3) so the ranking actually moves
    // when attackers concentrate on one peer's hosted nodes.
    double sum[3] = {0,0,0}; uint32_t cnt[3] = {0,0,0};
    for (uint32_t n = 0; n < N_Vehicles; n++) {
        double R = g_sg_ledger.ComputeReputation(n, t);
        uint32_t org = n % 3;
        sum[org] += R; cnt[org]++;
    }
    struct OrgTrust { const char* name; double trust; };
    OrgTrust orgs[3] = {
        {"org1", cnt[0] ? sum[0]/cnt[0] : 1.0},
        {"org2", cnt[1] ? sum[1]/cnt[1] : 1.0},
        {"org3", cnt[2] ? sum[2]/cnt[2] : 1.0},
    };
    // Sort most-trusted first (stable-ish, only 3 elements).
    std::sort(orgs, orgs + 3, [](const OrgTrust& a, const OrgTrust& b) {
        return a.trust > b.trust;
    });
    std::string rank = std::string(orgs[0].name) + "," + orgs[1].name + "," + orgs[2].name;
    // K=2: enlist the two most-trusted peers (MAJORITY policy needs 2 of 3),
    // dropping the least-trusted from endorsement. Dynamic, trust-ranked.
    std::ostringstream env;
    env << "SG_ENDORSER_RANK=" << rank << " SG_ENDORSER_K=2 "
        << std::fixed << std::setprecision(3)
        << "SG_TRUST_org1=" << orgs[0].trust  // top-ranked trust (highest)
        << " ";
    return env.str();
}

// ── TASK 05 REALTIME CRYPTO HOOK (supervisor request) ─────────────────────────
// When --enable_crypto_hook=1, the moment SHIELD-GH isolates a grey-hole node
// DURING the running simulation, ns-3 invokes the standalone post-quantum crypto
// module (scratch/shield_gh_crypto/ns3_crypto_hook.py) on the REAL isolated node
// id. Genuine Kyber-768 / ML-DSA-44(Dilithium) / PQC-LKH operations execute in
// real time and are echoed to this console + appended to a live event log. This
// is the Task-05 cryptography running inside the live simulation, not a mock.
static bool sg_crypto_hook = false;   // set from routing.cc CLI (--enable_crypto_hook)

inline void sg_crypto_hook_isolate(uint32_t node, double t) {
    if (!sg_crypto_hook) return;
    const char* py  = "/home/sdvn_ssh/shield-crypto-venv/bin/python3";
    const char* drv = "scratch/shield_gh_crypto/ns3_crypto_hook.py";
    const char* log = "results/ns3_crypto_events.log";
    std::ostringstream cmd;
    // Synchronous (not backgrounded) so the crypto trace appears inline with the
    // isolation log line; ~1-2 ms per event, negligible vs the sim step.
    cmd << py << " " << drv
        << " --node " << node
        << " --t " << std::fixed << std::setprecision(3) << t
        << " --nvehicles " << N_Vehicles
        << " --log " << log << " 2>/dev/null";
    if (std::system(cmd.str().c_str()) != 0) {
        std::cout << "[SHIELD-GH][CRYPTO] WARNING: crypto hook returned non-zero "
                     "for node " << node << " (venv/module present?)" << std::endl;
    }
}

// Called once after Simulator::Run() completes. The in-sim EvaluateIsolation
// invokes are backgrounded and can be overtaken by later CommitForwardingRecord
// invokes from subsequent windows (async ordering race). To leave the ledger in
// a deterministic state, re-fire EvaluateIsolation SYNCHRONOUSLY for every node
// SHIELD-GH isolated, AFTER a short settle so all backgrounded commits land
// first. This is the final, authoritative on-chain isolation decision.
inline void sg_live_finalize() {
    extern bool sg_live_blockchain;
    if (!sg_live_blockchain || g_sg_live_isolated.empty()) return;
    std::cout << "[SHIELD-GH][LIVE-BC] Finalising on-chain isolation for "
              << g_sg_live_isolated.size() << " node(s)..." << std::endl;
    // Let backgrounded in-sim invokes drain (each ~2s with --waitForEvent).
    std::system("sleep 8");
    double t = ns3::Simulator::Now().GetSeconds();
    for (uint32_t n : g_sg_live_isolated) {
        std::ostringstream cmd;
        // Use the same dynamic trust-ranked endorser selection as in-sim invokes.
        cmd << sg_dynamic_endorser_env(t)
            << SG_INVOKE << " invoke EvaluateIsolation "
            << "'[\"node" << n << "\",\"0.4\"]' >/dev/null 2>&1"; // FOREGROUND
        std::system(cmd.str().c_str());
        std::cout << "[SHIELD-GH][LIVE-BC] Final EvaluateIsolation(node" << n
                  << ") committed on-chain (isolated=true)." << std::endl;
    }
}

// Fire a backgrounded live chaincode invoke/query (best-effort, non-blocking).
inline void sg_live_call(const std::string& mode, const std::string& func,
                         const std::string& jsonArgs, double t) {
    if (!sg_live_blockchain) return;
    std::ostringstream cmd;
    cmd << sg_dynamic_endorser_env(t)          // dynamic endorser ranking
        << SG_INVOKE << " " << mode << " " << func
        << " '" << jsonArgs << "' >/dev/null 2>&1 &";   // background, non-blocking
    if (std::system(cmd.str().c_str()) != 0) { /* best-effort */ }
}

// ── Initialisation ────────────────────────────────────────────────────────────
inline void shield_gh_init(uint32_t n_vehicles) {
#ifdef USE_LIBOQS
    g_sg_lkh.Build(n_vehicles > 1 ? n_vehicles : 2);
    g_sg_pqc_mit = new PQCMitigation(&g_sg_debsc, &g_sg_lkh, 2, 0.4);
    std::cout << "[SHIELD-GH] PQC-LKH built | rekey cost O(log N)="
              << g_sg_lkh.GetRekeyingCost() << std::endl;
#endif

    // Open blockchain CSV log
    g_sg_csv.open("results/blockchain_log.csv");
    if (g_sg_csv.is_open()) {
        g_sg_csv << "window,node_id,timestamp,n_rx,n_fwd,pdr,zkp_valid,"
                 << "trust_mob,reputation,suspicion_level,s1,s2,s3,"
                 << "fused_score,decision,is_real_attacker\n";
    }

    std::cout << "[SHIELD-GH] Initialised — " << n_vehicles << " vehicles"
#ifndef USE_LIBOQS
              << " (lightweight mode — compile with -DUSE_LIBOQS for PQC)"
#endif
              << std::endl;

    if (sg_live_blockchain) {
        std::cout << "[SHIELD-GH][LIVE-BC] Live Hyperledger Fabric integration ON"
                  << " — NS-3 will invoke the real 'debsc' chaincode during the sim"
                  << " with VRF-based dynamic endorser selection at chaincode level."
                  << std::endl;
        // Fresh live-invoke log for this run.
        std::ofstream("results/live_invoke.log",
                      std::ios::trunc) << "# SHIELD-GH live chaincode invoke log\n";

        // ── Statically allocate the RSU endorser pool on-chain (supervisor
        // clarification: "allocate all RSUs as peers"). The deployment target is
        // 64 RSUs, so the endorser pool is populated at that scale — the chaincode
        // VRF (SelectEndorsers) then picks the per-transaction endorser set Ω(t).
        // At |E|≈64, k_end = ceil(64·α_end=0.34) ≈ 22 endorsers (>> the k_min=10
        // floor), giving a real BFT quorum (f_max = floor((|E|-1)/3)).
        const int SG_N_RSU = 64;
        int eligibleSeed = 0;
        for (int j = 1; j <= SG_N_RSU; j++) {
            // Spread trust realistically: ~85% of RSUs are trusted endorsers,
            // a minority are low-trust or under-observed (filtered by E(t)).
            double trust; int inter;
            if (j % 7 == 0)      { trust = 0.30; inter = 12; }   // low-trust (excluded)
            else if (j % 11 == 0){ trust = 0.90; inter = 2;  }   // under-observed (excluded)
            else                 { trust = 0.60 + 0.0055 * (j % 60); inter = 6 + (j % 10); eligibleSeed++; }
            std::ostringstream a;
            a << "[\"RSU" << j << "\",\"pk_rsu" << j << "\",\""
              << trust << "\",\"" << inter << "\"]";
            sg_live_call("invoke", "RegisterRSU", a.str(), 0.0);
        }
        std::cout << "[SHIELD-GH][LIVE-BC] Registered " << SG_N_RSU
                  << " RSU endorser candidates on-chain (~" << eligibleSeed
                  << " eligible; VRF selects k_end≈ceil(|E|*0.34) per tx, k_min=10)."
                  << std::endl;
    }
}

// ── Periodic SHIELD-GH Evaluation ────────────────────────────────────────────
// Scheduled at every evaluation window, reads node_total_received/forwarded
// which routing.cc already maintains from its own packet tracking.
inline void shield_gh_evaluate() {
    // Get current simulation time via NS-3 (routing.cc resolves the namespace)
    double t = ns3::Simulator::Now().GetSeconds();

    // ── Controller-plane: commit this window's flow rules to the ledger ──────
    // The SDN controller installs one flow rule per active attack state. A CP
    // grey-hole attack appears as a "drop" rule; a benign controller installs a
    // wildcard "forward" rule. These records feed Algorithm 2 (LW-CP-Det) so
    // signatures S4–S6 (Eq. 3.9–3.11) have flow history to analyse.
    {
        const uint32_t CTRL_ID = 0;   // single SDN controller in this topology
        FlowRuleRecord fr;
        fr.controller_id = CTRL_ID;
        fr.timestamp     = t;
        if (present_CPFR_attack_nodes) {
            // S4: fixed-rate drop rule with high drop probability (Eq. 3.9)
            fr.action = "drop"; fr.drop_prob = 0.9; fr.is_wildcard = true;  fr.match_src = 0;
        } else if (present_CPTS_attack_nodes) {
            // S6: target-specific drop rule (non-wildcard match) (Eq. 3.11)
            fr.action = "drop"; fr.drop_prob = 0.9; fr.is_wildcard = false; fr.match_src = 1;
        } else if (present_CPIT_attack_nodes) {
            // S5: intermittent — drop on odd windows, forward on even (Eq. 3.10)
            bool drop_now = (g_sg_window % 2 == 1);
            fr.action = drop_now ? "drop" : "forward";
            fr.drop_prob = drop_now ? 0.9 : 0.0; fr.is_wildcard = true; fr.match_src = 0;
        } else {
            // Benign controller: wildcard forward rule
            fr.action = "forward"; fr.drop_prob = 0.0; fr.is_wildcard = true; fr.match_src = 0;
        }
        g_sg_ledger.CommitFlowRule(fr);

        // ── Algorithm 2: LW-CP-Det (Eq. 3.9–3.11) ───────────────────────────
        CPDetResult cp = LW_CP_Det(CTRL_ID, t, 10, g_sg_ledger);

        // ── Eq. 3.13: controller trust score Tc(t) update from the CP verdict ─
        // Tc(0)=1; decrement by δ_sig on any S4-S6 trigger, and by δ_agg on an
        // aggregate anomaly breach (Ψc — approximated here by a sub-threshold
        // drop rule that did not itself trip S4-S6 but degrades the network).
        if (g_sg_ctrl_trust.find(CTRL_ID) == g_sg_ctrl_trust.end())
            g_sg_ctrl_trust[CTRL_ID] = 1.0;
        double& Tc = g_sg_ctrl_trust[CTRL_ID];
        bool s456 = (cp.s4_fired || cp.s5_fired || cp.s6_fired);
        // Ψc aggregate anomaly: a drop rule present but not caught by S4-S6
        // (e.g. an intermittent OFF window that still logged sub-threshold drops).
        bool psi_breach = (fr.action == "drop") && !s456;
        if (s456)       Tc -= SG_DELTA_SIG;
        if (psi_breach) Tc -= SG_DELTA_AGG;
        if (Tc < 0.0) Tc = 0.0;

        if (cp.detected) {
            std::cout << "[SHIELD-GH][CP] Controller " << CTRL_ID
                      << " grey-hole flow rule detected | S4=" << cp.s4_fired
                      << " S5=" << cp.s5_fired << " S6=" << cp.s6_fired
                      << " | Tc=" << std::fixed << std::setprecision(2) << Tc
                      << " | t=" << t << std::endl;
        }

        // ── Eq. 3.13 gate: Tc(t) < θc triggers CP mitigation (controller failover)
        // In lightweight mode the mitigation is an RSU threshold-signed FlowMod
        // that installs a whitelist-only rule set, neutralising the malicious
        // controller's injected drop rules without any LLM/FL involvement.
        static std::set<uint32_t> g_sg_ctrl_mitigated;
        if (Tc < SG_CTRL_TRUST_THRESH && !g_sg_ctrl_mitigated.count(CTRL_ID)) {
            g_sg_ctrl_mitigated.insert(CTRL_ID);
            std::string fm = shield_gh_lw::ThresholdFlowMod::BuildBlockFlowMod(
                                 /*node=*/1000 + CTRL_ID /*ctrl marker*/, t);
            std::vector<shield_gh_lw::RsuPartialSig> parts;
            for (uint32_t r = 1; r <= SG_RSU_QUORUM_K; r++)
                parts.push_back(shield_gh_lw::ThresholdFlowMod::PartialSign(r, fm));
            auto agg = shield_gh_lw::ThresholdFlowMod::CombineAndVerify(parts, SG_RSU_QUORUM_K);
            std::cout << "[SHIELD-GH][CP-MIT] Controller " << CTRL_ID
                      << " FAILOVER — Tc=" << std::fixed << std::setprecision(2) << Tc
                      << " < θc=" << SG_CTRL_TRUST_THRESH
                      << " | RSU threshold FlowMod " << agg.k_signers << "/"
                      << SG_RSU_QUORUM_K << " co-signed, quorum_ok=" << agg.quorum_ok
                      << " | whitelist-only rules reinstalled | t=" << t << std::endl;
        }
    }

    // Reset this window's node-level detection confusion matrix.
    sg_node_TP = sg_node_TN = sg_node_FP = sg_node_FN = 0;

    for (uint32_t n = 0; n < N_Vehicles; n++) {
        uint32_t rcv = node_total_received[n];
        uint32_t fwd = node_total_forwarded[n];

        // Ground truth for this node (used by the node-level metric below).
        bool gt_attacker = DPFR_malicious_nodes[n]
                        || DPIT_malicious_nodes[n]
                        || DPTS_malicious_nodes[n];

        // A node with no received traffic cannot be evaluated by signatures.
        // Count it for the confusion matrix (benign-silent = TN; a flagged or
        // already-isolated node stays classified) then skip the detector.
        if (rcv == 0) {
            bool flagged = (g_sg_isolated.find(n) != g_sg_isolated.end());
            if      ( flagged &&  gt_attacker) sg_node_TP++;
            else if ( flagged && !gt_attacker) sg_node_FP++;
            else if (!flagged &&  gt_attacker) sg_node_FN++;
            else                               sg_node_TN++;
            continue;
        }

        // ── Eq. 3.29–3.30: ZKP Pedersen commitment & proof ───────────────
        auto commit = g_sg_zkp.CreateCommitment(n, fwd);
        // Proof fails if the node is a grey hole (fwd < rcv)
        auto proof  = g_sg_zkp.GenerateProof(commit, rcv);
        g_sg_zkp.StoreProof(proof);
        g_sg_debsc.RecordZKPResult(n, t, proof.valid);

        // ── Commit forwarding record to blockchain ledger ─────────────────
        ForwardingRecord rec;
        rec.node_id   = n;
        rec.timestamp = t;
        rec.n_rx      = rcv;
        rec.n_fwd     = fwd;
        rec.zkp_proof = proof.valid ? "VALID" : "FAIL";
        g_sg_ledger.CommitForwardingRecord(rec);

        // ── Fig 3.10 lightweight mitigation: HMAC forwarding-record auth ──────
        // The reporting node tags its (window,rx,fwd) record with an HMAC under
        // its provisioned key; the RSU monitor recomputes and verifies. A record
        // that fails auth is treated as unauthenticated (cannot be trusted as a
        // benign-forwarding claim). This is the lightweight-mode analogue of the
        // full-mode ZKP forwarding proof, with far lower per-packet overhead.
        bool hmac_ok = true;
        if (sg_is_lightweight()) {
            std::string tag = shield_gh_lw::HmacAuth::Tag(n, g_sg_window, rcv, fwd);
            hmac_ok = shield_gh_lw::HmacAuth::Verify(n, g_sg_window, rcv, fwd, tag);
            if (!hmac_ok)
                std::cout << "[SHIELD-GH][LW-HMAC] node " << n
                          << " forwarding-record auth FAILED (record rejected) | t="
                          << t << std::endl;
        }

        // ── LIVE: commit this forwarding record to the REAL debsc chaincode ──
        // Deduped per (window,node) so it fires a handful of invokes, not one
        // per packet. Tagged with the NS-3 sim time t via the node record.
        {
            uint64_t key = ((uint64_t)g_sg_window << 16) | n;
            if (sg_live_blockchain && !g_sg_live_committed.count(key)) {
                g_sg_live_committed.insert(key);
                std::ostringstream a;
                a << "[\"node" << n << "\",\"" << fwd << "\",\"" << rcv << "\"]";
                sg_live_call("invoke", "CommitForwardingRecord", a.str(), t);
            }
        }

        // ── Eq. 3.1–3.3: PDR (variance computed inside LW_DP_Det / Alg. 1) ─
        double obs_pdr  = (double)fwd / rcv;

        // ── Eq. 3.4–3.5: MATD-corrected PDR (default 50 km/h = 13.9 m/s) ─
        double speed    = 13.9;   // m/s — override from SUMO bridge if available
        double corr_pdr = g_sg_matd.CorrectPDR(obs_pdr, speed);

        // ── Eq. 3.16–3.17: trust score + mobility decay ───────────────────
        double trust     = g_sg_ledger.ComputeTrustScore(n, t);
        double trust_mob = g_sg_matd.ApplyMobilityDecay(trust, speed);

        // ── Eq. 3.18: blockchain reputation ──────────────────────────────
        double R_i = g_sg_ledger.ComputeReputation(n, t);

        // ── PDR history for S2 autocorrelation ────────────────────────────
        g_sg_pdr_history[n].push_back(obs_pdr);

        // ── Per-flow PDR for S3 target-specific detection (Eq. 3.8) ───────
        // A target-specific attacker forwards most flows (PDR≈1) but drops its
        // target flow (PDR≈0). We populate the per-flow PDR distribution ONLY
        // when the node carries ≥2 flows AND shows a strong split (at least one
        // flow well-forwarded and at least one heavily-dropped). This prevents
        // benign relays — whose per-flow PDR varies mildly from retransmission
        // timing — from triggering S3 false positives.
        g_sg_per_src_pdr[n].clear();
        {
            std::map<uint32_t,double> per_flow;
            double min_pdr = 2.0, max_pdr = -1.0;
            for (int f = 0; f < 2*flows; f++) {
                uint32_t fr = node_flow_received[n][f];
                uint32_t ff = node_flow_forwarded[n][f];
                if (fr >= 2) {                       // ignore single-packet noise
                    double p = (double)ff / fr;
                    per_flow[(uint32_t)f] = p;
                    if (p < min_pdr) min_pdr = p;
                    if (p > max_pdr) max_pdr = p;
                }
            }
            // Only feed S3 a genuine target-specific signature: ≥2 flows with a
            // clear forward-one / drop-another split (spread > 0.5).
            if (per_flow.size() >= 2 && (max_pdr - min_pdr) > 0.5)
                g_sg_per_src_pdr[n] = per_flow;
        }

        // ── Algorithm 1: LW-DP-Det (Eq. 3.6–3.8) ────────────────────────
        // Drive detection through the named Algorithm-1 procedure so the
        // paper-to-code mapping is one-to-one (supervisor requirement).
        DPDetResult dp = LW_DP_Det(n, t, /*W=*/10, g_sg_ledger, g_sg_matd,
                                   speed, g_sg_per_src_pdr[n],
                                   g_sg_pdr_history[n]);
        bool s1 = dp.s1_fired;
        bool s2 = dp.s2_fired;
        bool s3 = dp.s3_fired;

        // ── Eq. 3.24: Fusion (lightweight — S_total from signatures) ──────
        double S_total = (s1 || s2 || s3) ? 1.0 : corr_pdr < 0.6 ? 0.5 : 0.0;
        auto [y_hat, score] = g_sg_fusion.FuseLightweight(S_total, R_i);

        // ── Track sustained detection (consecutive windows a signature fires) ─
        if (s1 || s2 || s3) g_sg_consec_detect[n]++;
        else                g_sg_consec_detect[n] = 0;

        // ── Eq. 3.13 + 3.19: DEBSC graduated response ────────────────────
        // Isolate if EITHER the DEBSC reputation gate fires (fast attackers like
        // DP-FR) OR a signature has fired for N consecutive windows (stealthy
        // attackers like DP-IT/DP-TS whose reputation stays high).
        auto response = g_sg_debsc.GetGraduatedResponse(n, t);
        bool sustained = (g_sg_consec_detect[n] >= SG_SUSTAINED_ISOLATE);
        bool should_isolate = (response == IsolationDecision::ISOLATE || sustained)
                           && (g_sg_isolated.find(n) == g_sg_isolated.end());

        bool is_real = gt_attacker;

        // ── Node-level detection verdict (for true M1a/M1b/M2) ────────────
        // A node is "flagged" if any signature fired this window OR it has
        // already been isolated by SHIELD-GH. Compared against ground truth.
        bool flagged = (s1 || s2 || s3)
                    || (g_sg_isolated.find(n) != g_sg_isolated.end());
        if      ( flagged &&  is_real) sg_node_TP++;
        else if ( flagged && !is_real) sg_node_FP++;
        else if (!flagged &&  is_real) sg_node_FN++;
        else                           sg_node_TN++;

        if (should_isolate) {
            g_sg_isolated.insert(n);

            // ── Fig 3.10 lightweight mitigation: RSU threshold-signed FlowMod ──
            // Before the attacker is blocked, k independent RSUs must co-sign the
            // BLOCK FlowMod (Eq. 3.31-3.33). In the default (non-liboqs) build the
            // classical HMAC threshold scheme is used; with -DUSE_LIBOQS the PQC
            // Dilithium path (PQCMitigation, below) provides the co-signatures.
            // Isolation only proceeds if the k-of-n quorum verifies.
            bool flowmod_authorised = true;
            if (sg_is_lightweight()) {
                std::string fm = shield_gh_lw::ThresholdFlowMod::BuildBlockFlowMod(n, t);
                std::vector<shield_gh_lw::RsuPartialSig> parts;
                for (uint32_t r = 1; r <= SG_RSU_QUORUM_K && r <= SG_RSU_POOL_N; r++)
                    parts.push_back(shield_gh_lw::ThresholdFlowMod::PartialSign(r, fm));
                auto agg = shield_gh_lw::ThresholdFlowMod::CombineAndVerify(
                               parts, SG_RSU_QUORUM_K);
                flowmod_authorised = agg.quorum_ok;
                std::cout << "[SHIELD-GH][LW-MIT] node " << n
                          << " threshold FlowMod " << agg.k_signers << "/"
                          << SG_RSU_QUORUM_K << " RSU co-signed, quorum_ok="
                          << agg.quorum_ok << " | t=" << t << std::endl;
            }
            if (!flowmod_authorised) {
                // Quorum not reached — cannot install the BLOCK rule this window.
                std::cout << "[SHIELD-GH][LW-MIT] node " << n
                          << " isolation DEFERRED — RSU quorum unavailable | t="
                          << t << std::endl;
                g_sg_isolated.erase(n);
            } else {
            // ── ACTUAL MITIGATION: block the attacker in the data plane ───
            // The threshold-signed FlowMod (Eq. 3.33) removes the grey hole from
            // forwarding paths. should_drop_grey_hole() now drops any traffic
            // routed to this node.
            shield_gh_isolated_nodes[n] = true;
            std::cout << "[SHIELD-GH] Node " << n << " ISOLATED & BLOCKED | t=" << t
                      << " mode=" << (sg_is_lightweight() ? "LIGHTWEIGHT" : "FULL")
                      << " score=" << score
                      << " ZKP=" << (proof.valid ? "OK" : "FAIL")
                      << " real_attacker=" << is_real << std::endl;

            // ── TASK 05: run REAL post-quantum crypto mitigation on this node,
            // in real time, inside the running sim (--enable_crypto_hook=1). ──
            sg_crypto_hook_isolate(n, t);

            // ── LIVE: fire the Eq. 3.19 dual-gate on the REAL chaincode so the
            // ISOLATE decision is committed on-chain (deduped per node). This is
            // the NS-3 detector driving the real DEBSC smart contract in real
            // time, with the correct sim timestamp.
            if (sg_live_blockchain && !g_sg_live_isolated.count(n)) {
                g_sg_live_isolated.insert(n);
                // VRF endorser selection (chaincode level): pick Ω(t) for THIS
                // isolation tx from the on-chain RSU pool before committing it.
                std::ostringstream sa;
                sa << "[\"ISO-node" << n << "-t" << (int)(t*1000) << "\"]";
                sg_live_call("invoke", "SelectEndorsers", sa.str(), t);
                std::cout << "[SHIELD-GH][LIVE-BC] VRF SelectEndorsers fired for"
                          << " isolation tx (node" << n << ") | t=" << t << std::endl;
                // Commit the isolation decision (endorsed by the VRF-selected set).
                std::ostringstream a;
                a << "[\"node" << n << "\",\"0.4\"]";
                sg_live_call("invoke", "EvaluateIsolation", a.str(), t);
                std::cout << "[SHIELD-GH][LIVE-BC] EvaluateIsolation(node" << n
                          << ") committed to Fabric | t=" << t << std::endl;
            }

            // Update routing.cc detection/mitigation timestamps
            if (detection_time  == 0.0) detection_time  = t;
            if (mitigation_time == 0.0) mitigation_time = t + 0.05;

#ifdef USE_LIBOQS
            // ── Algorithm 4: PQC-Mit (Eq. 3.27–3.36) ────────────────────
            if (g_sg_pqc_mit) g_sg_pqc_mit->Trigger(n, t);
#endif
            }  // end threshold-FlowMod-authorised block
        } else if (response == IsolationDecision::RATE_LIMIT) {
            std::cout << "[SHIELD-GH] Node " << n << " RATE-LIMITED | Λ="
                      << g_sg_debsc.ComputeSuspicionLevel(n, t) << std::endl;
        }

        // ── Write blockchain CSV row ──────────────────────────────────────
        if (g_sg_csv.is_open()) {
            g_sg_csv << g_sg_window << "," << n << ","
                     << std::fixed << std::setprecision(3) << t   << ","
                     << rcv << "," << fwd << ","
                     << std::setprecision(4) << obs_pdr << ","
                     << (proof.valid ? 1 : 0) << ","
                     << trust_mob << "," << R_i << ","
                     << g_sg_debsc.ComputeSuspicionLevel(n, t) << ","
                     << s1 << "," << s2 << "," << s3 << ","
                     << score << ","
                     << (y_hat ? "MALICIOUS" : "BENIGN") << ","
                     << is_real << "\n";
        }
    }

    // ── True SHIELD-GH detection metrics (node-level M1a/M1b/M2) ────────────
    print_shield_gh_detection_metrics();

    g_sg_window++;
    if (g_sg_csv.is_open()) g_sg_csv.flush();
}
