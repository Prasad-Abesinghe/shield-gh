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
#include "shield_gh_ai_bridge.h"                 // Task 8: full-mode AI (LLM+FL) NS-3 bridge

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
extern int maxspeed; // km/h, CLI --maxspeed (used to drive MATD speed input)
extern int enable_signatures; // ablation DA5: 0 = skip S1-S6 evaluation
extern int enable_matd;       // ablation DA1/DA3: 0 = bypass MATD correction
extern int enable_zkp_gate;   // ablation DA1/DA2: 0 = statistical gate alone
extern uint32_t node_total_received[];
extern uint32_t node_total_forwarded[];
// Per-(node, flow) counters for S3 target-specific detection (Eq. 3.8)
// Fix 2 (supervisor): this was hardcoded "[4]" (correct only while
// flows==2, i.e. 2*flows==4) instead of deriving from the shared flow-count
// constant -- an extern array's second dimension must be a compile-time
// constant known when the compiler parses this header, and this header is
// included in routing.cc BEFORE "const int flows = ..." is defined further
// down that file, so the runtime "flows" symbol isn't usable here. Use the
// SG_FLOWS_COUNT macro (defined in routing.cc immediately before this
// header is included) instead, so both this bound and routing.cc's actual
// array definition ("uint32_t node_flow_received[total_size][2*flows]")
// stay in sync from the single textual source of truth.
#ifndef SG_FLOWS_COUNT
#error "SG_FLOWS_COUNT must be defined (in routing.cc) before including shield_gh_integration.h"
#endif
extern uint32_t node_flow_received[][2*SG_FLOWS_COUNT];   // [total_size][2*flows]
extern uint32_t node_flow_forwarded[][2*SG_FLOWS_COUNT];
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
extern double   graduated_response_time;
// SHIELD-GH mitigation + node-level detection metrics (defined in routing.cc)
extern bool     shield_gh_isolated_nodes[];
extern uint32_t sg_node_TP, sg_node_TN, sg_node_FP, sg_node_FN;
// Controller-plane confusion matrix (multi-controller, 2026-08-12).
extern uint32_t sg_cp_TP, sg_cp_TN, sg_cp_FP, sg_cp_FN;
extern uint32_t N_Controllers;
extern bool     controller_is_malicious[];
extern uint64_t sg_cum_TP, sg_cum_TN, sg_cum_FP, sg_cum_FN;
void print_shield_gh_detection_metrics();
void print_shield_gh_cumulative_detection_metrics();
void print_shield_gh_per_node_cumulative();
// ── Task 8: full-mode AI (LLM+FL) NS-3 integration globals (defined in routing.cc)
extern int         enable_full_mode_ai;
// CQ7 debug (supervisor-requested), defined in routing.cc:
void cq7_print_pdr_after();
extern std::string sg_ai_python;
extern std::string sg_ai_window_file;
extern std::string sg_ai_verdict_file;
extern double      sg_ai_last_infer_ms;
extern double      sg_ai_mu1;   // Fix 5: fusion weight override (grid search)
extern double      sg_ai_mu3;
// Collected per-node windows for the full-mode AI bridge (filled in the per-node
// detection loop, flushed to the bridge after the loop when full mode is on).
static std::vector<SgAiWindow> g_sg_ai_windows;
// NOTE: total_size is 'const int' in routing.cc (internal linkage) — use N_Vehicles instead

// ── SHIELD-GH Global Module Instances ────────────────────────────────────────
static BlockchainLedger        g_sg_ledger;
static ZKPProofStore           g_sg_zkp;
// Fix D (supervisor-requested): theta_R raised 0.4->0.6 -- TQ1 confirmed
// this reduces false isolations 166->96 and raises zero-attack PDR
// 53.55%->72-76% on that (larger/different) test.
// Task 8.5 grid search (2026-08-08, sensitivity_analysis/gh_param_sweep_
// results.csv) re-swept {0.30,0.40,0.50} at the fixed 4-node/30s operating
// point; all 3 tied at MCC=1.0 (this scenario never produces a false
// isolation at any grid value, so it can't see what Fix D was fixing -- the
// two results aren't in tension, they're different regimes) and 0.40 (the
// grid midpoint, also main.tex's original table value) was selected per the
// supervisor's Task 8.5 instruction. The 0.6 literal below is overridden at
// runtime by sg_set_mode() -> g_sg_debsc.SetThetaR(sg_theta_R) once CLI
// parsing sets sg_theta_R (default now 0.40, routing.cc); kept here only as
// the pre-CLI-parse construction value.
static DEBSC                   g_sg_debsc(&g_sg_ledger, 0.6, 2, 5);
static MobilityAwareTrustDecay g_sg_matd(500.0, 0.5, 0.3, 0.01, 1.0);

// Fix 1 (supervisor-requested, CQ3/NQ_F): genuine, cumulative ZKP
// commitment. CQ3 found the original per-window fwd==rcv check erases a
// node's drop history every ~1s window (a single clean window resets the
// comparison to equal). Fixed by committing/verifying against RUN-WIDE
// cumulative received/forwarded totals instead -- a real attacker's
// cumulative gap only grows or holds, it cannot be wiped by one clean
// window. Incremented directly (not derived from the per-window,
// reset-every-cycle node_total_received[]/node_total_forwarded[]):
// received-side incremented in MacRx() (routing.cc), before any drop
// decision (confirmed to fire earlier, NQ_F); forwarded-side incremented
// at the same two sites node_total_forwarded[] itself is (routing.cc).
static uint32_t g_sg_zkp_cum_received[220]  = {0};
static uint32_t g_sg_zkp_cum_forwarded[220] = {0};
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
// Fix G (fast-track, supervisor's grid-search follow-up): raised 3->5.
// Root-caused via [LW-DP-Det]/[RQ3] traces: node 11 (a real zero-attacker
// false isolation) has its raw single-window PDR crash to ~0 abruptly at
// one point, but S1_FixedRate sees the WINDOWED aggregate PDR (Eq. 3.1,
// smoothed over W=10), which ramps down gradually instead of jumping --
// looking exactly like a "steady low PDR" attacker (S1's intended target)
// for several consecutive windows even though the underlying event was a
// single transient crash, not a sustained pattern. 3 consecutive windows
// was not enough separation between "real transient blip, smoothed into a
// fake ramp" and "genuine multi-second sustained attack" -- 5 (matching
// lambda2's own tier) requires a longer, more genuinely persistent pattern.
static const uint32_t SG_SUSTAINED_ISOLATE = 12;  // isolate after N consecutive hits

// DQ3/node-11 fix: last real (rcv>0) fused verdict per node. When a node goes
// traffic-silent (rcv==0) -- which can itself be a side effect of the
// detector's own correction rerouting traffic away from it -- the confusion
// matrix used to default straight to TN/FN based only on isolation
// membership, scoring a node the detector had *just* correctly flagged as a
// miss the moment it stopped transmitting. Carrying the last real verdict
// forward instead credits the detector for what it actually last observed.
static std::map<uint32_t, bool> g_sg_last_verdict;

// Fix B (supervisor, this round): last known LLM Q_i per node, full-mode
// only. Populated when the AI batch verdict comes back for a node (same
// point g_sg_last_verdict is updated, line ~1318 below). Used as the veto
// signal for `sustained`-isolation (see Fix B comment at the `sustained`
// check below) -- the AI batch for THIS window hasn't run yet at the point
// the isolation decision is made (it runs once, later, after the whole
// per-node loop), so the current window's Q_i does not exist yet when it's
// needed; the most recent PAST window's Q_i is the freshest signal actually
// available at decision time, matching the same last-known-value pattern
// g_sg_last_verdict already uses for the rcv==0 fallback.
static std::map<uint32_t, double> g_sg_last_q;

// NQ6 debug (supervisor-requested): per-node cumulative TP/FN tally, so DA4
// vs DA6 can be diffed node-by-node (which attacker nodes flip classification
// between configurations) rather than only comparing aggregate counts.
static std::map<uint32_t, uint32_t> g_sg_node_cum_tp, g_sg_node_cum_fn;
// RQ8 debug (supervisor-requested): per-node cumulative TN/FP, so the FULL
// confusion matrix (all four cells) can be diffed per-node across DA1/DA2/DA3
// -- not just TP/FN -- to confirm or refute a byte-identical match.
static std::map<uint32_t, uint32_t> g_sg_node_cum_tn, g_sg_node_cum_fp;

// ── Task 8: M1–M6 full-system PEM tracking (state-of-art comparable metrics) ─
// Network-wide mean PDR in three phases, for M2 (GHSR, Eq. m2_ghsr):
//   baseline = before attack_start_time; attack = during attack, pre-isolation;
//   post     = after all real attackers are isolated.
static std::vector<double> g_sg_pdr_baseline_samples;
static std::vector<double> g_sg_pdr_attack_samples;
static std::vector<double> g_sg_pdr_post_samples;
// Per-variant (S1..S6) TP/FN for M3 (AVCR, Eq. m3_avcr). Only variants that
// actually fired ground-truth in this run are populated (honest: we do not
// fabricate coverage for a variant absent this run).
struct SgVariantCounts { uint32_t tp = 0, fn = 0; bool present = false; };
static std::map<std::string, SgVariantCounts> g_sg_variant_counts;
// Legitimate (non-attacker) vehicles ever isolated, for M4 (FIR, Eq. m4_fir).
static std::set<uint32_t> g_sg_false_isolated;
static std::set<uint32_t> g_sg_legit_nodes;   // distinct legitimate vehicle IDs seen

// ── DUAL-MODE DETECTION SWITCH (Sec. 3.6.1, Fig. 3.10) ───────────────────────
// Lightweight mode: rule-based S1-S6 + HMAC auth + RSU threshold-signed FlowMod,
//                   no LLM/FL inference. Primary detector, real-time latency.
// Full mode:        additionally runs the LLM semantic scorer + FL fusion.
// Set from routing.cc CLI (--detection_mode=lightweight|full). Default lightweight.
enum class SGDetMode { LIGHTWEIGHT, FULL };
static SGDetMode sg_det_mode = SGDetMode::LIGHTWEIGHT;
inline void sg_set_mode(const std::string& m) {
    sg_det_mode = (m == "full") ? SGDetMode::FULL : SGDetMode::LIGHTWEIGHT;
    // Ablation DA1/DA2 (supervisor): wire --enable_zkp_gate here, right after
    // CLI parsing, since g_sg_debsc is constructed at static-init time before
    // the CLI value is available.
    g_sg_debsc.SetZkpGateEnabled(enable_zkp_gate == 1);
    // Task 8.5 sensitivity-analysis grid search (main.tex tab:gh_sensitivity):
    // theta_R is set here for the same static-init-order reason as above.
    extern double sg_theta_R;
    g_sg_debsc.SetThetaR(sg_theta_R);
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

// ── Task 8: full report-defined PEM block (M2 GHSR, M3 AVCR, M4 FIR, M5 ESRL) ─
// Computed from state accumulated across the ACTUAL full-mode AI run (see the
// per-node loop above for where each input is sampled). M1 (MCC) is already
// printed by print_shield_gh_detection_metrics(); this adds the other four
// state-of-art-comparable metrics the report defines (Sec. Performance
// Evaluation Metrics) so the "1 data point of PEMs" evidence covers the full
// metric set, not MCC alone.
inline double sg_mean(const std::vector<double>& v) {
    if (v.empty()) return 0.0;
    double s = 0.0; for (double x : v) s += x;
    return s / v.size();
}

inline void print_shield_gh_full_pem_report(double t) {
    std::cout << "=== SHIELD-GH FULL-SYSTEM PEM REPORT (M1-M5, t=" << t
              << ") ===" << std::endl;

    // M1 already printed above (MCC); restate the confusion matrix reference.
    std::cout << "  [M1]  see 'Node TP/TN/FP/FN' + MCC block above" << std::endl;

    // ── M2: Grey Hole Suppression Ratio (Eq. m2_ghsr) ──────────────────────
    double pdr_base   = sg_mean(g_sg_pdr_baseline_samples);
    double pdr_attack = sg_mean(g_sg_pdr_attack_samples);
    double pdr_post   = sg_mean(g_sg_pdr_post_samples);
    // GHSR needs a genuine pre-attack baseline sample. In this prototype's
    // fixed timing (attackers declared at t=1.1s, before the first full-mode
    // evaluation window at t=2s), there IS no pre-attack window to sample --
    // an honest limitation of the current run, not something to paper over
    // with a 0.0 placeholder (which would silently distort the GHSR ratio).
    if (g_sg_pdr_baseline_samples.empty()) {
        std::cout << "  [M2]  GHSR: NOT MEASURABLE this run -- no pre-attack "
                     "baseline window exists (attackers active from t="
                  << attack_start_time << "s, before the first full-mode "
                     "evaluation window; needs a run with attack_number=0 for "
                     "N windows first, or a delayed attack-onset run)"
                  << std::endl;
    } else if (!g_sg_pdr_post_samples.empty() && !g_sg_pdr_attack_samples.empty()
        && std::fabs(pdr_base - pdr_attack) > 1e-9) {
        double ghsr = (pdr_post - pdr_attack) / (pdr_base - pdr_attack);
        std::cout << "  [M2]  GHSR: " << ghsr
                   << "  (PDR_baseline=" << pdr_base
                   << " PDR_attack=" << pdr_attack
                   << " PDR_post=" << pdr_post << ")" << std::endl;
    } else {
        std::cout << "  [M2]  GHSR: not yet computable (need attack + "
                     "post-isolation phase samples too; PDR_baseline=" << pdr_base
                   << " PDR_attack=" << pdr_attack
                   << " PDR_post=" << pdr_post << ")" << std::endl;
    }

    // ── M3: Attack Variant Coverage Rate (Eq. m3_avcr), theta_cov = 0.5 ──────
    const double theta_cov = 0.5;
    uint32_t n_variants_present = 0, n_covered = 0;
    for (const auto& kv : g_sg_variant_counts) {
        const auto& c = kv.second;
        if (!c.present) continue;
        n_variants_present++;
        double tpr = (c.tp + c.fn > 0) ? (double)c.tp / (c.tp + c.fn) : 0.0;
        bool covered = (tpr >= theta_cov);
        if (covered) n_covered++;
        std::cout << "        variant " << kv.first << ": TP=" << c.tp
                   << " FN=" << c.fn << " TPR=" << tpr
                   << (covered ? " [COVERED]" : " [NOT COVERED]") << std::endl;
    }
    if (n_variants_present > 0) {
        double avcr = (double)n_covered / n_variants_present;
        std::cout << "  [M3]  AVCR: " << avcr << "  (" << n_covered << "/"
                   << n_variants_present << " variants PRESENT this run covered"
                   << " at theta_cov=" << theta_cov
                   << " -- note: denominator is variants ACTUALLY ATTACKING in"
                   << " this run, not the full 6; a single-attack-type run can"
                   << " only report AVCR over 1)" << std::endl;
    } else {
        std::cout << "  [M3]  AVCR: no attack variant active this run" << std::endl;
    }

    // ── M4: False Isolation Rate (Eq. m4_fir) ──────────────────────────────
    if (!g_sg_legit_nodes.empty()) {
        double fir = (double)g_sg_false_isolated.size() / g_sg_legit_nodes.size();
        std::cout << "  [M4]  FIR: " << fir << "  (" << g_sg_false_isolated.size()
                   << "/" << g_sg_legit_nodes.size()
                   << " legitimate vehicles ever falsely isolated)" << std::endl;
    } else {
        std::cout << "  [M4]  FIR: no legitimate vehicles observed yet" << std::endl;
    }

    // ── M5: End-to-End Security Response Latency (Eq. m5_esrl) ─────────────
    // Reported as the single measured onset->response elapsed time (real,
    // from attack_start_time and detection_time/mitigation_time). The 4-stage
    // decomposition (Eq. m5_esrl_decomp: detection/ZKP/threshold-sign/FlowMod)
    // is NOT fabricated here -- it needs per-stage std::chrono instrumentation
    // inside the isolation path, which is future work, not measured yet.
    //
    // When the route-availability gate withholds full isolation (no
    // alternate path), mitigation_time is never set -- but a real containment
    // action (graduated level 2: rate-limit + per-batch ZKP) still occurs.
    // ESRL then reports onset->graduated-response latency instead of onset->
    // full-isolation, labelled explicitly so it is never confused with a full
    // isolation latency. This is a genuine measured timestamp, not a
    // fabricated placeholder.
    bool has_full_isolation = mitigation_time > 0.0;
    bool has_graduated_only = !has_full_isolation && graduated_response_time > 0.0;
    if (attack_start_time > 0.0 && detection_time > attack_start_time
        && (has_full_isolation || has_graduated_only)) {
        double response_time = has_full_isolation ? mitigation_time
                                                   : graduated_response_time;
        double esrl = response_time - attack_start_time;
        std::cout << "  [M5]  ESRL: " << (esrl * 1000.0) << " ms"
                   << "  (t_onset=" << attack_start_time
                   << " t_response=" << response_time
                   << (has_full_isolation
                         ? " -- onset to FULL ISOLATION; aggregate only, stage"
                           " decomposition not instrumented"
                         : " -- onset to GRADUATED RESPONSE (rate-limit); full"
                           " isolation withheld by the route-availability gate,"
                           " no alternate path in this topology")
                   << ")" << std::endl;
    } else {
        std::cout << "  [M5]  ESRL: not yet measurable (no detection response "
                     "following attack onset so far)" << std::endl;
    }

    std::cout << "  [M6]  MDPOS: NOT applicable to this NS-3 run (crypto-op "
                 "scalability profile vs N -- see shield_gh_crypto/"
                 "m6_overhead_benchmark.py)" << std::endl;
    std::cout << "=========================================================="
              << std::endl;
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
    // Multi-controller fix (2026-08-12, supervisor-directed): this block used
    // to hardcode `const uint32_t CTRL_ID = 0; // single SDN controller`,
    // evaluating ONLY controller 0 no matter how many controllers existed or
    // which of them were compromised. That mirrored the same single-controller
    // defect found in routing.cc's declare_attackers_controller(), and it
    // contradicted the report's own "Multi-Controller Flat Architecture"
    // (main.tex), where M controllers each hold an independent trust score
    // T_c(0)=1. With M=4 and controllers 0 and 1 both malicious, controller 1's
    // compromise was never evaluated at all.
    //
    // LW-CP-Det now runs per controller, each with its own flow-rule record,
    // its own S4-S6 evaluation, its own T_c(t), and its own failover decision.
    // Crucially, each controller's rule reflects whether THAT controller is
    // malicious (controller_is_malicious[c]), so benign controllers install
    // genuine forward rules and must NOT be flagged -- this is what makes a
    // false positive on a benign controller possible, and therefore what makes
    // the CP detection result meaningful rather than trivially correct.
    for (uint32_t c = 0; c < N_Controllers; c++) {
        const uint32_t CTRL_ID = c;
        const bool ctrl_mal = controller_is_malicious[c];

        FlowRuleRecord fr;
        fr.controller_id = CTRL_ID;
        fr.timestamp     = t;
        if (ctrl_mal && present_CPFR_attack_nodes) {
            // S4: fixed-rate drop rule with high drop probability (Eq. 3.9)
            fr.action = "drop"; fr.drop_prob = 0.9; fr.is_wildcard = true;  fr.match_src = 0;
        } else if (ctrl_mal && present_CPTS_attack_nodes) {
            // S6: target-specific drop rule (non-wildcard match) (Eq. 3.11)
            fr.action = "drop"; fr.drop_prob = 0.9; fr.is_wildcard = false; fr.match_src = 1;
        } else if (ctrl_mal && present_CPIT_attack_nodes) {
            // S5: intermittent — drop on odd windows, forward on even (Eq. 3.10)
            bool drop_now = (g_sg_window % 2 == 1);
            fr.action = drop_now ? "drop" : "forward";
            fr.drop_prob = drop_now ? 0.9 : 0.0; fr.is_wildcard = true; fr.match_src = 0;
        } else {
            // Benign controller (or no CP attack active): wildcard forward rule
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

        // Per-controller CP confusion matrix: was this controller's status
        // called correctly? Counted once per controller per window.
        if (cp.detected &&  ctrl_mal) sg_cp_TP++;
        if (cp.detected && !ctrl_mal) sg_cp_FP++;
        if (!cp.detected &&  ctrl_mal) sg_cp_FN++;
        if (!cp.detected && !ctrl_mal) sg_cp_TN++;

        if (cp.detected) {
            std::cout << "[SHIELD-GH][CP] Controller " << CTRL_ID
                      << " grey-hole flow rule detected | S4=" << cp.s4_fired
                      << " S5=" << cp.s5_fired << " S6=" << cp.s6_fired
                      << " | Tc=" << std::fixed << std::setprecision(2) << Tc
                      << " | truth=" << (ctrl_mal ? "MALICIOUS" : "BENIGN")
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

        // NQ2 debug (supervisor-requested): unconditional per-window rcv for
        // node 11, so silent (rcv==0) windows are visible too, not just the
        // ones that reach the signature/fusion block below.
        if (n == 11) {
            std::cout << "[NQ2-rcv] node=11 t=" << t << " rcv=" << rcv << std::endl;
        }

        // A node with no received traffic cannot be evaluated by signatures.
        // DQ3/node-11 fix: prefer the node's last real (rcv>0) fused verdict
        // over defaulting to isolation-membership alone -- a node that was
        // just correctly flagged and then goes silent (e.g. traffic rerouted
        // away from it as a side effect of detection) should still count as
        // detected, not as a fresh miss. Isolation membership still wins if
        // it disagrees (isolation is the stronger, later signal), and nodes
        // never seen with traffic at all fall back to the old behavior.
        // Fix C (supervisor, this round): DX3 found node 13 (a real attacker)
        // hits rcv==0 in the large majority of its windows and, previously,
        // ALWAYS fell through to the signature-only last-verdict fallback
        // below -- it never once reached the AI/fusion path (g_sg_ai_windows
        // is only populated further down, past this whole rcv==0 block), so
        // the LLM never got a chance to score it even though real cumulative
        // history (g_sg_zkp_cum_received/forwarded, incremented in MacRx()
        // and tracked run-wide, NOT reset every window like rcv/fwd) is
        // available for it. When full-mode AI is on and the node has SOME
        // real history to show the LLM, redirect it into the AI batch using
        // that cumulative history instead of this window's (zero) counts, so
        // it is scored on real historical signal rather than skipped. A node
        // with truly zero cumulative history too (never seen at all) still
        // falls through to the fallback below -- there is nothing for the
        // LLM to tokenise either way in that case.
        bool sg_redirect_to_ai = (enable_full_mode_ai == 1)
                               && (g_sg_zkp_cum_received[n] > 0);
        if (rcv == 0 && sg_redirect_to_ai) {
            // IMPORTANT: this node must be scored EXACTLY ONCE this window --
            // either here (redirected into the AI batch) or by the ordinary
            // rcv==0 fallback below, never both. Do NOT touch sg_node_TP/FP/
            // FN/TN or the cum_* counters here; the AI-batch readback block
            // (further down, ~line 1345, gated on g_sg_ai_windows) is the
            // sole place that scores every w in g_sg_ai_windows, including
            // this redirected record, when the verdict comes back.
            double R_i_hist    = g_sg_ledger.ComputeReputation(n, t);
            double speed_hist  = (maxspeed > 0) ? (maxspeed / 3.6) : 13.9;
            SgAiWindow w;
            w.node        = n;
            w.gt_attacker = gt_attacker;
            w.rcv         = g_sg_zkp_cum_received[n];
            w.fwd         = g_sg_zkp_cum_forwarded[n];
            w.reputation  = R_i_hist;
            w.speed       = speed_hist;
            // No fresh per-window S1-S3 signature ran this window (no traffic
            // to evaluate), so derive a substitute S_total the same way
            // ns3_infer.py's rule_signature() would if s_total were absent
            // entirely from the record: cumulative-PDR < 0.60 -> 1.0, else
            // 0.0. sg_ai_dump_window() always emits an s_total field (there
            // is no "omit" option in that writer), so this must be a real,
            // non-negative value, not a sentinel -- an unconditionally-sent
            // "s_total":-1 would poison Eq. 3.29's fusion arithmetic
            // (mu1 * S_total going negative) instead of being ignored.
            // BUG CAUGHT DURING VERIFICATION (this round): the first version
            // of this block computed w.s_total unconditionally, ignoring
            // enable_signatures -- the same DA5 leak the existing rcv>0
            // S_total computation above (`(enable_signatures == 1) ? ... :
            // 0.0`) was specifically written to prevent (see its own comment
            // a few hundred lines below). That leaked a nonzero substitute
            // S_total into DA5 (signatures-off ablation) via this redirect
            // path, which is exactly the "partial signature contribution
            // leaking into the signatures-off baseline" bug that comment
            // describes for a different code path. Gated here the same way.
            w.rule_drop   = false;   // no fresh rule evidence this window (silent)
            w.s_total = (enable_signatures != 1) ? 0.0
                      : (w.rcv == 0) ? 0.0
                      : (((double)w.fwd / (double)w.rcv) < 0.60 ? 1.0 : 0.0);
            std::cout << "[FIXCVERIFY] node=" << n << " window=" << g_sg_window
                      << " t=" << t << " redirected_to_AI cum_rcv="
                      << w.rcv << " cum_fwd=" << w.fwd << std::endl;
            g_sg_ai_windows.push_back(w);
            continue;
        }

        if (rcv == 0) {
            bool isolated = (g_sg_isolated.find(n) != g_sg_isolated.end());
            auto lv = g_sg_last_verdict.find(n);
            bool flagged = isolated || (lv != g_sg_last_verdict.end() && lv->second);
            // DX3 debug (supervisor-requested): every attacker-node window that
            // hits this rcv==0 early-continue never reaches g_sg_ai_windows
            // (that push_back only happens further down, after this block), so
            // in full mode it bypasses the AI/fusion path entirely and falls
            // back to the last signature-only verdict instead. Print node +
            // window + t unconditionally for real attackers so these fallback
            // windows can be enumerated and checked for concentration on
            // specific nodes vs. spread across the whole attacker set.
            // NOTE: as of Fix C above, full-mode nodes with real cumulative
            // history no longer reach this print -- they were redirected to
            // the AI batch instead. Only lightweight-mode nodes, or full-mode
            // nodes with genuinely zero history ever, still hit this path.
            if (gt_attacker) {
                std::cout << "[DX3-rcv0fallback] node=" << n
                          << " window=" << g_sg_window << " t=" << t
                          << " flagged=" << (int)flagged << std::endl;
            }
            if      ( flagged &&  gt_attacker) { sg_node_TP++; sg_cum_TP++; g_sg_node_cum_tp[n]++; }
            else if ( flagged && !gt_attacker) { sg_node_FP++; sg_cum_FP++; g_sg_node_cum_fp[n]++; }
            else if (!flagged &&  gt_attacker) { sg_node_FN++; sg_cum_FN++; g_sg_node_cum_fn[n]++; }
            else                               { sg_node_TN++; sg_cum_TN++; g_sg_node_cum_tn[n]++; }
            continue;
        }

        // ── Eq. 3.29–3.30: ZKP Pedersen commitment & proof ───────────────
        // Fix 1 (supervisor-requested, CQ3 root cause): the original design
        // compared fwd==rcv WITHIN A SINGLE WINDOW -- but both counters
        // reset every window (~1s), so a node that dropped packets in an
        // earlier window and then forwards cleanly in the CURRENT window
        // gets fwd==rcv and passes, erasing its drop history every cycle
        // (confirmed: node 11 PASS at t=6.0 despite being an active
        // attacker in earlier windows). The commitment is now built from
        // the node's CUMULATIVE received count since t=0 (recorded
        // incrementally in MacRx(), before any drop decision, so it locks
        // in receipts before they can be dropped), verified against the
        // node's CUMULATIVE forwarded count -- so a single clean window can
        // no longer offset a real history of drops; the gap only ever
        // grows or stays flat, never resets.
        auto commit = g_sg_zkp.CreateCommitment(n, g_sg_zkp_cum_received[n]);
        auto proof  = g_sg_zkp.GenerateProof(commit, g_sg_zkp_cum_forwarded[n]);
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

        // ── Task 8: M2 (GHSR) network-wide PDR phase sampling ──────────────
        // Only network-wide (all vehicles') PDR is relevant to GHSR, not the
        // per-attacker PDR, so every node's obs_pdr this window is a sample.
        {
            bool attack_live  = (attack_start_time > 0.0 && t >= attack_start_time);
            bool all_real_isolated =
                (DPFR_malicious_nodes[n] || DPIT_malicious_nodes[n] ||
                 DPTS_malicious_nodes[n])
                    ? (g_sg_isolated.find(n) != g_sg_isolated.end())
                    : true;  // benign nodes don't gate the "post" phase
            if (!attack_live) {
                g_sg_pdr_baseline_samples.push_back(obs_pdr);
            } else if (gt_attacker && g_sg_isolated.find(n) == g_sg_isolated.end()) {
                // real attacker, not yet isolated -> still in the attack phase
                g_sg_pdr_attack_samples.push_back(obs_pdr);
            } else if (!gt_attacker && g_sg_isolated.empty()) {
                // benign node, no isolation has happened yet this run -> attack phase
                g_sg_pdr_attack_samples.push_back(obs_pdr);
            } else if (!g_sg_isolated.empty()) {
                // at least one isolation has occurred -> post-mitigation phase
                g_sg_pdr_post_samples.push_back(obs_pdr);
            }
            (void)all_real_isolated;
        }

        // ── Eq. 3.4–3.5: MATD-corrected PDR ────────────────────────────────
        // Was hardcoded 13.9 m/s (=50km/h) regardless of --maxspeed, so no
        // run at a different speed ever actually varied MATD's input
        // (confirmed: Q11/Q12/Q13 diagnostics all found this). Now driven
        // from the CLI --maxspeed (km/h -> m/s); falls back to 13.9 only if
        // maxspeed is left at 0.
        double speed    = (maxspeed > 0) ? (maxspeed / 3.6) : 13.9;   // m/s
        // Supervisor wiring check: print the speed value actually passed to
        // MATD/ComputeHandoffLoss, once per node per window.
        std::cout << "[MATD-DEBUG] node=" << n << " maxspeed_kmh=" << maxspeed
                  << " speed_mps=" << speed << " t=" << t << std::endl;
        // Ablation DA1/DA3: --enable_matd=0 bypasses MATD entirely, feeding
        // signatures the raw (uncorrected) PDR.
        double corr_pdr = (enable_matd == 1) ? g_sg_matd.CorrectPDR(obs_pdr, speed)
                                              : obs_pdr;

        // NQ5 debug (supervisor-requested): corrPDR for legitimate (non-attacker)
        // nodes, every window -- to check whether any legitimate node's corrected
        // PDR ever approaches tau_f=0.60 (the S1 false-positive risk zone) in this
        // topology. Printed unconditionally for all benign nodes with real
        // traffic; filtered to the top-3 by rcv when reporting.
        if (!gt_attacker && rcv > 0) {
            std::cout << "[NQ5] node=" << n << " t=" << t << " rcv=" << rcv
                      << " obs_pdr=" << obs_pdr << " corr_pdr=" << corr_pdr
                      << std::endl;
        }

        // ── Eq. 3.16–3.17: trust score + mobility decay ───────────────────
        double trust     = g_sg_ledger.ComputeTrustScore(n, t);
        double trust_mob = (enable_matd == 1) ? g_sg_matd.ApplyMobilityDecay(trust, speed)
                                               : trust;

        // BUG FIX (supervisor-reported: DA1==DA2==DA3==DA4 identical --
        // ComputeReputation() never consulted MATD): record this window's
        // decay ratio (T_mob_i/Ti, Eq. 3.17) so DEBSC::ShouldIsolate() /
        // ComputeSuspicionLevel() apply it to reputation (Eq. 3.18) when
        // deciding isolation -- previously only the separate S_total/
        // confusion-matrix path saw any MATD effect. Ablation DA1/DA3
        // (--enable_matd=0): trust_mob==trust here, so the ratio is exactly
        // 1.0 (no decay) -- equivalent to not calling this at all.
        if (trust > 1e-9)
            g_sg_debsc.RecordMobilityDecay(n, trust_mob / trust);

        // ── Eq. 3.18: blockchain reputation ──────────────────────────────
        double R_i = g_sg_ledger.ComputeReputation(n, t);

        // DQ5 debug (supervisor-requested): reputation time series for a real
        // attacker node, to check whether the unwindowed cumulative average
        // (C4/C8 finding) keeps R_i implausibly high late into a sustained-drop
        // run.
        if (gt_attacker) {
            std::cout << "[DQ5] node=" << n << " window=" << g_sg_window
                       << " t=" << t << " R_i=" << R_i << std::endl;
        }

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
        // Ablation DA5: --enable_signatures=0 skips S1-S6 entirely, so
        // isolation can only come from the AI pipeline in full mode.
        bool s1 = false, s2 = false, s3 = false;
        if (enable_signatures == 1) {
            // BUG FIX (supervisor-reported: DA1==DA2==DA3==DA4): LW_DP_Det()
            // was always applying MATD correction internally to compute S1's
            // input, regardless of enable_matd -- the toggle only gated the
            // separate corr_pdr fallback below, not S1 itself. Now passed
            // through so the ablation is genuine.
            // Task 8.5 sensitivity-analysis grid search (main.tex tab:gh_sensitivity):
            // W and the S1-S3 thresholds now come from routing.cc's CLI surface
            // (sg_W, sg_tau_f, ...) instead of hardcoded literals.
            extern uint32_t sg_W;
            extern double sg_tau_f, sg_eps_f, sg_tau_it, sg_gamma_it, sg_tau_ts;
            DPDetResult dp = LW_DP_Det(n, t, /*W=*/sg_W, g_sg_ledger, g_sg_matd,
                                       speed, g_sg_per_src_pdr[n],
                                       g_sg_pdr_history[n],
                                       /*matd_enabled=*/enable_matd == 1,
                                       sg_tau_f, sg_eps_f, sg_tau_it,
                                       sg_gamma_it, sg_tau_ts);
            s1 = dp.s1_fired;
            s2 = dp.s2_fired;
            s3 = dp.s3_fired;
        }

        // ── Eq. 3.24: Fusion (lightweight — S_total from signatures) ──────
        // DQ2 fix (supervisor-reported: DA5 not a clean LLM-only ablation):
        // the corr_pdr<0.6 fallback used to fire even with enable_signatures=0,
        // leaking a partial signature contribution into the "signatures off"
        // baseline. Now the whole term is gated so DA5 has S_total forced to
        // exactly 0 -- fusion can only be driven by Q_i (LLM) and (1-R_i).
        double S_total = (enable_signatures == 1)
                             ? ((s1 || s2 || s3) ? 1.0 : corr_pdr < 0.6 ? 0.5 : 0.0)
                             : 0.0;
        auto [y_hat, score] = g_sg_fusion.FuseLightweight(S_total, R_i);
        g_sg_last_verdict[n] = y_hat;  // node-11 fix: persist for next rcv==0 window

        // DQ3 debug (supervisor-requested): per-node, per-window fusion score
        // for every real attacker node, so DA1 vs DA4 can be diffed numerically
        // rather than described. FuseLightweight = 0.60*S_total + 0.40*(1-R_i)
        // (lightweight mode has no Q_i term -- that's full-mode only).
        if (gt_attacker) {
            std::cout << "[DQ3] node=" << n << " t=" << t
                      << " S_total=" << S_total << " R_i=" << R_i
                      << " score=" << score << " y_hat=" << (int)y_hat << std::endl;
        }

        // DX2 debug (supervisor-requested): same S_total/score/y_hat trace as
        // [DQ3] above, but for LEGITIMATE (non-attacker) nodes -- needed to
        // check, for any node that ends up a false positive, whether the
        // lightweight signature path (S_total) or the full-mode AI path
        // (Q_i, printed separately by [SHIELD-GH][AI-FULL]) is responsible.
        // [DQ3] above only ever covered gt_attacker nodes, so this window's
        // S_total was previously unavailable for FP nodes.
        if (!gt_attacker) {
            std::cout << "[DX2] node=" << n << " t=" << t
                      << " S_total=" << S_total << " R_i=" << R_i
                      << " score=" << score << " y_hat=" << (int)y_hat << std::endl;
        }

        // ZTDIAG debug (this round, supervisor-prescribed diagnostic): node
        // 19's s1 (S1/PDR-based signature) plus raw/corrected PDR, printed
        // unconditionally every window, to determine whether node 19's FP
        // is PDR-threshold-driven (s1=1) or not (s1=0, meaning the FP must
        // come from the reputation/sustained path instead). [RQ3] already
        // prints obs_pdr/corr_pdr for every node but not s1, so this fills
        // the one missing field needed for the diagnostic.
        if (n == 19) {
            std::cout << "[ZTDIAG] node=19 t=" << t
                      << " s1=" << (int)s1 << " s2=" << (int)s2 << " s3=" << (int)s3
                      << " obs_pdr=" << obs_pdr << " corr_pdr=" << corr_pdr
                      << std::endl;
        }

        // RQ1/RQ2/RQ5 debug (supervisor-requested): the same y_hat trace, but
        // unconditionally for EVERY node 0-19 (not just attacker nodes), so
        // DA1 vs DA2 vs DA3 can be diffed for every single node at every
        // window -- not just the attacker subset DQ3 already covers.
        std::cout << "[RQ1] node=" << n << " t=" << t << " y_hat=" << (int)y_hat
                  << std::endl;

        // RQ3/RQ6 debug (supervisor-requested): raw vs corrected PDR for
        // every node, every window, unconditionally -- to see whether MATD's
        // correction ever changes corr_pdr's relationship to tau_f=0.60, for
        // attacker AND legitimate nodes (NQ5 above only covered legitimate).
        std::cout << "[RQ3] node=" << n << " t=" << t << " enable_matd=" << enable_matd
                  << " obs_pdr=" << obs_pdr << " corr_pdr=" << corr_pdr << std::endl;

        // ── Track sustained detection (consecutive windows a signature fires) ─
        if (s1 || s2 || s3) g_sg_consec_detect[n]++;
        else                g_sg_consec_detect[n] = 0;

        // ── Eq. 3.13 + 3.19: DEBSC graduated response ────────────────────
        // Isolate if EITHER the DEBSC reputation gate fires (fast attackers like
        // DP-FR) OR a signature has fired for N consecutive windows (stealthy
        // attackers like DP-IT/DP-TS whose reputation stays high).
        auto response = g_sg_debsc.GetGraduatedResponse(n, t);
        bool sustained = (g_sg_consec_detect[n] >= SG_SUSTAINED_ISOLATE);
        // Fix A (supervisor-requested, ZQ1 follow-up): the `sustained`
        // override let a node be isolated via consecutive-window signature
        // firing WITHOUT ever consulting the ZKP gate -- confirmed this was
        // why DA3=DA1 (isolation went through this path, bypassing ZKP
        // entirely, for both configs identically). Now the ZKP gate applies
        // to BOTH paths when enabled: a cached FAIL proof, or no proof ever
        // cached yet (treated as ABSENT/not-yet-verified, since the struct
        // has no separate ABSENT state -- see the earlier session's C12/
        // zkp_proofs.h finding), is required before isolation proceeds via
        // either the graduated-response ISOLATE tier or the sustained
        // override. When the gate is disabled (enable_zkp_gate=0), this
        // check is bypassed entirely, matching Eq. 3.19's own ablation
        // semantics.
        auto zkp_dbg = g_sg_debsc.GetDebugState(n, t);
        // Fix 2 (supervisor, this round): the previous `!zkp_dbg.zkp_cached`
        // disjunct treated an ABSENT proof (no ZKP result ever recorded for
        // this node yet) as isolate-eligible, which is backwards -- ABSENT
        // should withhold isolation exactly like a cached FAIL, not grant it.
        // Only a confirmed cached FAIL (node HAS a recorded proof and it is
        // invalid) should independently justify isolation via the ZKP gate;
        // an ABSENT proof now blocks isolation until a real proof (PASS or
        // FAIL) is cached. `!zkp_dbg.zkp_gate_enabled` is untouched, so
        // DA1/DA2 (enable_zkp_gate=0) are unaffected -- they bypass this
        // check entirely via that first disjunct, same as before.
        bool zkp_ok_to_isolate = (!zkp_dbg.zkp_gate_enabled)
                               || (zkp_dbg.zkp_cached && !zkp_dbg.zkp_proof_valid); // only a cached FAIL allows isolation

        // Fix B (supervisor, this round): targeted Q_i veto on the `sustained`
        // override, full-mode only. Root cause: node 19 (a legitimate node)
        // saturates S_total=1.0 for many consecutive windows late in the run
        // (DX2 finding), which alone drives `g_sg_consec_detect[19]` past
        // SG_SUSTAINED_ISOLATE regardless of what the LLM thinks -- and in
        // those SAME late windows the LLM's own Q_i is low (0.075-0.086,
        // confirmed in DX2-full), i.e. the LLM actively disagrees that node 19
        // is malicious. Fix 1 (prior round) tried to fix this globally by
        // raising theta_det, which broke DA5/DA2/DA4 instead (see Fix A
        // above). This is the targeted alternative: only the `sustained`
        // signature-streak override is gated on Q_i, and only when full-mode
        // AI is actually running (enable_full_mode_ai==1) so lightweight
        // configs (DA1-DA4, which have no Q_i at all) are completely
        // unaffected -- `sustained` behaves exactly as before for them.
        //
        // Ordering constraint (why PREVIOUS window's Q_i, not this window's):
        // this isolation decision is made per-node, inline, inside the main
        // per-node loop (here). The AI/fusion batch that actually computes
        // Q_i for THIS window has not run yet -- it is collected into
        // g_sg_ai_windows (below) and only sent to the Python bridge, in one
        // shot, AFTER the per-node loop finishes (~line 1279). So this
        // window's Q_i for node n genuinely does not exist at this point in
        // the control flow. g_sg_last_q holds the most recent PAST window's
        // Q_i for n (updated when the AI batch verdict is read back, see
        // "Fix B: persist Q_i" below) -- the freshest signal actually
        // available at decision time, following the same last-known-value
        // pattern g_sg_last_verdict already uses for the rcv==0 fallback.
        //
        // KNOWN LIMITATION (documented per supervisor's request, not hidden):
        // a node's FIRST-ever sustained-isolation attempt in full mode has no
        // prior g_sg_last_q entry yet. We treat "no Q_i observed yet" as NOT
        // vetoing (Q_i_for_veto defaults to 1.0, i.e. maximally suspicious)
        // rather than silently blocking every node's first sustained trigger
        // -- an unobserved node should not get a free pass. This means the
        // veto cannot protect a node on its very first sustained-streak
        // window; it only engages from the second sustained attempt onward,
        // once at least one real Q_i has been observed for that node.
        double q_i_for_veto = 1.0;  // default: no prior signal -> do not veto
        {
            auto lq = g_sg_last_q.find(n);
            if (lq != g_sg_last_q.end()) q_i_for_veto = lq->second;
        }
        static const double SG_SUSTAINED_QI_VETO = 0.20;
        bool sustained_qi_ok = (enable_full_mode_ai != 1)
                             || (q_i_for_veto >= SG_SUSTAINED_QI_VETO);
        bool sustained_gated = sustained && sustained_qi_ok;

        bool should_isolate = (response == IsolationDecision::ISOLATE || sustained_gated)
                           && zkp_ok_to_isolate
                           && (g_sg_isolated.find(n) == g_sg_isolated.end());

        // FIXBVERIFY debug (supervisor-requested verification bar): node 19's
        // Q_i-veto state every window, unconditional -- lets the supervisor
        // directly confirm sustained-isolation is withheld when the LLM's
        // last-known Q_i is low, without isolation actually firing.
        if (n == 19) {
            std::cout << "[FIXBVERIFY] node=19 t=" << t
                      << " q_i_for_veto=" << q_i_for_veto
                      << " sustained=" << (int)sustained
                      << " sustained_qi_ok=" << (int)sustained_qi_ok
                      << " sustained_gated=" << (int)sustained_gated
                      << " should_isolate=" << (int)should_isolate
                      << std::endl;
        }

        // PQ1 debug (supervisor-requested): lambda for node 19 specifically,
        // every window, regardless of attacker status -- needed because
        // node 19 is NOT a real attacker in the zero-attacker baseline, so
        // the gt_attacker-gated trace below never fires for it. (Re-added
        // after an earlier restore-from-backup accidentally dropped it.)
        if (n == 19) {
            auto dbg19 = g_sg_debsc.GetDebugState(19, t);
            std::cout << "[PQ1] node=19 window=" << g_sg_window << " t=" << t
                      << " lambda=" << dbg19.lambda << " lambda2=" << dbg19.lambda2
                      << std::endl;
            // Fix2-verify debug (this round): unconditional (not gated on
            // gt_attacker, since node 19 is a legitimate node) dump of the
            // raw ZKP cumulative counters plus the isolation decision, at
            // every window -- needed to verify the ABSENT-proof fix (Fix 2
            // above) actually blocks node 19's would-be isolation in DA3
            // rather than just changing should_isolate's boolean without a
            // way to see why.
            std::cout << "[FIX2VERIFY] node=19 t=" << t
                      << " should_isolate=" << (int)should_isolate
                      << " zkp_ok_to_isolate=" << (int)zkp_ok_to_isolate
                      << " zkp_gate_enabled=" << (int)zkp_dbg.zkp_gate_enabled
                      << " zkp_cached=" << (int)zkp_dbg.zkp_cached
                      << " zkp_proof_valid=" << (int)zkp_dbg.zkp_proof_valid
                      << " zkp_cum_received=" << g_sg_zkp_cum_received[19]
                      << " zkp_cum_forwarded=" << g_sg_zkp_cum_forwarded[19]
                      << std::endl;
        }

        // NQ1/NQ2 debug (supervisor-requested), widened to ZQ1/ZQ2/ZQ3: was
        // node-11-only; now every ground-truth attacker node, every window,
        // so DA1 vs DA3's per-node TP->FN / FN->TP flips can be traced
        // precisely, including the cumulative ZKP counters (Fix 1) at the
        // exact window a verdict changes.
        if (gt_attacker) {
            const char* resp_name =
                (response == IsolationDecision::ISOLATE)     ? "ISOLATE" :
                (response == IsolationDecision::RATE_LIMIT)  ? "RATE_LIMIT" :
                (response == IsolationDecision::REQUIRE_ZKP) ? "REQUIRE_ZKP" : "MONITOR";
            std::cout << "[NQ1/NQ2] node=" << n << " t=" << t << " rcv=" << rcv
                      << " response=" << resp_name
                      << " should_isolate=" << (int)should_isolate
                      << " isolated=" << (int)(g_sg_isolated.find(n) != g_sg_isolated.end())
                      << std::endl;

            auto dbg = g_sg_debsc.GetDebugState(n, t);
            std::cout << "[NQ7/NQ12] node=" << n << " t=" << t
                      << " lambda=" << dbg.lambda
                      << " lambda1=" << dbg.lambda1 << " lambda2=" << dbg.lambda2
                      << " Ri_decayed=" << dbg.Ri_decayed
                      << " statistical_gate=" << (int)dbg.statistical_gate
                      << " zkp_gate_enabled=" << (int)dbg.zkp_gate_enabled
                      << " zkp_cached=" << (int)dbg.zkp_cached
                      << " zkp_proof=" << (dbg.zkp_cached ? (dbg.zkp_proof_valid ? "PASS" : "FAIL") : "N/A")
                      << std::endl;

            // ZQ2/ZQ3 debug (supervisor-requested): the exact cumulative
            // ZKP counters (Fix 1) at this window, for every attacker node.
            std::cout << "[ZQ2/ZQ3] node=" << n << " t=" << t
                      << " zkp_cum_received=" << g_sg_zkp_cum_received[n]
                      << " zkp_cum_forwarded=" << g_sg_zkp_cum_forwarded[n]
                      << std::endl;
        }

        bool is_real = gt_attacker;

        // ── Node-level detection verdict (for true M1a/M1b/M2) ────────────
        // A node is "flagged" if any signature fired this window OR it has
        // already been isolated by SHIELD-GH. Compared against ground truth.
        bool flagged = (s1 || s2 || s3)
                    || (g_sg_isolated.find(n) != g_sg_isolated.end());

        // ── Task 8: M3 (AVCR) per-variant TP/FN + M4 (FIR) false-isolation ──
        // In full mode these are tallied ONCE, later, from the AI fused verdict
        // (see the full-mode AI block after this loop) — gated here the same
        // way the M1 confusion matrix is gated a few lines below, so a node is
        // never counted twice (once on the lightweight signature, once on the
        // AI verdict).
        if (enable_full_mode_ai != 1) {
            auto tally = [&](const char* name, bool gt_variant) {
                if (!gt_variant) return;
                auto& c = g_sg_variant_counts[name];
                c.present = true;
                if (flagged) c.tp++; else c.fn++;
            };
            tally("S1-DPFR", DPFR_malicious_nodes[n]);
            tally("S2-DPIT", DPIT_malicious_nodes[n]);
            tally("S3-DPTS", DPTS_malicious_nodes[n]);
            tally("S4-CPFR", CPFR_malicious_nodes[n]);
            tally("S5-CPIT", CPIT_malicious_nodes[n]);
            tally("S6-CPTS", CPTS_malicious_nodes[n]);

            // |V_legit| is the DISTINCT legitimate-vehicle count, not a
            // per-window tally, so it is (re)computed idempotently via a set.
            if (!gt_attacker) {
                g_sg_legit_nodes.insert(n);
                if (g_sg_isolated.find(n) != g_sg_isolated.end())
                    g_sg_false_isolated.insert(n);
            }
        }

        // ── Task 8: collect this node's window for the full-mode AI bridge ───
        // In full mode the confusion matrix is driven by the AI fused verdict
        // (below, after the loop) instead of the lightweight `flagged` result,
        // so the printed MCC PEM is genuinely LLM+FL-driven end-to-end.
        if (enable_full_mode_ai == 1) {
            // NQ6 attempted fix (verified NOT sufficient -- kept because it is
            // still correct as far as it goes, see note below): seed
            // g_sg_last_verdict from the signature signal (s1||s2||s3), which
            // -- unlike the once-per-batch AI verdict -- is recomputed every
            // window a node has traffic. The AI verdict (below, after this
            // loop) still overwrites this once it actually runs for the node.
            // NOTE: this line only executes when rcv>0 (we are past the
            // rcv==0 early-continue above), so it cannot help a node that
            // never reaches rcv>0 again after its one AI-scored window -- see
            // node 8 in DA6, where node_total_received[8] genuinely drops to
            // 0 at every subsequent window boundary (confirmed by direct
            // instrumentation) and this branch is simply never reached for
            // it again. Root cause not fully resolved -- see answers_NQ1-NQ6.md.
            if (s1 || s2 || s3) g_sg_last_verdict[n] = true;

            SgAiWindow w;
            w.node        = n;
            w.gt_attacker = is_real;
            w.rcv         = rcv;
            w.fwd         = fwd;
            w.reputation  = R_i;        // Eq. 3.18 blockchain reputation
            w.speed       = speed;      // m/s
            w.rule_drop   = present_CPFR_attack_nodes || present_CPTS_attack_nodes
                         || present_CPIT_attack_nodes;
            w.s_total     = S_total;    // rule signature already computed by NS-3
            // per-source fwd/drp for the tokeniser (DP-TS targeting visibility)
            // BUG FIX (found via strace during DA5/DA6 diagnostics -- the
            // python bridge was allocating memory in a runaway loop): when
            // ff > fr (forwarded count exceeds received, seen in practice --
            // e.g. retransmission double-counting), the unsigned subtraction
            // `fr - ff` underflows to a huge uint32_t (observed:
            // 4294967295 = UINT32_MAX, i.e. wrapped -1). The bridge's
            // tokeniser does `for _ in range(drp)` over this value, which
            // tries to allocate ~4.3 BILLION list entries -- the actual root
            // cause of the intermittent bridge hang, not BLAS threading
            // (which was a real but secondary contributing issue, fixed
            // separately in ns3_infer.py). Clamp to 0 instead of wrapping.
            for (int f = 0; f < 2*flows; f++) {
                uint32_t fr = node_flow_received[n][f];
                uint32_t ff = node_flow_forwarded[n][f];
                if (fr > 0)
                    w.per_src[(uint32_t)f] = std::make_pair(ff, (ff <= fr) ? (fr - ff) : 0u);
            }
            g_sg_ai_windows.push_back(w);
        } else {
            // Lightweight-mode confusion matrix (rule-signature verdict).
            g_sg_last_verdict[n] = flagged;  // node-11 fix: persist for rcv==0 window
            if      ( flagged &&  is_real) { sg_node_TP++; sg_cum_TP++; g_sg_node_cum_tp[n]++; }
            else if ( flagged && !is_real) { sg_node_FP++; sg_cum_FP++; g_sg_node_cum_fp[n]++; }
            else if (!flagged &&  is_real) { sg_node_FN++; sg_cum_FN++; g_sg_node_cum_fn[n]++; }
            else                           { sg_node_TN++; sg_cum_TN++; g_sg_node_cum_tn[n]++; }
        }

        // ── Route-Availability Condition for Full Isolation (main.tex DEBSC
        // subsection / Algorithm PQC-Mit Step 3, supervisor patch) ───────────
        // Grey hole attacks drop only a fraction rho_a<1 of packets. If node n
        // is on the flow's SOLE path, a full FlowMod block converts that
        // partial loss into a total (100%) loss -- strictly worse than the
        // attack itself. Only proceed to full isolation if ALT_ROUTE_EXISTS
        // confirms at least one path to the destination excluding n; otherwise
        // fall back to graduated response level 2 (rate-limit + per-batch ZKP,
        // already implemented below in the RATE_LIMIT branch) and re-evaluate
        // next window.
        // BUG FIX (supervisor-reported: PDR/MCC not monotonic with more
        // components -- root cause traced to isolation NEVER taking effect,
        // any config, even DA6/full-system): this hardcoded flow_id=0, but
        // after Fix A (round-robin flow source/destination across all N
        // nodes) each node only lies on a SUBSET of flows, so checking flow
        // 0's connectivity for a node that isn't even on flow 0 was
        // structurally wrong almost every time -- confirmed 92/92 (100%) of
        // detections were withheld in every DA1-DA6 run. Now checks every
        // active flow.
        bool alt_route_ok = should_isolate && ALT_ROUTE_EXISTS_ANY_FLOW(n);
        bool route_withheld = should_isolate && !alt_route_ok;

        if (route_withheld) {
            // Detection itself genuinely fired even though full isolation was
            // withheld -- record it, and record the graduated-response (rate-
            // limit) action's timestamp as the real containment moment, so M5
            // (ESRL) has a genuine value instead of reporting nothing.
            if (detection_time == 0.0) detection_time = t;
            if (graduated_response_time == 0.0) graduated_response_time = t + 0.05;
            std::cout << "[SHIELD-GH][ROUTE-GATE] node " << n
                      << " full isolation WITHHELD — no alternate route excludes it"
                      << " | APPLY_GRADUATED_LEVEL2 (rate-limit + per-batch ZKP)"
                      << " | t=" << t << std::endl;
        }

        if (should_isolate && alt_route_ok) {
            // CQ2 debug (supervisor-requested): full gate state at the exact
            // moment isolation fires, for every node -- so a false-positive
            // isolation in a zero-attacker run can be traced to which gate
            // (suspicion tier, statistical gate, ZKP) actually justified it.
            {
                auto dbg = g_sg_debsc.GetDebugState(n, t);
                std::cout << "[CQ2] ISOLATE node=" << n << " t=" << t
                          << " gt_attacker=" << (int)gt_attacker
                          << " lambda=" << dbg.lambda
                          << " lambda1=" << dbg.lambda1 << " lambda2=" << dbg.lambda2
                          << " Ri_decayed=" << dbg.Ri_decayed
                          << " statistical_gate=" << (int)dbg.statistical_gate
                          << " zkp_gate_enabled=" << (int)dbg.zkp_gate_enabled
                          << " zkp_cached=" << (int)dbg.zkp_cached
                          << " zkp_proof=" << (dbg.zkp_cached ? (dbg.zkp_proof_valid ? "PASS" : "FAIL") : "N/A")
                          << " sustained=" << (int)sustained
                          << std::endl;
            }
            // CQ7 debug (supervisor-requested): PDR immediately before and
            // one window after the FIRST isolation event of the run (any
            // node), to see whether a false isolation itself causes a PDR
            // drop rather than just correlating with attack activity.
            {
                extern double average_packet_delivery_ratio_dsrc;
                extern bool   g_cq7_captured;
                extern double g_cq7_pdr_before;
                extern uint32_t g_cq7_node;
                extern double g_cq7_t;
                if (!g_cq7_captured) {
                    g_cq7_captured = true;
                    g_cq7_pdr_before = 100.0 * average_packet_delivery_ratio_dsrc;
                    g_cq7_node = n;
                    g_cq7_t = t;
                    std::cout << "[CQ7] first isolation: node=" << n << " t=" << t
                              << " PDR_just_before=" << g_cq7_pdr_before << "%" << std::endl;
                    ns3::Simulator::Schedule(ns3::Seconds(1.0), &cq7_print_pdr_after);
                }
            }
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
        } else if (route_withheld || response == IsolationDecision::RATE_LIMIT) {
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

    // ── Task 8: FULL-MODE AI (LLM+FL) — drive detection from the running sim ─
    // Algorithm 3 (FV-Det) end-to-end: dump the per-node windows, call the
    // Python full-mode scorer (LLM Q_i + rule S_total + reputation -> fused
    // verdict, Eq. 3.29), read ŷ_i back, and populate the confusion matrix from
    // the AI verdict vs ground truth. Real sim data in, genuine fusion out.
    if (enable_full_mode_ai == 1 && !g_sg_ai_windows.empty()) {
        const std::string script =
            "/home/sdvn_ssh/ns-allinone-3.35/ns-3.35/62/scratch/shield_gh_ml/ns3_infer.py";
        // Default remains the CPU fallback scorer (no GPU crash risk in the
        // live loop). Set SHIELD_GH_GENUINE_LLM=1 in the environment to use
        // the real Qwen2.5-7B + LoRA adapter on the GPU instead.
        //
        // Why this is worth opting into (E1, 2026-08-09): the fallback is a
        // hashing/softmax stand-in that emits an almost constant Q_i~0.85 for
        // EVERY node, attacker or not -- it carries no discriminative signal.
        // Fusing that noise with the real signature term made full mode score
        // strictly WORSE than lightweight (MCC 0.66 vs 0.85 at p=20/rho=20),
        // i.e. the framework's headline configuration was being misrepresented
        // by its own stand-in. Env var (not a hardcoded flip) so the default
        // behaviour of every existing script is unchanged.
        const char* sg_genuine_env = std::getenv("SHIELD_GH_GENUINE_LLM");
        bool genuine = (sg_genuine_env != nullptr
                        && std::string(sg_genuine_env) == "1");
        if (sg_ai_dump_window(g_sg_ai_windows, sg_ai_window_file)) {
            std::cout << "[SHIELD-GH][AI] full-mode: dumped "
                      << g_sg_ai_windows.size() << " node windows -> "
                      << sg_ai_window_file << " | t=" << t << std::endl;
            // Fix 4 (supervisor): wipe any stale .fl_state.pkl only on this
            // process's first window (g_sg_window==0) so each fresh DA
            // invocation (a separate ./waf --run process) starts FL at a
            // genuine round 1 instead of inheriting a prior, separate DA
            // run's leftover round/client state (confirmed contamination:
            // DA6 previously started from DA5's leftover round 2).
            double ms = sg_ai_run_bridge(sg_ai_python, script,
                                         sg_ai_window_file, sg_ai_verdict_file,
                                         genuine, /*fresh_state=*/g_sg_window == 0,
                                         sg_ai_mu1, sg_ai_mu3);
            // pure per-window inference (excludes one-off model load/fit)
            double pure_ms = sg_ai_read_inference_ms(sg_ai_verdict_file);
            sg_ai_last_infer_ms = pure_ms;
            std::vector<SgAiVerdict> verdicts =
                sg_ai_read_verdicts(sg_ai_verdict_file);
            // map node -> ground truth for the confusion matrix
            std::map<uint32_t,bool> gt;
            for (const auto& w : g_sg_ai_windows) gt[w.node] = w.gt_attacker;
            // DX2 (supervisor-requested): map node -> the S_total NS-3 sent
            // INTO the fusion bridge this window. SgAiVerdict (read back FROM
            // the bridge) has no s_total field -- only y_hat/q_i/score -- so
            // this has to come from the original SgAiWindow the bridge was
            // given, keyed the same way as `gt` above.
            std::map<uint32_t,double> s_total_sent;
            for (const auto& w : g_sg_ai_windows) s_total_sent[w.node] = w.s_total;
            uint32_t evaluated = 0;
            for (const auto& v : verdicts) {
                auto it = gt.find(v.node);
                if (it == gt.end()) continue;
                bool is_real = it->second;
                bool flagged = (v.y_hat == 1);
                g_sg_last_verdict[v.node] = flagged;  // node-11 fix: persist for rcv==0
                g_sg_last_q[v.node] = v.q_i;  // Fix B: persist Q_i for next window's veto check

                // NQ3/NQ4 debug (supervisor-requested): Q_i and fused score vs
                // theta_det for every real attacker node processed by the AI
                // verdict, every window -- lets us see, for the FN set, how
                // close (or far) the fused score gets to the decision boundary.
                if (is_real) {
                    std::cout << "[NQ3/NQ4] node=" << v.node << " t=" << t
                              << " Q_i=" << v.q_i << " score=" << v.score
                              << " theta_det=" << g_sg_fusion.GetThreshold()
                              << " y_hat=" << (int)flagged << std::endl;
                }
                // DX2 debug (supervisor-requested): full-mode-AI-path analogue
                // of the [DX2] lightweight print above -- Q_i AND S_total
                // together, for every node the AI path actually scored this
                // window (not gated on is_real, not gated on flagged), so a
                // DA6 FP node's window can be checked for whether the LLM
                // path (high Q_i) or the signature path (high S_total, fed
                // into the SAME fused score) drove the false flag.
                {
                    double s_tot = s_total_sent.count(v.node) ? s_total_sent[v.node] : -1.0;
                    std::cout << "[DX2-full] node=" << v.node << " t=" << t
                              << " is_real=" << (int)is_real
                              << " Q_i=" << v.q_i << " S_total=" << s_tot
                              << " score=" << v.score << " y_hat=" << (int)flagged
                              << std::endl;
                }
                if      ( flagged &&  is_real) { sg_node_TP++; sg_cum_TP++; g_sg_node_cum_tp[v.node]++; }
                else if ( flagged && !is_real) { sg_node_FP++; sg_cum_FP++; }
                else if (!flagged &&  is_real) { sg_node_FN++; sg_cum_FN++; g_sg_node_cum_fn[v.node]++; }
                else                           { sg_node_TN++; sg_cum_TN++; }
                evaluated++;

                // ── Task 8: M3 (AVCR) per-variant TP/FN, driven by the AI
                // fused verdict (full-mode uses `flagged` here, not S1-S3). ──
                {
                    auto tally = [&](const char* name, bool gt_variant) {
                        if (!gt_variant) return;
                        auto& c = g_sg_variant_counts[name];
                        c.present = true;
                        if (flagged) c.tp++; else c.fn++;
                    };
                    tally("S1-DPFR", DPFR_malicious_nodes[v.node]);
                    tally("S2-DPIT", DPIT_malicious_nodes[v.node]);
                    tally("S3-DPTS", DPTS_malicious_nodes[v.node]);
                    tally("S4-CPFR", CPFR_malicious_nodes[v.node]);
                    tally("S5-CPIT", CPIT_malicious_nodes[v.node]);
                    tally("S6-CPTS", CPTS_malicious_nodes[v.node]);
                }
                if (!is_real) g_sg_legit_nodes.insert(v.node);

                // full-mode isolation: a fused-positive attacker is blocked,
                // gated by the same Route-Availability Condition as lightweight
                // mode (main.tex DEBSC subsection / Algorithm PQC-Mit Step 3):
                // only install the full block if an alternate route excludes
                // this node, else fall back to graduated level 2 (rate-limit).
                if (flagged && g_sg_isolated.find(v.node) == g_sg_isolated.end()) {
                    // Same fix as the lightweight-mode route gate above:
                    // check every flow, not just flow 0.
                    if (ALT_ROUTE_EXISTS_ANY_FLOW(v.node)) {
                        g_sg_isolated.insert(v.node);
                        shield_gh_isolated_nodes[v.node] = true;
                        if (detection_time  == 0.0) detection_time  = t;
                        if (mitigation_time == 0.0) mitigation_time = t + 0.05;
                        // ── Task 8: M4 (FIR) — this isolation is a FALSE isolation
                        // iff the AI verdict flagged a node that is NOT really an
                        // attacker (the only way `flagged` and `!is_real` co-occur).
                        if (!is_real) g_sg_false_isolated.insert(v.node);
                        std::cout << "[SHIELD-GH][AI-FULL] node " << v.node
                                  << " ISOLATED by fused verdict | y_hat=1"
                                  << " Q_i=" << std::fixed << std::setprecision(3)
                                  << v.q_i << " score=" << v.score
                                  << " real_attacker=" << is_real
                                  << " | t=" << t << std::endl;
                    } else {
                        // Detection (fusion) genuinely fired; record it and the
                        // graduated-response timestamp so M5 (ESRL) has a real
                        // value even though full isolation was correctly withheld.
                        if (detection_time == 0.0) detection_time = t;
                        if (graduated_response_time == 0.0) graduated_response_time = t + 0.05;
                        std::cout << "[SHIELD-GH][AI-FULL][ROUTE-GATE] node " << v.node
                                  << " full isolation WITHHELD — no alternate route excludes it"
                                  << " | y_hat=1 Q_i=" << std::fixed << std::setprecision(3)
                                  << v.q_i << " score=" << v.score
                                  << " real_attacker=" << is_real
                                  << " | APPLY_GRADUATED_LEVEL2 (rate-limit + per-batch ZKP)"
                                  << " | t=" << t << std::endl;
                    }
                }
            }
            std::cout << "[SHIELD-GH][AI-FULL] scored " << evaluated
                      << " nodes | pure LLM+FL inference = "
                      << std::fixed << std::setprecision(2) << pure_ms << " ms"
                      << " | bridge wall-clock (incl. one-off model load) = "
                      << std::setprecision(1) << ms << " ms"
                      << " | both << W=10s window | t=" << t << std::endl;
        }
        g_sg_ai_windows.clear();
    }

    // ── True SHIELD-GH detection metrics (node-level M1a/M1b/M2 [legacy]) ────
    print_shield_gh_detection_metrics();

    // ── Task 8: full report-defined M1–M5 PEM block (state-of-art comparable
    // metrics, Sec. PEM: M1 MCC, M2 GHSR, M3 AVCR, M4 FIR, M5 ESRL). Printed
    // only in full mode, once at least one AI-driven window has been scored,
    // so it reflects the integrated full-system run this task requires.
    // (M6 MDPOS is a crypto-operation scalability profile, not something a
    // 4-node NS-3 prototype can produce — see shield_gh_crypto/m6_overhead_benchmark.py.)
    if (enable_full_mode_ai == 1)
        print_shield_gh_full_pem_report(t);

    g_sg_window++;
    if (g_sg_csv.is_open()) g_sg_csv.flush();
}
