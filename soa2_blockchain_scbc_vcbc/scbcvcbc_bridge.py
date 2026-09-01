#!/usr/bin/env python3
"""
scbcvcbc_bridge.py — SOA2 NS-3 ↔ real-blockchain bridge
=======================================================
Alabdulatif et al. (CMES 2024) SCBC/VCBC, evaluated on REAL Hyperledger
Fabric (not the in-memory NS-3 simulation).

Pipeline
--------
1. Read the per-window per-node PDR log NS-3 produces
   (results/vcbc_detection.csv — written by routing.cc::write_vcbc_csv).
2. Aggregate each node's delivered / not-delivered relay counts across windows.
3. Commit each node's relay record to the live SCBC/VCBC chaincode on the
   Fabric test-network (`peer chaincode invoke CommitRelayRecord`).
4. Run the on-chain SCBC (Alg.1-3) and VCBC (Alg.4-5) classification and read
   the authoritative White/Grey/Black verdicts back FROM the blockchain.
5. Compute the paper's metrics (PDR, TP/RO, classification accuracy, FPR/TPR)
   and write soa2_blockchain_results.csv.

This proves the classification is performed by a real deployed smart contract,
exactly like the SHIELD-GH DEBSC chaincode — consistent with SOA1.

Usage
-----
    # one-time: bring up network + deploy chaincode (see scbcvcbc_demo.sh header)
    python3 scbcvcbc_bridge.py                 # uses real Fabric
    python3 scbcvcbc_bridge.py --dry-run       # local classify, no Fabric needed

Run --dry-run to validate the CSV→metrics path without a running network; it
applies the SAME Alg.3 rules locally (identical to the chaincode).
"""

import os
import csv
import sys
import json
import argparse
import subprocess

# Shared controller-suppression model (see soa_suppression.py), one level up.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import soa_suppression

HOME = os.path.expanduser("~")
# routing.cc writes vcbc_detection.csv to a hardcoded absolute path under
# 62/results/ regardless of which root the binary was built/run from
# (Task 9: waf/build only exist under ns-3.35-g62build).
INPUT_CSV = os.path.join(HOME, "ns-allinone-3.35/ns-3.35/62/results/vcbc_detection.csv")
OUTPUT_CSV = os.path.join(HOME, "ns-allinone-3.35/ns-3.35/62/results/soa2_blockchain_results.csv")
FABRIC = os.path.join(HOME, "fabric-samples")
TESTNET = os.path.join(FABRIC, "test-network")

CHANNEL = "mychannel"
CC_NAME = "scbcvcbc"
PDR_THRESHOLD = 0.78        # window PDR below this = one "not delivered" relay vote
RATING_THRESHOLD = 50.0     # τ in Alg.3 (percent) — must match chaincode defaultThreshold


# ── Alg.3 local classifier (identical to chaincode classify()) ──────────────
def classify(delivered, not_delivered, thr=RATING_THRESHOLD):
    times = delivered + not_delivered
    if times == 0:
        return 100.0, "white"
    rating = delivered * 100.0 / times
    if rating == 0:
        return rating, "black"
    if rating > thr:
        return rating, "white"
    return rating, "grey"


# ── 1+2. Read CSV, aggregate per-node delivered / not-delivered counts ──────
def aggregate(input_csv):
    if not os.path.isfile(input_csv):
        sys.exit(f"[SOA2] ERROR: input not found: {input_csv}\n"
                 f"       Run NS-3 with --use_vcbc_detection=1 first.")
    with open(input_csv, newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        sys.exit("[SOA2] ERROR: CSV empty — no windows recorded.")

    header = rows[0].keys()
    node_ids = sorted({
        int(c.split("Node")[1].split("_")[0])
        for c in header if c.startswith("Node") and c.endswith("_PDR")
    })

    # Scale per-window PDR into a fixed number of relay opportunities so the
    # aggregated delivered/dropped ratio preserves the node's true PDR. This is
    # what lets the chaincode separate a greyhole (rating ~30% -> grey) from a
    # blackhole (rating 0 -> black); a per-window pass/fail would collapse both.
    RELAYS_PER_WINDOW = 10
    delivered = {n: 0 for n in node_ids}
    not_delivered = {n: 0 for n in node_ids}
    is_attacker = {n: 0 for n in node_ids}

    for row in rows:
        for n in node_ids:
            pdr = float(row.get(f"Node{n}_PDR", 1.0))
            is_attacker[n] = int(row.get(f"Node{n}_IsAttacker", 0))
            d = round(pdr * RELAYS_PER_WINDOW)
            delivered[n] += d
            not_delivered[n] += RELAYS_PER_WINDOW - d
    # Supervisor-directed model fix: ControllerCompromised (written by
    # routing.cc's write_vcbc_csv()) -- see report()'s suppression logic.
    controller_compromised = bool(int(rows[-1].get("ControllerCompromised", 0)))
    # Multi-controller model (2026-08-12): per-node controller status; a node
    # under a benign controller is not suppressed. Falls back to the run-wide
    # flag for CSVs written before this column existed.
    ctrl_per_node = {
        n: bool(int(rows[-1].get(f"Node{n}_CtrlCompromised",
                                 1 if controller_compromised else 0)))
        for n in node_ids
    }
    return (node_ids, delivered, not_delivered, is_attacker, len(rows),
            controller_compromised, ctrl_per_node)


# ── 3/4. Real Fabric chaincode calls ────────────────────────────────────────
def fabric_env():
    org1 = os.path.join(TESTNET, "organizations/peerOrganizations/org1.example.com")
    env = dict(os.environ)
    env.update({
        "PATH": os.path.join(FABRIC, "bin") + ":" + env.get("PATH", ""),
        "FABRIC_CFG_PATH": os.path.join(FABRIC, "config"),
        "CORE_PEER_TLS_ENABLED": "true",
        "CORE_PEER_LOCALMSPID": "Org1MSP",
        "CORE_PEER_TLS_ROOTCERT_FILE": f"{org1}/peers/peer0.org1.example.com/tls/ca.crt",
        "CORE_PEER_MSPCONFIGPATH": f"{org1}/users/Admin@org1.example.com/msp",
        "CORE_PEER_ADDRESS": "localhost:7051",
    })
    return env


def peer_invoke(args_json, env):
    orderer_ca = os.path.join(TESTNET, "organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem")
    p1 = os.path.join(TESTNET, "organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt")
    p2 = os.path.join(TESTNET, "organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt")
    cmd = ["peer", "chaincode", "invoke", "-o", "localhost:7050",
           "--ordererTLSHostnameOverride", "orderer.example.com",
           "--tls", "--cafile", orderer_ca, "-C", CHANNEL, "-n", CC_NAME,
           "--peerAddresses", "localhost:7051", "--tlsRootCertFiles", p1,
           "--peerAddresses", "localhost:9051", "--tlsRootCertFiles", p2,
           "-c", args_json]
    subprocess.run(cmd, env=env, cwd=TESTNET, check=True,
                   capture_output=True, text=True)


def peer_query(args_json, env):
    cmd = ["peer", "chaincode", "query", "-C", CHANNEL, "-n", CC_NAME, "-c", args_json]
    out = subprocess.run(cmd, env=env, cwd=TESTNET, check=True,
                         capture_output=True, text=True)
    return out.stdout.strip()


def run_on_fabric(node_ids, delivered, not_delivered, is_attacker):
    import time
    env = fabric_env()
    print("[SOA2] Committing relay records to the blockchain...")
    for n in node_ids:
        args = json.dumps({"function": "CommitRelayRecord",
                           "Args": [f"node{n}", str(delivered[n]),
                                    str(not_delivered[n]), str(is_attacker[n])]})
        peer_invoke(args, env)
        time.sleep(1)
    print("[SOA2] Running on-chain SCBC (Alg.1-3)...")
    peer_query(json.dumps({"function": "RunSCBC", "Args": [str(RATING_THRESHOLD)]}), env)
    all_json = peer_query(json.dumps({"function": "GetAllNodes", "Args": []}), env)
    records = json.loads(all_json) if all_json else []
    status = {}
    for rec in records:
        name = rec["nodeId"]
        if not name.startswith("node") or not name[4:].isdigit():
            continue  # ignore unrelated records (e.g. demo's car1/car2)
        status[int(name[4:])] = rec["status"]
    return status


def run_local(node_ids, delivered, not_delivered):
    return {n: classify(delivered[n], not_delivered[n])[1] for n in node_ids}


# ── 5. Metrics + report ─────────────────────────────────────────────────────
def mcc_from_confusion(TP, TN, FP, FN):
    """Matthews Correlation Coefficient, epsilon-guarded exactly like
    routing.cc::calculate_mcc() (Task 9: apples-to-apples MCC across SOA1/
    SOA3/SHIELD-GH, none of which previously computed MCC for SOA2)."""
    import math
    eps = 1e-6
    num = (TP * TN) - (FP * FN)
    den = math.sqrt((TP + FP + eps) * (TP + FN + eps) *
                    (TN + FP + eps) * (TN + FN + eps))
    return num / den if den else 0.0


def report(node_ids, status, delivered, not_delivered, is_attacker, total_windows, mode,
           controller_compromised=False, rng_run=1, suppression_prob=None,
           ctrl_per_node=None):
    """Supervisor-directed model fix (2026-08-09): SOA2 has no evidence
    channel independent of the controller (its blockchain smart contract
    still only sees what the controller lets it see -- unlike SHIELD-GH's
    DEBSC, which is fed directly by the LLM/Fusion Engine and RSU
    consensus, bypassing the controller). When the controller is
    compromised, a real detection (classified malicious on a genuine
    attacker) is SUPPRESSED before it becomes an actionable/reported
    result -- what would have been a TP is instead a FN. FP/TN unaffected."""
    prob = (soa_suppression.DEFAULT_SUPPRESSION_PROB
            if suppression_prob is None else suppression_prob)
    if ctrl_per_node is None:
        ctrl_per_node = {n: controller_compromised for n in node_ids}

    # Multi-controller model (2026-08-12): suppression decided per node from
    # that node's own controller. Nodes under benign controllers report
    # normally, so the network-wide MCC reflects the mix of domains.
    raw_cm = dict(TP=0, TN=0, FP=0, FN=0)
    sup_cm = dict(TP=0, TN=0, FP=0, FN=0)
    classified = {}
    for n in node_ids:
        detected = status[n] in ("grey", "black")
        a = bool(is_attacker[n])
        raw_cm["TP" if (detected and a) else "FP" if (detected and not a)
               else "FN" if a else "TN"] += 1

        eff = detected
        if detected and a and ctrl_per_node.get(n, False) and \
                soa_suppression.is_suppressed(n, rng_run, prob, "soa2"):
            eff = False
        sup_cm["TP" if (eff and a) else "FP" if (eff and not a)
               else "FN" if a else "TN"] += 1
        classified[n] = 1 if eff else 0

    raw_mcc = mcc_from_confusion(raw_cm["TP"], raw_cm["TN"],
                                 raw_cm["FP"], raw_cm["FN"])
    TP, TN, FP, FN = (sup_cm["TP"], sup_cm["TN"], sup_cm["FP"], sup_cm["FN"])

    N = len(node_ids)
    acc = (TP + TN) / N if N else 0.0
    fpr = FP / (FP + TN) if (FP + TN) else 0.0
    tpr = TP / (TP + FN) if (TP + FN) else 0.0
    mcc = mcc_from_confusion(TP, TN, FP, FN)

    # Paper metrics: PDR = delivered/total relays; RO Eq.3 = (Dnet+Dctrl)/Dnet
    tot_delivered = sum(delivered.values())
    tot_relays = sum(delivered[n] + not_delivered[n] for n in node_ids)
    net_pdr = tot_delivered / tot_relays if tot_relays else 0.0
    # Dctrl = one 100-byte smart-contract call per node per window (function calls).
    d_net = max(tot_relays, 1)
    d_ctrl = N * total_windows
    routing_overhead = (d_net + d_ctrl) / d_net

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print(f"║  SOA2  SCBC/VCBC on REAL blockchain  ({mode:<10})              ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║  Windows={total_windows:<4} Nodes={N:<3}  τ(rating)={RATING_THRESHOLD:.0f}%  pdrThr={PDR_THRESHOLD}     ║")
    print(f"║  TP={TP} TN={TN} FP={FP} FN={FN}                                       ║")
    print(f"║  Classification Accuracy : {acc*100:6.2f}%                          ║")
    print(f"║  False Positive Rate     : {fpr*100:6.2f}%                          ║")
    print(f"║  True Positive Rate      : {tpr*100:6.2f}%                          ║")
    print(f"║  M1 MCC (actionable)     : {mcc:+6.4f}                          ║")
    print(f"║  M1 MCC (raw, pre-suppr.): {raw_mcc:+6.4f}                          ║")
    if controller_compromised:
        print(f"║  Controller COMPROMISED — suppression p={prob:.2f}             ║")
    print(f"║  Network PDR (Eq.1)      : {net_pdr*100:6.2f}%                          ║")
    print(f"║  Routing Overhead (Eq.3) : {routing_overhead:6.3f}                          ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    for n in node_ids:
        truth = "ATTACKER" if is_attacker[n] else "BENIGN  "
        ok = "✓" if classified[n] == is_attacker[n] else "✗"
        rating = classify(delivered[n], not_delivered[n])[0]
        print(f"║   node{n:>2}: on-chain={status[n]:<5} truth={truth} "
              f"rating={rating:5.1f}% {ok}        ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")

    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    with open(OUTPUT_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Technique", "Mode", "Windows", "Nodes", "TP", "TN", "FP", "FN",
                    "Accuracy", "FPR", "TPR", "MCC", "NetworkPDR", "RoutingOverhead"])
        w.writerow(["SOA2_Alabdulatif_SCBC_VCBC", mode, total_windows, N,
                    TP, TN, FP, FN, f"{acc:.4f}", f"{fpr:.4f}", f"{tpr:.4f}",
                    f"{mcc:.4f}", f"{net_pdr:.4f}", f"{routing_overhead:.4f}"])
        w.writerow([])
        w.writerow(["Node", "Delivered", "NotDelivered", "Rating",
                    "OnChainStatus", "Classified", "IsAttacker", "Correct"])
        for n in node_ids:
            rating = classify(delivered[n], not_delivered[n])[0]
            w.writerow([n, delivered[n], not_delivered[n], f"{rating:.2f}",
                        status[n], classified[n], is_attacker[n],
                        1 if classified[n] == is_attacker[n] else 0])
    print(f"[SOA2] Results written to: {OUTPUT_CSV}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="classify locally (Alg.3) without a running Fabric network")
    ap.add_argument("--input", default=INPUT_CSV)
    args = ap.parse_args()

    (node_ids, delivered, not_delivered, is_attacker, windows,
     controller_compromised, ctrl_per_node) = aggregate(args.input)
    if args.dry_run:
        status = run_local(node_ids, delivered, not_delivered)
        report(node_ids, status, delivered, not_delivered, is_attacker, windows, "dry-run",
               controller_compromised, ctrl_per_node=ctrl_per_node)
    else:
        status = run_on_fabric(node_ids, delivered, not_delivered, is_attacker)
        report(node_ids, status, delivered, not_delivered, is_attacker, windows, "fabric",
               controller_compromised, ctrl_per_node=ctrl_per_node)


if __name__ == "__main__":
    main()
