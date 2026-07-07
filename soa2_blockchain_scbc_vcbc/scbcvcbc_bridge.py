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

HOME = os.path.expanduser("~")
INPUT_CSV = os.path.join(HOME, "ns-allinone-3.35/ns-3.35/results/vcbc_detection.csv")
OUTPUT_CSV = os.path.join(HOME, "ns-allinone-3.35/ns-3.35/results/soa2_blockchain_results.csv")
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
    return node_ids, delivered, not_delivered, is_attacker, len(rows)


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
def report(node_ids, status, delivered, not_delivered, is_attacker, total_windows, mode):
    TP = TN = FP = FN = 0
    classified = {}
    for n in node_ids:
        mal = 1 if status[n] in ("grey", "black") else 0
        classified[n] = mal
        a = is_attacker[n]
        if mal and a: TP += 1
        elif mal and not a: FP += 1
        elif not mal and a: FN += 1
        else: TN += 1

    N = len(node_ids)
    acc = (TP + TN) / N if N else 0.0
    fpr = FP / (FP + TN) if (FP + TN) else 0.0
    tpr = TP / (TP + FN) if (TP + FN) else 0.0

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
                    "Accuracy", "FPR", "TPR", "NetworkPDR", "RoutingOverhead"])
        w.writerow(["SOA2_Alabdulatif_SCBC_VCBC", mode, total_windows, N,
                    TP, TN, FP, FN, f"{acc:.4f}", f"{fpr:.4f}", f"{tpr:.4f}",
                    f"{net_pdr:.4f}", f"{routing_overhead:.4f}"])
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

    node_ids, delivered, not_delivered, is_attacker, windows = aggregate(args.input)
    if args.dry_run:
        status = run_local(node_ids, delivered, not_delivered)
        report(node_ids, status, delivered, not_delivered, is_attacker, windows, "dry-run")
    else:
        status = run_on_fabric(node_ids, delivered, not_delivered, is_attacker)
        report(node_ids, status, delivered, not_delivered, is_attacker, windows, "fabric")


if __name__ == "__main__":
    main()
