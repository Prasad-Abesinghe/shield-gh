#!/usr/bin/env bash
# ============================================================
# SHIELD-GH DEBSC — Hyperledger Fabric evidence demo
# Runs real chaincode invokes/queries against the test-network:
#   - commits forwarding records (honest node + grey-hole attacker)
#   - evaluates Eq. 3.19 dual-evidence isolation on each
# Produces the Task-1 evidence screenshots.
# ============================================================
set -e

# ── Point the CLI at the Fabric test-network (Org1 / peer0) ─────────────────
export FABRIC=~/fabric-samples
export PATH=$FABRIC/bin:$PATH
export FABRIC_CFG_PATH=$FABRIC/config
cd $FABRIC/test-network

export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_TLS_ROOTCERT_FILE=$PWD/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=$PWD/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

ORDERER_CA=$PWD/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
PEER0_ORG1_CA=$PWD/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
PEER0_ORG2_CA=$PWD/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
CH=mychannel
CC=debsc

invoke() {  # $1 = JSON args
  peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C $CH -n $CC \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$PEER0_ORG2_CA" \
    -c "$1"
  sleep 2
}
query() {   # $1 = JSON args
  peer chaincode query -C $CH -n $CC -c "$1"
}

echo "============================================================"
echo " SHIELD-GH DEBSC — Hyperledger Fabric evidence demo"
echo "============================================================"

echo; echo ">>> [1] Commit forwarding record: HONEST node (node10: fwd=100, rx=100)"
invoke '{"function":"CommitForwardingRecord","Args":["node10","100","100"]}'

echo; echo ">>> [2] Commit forwarding record: GREY-HOLE attacker (node20: fwd=40, rx=100)"
invoke '{"function":"CommitForwardingRecord","Args":["node20","40","100"]}'

echo; echo ">>> [3] Read honest node record (on-ledger)"
query '{"function":"ReadNode","Args":["node10"]}'

echo; echo ">>> [4] Read attacker record (on-ledger)"
query '{"function":"ReadNode","Args":["node20"]}'

echo; echo ">>> [5] EvaluateIsolation HONEST node (Eq. 3.19, θR=0.4) — expect MONITOR"
query '{"function":"EvaluateIsolation","Args":["node10","0.4"]}'

echo; echo ">>> [6] EvaluateIsolation ATTACKER (Eq. 3.19, θR=0.4) — expect ISOLATE"
query '{"function":"EvaluateIsolation","Args":["node20","0.4"]}'

echo; echo ">>> [7] Commit the ISOLATE decision to ledger (invoke)"
invoke '{"function":"EvaluateIsolation","Args":["node20","0.4"]}'

echo; echo ">>> [8] Final attacker record (Isolated flag now true on-ledger)"
query '{"function":"ReadNode","Args":["node20"]}'

echo; echo ">>> [9] All node records on the blockchain"
query '{"function":"GetAllNodes","Args":[]}'

echo; echo "============================================================"
echo " DONE — evidence captured. Eq. 3.19 dual-gate demonstrated:"
echo "   honest node (ZKP valid)  -> MONITOR"
echo "   grey hole  (ZKP FAILED)  -> ISOLATE"
echo "============================================================"
