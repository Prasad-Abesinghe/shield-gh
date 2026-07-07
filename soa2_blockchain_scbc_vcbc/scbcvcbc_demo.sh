#!/usr/bin/env bash
# ============================================================
# SOA2 — Alabdulatif et al. SCBC/VCBC — Hyperledger Fabric demo
# Runs the REAL chaincode (Alg. 1-5) against the test-network:
#   - commits relay records for honest / blackhole / greyhole cars
#   - SCBC: classify white/grey/black purely from delivered ratio
#   - VCBC: miner voting pre-filter (Alg.4) then classify (Alg.5)
# Produces the SOA2 blockchain evidence screenshots.
#
# Prereqs (one-time):
#   cd ~/fabric-samples/test-network
#   ./network.sh up createChannel -c mychannel
#   ./network.sh deployCC -ccn scbcvcbc \
#       -ccp <abs path>/soa2_blockchain_scbc_vcbc/chaincode-scbcvcbc \
#       -ccl go -c mychannel
# ============================================================
set -e

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
CC=scbcvcbc

invoke() {
  peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C $CH -n $CC \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$PEER0_ORG2_CA" \
    -c "$1"
  sleep 2
}
query() { peer chaincode query -C $CH -n $CC -c "$1"; }

echo "============================================================"
echo " SOA2 SCBC/VCBC (Alabdulatif et al.) — Fabric evidence demo"
echo "============================================================"

echo; echo ">>> [1] Commit relay records (delivered, notDelivered, isAttacker)"
echo "    honest car  car1: 95 delivered / 5 dropped"
invoke '{"function":"CommitRelayRecord","Args":["car1","95","5","0"]}'
echo "    BLACKHOLE   car2: 0 delivered / 50 dropped (drops everything)"
invoke '{"function":"CommitRelayRecord","Args":["car2","0","50","1"]}'
echo "    GREYHOLE    car3: 15 delivered / 45 dropped (rating ~25%)"
invoke '{"function":"CommitRelayRecord","Args":["car3","15","45","1"]}'

echo; echo ">>> [2] SCBC (Alg.1-3): classify by delivered ratio, no prior knowledge"
query '{"function":"RunSCBC","Args":["50.0"]}'

echo; echo ">>> [3] Read each car record after SCBC"
query '{"function":"ReadNode","Args":["car1"]}'
query '{"function":"ReadNode","Args":["car2"]}'
query '{"function":"ReadNode","Args":["car3"]}'

echo; echo ">>> [4] VCBC (Alg.4-5): miners cast prior reputation votes"
echo "    car1 voted white (w), car2 voted black (b), car3 voted grey (g)"
invoke '{"function":"SetReputation","Args":["car1","w"]}'
invoke '{"function":"SetReputation","Args":["car2","b"]}'
invoke '{"function":"SetReputation","Args":["car3","g"]}'
sleep 3   # let all reputation writes propagate to the query peer before RunVCBC

echo; echo ">>> [5] RunVCBC — voting pre-filter removes grey/black, then classify"
echo "    expect: only car1 survives (high reputation) -> early high PDR"
query '{"function":"RunVCBC","Args":["50.0"]}'

echo; echo ">>> [6] All node records on the blockchain (final evidence)"
query '{"function":"GetAllNodes","Args":[]}'

echo; echo "============================================================"
echo " DONE — SOA2 evidence captured:"
echo "   SCBC: blackhole car2 -> black, greyhole car3 -> grey, car1 -> white"
echo "   VCBC: voting excludes car2/car3 up front -> faster, higher PDR"
echo "============================================================"
