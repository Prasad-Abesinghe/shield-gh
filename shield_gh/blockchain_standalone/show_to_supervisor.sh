#!/usr/bin/env bash
# ============================================================
# SHIELD-GH Blockchain — supervisor demo (screenshot each section)
# Shows: 3-peer network, VRF endorser selection at chaincode level,
# eligibility filter, per-tx unpredictability, and bypass modes.
# Requires the Fabric test-network up with debsc chaincode (seq 4).
# ============================================================
set -u
FABRIC=~/fabric-samples
TN="$FABRIC/test-network"
export PATH="$FABRIC/bin:$PATH"
export FABRIC_CFG_PATH="$FABRIC/config"
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_TLS_ROOTCERT_FILE=$TN/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=$TN/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051
ORDERER_CA=$TN/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
CA1=$TN/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
CA2=$TN/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt

q(){ peer chaincode query -C mychannel -n debsc -c "$1"; }
# waitForEvent invoke — used for single decisive calls
inv(){ peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "$ORDERER_CA" -C mychannel -n debsc \
  --peerAddresses localhost:7051 --tlsRootCertFiles "$CA1" \
  --peerAddresses localhost:9051 --tlsRootCertFiles "$CA2" --waitForEvent -c "$1" >/dev/null 2>&1; sleep 1; }
# fast invoke (no waitForEvent) — used for bulk RSU registration
finv(){ peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "$ORDERER_CA" -C mychannel -n debsc \
  --peerAddresses localhost:7051 --tlsRootCertFiles "$CA1" \
  --peerAddresses localhost:9051 --tlsRootCertFiles "$CA2" -c "$1" >/dev/null 2>&1; }
pp(){ python3 -m json.tool; }

echo "############################################################"
echo "# [1] THREE-PEER NETWORK (answers 'only two peers??')"
echo "############################################################"
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -iE "NAMES|peer0.org[0-9].example.com|orderer"
echo

echo "############################################################"
echo "# [2] Chaincode committed on ALL THREE orgs"
echo "############################################################"
peer lifecycle chaincode querycommitted --channelID mychannel --name debsc
echo

echo "############################################################"
echo "# [3] Register the 64-RSU endorser pool (statically-allocated)"
echo "#     ~50 eligible; a minority are low-trust / under-observed (filtered)"
echo "############################################################"
for j in $(seq 1 64); do
  if   [ $((j % 7)) -eq 0 ]; then  t=0.30; n=12   # low-trust  -> excluded
  elif [ $((j % 11)) -eq 0 ]; then t=0.90; n=2    # under-obs. -> excluded
  else t=$(python3 -c "print(round(0.60+0.0055*($j%60),3))"); n=$((6 + j % 10)); fi
  finv "{\"function\":\"RegisterRSU\",\"Args\":[\"RSU$j\",\"pk_rsu$j\",\"$t\",\"$n\"]}"
done
echo "64 RSUs registered on-chain; waiting for batch commit..."; sleep 6
echo

echo "############################################################"
echo "# [4] VRF endorser selection at CHAINCODE level  (Rev. Block 15)"
echo "#     >= 10 endorsers per tx (scales with pool); different set per tx"
echo "############################################################"
summ(){ python3 -c "import sys,json;d=json.load(sys.stdin);print(' %s: mode=%s | eligible|E|=%d | k_end=%d endorsers | f_max=%d Byzantine tolerated | proofs_verify=%s'%(d['txId'],d['mode'],d['eligibleN'],d['kEnd'],d['fMax'],all(e['verify'] for e in d['selected'])));print('   Omega(t) =',sorted((e['rsuId'] for e in d['selected']),key=lambda s:int(s[3:])))"; }
echo "--- SelectEndorsers(TX-1001) ---"
q '{"function":"SelectEndorsers","Args":["TX-1001"]}' | summ
echo "--- SelectEndorsers(TX-2002)  [different seed -> different Omega(t)] ---"
q '{"function":"SelectEndorsers","Args":["TX-2002"]}' | summ
echo "   (full JSON incl. per-endorser beta/proof: append | python3 -m json.tool)"
echo

echo "############################################################"
echo "# [5] BYPASS MODES (graceful degradation, Eq. endorser_mode)"
echo "#     Degrade RSU trust until the eligible pool falls below k_min=10"
echo "############################################################"
# Degrade RSU9..RSU64 to low trust -> leave <10 eligible -> DEFERRED
for j in $(seq 9 64); do finv "{\"function\":\"RegisterRSU\",\"Args\":[\"RSU$j\",\"pk_rsu$j\",\"0.20\",\"8\"]}"; done
sleep 6
echo "--- ~8 eligible (< k_min=10) -> DEFERRED ---"
q '{"function":"SelectEndorsers","Args":["TX-DEFER"]}' | python3 -c "import sys,json;d=json.load(sys.stdin);print(' mode:',d['mode'],'| eligible:',d['eligibleN'],'| note:',d['note'])"
# Degrade the remaining RSU1..8 -> 0 eligible -> EMERGENCY
for j in $(seq 1 8); do finv "{\"function\":\"RegisterRSU\",\"Args\":[\"RSU$j\",\"pk_rsu$j\",\"0.20\",\"8\"]}"; done
sleep 6
echo "--- No eligible RSU -> EMERGENCY (single highest-trust endorser + audit) ---"
q '{"function":"SelectEndorsers","Args":["TX-EMERG"]}' | python3 -c "import sys,json;d=json.load(sys.stdin);print(' mode:',d['mode'],'| selected:',[e['rsuId'] for e in d['selected']],'| note:',d['note'])"
echo
echo "############################################################"
echo "# DONE. VRF dynamic endorser selection demonstrated on real Fabric."
echo "############################################################"
