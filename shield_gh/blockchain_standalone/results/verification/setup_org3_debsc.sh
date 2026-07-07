#!/usr/bin/env bash
# ============================================================
# Install + approve the debsc chaincode on Org3's peer so a THREE-peer
# network (org1/org2/org3) can all endorse. Run AFTER:
#   ./network.sh deployCC -ccn debsc ... -c mychannel    (org1+org2, seq 2)
#   cd addOrg3 && ./addOrg3.sh up -c mychannel
# ============================================================
set -e
FABRIC="${FABRIC:-$HOME/fabric-samples}"
TN="$FABRIC/test-network"
cd "$TN"
export PATH="$FABRIC/bin:$PATH"
export FABRIC_CFG_PATH="$FABRIC/config"
export CORE_PEER_TLS_ENABLED=true

# --- point CLI at Org3 peer ---
export CORE_PEER_LOCALMSPID=Org3MSP
export CORE_PEER_TLS_ROOTCERT_FILE=$TN/organizations/peerOrganizations/org3.example.com/peers/peer0.org3.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=$TN/organizations/peerOrganizations/org3.example.com/users/Admin@org3.example.com/msp
export CORE_PEER_ADDRESS=localhost:11051
ORDERER_CA=$TN/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem

echo ">>> installing debsc.tar.gz on org3 peer..."
peer lifecycle chaincode install "$TN/debsc.tar.gz"

# Resolve the installed package ID (label debsc_1.0) for the committed sequence.
PKGID=$(peer lifecycle chaincode queryinstalled 2>/dev/null \
        | grep -oE 'debsc_1.0:[a-f0-9]+' | tail -1)
echo ">>> package id: $PKGID"

# Match the currently committed sequence (deployCC used sequence 2 here; adjust
# if you redeploy). Query it so this script stays correct across redeploys.
SEQ=$(peer lifecycle chaincode querycommitted --channelID mychannel --name debsc 2>/dev/null \
      | grep -oE 'Sequence: [0-9]+' | grep -oE '[0-9]+' | head -1)
SEQ="${SEQ:-2}"
echo ">>> approving debsc (sequence $SEQ) as Org3..."
peer lifecycle chaincode approveformyorg -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "$ORDERER_CA" --channelID mychannel --name debsc \
  --version 1.0 --package-id "$PKGID" --sequence "$SEQ"

echo ">>> org3 can now query/endorse debsc:"
peer chaincode query -C mychannel -n debsc -c '{"function":"ReadNode","Args":["node0"]}' || true
echo ">>> Org3 setup complete — network now has THREE endorsing peers."
