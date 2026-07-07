#!/usr/bin/env bash
# ============================================================
#  debsc_invoke.sh — fire ONE Fabric chaincode invoke/query for the
#  SHIELD-GH live-blockchain integration, called from inside the NS-3
#  simulation (scratch/routing.cc via shield_gh_integration.h) as an
#  asynchronous background process so the NS-3 event loop never blocks
#  on the ~1-2s peer round-trip.
#
#  Usage:  debsc_invoke.sh <mode> <function> <json-args-array>
#     mode = invoke | query
#  e.g.
#     debsc_invoke.sh invoke CommitForwardingRecord '["node0","40","100"]'
#     debsc_invoke.sh invoke EvaluateIsolation      '["node0","0.4"]'
#     debsc_invoke.sh query  ReadNode               '["node0"]'
#
#  DYNAMIC BLOCKCHAIN ENDORSER SELECTION (supervisor request):
#  The endorsing peer set is NOT hardcoded. It is chosen at call time from
#  a trust-ranked peer roster. Env var SG_ENDORSER_RANK is a comma list of
#  peer keys ordered MOST-trusted first (e.g. "org1,org2" or "org2,org1"),
#  and SG_ENDORSER_K is how many top-ranked peers to enlist as endorsers
#  (default = all in the rank list). NS-3 recomputes this ranking each
#  window from on-ledger reputation Ri (Eq. 3.18) so a peer whose trust
#  degrades is dropped from the endorser set. Falls back to org1,org2 if
#  no ranking is supplied, so the script is always runnable standalone.
#
#  Each call appends a one-line status to results/live_invoke.log so the
#  run is auditable. Failures never abort the simulation (best-effort).
# ============================================================
set -u
FABRIC="${FABRIC:-$HOME/fabric-samples}"
TN="$FABRIC/test-network"
CH="${SG_CHANNEL:-mychannel}"
CC="${SG_CC:-debsc}"
HERE="$(cd "$(dirname "$0")" && pwd)"
LIVELOG="$HERE/results/live_invoke.log"
mkdir -p "$HERE/results"

MODE="${1:-}"
FUNC="${2:-}"
ARGS="${3:-[]}"
if [[ -z "$MODE" || -z "$FUNC" ]]; then
  echo "usage: $0 <invoke|query> <function> <json-args>" >&2; exit 2
fi

export PATH="$FABRIC/bin:$PATH"
export FABRIC_CFG_PATH="$FABRIC/config"
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_TLS_ROOTCERT_FILE="$TN/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
export CORE_PEER_MSPCONFIGPATH="$TN/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
export CORE_PEER_ADDRESS=localhost:7051

ORDERER_CA="$TN/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
ORG1_CA="$TN/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
ORG2_CA="$TN/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
ORG3_CA="$TN/organizations/peerOrganizations/org3.example.com/peers/peer0.org3.example.com/tls/ca.crt"

# ── resolve one peer key -> "--peerAddresses host --tlsRootCertFiles ca" ──────
# The network runs THREE peers (org1@7051, org2@9051, org3@11051); the endorser
# set is chosen dynamically from these by trust rank (see SG_ENDORSER_RANK).
peer_flags() {
  case "$1" in
    org1) echo "--peerAddresses localhost:7051  --tlsRootCertFiles $ORG1_CA" ;;
    org2) echo "--peerAddresses localhost:9051  --tlsRootCertFiles $ORG2_CA" ;;
    org3) echo "--peerAddresses localhost:11051 --tlsRootCertFiles $ORG3_CA" ;;
    *)    echo "" ;;
  esac
}

# ── DYNAMIC ENDORSER SELECTION ────────────────────────────────────────────────
# Build the endorsing-peer flag string from the trust-ranked roster.
RANK="${SG_ENDORSER_RANK:-org1,org2,org3}"
IFS=',' read -r -a RANKED <<< "$RANK"
K="${SG_ENDORSER_K:-${#RANKED[@]}}"
ENDORSERS=""
CHOSEN=""
cnt=0
for p in "${RANKED[@]}"; do
  [[ $cnt -ge $K ]] && break
  f="$(peer_flags "$p")"
  [[ -z "$f" ]] && continue
  ENDORSERS="$ENDORSERS $f"
  CHOSEN="${CHOSEN:+$CHOSEN,}$p"
  cnt=$((cnt+1))
done
# Safety fallback: never send an invoke with zero endorsers.
if [[ -z "$ENDORSERS" ]]; then
  ENDORSERS="$(peer_flags org1) $(peer_flags org2) $(peer_flags org3)"
  CHOSEN="org1,org2,org3(fallback)"
fi

PAYLOAD="{\"function\":\"$FUNC\",\"Args\":$ARGS}"

if [[ "$MODE" == "query" ]]; then
  OUT="$(peer chaincode query -C "$CH" -n "$CC" -c "$PAYLOAD" 2>&1)"
  RC=$?
  printf '%s  QUERY  %-24s rc=%s %s\n' "$(date +%H:%M:%S)" "$FUNC" "$RC" \
    "$(echo "$OUT" | head -c 120)" >> "$LIVELOG"
else
  OUT="$(peer chaincode invoke \
    -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" \
    -C "$CH" -n "$CC" \
    $ENDORSERS \
    --waitForEvent \
    -c "$PAYLOAD" 2>&1)"
  RC=$?
  STATUS="$(echo "$OUT" | grep -o 'status:[0-9]*' | head -1)"
  printf '%s  INVOKE %-24s endorsers=[%s] rc=%s %s\n' "$(date +%H:%M:%S)" "$FUNC" \
    "$CHOSEN" "$RC" "${STATUS:-$(echo "$OUT" | head -c 80)}" >> "$LIVELOG"
fi
exit 0
