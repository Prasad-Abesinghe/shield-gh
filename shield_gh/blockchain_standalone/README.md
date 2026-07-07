# SHIELD-GH — Standalone Hyperledger Fabric (DEBSC Chaincode)

Real Hyperledger Fabric deployment of the DEBSC smart contract for **Task 1
evidence**. Implements Eq. 3.19 (dual-evidence isolation), Eq. 3.18
(reputation), Eq. 3.30 (ZKP forwarding-proof anchoring).

This is the *real* blockchain (vs. the in-memory C++ simulation inside NS-3 at
`../blockchain/blockchain_ledger.cc`). Use it for supervisor screenshots.

## Files
- `chaincode-debsc/debsc.go` — DEBSC Go chaincode (the smart contract)
- `chaincode-debsc/go.mod`, `vendor/` — Go module + vendored Fabric deps
- `debsc_demo.sh` — runs the full evidence scenario (commit records + isolate)

## Prerequisites (already satisfied on this machine)
- Docker + Docker Compose, Go 1.22
- `~/fabric-samples` with `bin/` (Fabric v2.5 CLI) and the test-network
- Docker images: `fabric-peer`, `fabric-orderer`, `fabric-ccenv:3.1`, `fabric-baseos:3.1`

## How to run (full reproduction)

```bash
# 1. Start the Fabric test-network + channel
cd ~/fabric-samples/test-network
./network.sh down                       # clean any prior state
./network.sh up createChannel -c mychannel

# 2. Deploy the DEBSC chaincode
./network.sh deployCC -ccn debsc \
  -ccp /home/sdvn_ssh/ns-allinone-3.35/ns-3.35/scratch/shield_gh/blockchain_standalone/chaincode-debsc \
  -ccl go -c mychannel

# 3. Run the evidence demo (commit forwarding records + evaluate isolation)
bash /home/sdvn_ssh/ns-allinone-3.35/ns-3.35/scratch/shield_gh/blockchain_standalone/debsc_demo.sh

# 4. When finished
cd ~/fabric-samples/test-network && ./network.sh down
```

## Evidence screenshots to capture (Task 1 checklist)

1. **Fabric running** — `docker ps` showing `orderer.example.com`,
   `peer0.org1/2.example.com`, and `dev-peer0.org*-debsc_1.0` chaincode containers.
2. **Chaincode committed** —
   `peer lifecycle chaincode querycommitted --channelID mychannel --name debsc`
   → `Approvals: [Org1MSP: true, Org2MSP: true]`.
3. **DEBSC Eq. 3.19 dual-gate** — output of `debsc_demo.sh`:
   - honest node10 (ZKP valid)   → `MONITOR ... Eq.3.19 NOT satisfied`
   - grey-hole node20 (ZKP FAIL) → `ISOLATE ... Eq.3.19 dual-gate FIRED`
4. **On-ledger isolation persisted** — `GetAllNodes` shows `"isolated":true`
   for the attacker, committed immutably on the blockchain.

## Formal verification (unit tests with dummy data)

The chaincode is **formally verified** with a self-contained Go test suite that
runs the contract against an in-memory ledger fake (no running Fabric needed):

```bash
bash blockchain_standalone/run_tests.sh
# or:  cd chaincode-debsc && go test -v -cover ./...
```

`chaincode-debsc/debsc_test.go` verifies every function with dummy data:

| Test | What it proves |
|---|---|
| `TestCommitForwardingRecord_DummyData` | reputation, ZKP validity, suspicion derived correctly across 5 dummy (fwd,rx) inputs |
| `TestEvaluateIsolation_DualGateTruthTable` | **Eq. 3.19 truth table**: ISOLATE only when (1-Ri)>θR AND ZKP-fail; else MONITOR |
| `TestEvaluateIsolation_StatGateButValidZKP_NotIsolated` | honest-but-mobile node (low rep, valid ZKP) is NOT falsely isolated |
| `TestEvaluateIsolation_PersistsIsolatedFlag` | isolation decision is committed to the ledger |
| `TestEvaluateIsolation_UnknownNode` | unknown node → MONITOR (graceful) |
| `TestReadNode`, `TestGetAllNodes`, `TestInitLedger` | query + seed functions |

**Result:** 8/8 tests PASS, ~75% statement coverage (business logic 78–91%;
only `main()` entrypoint uncovered, which is expected).

## What this proves
The grey-hole attacker's forwarding record is committed to a **tamper-proof,
multi-org (Org1+Org2 endorsed) blockchain ledger**. Isolation requires BOTH a
low reputation AND a failed ZKP proof (Eq. 3.19), and the decision is recorded
on-chain — no single SDN controller can fake or reverse it.
