# SHIELD-GH Blockchain — Functional Verification Evidence

Real Hyperledger Fabric (`debsc` Go chaincode) — Task 1 of the SHIELD-GH
Implementation Guide. Each task below is a separate screenshot with a brief
description. Run each command **in your terminal** and screenshot the output;
the same commands were run here and the captured output is in the `.log` files
next to this README.

Prereq for Tasks 2–5: the Fabric test-network must be up with the `debsc`
chaincode deployed (see Task 2). Stop it afterwards with:
`cd ~/fabric-samples/test-network && ./network.sh down`.

---

## Task 1 — Smart-Contract Formal Verification (unit tests)
**Proves:** the DEBSC contract logic (Eq. 3.19 dual-gate, Eq. 3.18 reputation,
Eq. 3.30 ZKP) is functionally correct against dummy data. No Fabric needed.

```bash
cd /home/sdvn_ssh/ns-allinone-3.35/ns-3.35/scratch/shield_gh/blockchain_standalone
export PATH=$PATH:/usr/local/go/bin
bash run_tests.sh
```
Screenshot: the `--- PASS` list (8 tests) + `ok debsc` + the coverage table.
Log: `taskA_formal_verification.log`

---

## Task 2 — Live Hyperledger Fabric: THREE-peer network + chaincode deployed
**Proves:** real Fabric network with THREE org peers (org1/org2/org3) + orderer,
`debsc` chaincode installed on all three so any can endorse.

```bash
cd ~/fabric-samples/test-network
# 1) base 2-org network + channel
./network.sh up createChannel -c mychannel
./network.sh deployCC -ccn debsc \
  -ccp /home/sdvn_ssh/ns-allinone-3.35/ns-3.35/scratch/shield_gh/blockchain_standalone/chaincode-debsc \
  -ccl go -c mychannel
# 2) add the THIRD org/peer and join it to the channel
cd addOrg3 && ./addOrg3.sh up -c mychannel && cd ..
# 3) install + approve debsc on org3 (so org3 can endorse) — see
#    results/verification/setup_org3_debsc.sh for the exact commands
bash /home/sdvn_ssh/ns-allinone-3.35/ns-3.35/scratch/shield_gh/blockchain_standalone/results/verification/setup_org3_debsc.sh

docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -iE "NAMES|peer0|orderer"
```
Screenshot: THREE `peer0.orgN.example.com` containers (7051/9051/11051) + orderer
+ the three `dev-peer0.orgN...debsc` chaincode containers.
Logs: `taskB_network_up.log`, `taskB_deploy.log`, `taskB_three_peers.log`

---

## Task 3 — NS-3 → Fabric integration with correct timing  *(supervisor request)*
**Proves:** NS-3 does not just drive the in-memory ledger — it invokes the REAL
`debsc` chaincode DURING the simulation, tagged with the NS-3 clock. When
SHIELD-GH detects a grey-hole it fires `EvaluateIsolation` (Eq. 3.19) on-chain
in real time.

```bash
cd /home/sdvn_ssh/ns-allinone-3.35/ns-3.35
LD_LIBRARY_PATH=build/lib:build ./build/scratch/routing \
  --enable_shield_gh=1 --attack_number=1 --drop_rate=60 --live_blockchain=1 --simTime=25
```
Screenshot the `[SHIELD-GH][LIVE-BC]` lines showing the sim timestamps, e.g.:
```
[SHIELD-GH][LIVE-BC] Live Hyperledger Fabric integration ON ...
[SHIELD-GH] Node 1 ISOLATED & BLOCKED | t=4.00 ... ZKP=FAIL real_attacker=1
[SHIELD-GH][LIVE-BC] EvaluateIsolation(node1) committed to Fabric | t=4.00
[SHIELD-GH] Node 0 ISOLATED & BLOCKED | t=6.00 ...
[SHIELD-GH][LIVE-BC] EvaluateIsolation(node0) committed to Fabric | t=6.00
[SHIELD-GH][LIVE-BC] Finalising on-chain isolation for 2 node(s)...
```
Log: `taskC_ns3_live_run.log`

Then screenshot the on-chain state that NS-3 wrote (grey-holes isolated,
honest relay not):
```bash
cd ~/fabric-samples/test-network
# (set Org1 admin env — see debsc_demo.sh lines 17-23, or source it)
peer chaincode query -C mychannel -n debsc -c '{"function":"ReadNode","Args":["node0"]}'
peer chaincode query -C mychannel -n debsc -c '{"function":"ReadNode","Args":["node1"]}'
peer chaincode query -C mychannel -n debsc -c '{"function":"ReadNode","Args":["node2"]}'
```
Expected:
```
node0 -> reputation:0 zkpValid:false isolated:true    (grey-hole, Eq.3.19 fired)
node1 -> reputation:0 zkpValid:false isolated:true    (grey-hole, Eq.3.19 fired)
node2 -> reputation:1 zkpValid:true  isolated:false   (honest, correctly kept)
```
Log: `taskC_onchain_final.log`

---

## Task 4 — Dynamic blockchain endorser selection  *(supervisor request)*
**Proves:** with THREE peers in the pool, the endorsing set is chosen dynamically
per invoke by trust rank (org peers ranked by on-ledger reputation Ri, Eq. 3.18).
Under the MAJORITY (2-of-3) policy each invoke enlists the TOP-2 most-trusted and
DROPS the least-trusted — genuine selection, not the static "always all peers".

```bash
grep -oE 'endorsers=\[[^]]*\]' \
  /home/sdvn_ssh/ns-allinone-3.35/ns-3.35/scratch/shield_gh/blockchain_standalone/results/live_invoke.log \
  | sort | uniq -c
```
Screenshot: different top-2 pairs across `{org1,org2,org3}` (e.g. `[org3,org1]`,
`[org2,org3]`) — the chosen endorser pair follows live trust; org3 is a real
participant. Optional manual demo showing all three rotate:
```bash
BR=/home/sdvn_ssh/ns-allinone-3.35/ns-3.35/scratch/shield_gh/blockchain_standalone/debsc_invoke.sh
SG_ENDORSER_RANK=org1,org2,org3 SG_ENDORSER_K=2 bash $BR invoke CommitForwardingRecord '["nodeX","50","100"]'
SG_ENDORSER_RANK=org3,org1,org2 SG_ENDORSER_K=2 bash $BR invoke CommitForwardingRecord '["nodeX","50","100"]'
SG_ENDORSER_RANK=org2,org3,org1 SG_ENDORSER_K=2 bash $BR invoke CommitForwardingRecord '["nodeX","50","100"]'
tail -3 /home/sdvn_ssh/ns-allinone-3.35/ns-3.35/scratch/shield_gh/blockchain_standalone/results/live_invoke.log
# -> endorsers=[org1,org2] / [org3,org1] / [org2,org3]  all status:200
```
Implementation: `debsc_invoke.sh` (SG_ENDORSER_RANK / SG_ENDORSER_K, 3-peer map) +
`shield_gh_integration.h::sg_dynamic_endorser_env()` (ranks all 3 orgs, top-2).
Log: `taskD_dynamic_endorser.log`

---

## Task 5 — VRF-based dynamic endorser selection at CHAINCODE level  *(Supervisor Revision Block 15)*
**Proves:** endorser selection is done INSIDE the chaincode via a Verifiable
Random Function over the on-ledger RSU pool — implementing every equation of the
spec: E(t) eligibility filter, per-tx seed s_tx, VRF eval/verify (β_j, π_j),
top-k_end selection Ω(t), k_end/f_max, and the 4-mode bypass (NORMAL/RELAXED/
DEFERRED/EMERGENCY). 64 RSUs are statically allocated as the endorser pool; the
VRF picks a DIFFERENT, unpredictable endorser set per transaction.

**SCALE (supervisor: "have at least 10 endorsers, else no consensus"):** the
endorser count scales with the pool — k_end = max(k_min=10, ⌈|E|·0.34⌉). With
64 RSUs → ~50 eligible → **17 endorsers per tx**, tolerating f_max=16 Byzantine
RSUs. The k_min=10 hard floor guarantees a real BFT quorum even for smaller pools.

**One-shot demo (register 64 RSUs + select + bypass modes):**
```bash
bash /home/sdvn_ssh/ns-allinone-3.35/ns-3.35/scratch/shield_gh/blockchain_standalone/show_to_supervisor.sh
```
Screenshot section [4]: two txs each select 17 different endorsers (Ω(t)),
`f_max=16`, all proofs verify. Log: `taskE_vrf_64rsu_scale.log`

**5a — unit tests (all 5 steps):**
```bash
cd /home/sdvn_ssh/ns-allinone-3.35/ns-3.35/scratch/shield_gh/blockchain_standalone
export PATH=$PATH:/usr/local/go/bin && bash run_tests.sh
```
Screenshot the 7 `TestSelectEndorsers_*`/`TestVRFVerify_*` PASS lines +
`SelectEndorsers 90.0%` coverage. Log: `taskE_vrf_tests.log`

**5b — live on real Fabric (register pool + select):**
```bash
# (set Org1 admin env first — see debsc_demo.sh)
peer chaincode query -C mychannel -n debsc -c '{"function":"SelectEndorsers","Args":["TX-1001"]}'
peer chaincode query -C mychannel -n debsc -c '{"function":"SelectEndorsers","Args":["TX-2002"]}'
```
Screenshot: two DIFFERENT VRF-selected endorser sets Ω(t) (different `seed`,
`verify:true` on each), proving per-transaction unpredictability. Ineligible RSUs
(low trust / under-observed) are filtered. Log: `taskE_vrf_endorser_selection.log`

**5c — bypass modes:** `taskE_vrf_bypass_modes.log` shows DEFERRED (pool<k_min) and
EMERGENCY (pool empty → single highest-trust endorser + audit).

**5d — NS-3 drives it live:**
```bash
cd /home/sdvn_ssh/ns-allinone-3.35/ns-3.35
LD_LIBRARY_PATH=build/lib:build ./build/scratch/routing \
  --enable_shield_gh=1 --attack_number=1 --drop_rate=60 --live_blockchain=1 --simTime=25
```
Screenshot the `[SHIELD-GH][LIVE-BC] Registered 6 RSU...` and
`VRF SelectEndorsers fired for isolation tx (nodeN)` lines — NS-3 invoking the
chaincode VRF before each on-chain isolation. Log: `taskE_vrf_ns3_driven.log`

Implementation: `chaincode-debsc/endorser_vrf.go` (SelectEndorsers, vrfEval/Verify,
RegisterRSU, 4-mode bypass) + `endorser_vrf_test.go` (7 tests) + NS-3 hooks in
`shield_gh_integration.h` (RSU pool registration + per-isolation SelectEndorsers).

---

### Files
| File | What it shows |
|---|---|
| `taskA_formal_verification.log` | 8 unit tests PASS + coverage |
| `taskB_network_up.log` / `taskB_deploy.log` | Fabric up + debsc committed |
| `taskC_ns3_live_run.log` | NS-3 live-invoking chaincode w/ sim timing |
| `taskC_onchain_final.log` | on-chain records written by the NS-3 sim |
| `taskD_dynamic_endorser.log` | dynamic trust-ranked endorser selection |
