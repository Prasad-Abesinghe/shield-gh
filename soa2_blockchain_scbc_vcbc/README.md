# SOA2 — Alabdulatif et al. SCBC/VCBC on Real Blockchain

Second state-of-the-art baseline for the SHIELD-GH comparison.

**Paper:** Alabdulatif, Alharbi, Mchergui, Moulahi, *"Mitigating Blackhole and
Greyhole Routing Attacks in Vehicular Ad Hoc Networks Using Blockchain Based
Smart Contracts"*, CMES 2024, vol.138 no.2, pp.2005–2021. DOI 10.32604/cmes.2023.029769.

This implements the paper's two smart contracts **on a real Hyperledger Fabric
network** (same test-network used by our SHIELD-GH DEBSC chaincode), not the
in-memory simulation. The paper itself used Remix/Solidity as proof-of-concept;
we deploy real Go chaincode for consistency with SOA1.

## What the chaincode implements

| Paper | Chaincode function | Meaning |
|-------|--------------------|---------|
| Alg. 3 `updateNode` | `classify()` | rating = delivered·100/(delivered+notDelivered); 0→black, ≤τ→grey, >τ→white |
| Alg. 1 SCBC | `RunSCBC` | classify every node from delivered ratio (no prior knowledge) |
| Alg. 4 `makeVoting` | `makeVoting()` | drop nodes whose miner reputation is grey/black |
| Alg. 5 VCBC | `RunVCBC` | voting pre-filter (Alg.4) then SCBC classification on survivors |
| — | `CommitRelayRecord` | append-only, tamper-proof relay evidence |
| — | `SetReputation` | miner's prior vote (w/g/b) for VCBC |

`black` = drops everything (rating 0), `grey` = partial/unpredictable drop
(rating ≤ τ), `white` = good relay usable by AODV (rating > τ). τ default = 50%.

## Layout

```
soa2_blockchain_scbc_vcbc/
├── chaincode-scbcvcbc/
│   ├── scbcvcbc.go        # the SCBC + VCBC smart contracts (Alg.1-5)
│   ├── scbcvcbc_test.go   # 8 unit tests, in-memory ledger fake, 76.5% cov
│   ├── go.mod / go.sum / vendor/   # Fabric deps (vendored, builds offline)
├── scbcvcbc_demo.sh       # live invoke/query demo on the test-network
├── scbcvcbc_bridge.py     # NS-3 CSV → real blockchain → paper metrics
├── run_tests.sh           # go test runner (no Fabric needed)
└── README.md
```

## Run

### 1. Unit tests (no Fabric)
```bash
bash run_tests.sh        # 8 tests pass, ~76% coverage
```

### 2. Deploy + live demo (real blockchain)
```bash
cd ~/fabric-samples/test-network
./network.sh up createChannel -c mychannel        # if not already up
./network.sh deployCC -ccn scbcvcbc \
    -ccp /home/sdvn_ssh/ns-allinone-3.35/ns-3.35/scratch/soa2_blockchain_scbc_vcbc/chaincode-scbcvcbc \
    -ccl go -c mychannel
bash /home/sdvn_ssh/.../soa2_blockchain_scbc_vcbc/scbcvcbc_demo.sh
```
Demo proves: SCBC classifies blackhole→black, greyhole→grey, honest→white;
VCBC voting excludes both malicious cars up front (only car1 survives).

### 3. NS-3 ↔ blockchain bridge
```bash
# NS-3 logs per-window per-node PDR to results/vcbc_detection.csv
./waf --run "routing ... --use_vcbc_detection=1"
# then classify on the real ledger + compute metrics:
python3 scbcvcbc_bridge.py            # uses real Fabric
python3 scbcvcbc_bridge.py --dry-run  # local Alg.3, no Fabric (validation)
```
Writes `results/soa2_blockchain_results.csv` with TP/TN/FP/FN, classification
accuracy, FPR, TPR, network PDR (Eq.1) and routing overhead (Eq.3).

### 4. Attacker-percentage sweep + plots (supervisor's request)
Vary the independent variable (attacker %) and plot how the metrics respond:
```bash
python3 scbcvcbc_sweep.py                                  # local model, default sweep
python3 scbcvcbc_sweep.py --N 30 --seeds 30 \
        --fracs 0.05,0.1,0.15,0.2,0.3,0.4,0.5,0.6          # high-res curves
python3 scbcvcbc_sweep.py --backend fabric --N 6 --seeds 1 # same, on real chaincode (slow)
```
Outputs to `results/`:
- `soa2_sweep_panel.png` — 2×2 panel: accuracy, PDR, TPR/FPR, routing overhead
- `soa2_sweep_{acc,pdr,ro}.png` — individual figures for slides
- `soa2_sweep_results.csv` — raw per-seed rows

**What the curves show** (and why they move — the supervisor noted a test
network may look flat unless a confound is modelled): observed forwarding ratio
is a node's own behaviour AND its downstream path, so as attacker density rises,
path contamination drags honest nodes' observed PDR toward the threshold while
greyholes straddle τ. Result:
- **Network PDR falls** monotonically (~0.91 → 0.71 from 5%→60% attackers).
- **TPR rises** with density (greyholes' PDR sags below τ, easier to catch).
- **SCBC accuracy ≈ 1.0; VCBC ≈ 0.90–0.96 with non-zero FPR** — reproduces the
  paper's finding that VCBC's noisy miner-voting trades some precision.
- **Routing overhead** is flat in attacker % (Eq.3 depends on node count, not mix).

The `local` backend runs the identical Alg.3 classifier in-process for smooth
many-seed curves; `fabric` proves the same trend through the deployed chaincode.

## Metrics (Eqs. from paper §5.2)
- **PDR** = Drcv / Dtotal (delivered relays / total relays)
- **RO**  = (Dnet + Dctrl) / Dnet — Dctrl = one 100-byte smart-contract call
  per node per window
- Classification accuracy / FPR / TPR against ground-truth attacker labels.

## Separation from SHIELD-GH and SOA1
This directory is fully self-contained. It does **not** touch `routing.cc`
detection logic, the SHIELD-GH `shield_gh/` tree, or SOA1
(`soa_baselines/malik_detection.h`). The only shared input is the per-window
PDR CSV NS-3 already produces.
```
```
