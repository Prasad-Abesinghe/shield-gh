# SHIELD-GH Task 05 — Screenshot Evidence Pack

Three categories, as requested. Each PNG is a captioned screenshot; open in order.

## A. Code evidence (the real cryptography)
- **A1_code_kyber_dilithium.png** — genuine Kyber-768 + Dilithium(ML-DSA-44) primitives.
- **A2_code_pqc_lkh.png** — PQC-LKH logical key hierarchy re-key (O(log N), excludes isolated node).
- **A3_code_zkp_debsc.png** — Pedersen commitment + zero-knowledge proof + DEBSC dual-gate.
- **A4_code_filetree.png** — module layout; every file maps to a report equation.

## B. Standalone verification evidence
- **B1_standalone_pytest.png** — 31/31 unit tests pass, one per equation (27 real-PQC + 4 fallback).
- **B2_standalone_transcript.png** — full end-to-end mitigation run on a scripted attacker + honest control.

## C. NS-3 realtime evidence (crypto running inside the simulation)
- **C1_ns3_realtime_crypto.png** — `--enable_crypto_hook=1`: real Kyber/Dilithium/PQC-LKH fire the moment
  ns-3 isolates each grey-hole node during the live run.
- **C2_ns3_crypto_eventlog.png** — the persisted per-event crypto log with real sim timestamps + node ids.

### How to reproduce C (realtime)
```bash
cd <ns-3.35 root>
./waf build --targets=routing
./waf --run "routing --N_Vehicles=20 --simTime=15 --architecture=0 \
      --routing_algorithm=4 --maxspeed=80 --attack_number=1 --enable_crypto_hook=1"
```
Watch for `[SHIELD-GH] Node N ISOLATED` immediately followed by the `THRESHOLD / FLOWMOD /
PQC-LKH / DONE` crypto lines. Backend = liboqs (genuine post-quantum).
