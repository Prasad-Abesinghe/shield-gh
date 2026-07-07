# SHIELD-GH — Task 05: Cryptographic Content

Real, runnable implementation of **all** the cryptographic mechanisms specified
in the SHIELD-GH proposal (`main.tex`, `Grey_Hole_Attack_Proposal.pdf`):
key sharing via a **logical key hierarchy (PQC-LKH)**, **authentication**,
zero-knowledge forwarding proofs, threshold blacklisting, distributed key
generation, and controller key revocation.

This is a **standalone Python module** (like `scratch/loris_crypto/`) — the crypto
is proven with a passing test suite and reproducible evidence vectors, decoupled
from the NS-3 data-plane simulation. It does **not** touch `routing.cc`.

## Backend (Hybrid, as requested)

Genuine post-quantum crypto when [liboqs](https://openquantumsafe.org) is present,
otherwise a documented classical stand-in with an identical API:

| Primitive | Genuine PQC backend (active here) | Classical fallback |
|-----------|-----------------------------------|--------------------|
| Kyber KEM | **Kyber-512 / Kyber-768** (liboqs 0.15.0, Module-LWE, IND-CCA2) | X25519 ECDH + HKDF-SHA256 |
| Dilithium sig | **ML-DSA-44** = CRYSTALS-Dilithium-2 (FIPS-204, Module-LWE, EUF-CMA) | Ed25519 (EdDSA) |
| Pedersen / ZKP | real 2048-bit MODP group (RFC 3526 grp 14), Schnorr σ-protocol + Fiat-Shamir | same (backend-independent) |
| DKG | Pedersen/Feldman VSS over secp256k1 order | same |

Active backend is recorded in `vectors/backend.json`. The fallback is real, secure
classical crypto — but **not** quantum-resistant, and is flagged as such.

## Files → report equations

| File | Report | Equations / Algorithms |
|------|--------|------------------------|
| `pqc_primitives.py` | §3.6.8 | Kyber `Enc`/`Dec` (3.25/3.26); Dilithium `Sign`/`Verify` (3.27/3.28) |
| `pedersen_zkp.py` | §3.6.8, Blk 5 | Pedersen commitment `C=g^n h^r` (3.29); `ZKP.Prove`/`Verify` (3.30); 3-state model `Π_ZKP∈{PASS,FAIL,ABSENT}` (`eq:zkp_state`); RSU cross-ref (`eq:rsu_crossref`); DEBSC dual-gate `Isolate` (`eq:debsc`) |
| `threshold_sig.py` | §3.6.8, Blk 8 | `TS.PartialSign`/`Combine`/`Verify` (3.31/3.32/3.33); Pedersen DKG share/pubkey (`eq:dkg_share`/`eq:dkg_pubkey`); threshold re-key auth (`eq:rekey_sig`) |
| `pqc_lkh.py` | §3.6.9 / `sec:pqc_lkh`, Fig 3.11 | Key set `K_j` (3.34/`eq:lkh_keys`); group re-key `(K_grp,c_root)` (3.35/`eq:lkh_grp`); path re-key `(K_u^new,c_u)` (3.36/`eq:lkh_rekey`); lazy join/depart |
| `authentication.py` | Alg 5 & 6 | Dilithium FlowMod install + anti-replay; `Controller-Failover` + `BLOCKCHAIN_REVOKE_KEY` (Alg 5); `ZKP-Crosscheck` (Alg 6) |
| `gen_evidence.py` | Fig 3.5 | End-to-end mitigation flowchart transcript + golden vectors |
| `tests/` | all | 31 pytest cases, one per equation/property |

## The "logical key hierarchy" (PQC-LKH)

Vehicles are leaves of a binary tree; every node holds a Kyber keypair. Isolating a
vehicle refreshes **only** its leaf→root path — exactly `⌈log₂ N⌉` Kyber operations
versus `N−1` for naive unicast (Fig 3.11). The refreshed root distributes a new group
key `K_grp'`; the isolated vehicle, holding only stale path keys, **cannot** decapsulate
it and is cryptographically excluded without any direct contact. Proven in
`test_lkh_isolated_vehicle_excluded` and the evidence transcript.

## Run

```bash
# one-time (already done on this host):
python3 -m venv ~/shield-crypto-venv
~/shield-crypto-venv/bin/pip install pycryptodome liboqs-python pytest pytest-cov

# tests (both backends):
~/shield-crypto-venv/bin/python3 -m pytest tests/ -v

# evidence transcript + golden vectors:
~/shield-crypto-venv/bin/python3 gen_evidence.py

# everything at once:
bash verify_all.sh
```

## Visual evidence / screenshots (`figures/`)

`~/shield-crypto-venv/bin/python3 gen_figures.py` renders 4 screenshot-ready PNGs
from **real runs** of the module (same look as the report figures):

- `fig1_pipeline.png` — the 6-gate mitigation pipeline, each gate marked OK.
- `fig2_lkh_tree.png` — the PQC-LKH binary tree before/after isolating V3
  (refreshed path highlighted; 3 Kyber ops = ⌈log₂8⌉).
- `fig3_rekey_cost.png` — measured O(log N) vs O(N) re-key cost curve.
- `fig4_zkp_debsc.png` — 3-state ZKP + DEBSC truth table (honest node spared,
  every attacker variant isolated).

For terminal screenshots, run `~/shield-crypto-venv/bin/python3 -m pytest tests/ -v`
(31 green) and `gen_evidence.py` (the transcript) and capture the console.

## Evidence (`vectors/`)

- `evidence_transcript.txt` — step-by-step run of Fig 3.5: attacker V3
  detected → ZKP FAIL → DEBSC isolate → 3-of-5 threshold blacklist →
  Dilithium FlowMod installed (replay blocked) → PQC-LKH re-key excludes V3;
  honest high-loss V5 **not** isolated; forged controller command rejected.
- `golden_vector.json` — machine-checkable outcomes & key digests.
- `backend.json`, `pip_freeze.txt` — reproducibility.

## Relationship to the existing C++ stubs

`scratch/shield_gh/crypto/*.cc` are non-compiling skeletons that require liboqs
linked into NS-3 (`-DUSE_LIBOQS`, excluded from the lightweight build). This module
supersedes them with a real, tested implementation of the same equations.
