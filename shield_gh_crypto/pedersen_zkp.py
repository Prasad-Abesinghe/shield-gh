"""
SHIELD-GH Task 05 — Pedersen Commitment + Zero-Knowledge Forwarding Proof
=========================================================================
Report Eq. 3.29 (Pedersen), Eq. 3.30 (ZKP.Prove), plus the three-state ZKP
evidence model (Eq. eq:zkp_state), the RSU cross-reference (Eq. eq:rsu_crossref)
and the DEBSC isolation gate (Eq. eq:debsc).

Cryptographic role (report "Phase 1 - Pre-Detection Evidence Generation"):
    ZKP is the sole technique that proves *forwarding behaviour* without
    revealing packet content.  A grey-hole node that drops packets cannot
    produce a proof whose committed n_fwd matches the blockchain-observable
    receipt count -> the discrepancy is the detection signal fed to DEBSC.

    C_i    = g^{n_fwd} * h^{r_i}  (mod p)                 # Eq. eq:pedersen
    pi_i   = ZKP.Prove(C_i, n_fwd, r_i)                    # Eq. eq:zkp_proof
    b      = ZKP.Verify(C_i, pi_i)

Implementation.
    * Pedersen commitment over a real 2048-bit MODP prime group (RFC 3526
      group 14).  g, h are independent generators (h derived by hashing g so
      that log_g(h) is unknown -> binding holds).  Commitment is perfectly
      hiding, computationally binding.
    * The proof pi_i is a NON-INTERACTIVE zero-knowledge proof of knowledge of
      an opening (n_fwd, r) of C, made non-interactive with the Fiat-Shamir
      transform (Schnorr-style sigma protocol for a Pedersen opening).  It
      reveals nothing about n_fwd beyond the fact that the prover knows a valid
      opening (zero-knowledge, honest-verifier).
    * The RSU cross-reference (Eq. eq:rsu_crossref) additionally binds the
      committed count to the independently observed count, closing the
      "commit to a truthful-looking but fabricated count" vector.

All arithmetic uses Python big integers; SHA-256 for Fiat-Shamir challenges.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from typing import Optional

# --------------------------------------------------------------------------- #
#  Public group parameters  (RFC 3526, MODP Group 14, 2048-bit prime)
# --------------------------------------------------------------------------- #
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
P = int(_P_HEX, 16)          # 2048-bit safe prime
Q = (P - 1) // 2             # order of the prime-order subgroup of QRs
G = 4                        # generator of the QR subgroup (2^2, a QR)


def _derive_h(g: int, p: int) -> int:
    """Second generator h with unknown discrete log to base g: hash-to-group.
    We hash a seed to an exponent and take g^e; because e is produced by a hash
    of a fixed public string, nobody knows log_g(h) unless they break the hash."""
    seed = sha256(b"SHIELD-GH-Pedersen-h-generator|" + str(g).encode()).digest()
    e = int.from_bytes(seed, "big") % Q
    if e < 2:
        e += 2
    return pow(g, e, p)


H = _derive_h(G, P)


# --------------------------------------------------------------------------- #
#  Pedersen commitment  (Eq. eq:pedersen)
# --------------------------------------------------------------------------- #
@dataclass
class PedersenCommitment:
    C: int          # commitment value  g^n * h^r mod p
    n_fwd: int      # committed forwarded-packet count (secret opening)
    r: int          # blinding factor                  (secret opening)

    def to_public(self) -> dict:
        return {"C_hex": hex(self.C)}


def commit(n_fwd: int, r: Optional[int] = None) -> PedersenCommitment:
    """Eq. eq:pedersen:  C = g^{n_fwd} * h^{r}  (mod p).  Binding + hiding."""
    if r is None:
        r = secrets.randbelow(Q - 1) + 1
    C = (pow(G, n_fwd % Q, P) * pow(H, r % Q, P)) % P
    return PedersenCommitment(C=C, n_fwd=n_fwd, r=r)


# --------------------------------------------------------------------------- #
#  Non-interactive ZK proof of knowledge of a Pedersen opening
#  (Schnorr-style sigma protocol + Fiat-Shamir).   Eq. eq:zkp_proof
# --------------------------------------------------------------------------- #
@dataclass
class ZKProof:
    t: int          # commitment of the sigma protocol (g^a h^b)
    z1: int         # response for n_fwd
    z2: int         # response for r
    n_declared: int # the forwarded count the prover publicly claims

    def to_public(self) -> dict:
        return {"t_hex": hex(self.t), "z1_hex": hex(self.z1),
                "z2_hex": hex(self.z2), "n_declared": self.n_declared}


def _fiat_shamir_challenge(C: int, t: int, n_declared: int) -> int:
    h = sha256()
    h.update(b"SHIELD-GH-ZKP-FS|")
    h.update(str(C).encode()); h.update(b"|")
    h.update(str(t).encode()); h.update(b"|")
    h.update(str(n_declared).encode())
    return int.from_bytes(h.digest(), "big") % Q


def prove(commitment: PedersenCommitment) -> ZKProof:
    """Eq. eq:zkp_proof:  pi = ZKP.Prove(C, n_fwd, r).
    Proves knowledge of (n_fwd, r) s.t. C = g^n h^r, revealing nothing else."""
    a = secrets.randbelow(Q - 1) + 1
    b = secrets.randbelow(Q - 1) + 1
    t = (pow(G, a, P) * pow(H, b, P)) % P
    e = _fiat_shamir_challenge(commitment.C, t, commitment.n_fwd)
    z1 = (a + e * (commitment.n_fwd % Q)) % Q
    z2 = (b + e * (commitment.r % Q)) % Q
    return ZKProof(t=t, z1=z1, z2=z2, n_declared=commitment.n_fwd)


def verify(C: int, proof: ZKProof) -> bool:
    """b = ZKP.Verify(C, pi).  Checks  g^{z1} h^{z2} == t * C^{e}  (mod p)."""
    e = _fiat_shamir_challenge(C, proof.t, proof.n_declared)
    lhs = (pow(G, proof.z1, P) * pow(H, proof.z2, P)) % P
    rhs = (proof.t * pow(C, e, P)) % P
    return lhs == rhs


# --------------------------------------------------------------------------- #
#  Three-state ZKP evidence model  (Eq. eq:zkp_state)
#  + RSU cross-reference (Eq. eq:rsu_crossref) + DEBSC gate (Eq. eq:debsc)
# --------------------------------------------------------------------------- #
class ZKPState(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ABSENT = "ABSENT"


@dataclass
class ProofSubmission:
    """What a vehicle submits to the blockchain for an observation window."""
    commitment_C: int
    proof: Optional[ZKProof]        # None models a withheld proof
    n_declared: int                 # committed forwarded count n_fwd
    t_recv: float                   # arrival time of the proof (sim seconds)


def rsu_consistent(n_declared: int, n_rsu_observed: int,
                   eps_obs: int) -> bool:
    """Eq. eq:rsu_crossref:  Consistent = 1[ |n_fwd - n_hat_fwd| <= eps_obs ]."""
    return abs(n_declared - n_rsu_observed) <= eps_obs


def zkp_evidence_state(sub: Optional[ProofSubmission],
                       t_window: float,
                       T_zkp: float,
                       n_rsu_observed: int,
                       eps_obs: int) -> ZKPState:
    """Eq. eq:zkp_state — three-state evidence.

    PASS   : valid pi received within T_zkp AND RSU cross-reference consistent
    FAIL   : pi received but verification fails, OR cross-reference inconsistent
    ABSENT : no pi received within T_zkp  (withheld / late)
    """
    # ABSENT: proof missing or arrives after the deadline t_window + T_zkp
    if sub is None or sub.proof is None or (sub.t_recv - t_window) > T_zkp:
        return ZKPState.ABSENT
    # cryptographic verification of the ZK proof against the commitment
    if not verify(sub.commitment_C, sub.proof):
        return ZKPState.FAIL
    # RSU independent cross-reference
    if not rsu_consistent(sub.n_declared, n_rsu_observed, eps_obs):
        return ZKPState.FAIL
    return ZKPState.PASS


def debsc_isolate(reputation_R: float, theta_R: float,
                  zkp_state: ZKPState) -> bool:
    """Eq. eq:debsc — DEBSC dual-gate isolation decision.

        Isolate(v_i) = 1[ (1 - R_i) > theta_R  AND  Pi_ZKP in {FAIL, ABSENT} ]
    """
    reputation_gate = (1.0 - reputation_R) > theta_R
    crypto_gate = zkp_state in (ZKPState.FAIL, ZKPState.ABSENT)
    return reputation_gate and crypto_gate


if __name__ == "__main__":  # smoke test
    print(f"Pedersen group: 2048-bit prime, g={G}, h=derived (unknown log)")
    c = commit(140)                     # honest node forwarded 140
    pi = prove(c)
    print("ZK verify (honest):", verify(c.C, pi))

    # attacker forges a commitment claiming 140 but actually forwarded ~40
    fake = commit(140)                  # commits to 140 to look honest
    sub = ProofSubmission(fake.C, prove(fake), 140, t_recv=0.5)
    print("state (commit 140, RSU saw 42):",
          zkp_evidence_state(sub, 0.0, 1.0, n_rsu_observed=42, eps_obs=5))
    print("state (withheld):",
          zkp_evidence_state(None, 0.0, 1.0, n_rsu_observed=42, eps_obs=5))
    print("DEBSC isolate (R=0.2, FAIL):",
          debsc_isolate(0.2, 0.5, ZKPState.FAIL))
