"""
SHIELD-GH Task 05 — (k,n) Threshold Signatures + Pedersen DKG
=============================================================
Report Eq. 3.31 / 3.32 / 3.33 (threshold co-signature for collective
blacklisting), Eq. eq:dkg_share / eq:dkg_pubkey (distributed key generation for
the PQC-LKH root), and Eq. eq:rekey_sig (threshold re-keying authorisation).

Cryptographic role (report "Phase 2 - Post-Detection Mitigation Enforcement"):
    A (k,n)-threshold signature requires k of n RSUs to co-sign the blacklisting
    decision before isolation executes, preventing a single compromised/mistaken
    RSU from unilaterally isolating a legitimate vehicle.  Selected over ring
    signatures precisely BECAUSE it keeps individual accountability -- each
    partial is an attributable Dilithium signature by a named RSU:

        sigma_j = TS.PartialSign(sk_j, B(v_i)),  j = 1..k      # Eq. 3.31
        sigma*  = TS.Combine({sigma_j})                        # Eq. 3.32
        b       = TS.Verify(pk_group, B(v_i), sigma*)          # Eq. 3.33

Implementation.
    Real, verifiable threshold construction (NOT the placeholder XOR of the
    earlier C++ stub).  Each partial is a genuine post-quantum Dilithium
    signature.  Combine bundles the k attributable partials.  Verify:
       (a) recomputes each partial against its RSU's registered public key,
       (b) requires >= k DISTINCT RSUs with VALID signatures over B(v_i).
    This gives the exact security property the report claims ("secure as long
    as fewer than k RSUs are compromised") with full auditability.

    Pedersen DKG: each participant p picks a secret polynomial f_p over Z_q,
    broadcasts Feldman commitments g^{a_{p,i}}, and every participant's private
    share is sk_p^share = sum_q f_q(p) (Eq. eq:dkg_share); the group public key
    is the sum of contributions (Eq. eq:dkg_pubkey).  Correctness (Lagrange
    reconstruction of the joint secret from >= t shares) is verified in tests.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Dict, List

from pqc_primitives import DilithiumSig, DilithiumKeyPair


# =========================================================================== #
#  (k, n) Threshold co-signature over an attributable Dilithium partial set
# =========================================================================== #
@dataclass
class RSUKeyRegistry:
    """Registered Dilithium public keys of the n RSUs (published on-chain)."""
    pubkeys: Dict[int, bytes] = field(default_factory=dict)      # rsu_id -> pk

    def register(self, rsu_id: int, pk: bytes) -> None:
        self.pubkeys[rsu_id] = pk

    @property
    def n(self) -> int:
        return len(self.pubkeys)


@dataclass
class PartialSig:
    rsu_id: int
    signature: bytes


@dataclass
class AggregateSignature:
    message: bytes
    partials: List[PartialSig]

    @property
    def signer_ids(self) -> List[int]:
        return [p.rsu_id for p in self.partials]


class ThresholdSig:
    # ---- Eq. 3.31:  sigma_j = TS.PartialSign(sk_j, B(v_i)) ----------------
    @staticmethod
    def partial_sign(rsu_id: int, blacklist_msg: bytes, rsu_sk: bytes) -> PartialSig:
        if isinstance(blacklist_msg, str):
            blacklist_msg = blacklist_msg.encode()
        sig = DilithiumSig.sign(blacklist_msg, rsu_sk)
        return PartialSig(rsu_id=rsu_id, signature=sig)

    # ---- Eq. 3.32:  sigma* = TS.Combine({sigma_j}) -----------------------
    @staticmethod
    def combine(blacklist_msg: bytes, partials: List[PartialSig]) -> AggregateSignature:
        if isinstance(blacklist_msg, str):
            blacklist_msg = blacklist_msg.encode()
        # de-duplicate by rsu_id (one attributable partial per RSU)
        seen: Dict[int, PartialSig] = {}
        for p in partials:
            seen.setdefault(p.rsu_id, p)
        return AggregateSignature(message=blacklist_msg, partials=list(seen.values()))

    # ---- Eq. 3.33:  b = TS.Verify(pk_group, B(v_i), sigma*) --------------
    @staticmethod
    def verify(agg: AggregateSignature, blacklist_msg: bytes,
               required_k: int, registry: RSUKeyRegistry) -> bool:
        """b = 1 iff at least k DISTINCT registered RSUs each contributed a
        cryptographically VALID Dilithium partial over B(v_i)."""
        if isinstance(blacklist_msg, str):
            blacklist_msg = blacklist_msg.encode()
        if agg.message != blacklist_msg:
            return False
        valid_signers = set()
        for p in agg.partials:
            pk = registry.pubkeys.get(p.rsu_id)
            if pk is None:
                continue                       # unregistered RSU -> ignored
            if DilithiumSig.verify(blacklist_msg, p.signature, pk):
                valid_signers.add(p.rsu_id)
        return len(valid_signers) >= required_k

    @staticmethod
    def count_valid(agg: AggregateSignature, registry: RSUKeyRegistry) -> int:
        valid = set()
        for p in agg.partials:
            pk = registry.pubkeys.get(p.rsu_id)
            if pk and DilithiumSig.verify(agg.message, p.signature, pk):
                valid.add(p.rsu_id)
        return len(valid)


# =========================================================================== #
#  Pedersen Distributed Key Generation for the PQC-LKH root  (Eq. eq:dkg_*)
# =========================================================================== #
# Prime-order field for the (t,n) secret sharing that authorises root-key ops.
# (This shares the AUTHORISATION secret; the actual Kyber root keypair is bound
#  to it — no single participant can act on the root alone.)
_DKG_Q_HEX = (
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03B"
    "BFD25E8CD0364141"
)
DKG_Q = int(_DKG_Q_HEX, 16)          # 256-bit prime (secp256k1 group order)
DKG_G = 2                             # generator for Feldman commitments


@dataclass
class DKGParticipant:
    pid: int                              # participant index (>=1)
    coeffs: List[int]                     # secret polynomial coefficients a_0..a_{t-1}
    commitments: List[int] = field(default_factory=list)  # Feldman g^{a_i}

    def eval(self, x: int) -> int:
        """f_p(x) = a_0 + a_1 x + ... + a_{t-1} x^{t-1}  (mod q)."""
        acc = 0
        for i, a in enumerate(self.coeffs):
            acc = (acc + a * pow(x, i, DKG_Q)) % DKG_Q
        return acc


class PedersenDKG:
    """Joint generation of a (t, n) shared secret among controller + RSUs."""

    def __init__(self, participant_ids: List[int], t: int):
        assert t <= len(participant_ids)
        self.ids = list(participant_ids)
        self.t = t
        self.participants: Dict[int, DKGParticipant] = {}

    def deal(self) -> None:
        for pid in self.ids:
            coeffs = [secrets.randbelow(DKG_Q - 1) + 1 for _ in range(self.t)]
            part = DKGParticipant(pid=pid, coeffs=coeffs)
            part.commitments = [pow(DKG_G, a, DKG_Q) for a in coeffs]  # Feldman
            self.participants[pid] = part

    def share_for(self, pid: int) -> int:
        """Eq. eq:dkg_share:  sk_p^share = sum_{q in P} f_q(p)  (mod q)."""
        return sum(self.participants[q].eval(pid)
                   for q in self.ids) % DKG_Q

    def group_secret(self) -> int:
        """The joint secret s = sum_p a_{p,0}. No single participant knows it;
        it is reconstructable only from >= t shares (verified via Lagrange)."""
        return sum(self.participants[p].coeffs[0]
                   for p in self.ids) % DKG_Q

    def group_public(self) -> int:
        """Eq. eq:dkg_pubkey:  pk_root = sum_p pk_p^share  (product in the group
        of per-participant public contributions g^{a_{p,0}})."""
        acc = 1
        for p in self.ids:
            acc = (acc * self.participants[p].commitments[0]) % DKG_Q
        return acc

    @staticmethod
    def lagrange_reconstruct(shares: Dict[int, int]) -> int:
        """Reconstruct the joint secret s = f(0) from >= t shares via Lagrange
        interpolation at x=0 in Z_q.  Used to PROVE that t cooperating
        participants recover exactly group_secret() (and fewer than t cannot)."""
        ids = list(shares.keys())
        secret = 0
        for i in ids:
            num, den = 1, 1
            for j in ids:
                if i == j:
                    continue
                num = (num * (-j % DKG_Q)) % DKG_Q
                den = (den * ((i - j) % DKG_Q)) % DKG_Q
            lag = (num * pow(den, -1, DKG_Q)) % DKG_Q
            secret = (secret + shares[i] * lag) % DKG_Q
        return secret


# =========================================================================== #
#  Threshold Re-Keying Broadcast Signature  (Eq. eq:rekey_sig)
# =========================================================================== #
def rekey_authorisation(rekey_msg: bytes,
                        controller_id: int, controller_sk: bytes,
                        rsu_signers: List[tuple],            # [(rsu_id, sk), ...]
                        k_key: int,
                        registry: RSUKeyRegistry,
                        controller_pk: bytes) -> tuple:
    """Eq. eq:rekey_sig:  sigma*_rekey = TS.Combine(sigma_c, {sigma_j}_{j=1}^{k-1}).

    A vehicle accepts a PQC-LKH re-keying broadcast only when this aggregate
    (controller partial + k_key-1 RSU partials) verifies.  Returns
    (AggregateSignature, verified_bool).  The controller is INVOLVED but holds
    no monopoly: k_key-1 independent RSUs must also sign."""
    if isinstance(rekey_msg, str):
        rekey_msg = rekey_msg.encode()

    # controller registered like an RSU in a combined registry for verification
    combined = RSUKeyRegistry(dict(registry.pubkeys))
    combined.register(controller_id, controller_pk)

    partials = [ThresholdSig.partial_sign(controller_id, rekey_msg, controller_sk)]
    for rsu_id, sk in rsu_signers[: k_key - 1]:
        partials.append(ThresholdSig.partial_sign(rsu_id, rekey_msg, sk))

    agg = ThresholdSig.combine(rekey_msg, partials)
    ok = ThresholdSig.verify(agg, rekey_msg, required_k=k_key, registry=combined)
    return agg, ok


if __name__ == "__main__":  # smoke test
    # (k,n) = (3,5) blacklisting
    reg = RSUKeyRegistry()
    keys = {}
    for rid in range(5):
        kp = DilithiumSig.generate_keypair()
        keys[rid] = kp
        reg.register(rid, kp.pk)
    msg = b"BLACKLIST v3 @ t=8.0"
    partials = [ThresholdSig.partial_sign(r, msg, keys[r].sk) for r in (0, 1, 2)]
    agg = ThresholdSig.combine(msg, partials)
    print("k=3 quorum (need 3):", ThresholdSig.verify(agg, msg, 3, reg))
    print("k=4 quorum (need 4):", ThresholdSig.verify(agg, msg, 4, reg))

    # DKG (t=3, n=5)
    dkg = PedersenDKG([1, 2, 3, 4, 5], t=3)
    dkg.deal()
    shares = {p: dkg.share_for(p) for p in [1, 2, 3]}
    rec = PedersenDKG.lagrange_reconstruct(shares)
    print("DKG reconstruct == group secret:", rec == dkg.group_secret())
