"""
SHIELD-GH Task 05 — Authentication, Key Revocation, ZKP Cross-Check
===================================================================
Ties the primitives together into the two control-plane procedures the report
specifies:

  * Dilithium FlowMod authentication (Eq. 3.27/3.28): an OpenFlow switch installs
    an isolation block-rule ONLY if the controller's Dilithium signature verifies.
  * Algorithm 5 Controller-Failover + Key Revocation (sec:alg_failover):
    revoke a failed controller's signing key via RSU consensus, pick the next
    eligible controller from the segment's ordered list, refresh its DKG share.
  * Algorithm 6 ZKP-Crosscheck (sec:alg_zkp_crosscheck): three-state proof model
    with RSU observation cross-reference (delegates to pedersen_zkp).

These are the "authentication ... etc." part of Task 05.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from pqc_primitives import DilithiumSig, DilithiumKeyPair
from pedersen_zkp import (ProofSubmission, ZKPState, zkp_evidence_state)


# =========================================================================== #
#  Dilithium-authenticated FlowMod installation  (Eq. 3.27 / 3.28)
# =========================================================================== #
@dataclass
class FlowMod:
    """An SDN isolation command: block traffic for/via a suspect vehicle."""
    switch_id: int
    action: str          # e.g. "BLOCK"
    target_vehicle: int
    nonce: int           # anti-replay
    def message(self) -> bytes:
        return f"FLOWMOD|sw={self.switch_id}|act={self.action}|" \
               f"veh={self.target_vehicle}|nonce={self.nonce}".encode()


class RevocationList:
    """On-chain key revocation set (Eq. Alg5 BLOCKCHAIN_REVOKE_KEY)."""
    def __init__(self):
        self._revoked: set = set()
    def revoke(self, pk: bytes) -> None:
        self._revoked.add(bytes(pk))
    def is_revoked(self, pk: bytes) -> bool:
        return bytes(pk) in self._revoked


def controller_sign_flowmod(fm: FlowMod, controller_sk: bytes) -> bytes:
    """Eq. 3.27:  sigma = Dilithium.Sign(sk_c, M)."""
    return DilithiumSig.sign(fm.message(), controller_sk)


def switch_install_flowmod(fm: FlowMod, sigma: bytes, controller_pk: bytes,
                           revlist: RevocationList,
                           seen_nonces: set) -> bool:
    """Switch-side gate. Installs the block rule (returns True) iff:
        b = Dilithium.Verify(pk_c, M, sigma) == 1   (Eq. 3.28)
        AND the controller key is NOT revoked
        AND the nonce is fresh (anti-replay)."""
    if revlist.is_revoked(controller_pk):
        return False
    if fm.nonce in seen_nonces:
        return False                      # replay
    if not DilithiumSig.verify(fm.message(), sigma, controller_pk):
        return False                      # forged / tampered
    seen_nonces.add(fm.nonce)
    return True                           # b == 1 -> install block rule


# =========================================================================== #
#  Algorithm 5 — Controller Failover and Key Revocation
# =========================================================================== #
@dataclass
class Controller:
    cid: int
    keypair: DilithiumKeyPair
    trust: float                          # T_c(t)


@dataclass
class FailoverResult:
    segment: int
    new_controller: Optional[int]
    revoked_pk: Optional[bytes]
    degraded: bool


def controller_failover(failed_cid: int,
                        segment_ordered_lists: Dict[int, List[Controller]],
                        theta_c: float,
                        revlist: RevocationList,
                        dkg_refresh) -> List[FailoverResult]:
    """Algorithm 5. For each active segment of the failed controller, walk the
    ordered replacement list, pick the first eligible (trust > theta_c), revoke
    the failed key via RSU consensus, and refresh the new controller's DKG share.
    If none eligible -> degraded mode for that segment (Eq. eq:degraded_mode)."""
    results: List[FailoverResult] = []
    for seg, ordered in segment_ordered_lists.items():
        selected = None
        for c in ordered:                       # ordered-list traversal (load spread)
            if c.cid != failed_cid and c.trust > theta_c:
                selected = c
                break
        if selected is None:
            results.append(FailoverResult(seg, None, None, degraded=True))
            continue
        # BLOCKCHAIN_REVOKE_KEY(pk_failed) via RSU consensus
        failed_pk = next((c.keypair.pk for c in ordered if c.cid == failed_cid), None)
        if failed_pk is not None:
            revlist.revoke(failed_pk)
        # REFRESH_DKG_SHARE(c_new, {RSU_j})
        dkg_refresh(selected.cid)
        results.append(FailoverResult(seg, selected.cid, failed_pk, degraded=False))
    return results


# =========================================================================== #
#  Algorithm 6 — ZKP-Crosscheck  (thin wrapper over pedersen_zkp 3-state model)
# =========================================================================== #
def zkp_crosscheck(sub: Optional[ProofSubmission],
                   t_window: float, T_zkp: float,
                   n_rsu_observed: int, eps_obs: int) -> ZKPState:
    """Algorithm 6: returns PASS / FAIL / ABSENT per Eq. eq:zkp_state."""
    return zkp_evidence_state(sub, t_window, T_zkp, n_rsu_observed, eps_obs)


if __name__ == "__main__":  # smoke test
    ck = DilithiumSig.generate_keypair()
    revlist, nonces = RevocationList(), set()
    fm = FlowMod(switch_id=7, action="BLOCK", target_vehicle=3, nonce=1001)
    sig = controller_sign_flowmod(fm, ck.sk)
    print("install (valid):", switch_install_flowmod(fm, sig, ck.pk, revlist, nonces))
    print("install (replay):", switch_install_flowmod(fm, sig, ck.pk, revlist, nonces))
    revlist.revoke(ck.pk)
    fm2 = FlowMod(7, "BLOCK", 3, nonce=1002)
    print("install (revoked key):",
          switch_install_flowmod(fm2, controller_sign_flowmod(fm2, ck.sk),
                                 ck.pk, revlist, nonces))
