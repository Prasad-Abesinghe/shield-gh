"""
SHIELD-GH Task 05 — cryptographic test suite.
Every test names the report equation it verifies.  Run:
    ~/shield-crypto-venv/bin/python3 -m pytest tests/ -v
"""
import os
import sys
import secrets

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pqc_primitives as pqc
from pqc_primitives import KyberKEM, DilithiumSig
import pedersen_zkp as zk
from pedersen_zkp import (commit, prove, verify, ProofSubmission, ZKPState,
                          zkp_evidence_state, rsu_consistent, debsc_isolate)
import threshold_sig as ts
from threshold_sig import (ThresholdSig, RSUKeyRegistry, PedersenDKG,
                           rekey_authorisation)
from pqc_lkh import PQCLogicalKeyHierarchy
import authentication as au
from authentication import (FlowMod, RevocationList, controller_sign_flowmod,
                            switch_install_flowmod, controller_failover,
                            Controller)


# ---------------------------------------------------------------- backend ----
def test_backend_available():
    info = pqc.backend_report()
    assert info["backend"] in ("liboqs", "classical-fallback")
    # We built liboqs; assert genuine PQC is active in this environment.
    assert info["backend"] == "liboqs", info
    assert info["quantum_resistant"] is True


# ------------------------------------------------ Kyber KEM  (Eq. 3.25/3.26) --
@pytest.mark.parametrize("level", [512, 768])
def test_kyber_encaps_decaps_agree(level):
    kem = KyberKEM(level)
    kp = kem.generate_keypair()
    K1, c = kem.encapsulate(kp.pk)          # Eq. 3.25
    K2 = kem.decapsulate(kp.sk, c)          # Eq. 3.26
    assert K1 == K2 and len(K1) == 32

def test_kyber_wrong_sk_fails():
    kem = KyberKEM(768)
    a, b = kem.generate_keypair(), kem.generate_keypair()
    K1, c = kem.encapsulate(a.pk)
    assert kem.decapsulate(b.sk, c) != K1   # excluded holder can't recover K


# ------------------------------------------- Dilithium sig (Eq. 3.27/3.28) ----
def test_dilithium_sign_verify():
    kp = DilithiumSig.generate_keypair()
    m = b"FlowMod: BLOCK vehicle 3"
    sig = DilithiumSig.sign(m, kp.sk)       # Eq. 3.27
    assert DilithiumSig.verify(m, sig, kp.pk) is True    # Eq. 3.28 -> b=1

def test_dilithium_tamper_and_wrong_key():
    kp, other = DilithiumSig.generate_keypair(), DilithiumSig.generate_keypair()
    m = b"FlowMod: BLOCK vehicle 3"
    sig = DilithiumSig.sign(m, kp.sk)
    assert DilithiumSig.verify(b"FlowMod: BLOCK vehicle 9", sig, kp.pk) is False
    assert DilithiumSig.verify(m, sig, other.pk) is False


# ------------------------------------- Pedersen commitment + ZKP (3.29/3.30) --
def test_pedersen_binding_hiding_and_zkp():
    c = commit(140)
    # commitment reproduces g^n h^r
    assert pow(zk.G, 140 % zk.Q, zk.P) * pow(zk.H, c.r % zk.Q, zk.P) % zk.P == c.C
    pi = prove(c)                            # Eq. 3.30
    assert verify(c.C, pi) is True

def test_zkp_reject_forged_proof():
    c = commit(140)
    pi = prove(c)
    pi.z1 = (pi.z1 + 1) % zk.Q               # corrupt response
    assert verify(c.C, pi) is False

def test_zkp_hiding_two_commits_differ():
    # same count, different randomness -> different commitments (hiding)
    assert commit(50).C != commit(50).C


# --------------------------- three-state ZKP model + DEBSC gate (state/debsc) --
def test_zkp_state_pass():
    c = commit(100)
    sub = ProofSubmission(c.C, prove(c), 100, t_recv=0.3)
    assert zkp_evidence_state(sub, 0.0, 1.0, 100, 5) == ZKPState.PASS

def test_zkp_state_fail_crossref():
    c = commit(100)                          # claims 100, RSU saw 40
    sub = ProofSubmission(c.C, prove(c), 100, t_recv=0.3)
    assert zkp_evidence_state(sub, 0.0, 1.0, 40, 5) == ZKPState.FAIL

def test_zkp_state_fail_bad_proof():
    c = commit(100)
    pi = prove(c); pi.z2 = (pi.z2 + 7) % zk.Q
    sub = ProofSubmission(c.C, pi, 100, t_recv=0.3)
    assert zkp_evidence_state(sub, 0.0, 1.0, 100, 5) == ZKPState.FAIL

def test_zkp_state_absent_withheld_and_late():
    assert zkp_evidence_state(None, 0.0, 1.0, 40, 5) == ZKPState.ABSENT
    c = commit(100)
    late = ProofSubmission(c.C, prove(c), 100, t_recv=5.0)   # after deadline
    assert zkp_evidence_state(late, 0.0, 1.0, 100, 5) == ZKPState.ABSENT

def test_debsc_dual_gate():
    # attacker: low reputation + FAIL -> isolate
    assert debsc_isolate(0.2, 0.5, ZKPState.FAIL) is True
    # attacker: low reputation + ABSENT -> isolate (self-report evasion closed)
    assert debsc_isolate(0.2, 0.5, ZKPState.ABSENT) is True
    # legit node: high loss but valid ZKP PASS -> NOT isolated (no false positive)
    assert debsc_isolate(0.2, 0.5, ZKPState.PASS) is False
    # low-rep alone without crypto failure -> NOT isolated
    assert debsc_isolate(0.9, 0.5, ZKPState.FAIL) is False


# --------------------------------- (k,n) threshold co-sign (Eq. 3.31/32/33) ---
def _rsu_fleet(n):
    reg, keys = RSUKeyRegistry(), {}
    for r in range(n):
        kp = DilithiumSig.generate_keypair()
        keys[r] = kp
        reg.register(r, kp.pk)
    return reg, keys

def test_threshold_quorum_met_and_not_met():
    reg, keys = _rsu_fleet(5)
    msg = b"BLACKLIST vehicle 3"
    parts = [ThresholdSig.partial_sign(r, msg, keys[r].sk) for r in (0, 1, 2)]
    agg = ThresholdSig.combine(msg, parts)          # Eq. 3.32
    assert ThresholdSig.verify(agg, msg, 3, reg) is True    # Eq. 3.33 (k=3)
    assert ThresholdSig.verify(agg, msg, 4, reg) is False   # 3 < 4

def test_threshold_rejects_forged_partial():
    reg, keys = _rsu_fleet(5)
    msg = b"BLACKLIST vehicle 3"
    good = [ThresholdSig.partial_sign(r, msg, keys[r].sk) for r in (0, 1)]
    # RSU 2's "partial" is a signature over a DIFFERENT message -> invalid
    forged = ThresholdSig.partial_sign(2, b"other", keys[2].sk)
    agg = ThresholdSig.combine(msg, good + [forged])
    assert ThresholdSig.count_valid(agg, reg) == 2  # forged not counted
    assert ThresholdSig.verify(agg, msg, 3, reg) is False

def test_threshold_duplicate_rsu_counts_once():
    reg, keys = _rsu_fleet(5)
    msg = b"BLACKLIST vehicle 3"
    parts = [ThresholdSig.partial_sign(0, msg, keys[0].sk) for _ in range(4)]
    agg = ThresholdSig.combine(msg, parts)
    assert ThresholdSig.count_valid(agg, reg) == 1  # one distinct RSU only


# ------------------------------------------------- Pedersen DKG (Eq. dkg_*) ---
def test_dkg_threshold_reconstruction():
    dkg = PedersenDKG([1, 2, 3, 4, 5], t=3)
    dkg.deal()
    s = dkg.group_secret()
    # any 3 shares reconstruct the joint secret
    for combo in ([1, 2, 3], [2, 4, 5], [1, 3, 5]):
        shares = {p: dkg.share_for(p) for p in combo}
        assert PedersenDKG.lagrange_reconstruct(shares) == s

def test_dkg_below_threshold_does_not_reconstruct():
    dkg = PedersenDKG([1, 2, 3, 4, 5], t=3)
    dkg.deal()
    shares = {p: dkg.share_for(p) for p in [1, 2]}   # only 2 < t=3
    assert PedersenDKG.lagrange_reconstruct(shares) != dkg.group_secret()


# ----------------------------------- threshold re-key authorisation (rekey) ---
def test_rekey_needs_controller_plus_rsus():
    reg, keys = _rsu_fleet(5)
    ck = DilithiumSig.generate_keypair()
    msg = b"REKEY path refresh after isolating v3"
    rsus = [(r, keys[r].sk) for r in (0, 1)]
    agg, ok = rekey_authorisation(msg, 99, ck.sk, rsus, k_key=3, registry=reg,
                                  controller_pk=ck.pk)
    assert ok is True                          # controller + 2 RSUs = 3
    # controller alone (k_key would need 3 but only supplies itself+0 RSUs)
    agg2, ok2 = rekey_authorisation(msg, 99, ck.sk, [], k_key=3, registry=reg,
                                    controller_pk=ck.pk)
    assert ok2 is False                        # no monopoly for the controller


# --------------------------------------- PQC-LKH tree (Eq. 3.34/3.35/3.36) ----
def test_lkh_group_key_derivation():
    lkh = PQCLogicalKeyHierarchy(768)
    lkh.build([1, 2, 3, 4, 5, 6, 7, 8])
    K_grp, c_root = lkh.encapsulate_group_key()          # Eq. 3.35
    # every active vehicle recovers the SAME group key via sk_root
    for v in lkh.active_vehicles():
        assert lkh.derive_group_key(v, c_root) == K_grp  # Eq. 3.34 path key

def test_lkh_isolation_cost_is_logN():
    for n, exp in [(8, 3), (16, 4), (4, 2)]:
        lkh = PQCLogicalKeyHierarchy(768)
        lkh.build(list(range(1, n + 1)))
        lkh.encapsulate_group_key()
        tr = lkh.isolate_and_rekey(2)                    # Eq. 3.36
        assert tr["kyber_ops"] == exp                    # exactly ceil(log2 N)
        assert tr["expected_log2N"] == exp

def test_lkh_isolated_vehicle_excluded():
    """The core security guarantee: after re-key, the NEW group key is different
    and the isolated vehicle's stale root sk can no longer derive it, while a
    remaining vehicle can."""
    lkh = PQCLogicalKeyHierarchy(768)
    lkh.build([1, 2, 3, 4, 5, 6, 7, 8])
    K_old, c_old = lkh.encapsulate_group_key()
    stale_root_sk = lkh.nodes[0].keypair.sk              # V3 held this before
    tr = lkh.isolate_and_rekey(3)
    # find the root broadcast carrying the new group-key ciphertext
    root_bc = [b for b in tr["broadcasts"] if b[1] == -1]
    assert root_bc, "root re-key broadcast expected"
    _, _, c_new = root_bc[0]
    new_root_sk = lkh.nodes[0].keypair.sk
    K_new = lkh.kem.decapsulate(new_root_sk, c_new)      # remaining vehicle
    assert K_new != K_old                                # key actually rotated
    # isolated V3 (stale root sk) cannot derive the new key
    assert lkh.kem.decapsulate(stale_root_sk, c_new) != K_new

def test_lkh_lazy_join():
    lkh = PQCLogicalKeyHierarchy(768)
    lkh.build([1, 2, 3, 4, 5, 6])            # 2 vacant slots in an 8-leaf tree
    lkh.isolate_and_rekey(3)                  # vacates one more
    res = lkh.join(99)
    assert 99 in lkh.active_vehicles()
    assert res["leaf_idx"] >= lkh.leaf_start


# ------------------------------------- FlowMod auth + revocation (Alg 5) ------
def test_flowmod_auth_replay_and_revocation():
    ck = DilithiumSig.generate_keypair()
    rev, nonces = RevocationList(), set()
    fm = FlowMod(7, "BLOCK", 3, nonce=1)
    sig = controller_sign_flowmod(fm, ck.sk)
    assert switch_install_flowmod(fm, sig, ck.pk, rev, nonces) is True
    assert switch_install_flowmod(fm, sig, ck.pk, rev, nonces) is False  # replay
    rev.revoke(ck.pk)
    fm2 = FlowMod(7, "BLOCK", 3, nonce=2)
    sig2 = controller_sign_flowmod(fm2, ck.sk)
    assert switch_install_flowmod(fm2, sig2, ck.pk, rev, nonces) is False  # revoked

def test_flowmod_rejects_forged_controller():
    ck, attacker = DilithiumSig.generate_keypair(), DilithiumSig.generate_keypair()
    rev, nonces = RevocationList(), set()
    fm = FlowMod(7, "BLOCK", 3, nonce=1)
    forged = controller_sign_flowmod(fm, attacker.sk)   # signed by wrong key
    assert switch_install_flowmod(fm, forged, ck.pk, rev, nonces) is False


def test_controller_failover_and_degraded():
    def mk(cid, trust):
        return Controller(cid, DilithiumSig.generate_keypair(), trust)
    c0, c1, c2 = mk(0, 0.1), mk(1, 0.8), mk(2, 0.9)
    rev = RevocationList()
    refreshed = []
    # segment 10 has eligible c1; segment 20 has only low-trust -> degraded
    lists = {10: [c0, c1, c2], 20: [c0, mk(3, 0.05)]}
    res = controller_failover(0, lists, theta_c=0.5, revlist=rev,
                              dkg_refresh=refreshed.append)
    by_seg = {r.segment: r for r in res}
    assert by_seg[10].new_controller == 1 and not by_seg[10].degraded
    assert rev.is_revoked(c0.keypair.pk)
    assert 1 in refreshed
    assert by_seg[20].degraded is True
