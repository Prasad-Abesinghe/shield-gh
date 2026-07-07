"""
SHIELD-GH Task 05 — exercise the CLASSICAL fallback path directly.
Even though liboqs is active in this environment, we prove the documented
fallback (X25519-ECDH+HKDF KEM, Ed25519 signatures) is correct, so the module
still runs on hosts without liboqs.  We do this by monkeypatching the backend
flag off for the duration of these tests.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pqc_primitives as pqc
from pqc_primitives import KyberKEM, DilithiumSig


@pytest.fixture
def force_fallback(monkeypatch):
    monkeypatch.setattr(pqc, "_OQS", None)      # pretend liboqs absent
    yield


def test_fallback_kem_roundtrip(force_fallback):
    kem = KyberKEM(768)
    kp = kem.generate_keypair()
    K1, c = kem.encapsulate(kp.pk)
    K2 = kem.decapsulate(kp.sk, c)
    assert K1 == K2 and len(K1) == 32

def test_fallback_kem_wrong_key(force_fallback):
    kem = KyberKEM(768)
    a, b = kem.generate_keypair(), kem.generate_keypair()
    K1, c = kem.encapsulate(a.pk)
    assert kem.decapsulate(b.sk, c) != K1

def test_fallback_signature(force_fallback):
    kp = DilithiumSig.generate_keypair()
    m = b"FlowMod fallback"
    sig = DilithiumSig.sign(m, kp.sk)
    assert DilithiumSig.verify(m, sig, kp.pk) is True
    assert DilithiumSig.verify(b"tampered", sig, kp.pk) is False

def test_fallback_signature_wrong_key(force_fallback):
    a, b = DilithiumSig.generate_keypair(), DilithiumSig.generate_keypair()
    sig = DilithiumSig.sign(b"m", a.sk)
    assert DilithiumSig.verify(b"m", sig, b.pk) is False
