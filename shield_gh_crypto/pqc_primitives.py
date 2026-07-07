"""
SHIELD-GH Task 05 — Post-Quantum Cryptographic Primitives
=========================================================
Report section 3.6.8 ("Post-Quantum Cryptographic Mitigation Formulations")
and section "Selected Cryptographic Techniques by Phase".

Implements, with GENUINE post-quantum crypto when liboqs is available:

  CRYSTALS-Kyber KEM  (Eq. 3.25 / 3.26)
      (K, c) = Kyber.Enc(pk, m),  m <-$ {0,1}^256      # eq:kyber_enc
      K      = Kyber.Dec(sk, c)                          # eq:kyber_dec
      Kyber-512 in lightweight mode, Kyber-768 in full mode.

  CRYSTALS-Dilithium signatures  (Eq. 3.27 / 3.28)
      sigma = Dilithium.Sign(sk_c, M)                    # eq:dilithium_sign
      b     = Dilithium.Verify(pk_c, M, sigma)           # eq:dilithium_verify

Backend selection (user chose "Hybrid"):
  * If liboqs-python is importable -> use the REAL NIST PQC algorithms:
        Kyber512 / Kyber768               (Module-LWE, IND-CCA2)
        ML-DSA-44  == CRYSTALS-Dilithium-2 (FIPS-204, Module-LWE, EUF-CMA)
        (falls back to legacy "Dilithium2" mechanism name if present)
  * Otherwise -> a DOCUMENTED classical stand-in with the identical API and
        the identical (K,c)/(sigma) equation shape, so every downstream module
        (LKH, threshold, DKG) runs unchanged.  The stand-in uses:
        KEM       = ephemeral X25519 ECDH + HKDF-SHA256   (32-byte shared key)
        signature = Ed25519                                (EdDSA)
    These are real, secure classical primitives; they are NOT quantum-resistant
    and are clearly reported as a fallback in the evidence transcript.

The public API (KyberKEM, DilithiumSig, BACKEND) is identical in both cases.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Tuple

# --------------------------------------------------------------------------- #
# Backend detection
# --------------------------------------------------------------------------- #
_OQS = None
try:  # pragma: no cover - depends on install environment
    import oqs as _OQS  # liboqs-python
except Exception:  # pragma: no cover
    _OQS = None

BACKEND = "liboqs" if _OQS is not None else "classical-fallback"

# Kyber security level -> liboqs mechanism name.
# Report: "Kyber-512 is used in lightweight mode; Kyber-768 in full mode."
_KYBER_MECH = {512: "Kyber512", 768: "Kyber768", 1024: "Kyber1024"}


def _pick_dilithium_mechanism() -> str:
    """Report specifies CRYSTALS-Dilithium-2.  liboqs >= 0.10 ships the FIPS-204
    standardised name ML-DSA-44 (identical scheme, level-2 parameters) and may
    or may not still expose the legacy "Dilithium2" alias."""
    if _OQS is None:
        return "Ed25519(classical-fallback)"
    enabled = set(_OQS.get_enabled_sig_mechanisms())
    for name in ("Dilithium2", "ML-DSA-44"):
        if name in enabled:
            return name
    # last resort: any Dilithium/ML-DSA level-2 mechanism
    for name in sorted(enabled):
        if "Dilithium" in name or "ML-DSA" in name:
            return name
    raise RuntimeError("No Dilithium/ML-DSA mechanism in liboqs build")


DILITHIUM_MECH = _pick_dilithium_mechanism()


def backend_report() -> dict:
    """Machine-readable description of the active crypto backend (for evidence)."""
    info = {
        "backend": BACKEND,
        "quantum_resistant": BACKEND == "liboqs",
        "dilithium_mechanism": DILITHIUM_MECH,
        "kyber_mechanisms": _KYBER_MECH,
    }
    if _OQS is not None:
        info["liboqs_version"] = _OQS.oqs_version()
    return info


# =========================================================================== #
#  CRYSTALS-Kyber KEM  (Eq. 3.25 / 3.26)
# =========================================================================== #
@dataclass
class KyberKeyPair:
    pk: bytes
    sk: bytes
    level: int  # 512 / 768 / 1024


class KyberKEM:
    """Key-encapsulation mechanism. Used for group re-keying after isolation
    (Eq. 3.25/3.26) and inside the PQC-LKH tree (Eq. 3.35/3.36)."""

    def __init__(self, level: int = 768):
        if level not in _KYBER_MECH:
            raise ValueError(f"Unsupported Kyber level {level}")
        self.level = level

    # ---- key generation ---------------------------------------------------
    def generate_keypair(self) -> KyberKeyPair:
        if _OQS is not None:
            with _OQS.KeyEncapsulation(_KYBER_MECH[self.level]) as kem:
                pk = kem.generate_keypair()
                sk = kem.export_secret_key()
            return KyberKeyPair(pk=pk, sk=sk, level=self.level)
        return self._fallback_keypair()

    # ---- Eq. 3.25:  (K, c) = Kyber.Enc(pk, m) -----------------------------
    def encapsulate(self, pk: bytes) -> Tuple[bytes, bytes]:
        """Returns (K, c): K is the encapsulated 256-bit session key, c its
        ciphertext.  m <-$ {0,1}^256 is drawn internally by the KEM."""
        if _OQS is not None:
            with _OQS.KeyEncapsulation(_KYBER_MECH[self.level]) as kem:
                c, K = kem.encap_secret(pk)
            return K, c
        return self._fallback_encaps(pk)

    # ---- Eq. 3.26:  K = Kyber.Dec(sk, c) ----------------------------------
    def decapsulate(self, sk: bytes, c: bytes) -> bytes:
        """Only the holder of the correct sk recovers K.  An isolated vehicle,
        excluded from key refresh, cannot derive the new group session key."""
        if _OQS is not None:
            with _OQS.KeyEncapsulation(_KYBER_MECH[self.level], secret_key=sk) as kem:
                return kem.decap_secret(c)
        return self._fallback_decaps(sk, c)

    # ------------------------------------------------------------------ #
    #  Classical fallback: X25519 ECDH + HKDF-SHA256 (real, not PQ)      #
    # ------------------------------------------------------------------ #
    def _fallback_keypair(self) -> KyberKeyPair:
        # DER-encode both keys (PyCryptodome cannot re-import raw X25519 pubkeys)
        from Crypto.PublicKey import ECC
        sk_obj = ECC.generate(curve="Curve25519")
        sk = sk_obj.export_key(format="DER")
        pk = sk_obj.public_key().export_key(format="DER")
        return KyberKeyPair(pk=pk, sk=sk, level=self.level)

    def _fallback_encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        from Crypto.PublicKey import ECC
        from Crypto.Protocol.DH import key_agreement
        from Crypto.Hash import SHA256
        from Crypto.Protocol.KDF import HKDF
        eph = ECC.generate(curve="Curve25519")
        peer = ECC.import_key(pk)
        shared = key_agreement(static_priv=eph, static_pub=peer,
                               kdf=lambda x: x)
        K = HKDF(shared, 32, salt=b"", hashmod=SHA256,
                 context=b"SHIELD-GH-Kyber-fallback")
        c = eph.public_key().export_key(format="DER")  # ephemeral pub = ciphertext
        return K, c

    def _fallback_decaps(self, sk: bytes, c: bytes) -> bytes:
        from Crypto.PublicKey import ECC
        from Crypto.Protocol.DH import key_agreement
        from Crypto.Hash import SHA256
        from Crypto.Protocol.KDF import HKDF
        static = ECC.import_key(sk)                     # DER private key
        eph_pub = ECC.import_key(c)                     # DER ephemeral pub
        shared = key_agreement(static_priv=static, static_pub=eph_pub,
                               kdf=lambda x: x)
        return HKDF(shared, 32, salt=b"", hashmod=SHA256,
                    context=b"SHIELD-GH-Kyber-fallback")


# =========================================================================== #
#  CRYSTALS-Dilithium signatures  (Eq. 3.27 / 3.28)
# =========================================================================== #
@dataclass
class DilithiumKeyPair:
    pk: bytes
    sk: bytes


class DilithiumSig:
    """EUF-CMA signature over controller FlowMod / isolation commands and over
    RSU threshold-signature partials (Eq. 3.27/3.28, 3.31)."""

    @staticmethod
    def generate_keypair() -> DilithiumKeyPair:
        if _OQS is not None:
            with _OQS.Signature(DILITHIUM_MECH) as s:
                pk = s.generate_keypair()
                sk = s.export_secret_key()
            return DilithiumKeyPair(pk=pk, sk=sk)
        return DilithiumSig._fallback_keypair()

    # ---- Eq. 3.27:  sigma = Dilithium.Sign(sk_c, M) -----------------------
    @staticmethod
    def sign(message: bytes, sk: bytes) -> bytes:
        if isinstance(message, str):
            message = message.encode()
        if _OQS is not None:
            with _OQS.Signature(DILITHIUM_MECH, secret_key=sk) as s:
                return s.sign(message)
        return DilithiumSig._fallback_sign(message, sk)

    # ---- Eq. 3.28:  b = Dilithium.Verify(pk_c, M, sigma) ------------------
    @staticmethod
    def verify(message: bytes, signature: bytes, pk: bytes) -> bool:
        if isinstance(message, str):
            message = message.encode()
        if _OQS is not None:
            with _OQS.Signature(DILITHIUM_MECH) as s:
                try:
                    return bool(s.verify(message, signature, pk))
                except Exception:
                    return False
        return DilithiumSig._fallback_verify(message, signature, pk)

    # ------------------------------------------------------------------ #
    #  Classical fallback: Ed25519 (EdDSA), real signature scheme        #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _fallback_keypair() -> DilithiumKeyPair:
        from Crypto.PublicKey import ECC
        sk_obj = ECC.generate(curve="Ed25519")
        sk = sk_obj.export_key(format="DER")            # private key (DER)
        pk = sk_obj.public_key().export_key(format="DER")
        return DilithiumKeyPair(pk=pk, sk=sk)

    @staticmethod
    def _fallback_sign(message: bytes, sk: bytes) -> bytes:
        from Crypto.PublicKey import ECC
        from Crypto.Signature import eddsa
        key = ECC.import_key(sk)                        # DER private key
        signer = eddsa.new(key, mode="rfc8032")
        return signer.sign(message)

    @staticmethod
    def _fallback_verify(message: bytes, signature: bytes, pk: bytes) -> bool:
        from Crypto.PublicKey import ECC
        from Crypto.Signature import eddsa
        key = ECC.import_key(pk)
        verifier = eddsa.new(key, mode="rfc8032")
        try:
            verifier.verify(message, signature)
            return True
        except (ValueError, TypeError):
            return False


if __name__ == "__main__":  # smoke test
    print("Backend:", backend_report())
    kem = KyberKEM(768)
    kp = kem.generate_keypair()
    K1, c = kem.encapsulate(kp.pk)
    K2 = kem.decapsulate(kp.sk, c)
    print("Kyber KEM agree:", K1 == K2, "| |K|=", len(K1), "| |c|=", len(c))
    dk = DilithiumSig.generate_keypair()
    sig = DilithiumSig.sign(b"FlowMod: BLOCK v3", dk.sk)
    print("Dilithium verify(ok):", DilithiumSig.verify(b"FlowMod: BLOCK v3", sig, dk.pk))
    print("Dilithium verify(tamper):", DilithiumSig.verify(b"FlowMod: BLOCK v9", sig, dk.pk))
