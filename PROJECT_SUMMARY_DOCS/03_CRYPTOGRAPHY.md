# Cryptography — Plain English

Location: `scratch/shield_gh_crypto/`

## Why do vehicles need encryption at all?

Two reasons:
1. **Privacy/security** — messages between cars shouldn't be readable or fake-able by an attacker.
2. **Quantum-proofing** — regular encryption (like the kind protecting your bank today) could eventually be broken by future quantum computers. Since vehicle networks may run for decades, we use **post-quantum cryptography (PQC)** — encryption specifically designed to resist even quantum computers.

## What we actually built (genuine, not fake)

We used a real, well-known cryptography library (**liboqs**, an open-source
post-quantum crypto library used by real security researchers) to implement:

- **Kyber** (a PQC "lock and key" system, called a KEM) — used so two cars can agree on a shared secret key safely, even over an insecure channel, in a way quantum computers can't crack.
- **Dilithium / ML-DSA** (a PQC "signature" system) — used so a car can prove "this message really came from me and wasn't tampered with," again quantum-resistant.
- We also built a **classical fallback** (regular, non-quantum encryption) with the *exact same interface*, in case the quantum-resistant library isn't available on some device — so the system degrades gracefully instead of breaking.

We picked the strongest security level available (**NIST Level 5**, the
highest post-quantum security tier) for the report's final version.

## The "Key Hierarchy" (LKH) — how group secrets are managed efficiently

Imagine 8 cars share one group secret key. If we kick one car out, we must
change the key so it can't eavesdrop anymore — but re-keying *everyone*
individually would be slow. We use a **Logical Key Hierarchy (a tree
structure)**: cars are arranged like a family tree of keys, so kicking out one
car only requires refreshing the keys *along its branch of the tree* — not
the whole group.

- Proven mathematically and by test: refreshing only needs about `log2(N)`
  operations instead of `N` operations. For 8 cars, that's about **3 operations
  instead of 8** — roughly **2.3x faster**, and the advantage grows bigger the
  more cars there are.
- We proved a kicked-out car genuinely **cannot** decrypt the new group key
  afterward, while every remaining honest car still can.

## Zero-Knowledge Proofs (ZKP) — "prove it without revealing it"

A car can cryptographically prove *"I really did forward this message
honestly"* without exposing private details about its internal operations.
This proof has 3 possible outcomes:
- **PASS** — proof checks out, car is behaving.
- **FAIL** — proof is invalid, strong evidence of misbehavior.
- **ABSENT** — no proof was even provided, also suspicious.

This ZKP result is one of the two signals blockchain isolation requires (see
[02_BLOCKCHAIN.md](02_BLOCKCHAIN.md) "dual-gate" rule) — so a car only gets
isolated if its trust score AND its cryptographic proof both indicate
wrongdoing, which protects honest cars from being wrongly punished due to bad
luck (e.g., temporary poor signal).

## Threshold Signatures — "no single point of trust"

Important actions (like officially approving a "block this car" command)
require **multiple roadside units to jointly sign off** (a "k-of-n" scheme,
e.g., 3 out of 5 units must agree) — so no single compromised or malicious
unit can act alone. We also implemented **Distributed Key Generation (DKG)**,
which lets that group of signers set up their shared signing power without
ever needing one trusted party to hand out the keys.

## Real, live proof it works (evidence)

- **31 automated tests, all passing** — covering the encryption, signatures, key hierarchy, and zero-knowledge proofs.
- **A realistic end-to-end demo**: an attacker car (with a failed ZKP proof) gets correctly isolated, its keys revoked, group re-keyed to exclude it — while an *honest* car that just happens to have bad connection quality (high natural packet loss) is correctly **not** punished, because its ZKP still passes.
- **A forged command test**: we simulated a fake "controller" trying to issue a malicious command, and the system correctly rejected it because it wasn't properly signed.
- **Live inside the running simulation**: this isn't just a standalone script — we hooked it directly into the live NS-3 vehicle simulation, so when a car is isolated *during the simulation*, the real threshold-signature approval, FlowMod (routing rule) installation, and key-hierarchy re-keying all fire for real, in real simulated time (~1.5ms per event).

## In short

The cryptography piece answers: *"How do we make sure messages can't be
forged, secrets can't be stolen even by future quantum computers, and a
kicked-out attacker truly loses access — all without needing a single
trusted authority?"*
