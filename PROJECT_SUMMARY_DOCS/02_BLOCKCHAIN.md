# Blockchain — Plain English

## Why do we even need a blockchain here?

If only *one* car decides "that other car is an attacker," how do we know
it's telling the truth? Maybe that car is lying, or made a mistake, or is
itself compromised. A blockchain solves this by making the decision
**shared, agreed-upon, and tamper-proof** — like a group of witnesses signing
off on a police report instead of trusting one person's word.

## What we actually built (not a toy)

We used **Hyperledger Fabric** — this is a real, production-grade blockchain
platform (the same category of tech used by companies like IBM and Walmart
for supply-chain tracking). This is **not a pretend/simulated blockchain** —
it's the real thing, running as real software on the machine, with a real
smart contract ("chaincode") written in Go.

Location: `scratch/shield_gh/blockchain_standalone/`

There are actually **two blockchain pieces** in this project, and it's
important not to confuse them:
1. **The real Fabric blockchain** (above) — genuinely runs, genuinely records data.
2. **An in-memory "pretend ledger"** inside the NS-3 simulation code itself
   (`blockchain_ledger.cc`) — used for quick internal bookkeeping during the
   simulation, but it is NOT a real blockchain (no real blocks, no consensus).
   We built the connection so the real one and the simulation one talk to each
   other live (see below).

## What the smart contract (the "rulebook") does — called DEBSC

Think of DEBSC as the digital rulebook everyone agrees to follow:

- **Reputation tracking**: every car has a trust score that goes down when it misbehaves.
- **Dual-gate isolation rule**: a car only gets formally isolated if **two independent checks agree** — (1) its trust score has dropped too low, AND (2) a cryptographic proof (ZKP, see crypto doc) has failed. Requiring *both* avoids kicking out an honest car just because of bad luck (e.g., temporary bad signal).
- **Zero-Knowledge Proof (ZKP) verification**: cars can prove "I forwarded honestly" without revealing private details — like proving you paid without showing your bank statement.

## Live connection to the driving simulation

We connected the actual NS-3 vehicle simulation to the real running blockchain,
so that when the simulation detects an attacker **in real simulated time**, it
actually writes that decision to the real blockchain — not just logs it locally.

- Turn on with `--live_blockchain=1` when running the simulation.
- We fixed a timing bug where a late-arriving update could accidentally
  "un-flag" an attacker that was already correctly isolated (an ordering/race
  condition) — now isolation is treated as permanent/final once recorded.

## Who gets to approve/endorse a blockchain entry? (Endorser selection)

In Hyperledger Fabric, before something gets written to the ledger, a set of
"peers" (think: notary witnesses) must review and approve (endorse) it. We
made this selection process:

- **Multi-organization**: 3 separate organizations run peers (not just one, so no single party controls approval).
- **Trust-ranked and dynamic**: instead of always using the same fixed witnesses, we pick the most trustworthy available "roadside units" (RSUs) each time, using a **VRF** (Verifiable Random Function — a cryptographically fair, unpredictable-but-provable lottery) so the choice can't be gamed or predicted in advance.
- **Scales to real deployment size**: tested with a pool of 64 roadside units, picking ~17 trusted endorsers per decision with a minimum-of-10 safety floor (so there are always enough witnesses for a valid consensus even if some are excluded for being untrustworthy or under-observed).

## Proof it really works (evidence we captured)

- **Formal correctness tests**: 8/8 (and later 25/25) automated tests pass on the smart contract's logic (does isolation trigger correctly? does it avoid false positives? etc.).
- **Live real-time test**: ran the vehicle simulation and watched, in real time, the blockchain receive and correctly record "node X isolated" the moment the simulation detected an attack — with matching timestamps.
- **Dynamic endorser test**: proved the set of approving witnesses actually changes between decisions (not hard-coded to always be the same 2-3 peers), based on live trust scores.
- **Scale test**: verified this still works cleanly with 64 roadside units registered, not just a handful.

## In short

The blockchain piece answers: *"How do we all agree, permanently and fairly,
that a car is an attacker — without trusting any single party, and without
that decision being fake or quietly reversible?"* — and it's built on real,
working blockchain software, not a mock-up.
