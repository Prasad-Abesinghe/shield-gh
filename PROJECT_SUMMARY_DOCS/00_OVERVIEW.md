# SHIELD-GH — The Big Picture

## The problem we're solving

Imagine a network of self-driving cars (or roadside units) passing messages to
each other to find the best route — this is called an **SDVN** (Software
Defined Vehicular Network). Normally, every car forwards messages honestly.

But a **"grey-hole attack"** is when one bad car pretends to behave normally
but secretly drops some of the messages passing through it — sometimes
randomly, sometimes in bursts, sometimes only targeting one specific
conversation. It's sneaky because it doesn't drop *everything* (that would be
too obvious, called a "black-hole attack") — it drops *just enough* to cause
damage while staying hidden.

**SHIELD-GH** is our system to:
1. **Detect** these grey-hole attackers (figure out which car is misbehaving).
2. **Isolate** them (stop routing traffic through them).
3. **Prove** the detection was fair and tamper-proof (using blockchain).
4. **Protect** all of this with strong (future-proof, quantum-resistant) encryption.
5. **Recover trust safely** (re-key everyone else so the kicked-out attacker can't rejoin secretly).

## The 4 main technical pillars

Think of it like a security system for a building:

| Pillar | Analogy | What it does |
|---|---|---|
| **Detection Rules** (Task 1/2) | Security guards watching camera patterns | Simple math rules that spot suspicious dropping patterns (6 different attack styles, named S1–S6) |
| **AI / LLM** (Task 6) | A smart detective who catches the *cleverest* attackers the guards miss | A ChatGPT-style AI model reads the traffic "logs" and catches attacks that are too subtle for simple rules |
| **Blockchain** (Task 4) | A shared, tamper-proof notebook everyone can trust | Records "this car is guilty" so no single car can lie about it, and everyone agrees together (like a jury) |
| **Cryptography** (Task 5) | Locks, ID cards, and safes | Makes sure messages are signed, encrypted, and that a kicked-out attacker loses their "keys" to the group |

## Two modes we built

- **Lightweight mode** — just the rule-based guards + blockchain + basic
  security. Fast, works everywhere, good enough for most attacks.
- **Full mode** — adds the AI detective + Federated Learning (cars teaching
  each other without sharing raw data) for the sneakiest attacks the simple
  rules can't catch alone.

## What "done" looks like so far

- ✅ We can detect all 6 attack styles (3 "data-plane" + 3 "control-plane" variants) with **perfect accuracy** in our test network (0 false alarms).
- ✅ We built a **real blockchain** (Hyperledger Fabric — the same tech banks/supply-chains use), not just a pretend one, and it really talks to our simulated cars in real time.
- ✅ We built **real post-quantum encryption** (the kind that even future quantum computers can't break), not just a placeholder.
- ✅ We built and trained a **real AI model** (Qwen2.5, a 7-billion-parameter model, similar scale to small ChatGPT-style models) that catches the sneakiest attacks the simple rules miss.
- ✅ We connected **everything together** — AI + rules + blockchain — running live inside the actual network simulation, not as separate demos.
- ✅ We double-checked our own results for weaknesses (Task 7.75) and found the system itself is solid — only our small test scenario (a toy "1-road, 5-car" layout) makes one specific measurement (network delivery rate) look artificially bad, which is fixable by testing on a bigger, more realistic road network.

## What's next (not done yet)

- Running the **big, full-scale experiments** (hundreds of vehicles, real Galle-city road map from SUMO traffic simulator) and comparing against the 3 other published research methods.
- Writing up the results, analysis, and conclusion sections of the report.

See [01_TASKS_STATUS.md](01_TASKS_STATUS.md) for the full task-by-task breakdown.
