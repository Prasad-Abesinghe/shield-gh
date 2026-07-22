# The Core Idea — How Grey-Hole Detection Works

This is the foundation everything else (AI, blockchain, crypto) builds on top of.

## The attack, explained simply

A **grey-hole attacker** is a car/node that agrees to forward messages, but
secretly drops some of them. We test 6 flavors of this:

**Data-plane attacks (the attacker drops actual data packets):**
- **S1 — Fixed-Rate (DP-FR):** drops a steady percentage of packets (e.g., always drop 60%).
- **S2 — Intermittent (DP-IT):** turns dropping on and off in bursts, to look like normal network hiccups.
- **S3 — Target-Specific (DP-TS):** only attacks one specific conversation/flow, leaves everything else alone (hardest to notice).

**Control-plane attacks (the attacker lies to the network controller instead of dropping data):**
- **S4 — CP Fixed-Rate:** sends fake/bad routing instructions at a steady rate.
- **S5 — CP Intermittent:** sends bad instructions in bursts.
- **S6 — CP Target-Specific:** sends bad instructions only about one target.

## How we catch them (the "lightweight" rule-based layer)

Each car/node keeps track of its own **Packet Delivery Ratio (PDR)** — basically
"what % of messages that passed through me did I actually forward?" We watch
this pattern over a sliding time window and apply simple statistical signatures:

- If PDR is **steadily low** → looks like S1 (Fixed-Rate).
- If PDR **flips between good and bad periodically** → looks like S2 (Intermittent).
- If PDR is fine for *most* traffic but bad for *one specific route* → looks like S3 (Target-Specific).
- Similar checks exist on the controller side for S4–S6.

This is fast, doesn't need AI, and works on any hardware. In our tests it
reaches **perfect detection (MCC = 1.0, zero false alarms)** for all 6 attack
types once tuned correctly.

## Why we needed AI on top (see [04_AI_LLM_FL.md](04_AI_LLM_FL.md))

The rules above are good, but a *very* clever attacker could disguise their
drop pattern to slip past simple statistics — especially the "intermittent"
(S2/DP-IT) and "target-specific" (S3/DP-TS) styles, which are naturally the
hardest to tell apart from normal network noise (e.g., a car briefly losing
signal during a real handoff between towers). That's exactly where we bring in
the AI/LLM layer — it reads the *pattern of events* more like a human would,
instead of just checking a percentage threshold.

## What happens once an attacker is caught

1. **Isolate**: stop routing any traffic through that node.
2. **Record on blockchain**: write "this node is guilty" to the shared,
   tamper-proof ledger so every honest car agrees and no one can quietly
   un-flag the attacker later.
3. **Re-key**: refresh the shared secret keys for the *rest* of the group so
   the kicked-out attacker can't decrypt future messages even if it keeps
   listening (see [03_CRYPTOGRAPHY.md](03_CRYPTOGRAPHY.md)).

## Two ways to run it

| Mode | What's active | When to use |
|---|---|---|
| **Lightweight** | Rules (S1–S6) + blockchain + basic signing | Default; fast; proven perfect on our test attacks |
| **Full** | Everything in Lightweight **+ AI/LLM + Federated Learning** | For catching the subtlest attacks; used in Task 8 evidence |

Run examples live in `scratch/routing.cc` via command-line flags like
`--detection_mode=lightweight` or `--detection_mode=full
--enable_full_mode_ai=1`. See [[shield-gh-project]] memory notes / `SHIELD_GH_Implementation_Guide.md`
for exact commands.
