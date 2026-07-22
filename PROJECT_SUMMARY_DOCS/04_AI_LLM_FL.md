# AI: LLM + Federated Learning — Plain English

Location: `scratch/shield_gh_ml/`

## Why do we need AI on top of simple rules?

The rule-based detector (see [06_DETECTION_BASICS.md](06_DETECTION_BASICS.md))
is great at catching obvious attack patterns, but two attack styles are
naturally hard to catch with simple math:
- **DP-IT (Intermittent)** — attacker turns dropping on/off, trying to look like normal network noise.
- **DP-TS (Target-Specific)** — attacker only targets one conversation, hiding in the crowd.

An **LLM (Large Language Model)** — the same category of AI behind tools like
ChatGPT — is much better at spotting subtle *patterns over time* rather than
just a single percentage number. So we added an LLM as a smarter "second
opinion" layer for the hardest cases.

## Step 1: Picking which AI model to use (Task 6)

We needed a model that is:
- Not too small (weak at the task) and not too huge (too slow/expensive to run on vehicle-scale hardware) — the target range was **4 billion to 15 billion parameters** ("parameters" = roughly the "brain size" of the AI model).
- Good enough at telling apart 7 categories: normal traffic + the 6 attack types (S1–S6).

We tested **4 real candidate models** head-to-head, actually training and
timing each one (not just guessing from spec sheets):

| Model | Size | Accuracy (MCC*) | Speed |
|---|---|---|---|
| Mistral-7B | 7B | Weak (0.21) | 20ms |
| **Qwen2.5-7B** ✅ chosen | 7B | Strong (0.80) | **17.8ms — fastest** |
| Nemo-12B | 12B | Good (0.75) | 27.6ms |
| Qwen2.5-14B | 14B | Best (0.81) | 33.7ms (slowest) |

\* *MCC = Matthews Correlation Coefficient, a fairness-adjusted accuracy score from -1 (always wrong) to +1 (always right); 0 means random guessing.*

**We picked Qwen2.5-7B** — it ties for best accuracy while being the fastest,
so it's the best value for a system that needs to react quickly. This
selection was reviewed and **approved by the supervisor**.

## Step 2: Actually training the AI model (Task 6.5)

We didn't just pick a model off the shelf — we **fine-tuned** it (specialized
training on our specific attack-detection task) using a technique called
**LoRA** (a lightweight way to adjust a big AI model without retraining the
whole thing from scratch — much faster and cheaper).

- Trained on a real gaming-grade GPU (RTX 5090) in under 2 minutes.
- **Result: MCC = 0.79** on data the model had never seen before (a solid, honest result).
- The AI is noticeably better than simple rules specifically on the two hardest attack types (Intermittent and Target-Specific) — exactly where it was needed.
- Runs in **~18 milliseconds** per check — fast enough to use live, in real time.

### The hardest technical problem we hit

The training GPU had occasional random crashes (a known issue with very new
GPU hardware under heavy AI training load). We built a **self-healing training
script** that automatically saves progress and resumes after a crash, so
training completes reliably without needing a person to babysit it.

## Step 3: Federated Learning (FL) — cars teaching each other, privately

**Federated Learning** means: instead of every car sending its private data to
one central server to train a better AI model, each car trains a little bit
locally and only shares the *lessons learned* (called "gradients" or model
updates) — not the raw data. This protects privacy.

The problem: what if one car is malicious and sends **poisoned** (deliberately
corrupted) updates to sabotage the shared AI model?

**Our fix**: every update a car wants to contribute must first be
cryptographically committed to the blockchain (see [02_BLOCKCHAIN.md](02_BLOCKCHAIN.md))
before it's accepted — this lets us verify integrity and catch tampering.

**Proof it works** (tested with 4 honest cars + 1 poisoning attacker, over 5 rounds):

| Setting | Result |
|---|---|
| Poison-detection turned **ON** | Attacker's bad updates rejected **5 out of 5 times**; shared AI model stays healthy (MCC 0.75) |
| Poison-detection turned **OFF** | Attacker succeeds; shared AI model quality collapses (MCC drops to 0.41) |

This proves the blockchain-backed integrity check is genuinely doing its job
— without it, one bad car can quietly wreck the AI for everyone.

## Step 4: Fusion — combining all 3 signals into one final verdict

For the final decision on "is this car an attacker?", we combine **three**
independent signals:
1. The simple **rule-based signature score** (fast, cheap).
2. The **AI/LLM score** (catches subtle patterns).
3. The car's on-chain **reputation score** (history of trust).

These three scores are combined with a weighted formula to produce one final
verdict. We tested this and found the AI layer successfully "rescues" the two
hardest attack types that the rule-based layer alone completely misses:

| Attack type | Rules alone | AI alone | Combined (final) |
|---|---|---|---|
| Intermittent (DP-IT) | Missed (0%) | Catches it (79%) | **79% (caught)** |
| Target-Specific (DP-TS) | Missed (0%) | Catches it (79%) | **79% (caught)** |
| All other 4 types | Already perfect | Also perfect | **~100%** |

### A statistics double-check we did (supervisor requested)

The supervisor asked us to verify our combination-weight choices weren't just
a fluke from one lucky test split. We ran a much more rigorous check (30
repeated test splits, statistical significance testing) and found our
original tuning **wasn't fully solid** — so we corrected our approach and now
keep the 3-way combination general/flexible rather than locking in
specific numbers that weren't proven robust. This was a case of a
supervisor's skepticism turning out to be justified, and we fixed it properly
rather than defending the original number.

## In short

The AI piece answers: *"How do we catch the smartest, most disguised
attackers that simple rules miss — while still letting cars learn from each
other privately, and without letting a malicious car poison what everyone
else learns?"*
