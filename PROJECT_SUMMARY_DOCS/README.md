# SHIELD-GH — Project Summary Docs (Plain English)

These documents explain what has been built so far in the SHIELD-GH project,
written in simple language for our own understanding — not for the formal
report. Read them in this order if you're new to the project:

1. **[00_OVERVIEW.md](00_OVERVIEW.md)** — What is SHIELD-GH? The big picture in 2 minutes.
2. **[01_TASKS_STATUS.md](01_TASKS_STATUS.md)** — The full task list (1–20) with simple done/not-done status.
3. **[06_DETECTION_BASICS.md](06_DETECTION_BASICS.md)** — How the "grey-hole attack" detection actually works (the core idea).
4. **[02_BLOCKCHAIN.md](02_BLOCKCHAIN.md)** — The blockchain part (Task 4/Task 1).
5. **[03_CRYPTOGRAPHY.md](03_CRYPTOGRAPHY.md)** — The encryption/security part (Task 5).
6. **[04_AI_LLM_FL.md](04_AI_LLM_FL.md)** — The AI part: the LLM (ChatGPT-like model) and Federated Learning (Task 6).
7. **[05_TASK8_FULL_INTEGRATION.md](05_TASK8_FULL_INTEGRATION.md)** — How everything (AI + blockchain + network simulation) was connected together and proven to work (Task 8).
8. **[07_DESIGN_REVIEW_TASK7_75.md](07_DESIGN_REVIEW_TASK7_75.md)** — A quality check we did: is anything broken? (Short answer: no, one number just needs a better test setup).

## What is this project, in one sentence?

We are testing a smart vehicle network (like self-driving cars talking to each
other) to catch a sneaky attacker called a **"grey-hole"** — a car/router that
pretends to forward messages but secretly drops some of them — using a mix of
**rule-based detection**, **AI (LLM)**, **blockchain**, and **strong encryption**,
and we compare our method against 3 other published research methods to prove
ours is better.

## Where things live in the code

| Thing | Folder |
|---|---|
| Main simulation | `scratch/routing.cc` |
| Report (LaTeX) | `scratch/main.tex` |
| Blockchain | `scratch/shield_gh/blockchain_standalone/` |
| Cryptography | `scratch/shield_gh_crypto/` |
| AI / LLM / Federated Learning | `scratch/shield_gh_ml/` |
| Task list (original) | `scratch/tasks.md` |
