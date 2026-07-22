# Task List — Plain English Status

Source of truth: `scratch/tasks.md`. This is the same list, explained simply.

| # | Task (short) | What it actually means | Status |
|---|---|---|---|
| 1 | Identify design flaws | Look at the original plan and find weak points before building | ✅ Done |
| 2 | Correct flaws | Fix those weak points | ✅ Done |
| 3 | State-of-the-art simulation with SUMO | Recreate 3 other published papers' methods in our simulator using real traffic (SUMO) so we have something fair to compare against | ✅ Done |
| 4 | Blockchain implementation | Build the real tamper-proof "shared notebook" system | ✅ Done — see [02_BLOCKCHAIN.md](02_BLOCKCHAIN.md) |
| 5 | Cryptographic method implementation | Build the real encryption/signing/key-management system | ✅ Done — see [03_CRYPTOGRAPHY.md](03_CRYPTOGRAPHY.md) |
| 6 | AI/LLM model selection + pipeline settings | Pick which AI model to use and document how it will be set up | ✅ Done |
| 6.5 | LLM evidence + ML/LLM component implementation | Actually build and train the chosen AI model, and prove it works with real numbers | ✅ Done — see [04_AI_LLM_FL.md](04_AI_LLM_FL.md) |
| 7 | Upgrade research questions + evaluation metrics + experiment design | Decide exactly what questions we're answering and how we'll measure success | ✅ Done |
| 7.5 | Apply supervisor's AI-related patches | Apply all the fix requests the supervisor sent so far | ✅ Done |
| 7.75 | Check for design flaws if results look poor | Self-audit: did anything come out badly? If so, is it a real design problem? | ✅ Done — see [07_DESIGN_REVIEW_TASK7_75.md](07_DESIGN_REVIEW_TASK7_75.md). Finding: no algorithm is broken; one small-scenario test setup issue was flagged for later tasks |
| 8 | Full system integration evidence (1 real data point, correct timing) | Prove that AI + rules + blockchain all genuinely run together inside the live simulation — not faked or bypassed | ✅ Done — see [05_TASK8_FULL_INTEGRATION.md](05_TASK8_FULL_INTEGRATION.md) |
| 8.5 | Sensitivity analysis for full system | Test how results change when we tweak settings (e.g., more attackers, different drop rates) | ⏳ Not started |
| 9 | Confirm our method beats all 3 other papers (quick 10s test) | A fast sanity-check run comparing us vs the competition | ⏳ Not started |
| 9.5 | Ablation study + graphs | Turn parts of our system off one at a time to see how much each part actually helps | ⏳ Not started |
| 10 | Full research experiments + graphs | The big, final, full-scale test runs and charts | ⏳ Not started |
| 11 | Write Result Analysis | Report writing | ⏳ Not started |
| 12 | Write Discussion | Report writing | ⏳ Not started |
| 13 | Write Conclusion + Appendix | Report writing | ⏳ Not started |
| 14 | Submit final report to supervisor | — | ⏳ Not started |
| 15 | Technical review round 1 | Address supervisor's comments and resubmit | ⏳ Not started |
| 16 | Technical review round 2 | Address more comments and resubmit | ⏳ Not started |
| Special 1 | Demo GUI | A visual demo interface for the simulation | ⏳ Not started |
| Special 2 | Toy/real test bed | A physical or simplified demo setup | ⏳ Not started |
| Special 3 | Demo video | Record a demo video | ⏳ Not started |
| Special 4 | Send final presentation | — | ⏳ Not started |
| Special 5 | Present demo + presentation | — | ⏳ Not started |
| 17 | Make report concise | Trim repeated/unnecessary content | ⏳ Not started |
| 18 | Copy report to Elsevier template | Reformat for the journal/publisher's required style | ⏳ Not started |
| 19 | Condense/improve phrasing + references | Polish writing and citations | ⏳ Not started |
| 20 | Improve acceptance rate | Final polish to maximize chances of publication acceptance | ⏳ Not started |

## Quick summary

- **Everything up through Task 8 is done.** That covers: design, all 3 competitor
  re-implementations, blockchain, cryptography, AI/LLM+Federated Learning, and
  wiring it all together inside the live simulation with real proof it works.
- **Task 8.5 onward is the "big experiments + writing" phase** — this is what's
  left: bigger tests, comparison charts, and writing up the results in the report.
