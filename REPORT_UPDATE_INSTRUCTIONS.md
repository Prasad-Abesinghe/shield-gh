# Instructions: Updating `main.tex` with Final Results, Conclusion, and Related Sections

**Purpose.** This document is a step-by-step guide for updating the thesis
report (`main.tex`) to replace placeholder/expected/early-prototype results
with the real, verified DA1-DA6 final results produced during this
investigation. It also covers the Conclusion chapter and other sections that
should be brought in line with what was actually implemented and measured.

**Source of truth for numbers.** Every number referenced below comes from
[`diagnostic_questions/answers_all_fixes_DA1-6_v140.md`](diagnostic_questions/answers_all_fixes_DA1-6_v140.md)
(the final, verified DA1-DA6 table at v=140 km/h, all 5 fixes applied). Do
not invent, round differently, or "clean up" any number when moving it into
`main.tex` — copy it exactly as it appears there. If a number is needed that
is not in that file, check
[`diagnostic_questions/answers_final_DA1-6_with_sustained_fix.md`](diagnostic_questions/answers_final_DA1-6_with_sustained_fix.md)
and [`diagnostic_questions/answers_grid_search.md`](diagnostic_questions/answers_grid_search.md)
next; if it's in neither, do not fabricate it — flag it and ask, or mark it
explicitly as not-yet-measured rather than guessing.

---

## 0. Before you start

1. Confirm which of the two working copies is authoritative
   (`.../ns-3.35/62/scratch` vs `.../ns-3.35/scratch62`) — per the "Build
   environment note" in `answers_all_fixes_DA1-6_v140.md`, this repo
   (`62/scratch`) is the source of truth for edits; nothing has been
   committed to git yet for the DA1-6 work.
2. Create a new branch or at least confirm `git status` is clean before
   editing `main.tex` (it is currently modified — check `git diff main.tex`
   first so you don't mix unrelated pending edits with this update).
3. Keep a running list of every table/figure label you touch, since
   `\ref{}`/`\label{}` cross-references elsewhere in the document may need
   updating too (search with `grep -n "ref{tab:...}\|ref{fig:...}"`).

---

## 1. Replace `\section{Expected Results}` with real results

**Location:** `main.tex`, line ~5728 (`\label{sec:expected_results}`),
running through line ~5869 (just before `\chapter{Timeline and Resource
Required}`).

This entire section is currently framed as *analytical projections*
("expected performance... derived from formal attack models... since full
simulation experiments are scheduled for Milestone 14"). That framing is now
obsolete — the DA1-DA6 experiments have actually been run. Steps:

1. **Rename the section** from `Expected Results` to something like
   `Final Detection Results (DA1--DA6)` and update
   `\label{sec:expected_results}` to `\label{sec:final_results}` (grep the
   whole doc for any `\ref{sec:expected_results}` and update those too).
2. **Rewrite the intro paragraph** (currently starting "The following
   sections present the expected performance results...") to state plainly
   that these are measured results from real NS-3 runs: N_Vehicles=20,
   attack_percentage=40, drop_rate=60, attack_number=1 (DP-FR),
   routing_algorithm=4, architecture=0, simTime=30, maxspeed=140 km/h — the
   exact configuration documented at the top of
   `answers_all_fixes_DA1-6_v140.md`.
3. **Insert the final DA1-DA6 table** (copy verbatim from the top of that
   file) as a proper LaTeX table, e.g.:

   | Config | Cum TP | Cum FP | Cum FN | MCC |
   |---|---|---|---|---|
   | DA1 (sig only) | 213 | 20 | 11 | 0.89 |
   | DA2 (+MATD) | 213 | 1 | 11 | 0.96 |
   | DA3 (+ZKP) | 213 | 20 | 11 | 0.89 |
   | DA4 (full lightweight) | 213 | 1 | 11 | 0.96 |
   | DA5 (LLM+FL only) | 148 | 0 | 76 | 0.73 |
   | DA6 (full system) | 213 | 28 | 11 | 0.86 |

   Include Cum TN per config as a footnote (DA1/DA3=316, DA2/DA4=335,
   DA5=336, DA6=308) and note n_evals=560 for every config.
4. **State the three named hypotheses and their outcomes explicitly**,
   matching the honest framing already written in the diagnostic file:
   - MCC increases DA1→DA4: **MET** (0.89→0.96, DA3 unchanged from DA1 but
     no step decreases).
   - DA2's FP lower than DA1's FP: **MET** (20→1, ~95% reduction from MATD).
   - DA6 exceeds DA4: **NOT MET** (0.86 < 0.96) — include the root-cause
     explanation (see §2 below) rather than omitting the negative result.
5. **Replace each of the old subsections** (`How Detection Metrics Vary with
   Attack Variant and Intensity`, `How PDR Varies with Drop Rate`, `How
   Detection Accuracy Varies with Attack Intensity`, `Detection Latency and
   Mitigation Response Time`, and whatever follows through line ~5869) —
   read them first (`sed -n '5744,5869p' main.tex`) and, for each one:
   - If the diagnostic-questions work produced a real measured version of
     that claim, replace the analytical prose with the measured version and
     cite the evidence file.
   - If no real measurement exists yet for that specific claim (e.g. a full
     drop-rate sweep ρ∈{20,40,60,80}% across all three modes), **do not
     delete the subsection** — instead relabel it clearly as future
     work/not-yet-measured (e.g. rename to "Projected Sensitivity to Drop
     Rate (Not Yet Measured)") so the report stays honest about what is
     analytical vs. empirical. This mirrors the "partially answerable"
     framing already used throughout `50_Diagnostic_Questions_Answers.md`.

## 2. Add the DA6-vs-DA4 root-cause finding as its own subsection

This is a genuine, non-obvious research finding (not just a number) and
deserves its own subsection rather than being buried in a footnote — it
directly explains why the full system doesn't beat the lightweight-only
configuration despite hitting the 0.85 MCC target.

Add a subsection (e.g. `Why the Full System (DA6) Does Not Exceed
Lightweight-Only (DA4)`) under the new results section, summarizing:
- Of 224 total attacker evaluations in DA6, only 175 reach the AI fusion
  path; the other 49 have `rcv==0` that window and silently fall back to
  the lightweight signature-only verdict (no MATD/ZKP correction).
- The AI fusion path itself is 175/175 = 100% TP when it runs.
- All 11 FNs and 38 of 213 TPs, plus the FP gap (28 vs DA4's 1), trace to
  this fallback path, not to the AI/fusion logic itself.
- This is an **architectural gap**, not a tuning problem — the fusion-weight
  grid search (µ1 ∈ {0.34, 0.55, 0.65, 0.75}) produced *identical* results
  (213/28/11/0.86) at every setting, confirming the bottleneck is the
  fallback path, not µ1/µ2/µ3.
- Note the fix direction for future work: route the `rcv==0` fallback branch
  through MATD/ZKP-adjusted logic too, or feed `rcv==0` windows to the AI
  path with an explicit "silent window" feature.
- Also mention the revised theoretical ceiling: with Fix 1 (attacker
  placement restricted to the reachable mesh region), the old structural
  cap (MCC=0.4714) no longer applies — the ceiling is now the ordinary
  perfect-detector ceiling (MCC=1.0), and DA4's 0.96 is genuinely close to
  it.

## 3. Update or retire `\section{Current Simulation Results}` (line ~5593)

This section (Run 1 / Run 2, 5-node topology, MCC=0 caveat) is the old
early-prototype baseline predating Fixes 1-5. Two options — pick based on
how the supervisor wants the narrative structured:

- **Option A (recommended):** Keep it as-is but retitle to something like
  `Early Prototype Baseline (Pre-Fix, 5-Node Topology)` and add one sentence
  at the end explicitly pointing forward to the new final-results section,
  e.g. "This early prototype used a fixed 5-node topology with a known MCC
  measurement limitation (footnote); all results from
  Section~\ref{sec:final_results} onward supersede this baseline with a
  20-vehicle mesh-constrained topology and corrected TP/TN/FP/FN
  accounting."
- **Option B:** Move this section to an appendix if the supervisor prefers
  the main Results chapter to only show final numbers.

Do not delete it outright — it documents real historical validation and the
MCC=0 caveat is instructive.

## 4. Update the per-config CLI parameter table

Insert the DA1-DA6 CLI flag delta table from `answers_all_fixes_DA1-6_v140.md`
(the `enable_signatures / enable_matd / enable_zkp_gate / detection_mode /
enable_full_mode_ai` table) somewhere near the Simulation Settings section
(`\subsection{SHIELD-GH Detection Parameters}`, line ~3920) or immediately
before the final results table — whichever keeps methodology and results
close together. This table is what lets a reader map "DA2" → "which
components are actually on."

## 5. Add the Fix 5 fusion-weight default change to Methodology

`shield_gh_ml/fusion.py`'s `FusionWeights` dataclass default changed to
`mu1=0.65, mu2=0.20, mu3=0.15` (previously 0.34/0.33/0.33) as a result of the
grid search. If Eq. 3.29 or nearby text in
`\subsection{LLM-Based Semantic Threat Scoring and Fusion}` (line ~2392)
states the old default weights, update them and add a one-sentence note that
the values were tuned via grid search over training data (cite the grid
search table) with the tie-break rationale (grid midpoint, not a boundary
value).

## 6. Rewrite the Conclusion chapter (line ~6006)

The current Conclusion is written entirely in future tense ("Simulations
*will* be used to assess...", "The project *will* also assist...") because
it predates any real results. Rewrite in past/present tense to reflect what
was actually built and measured:

1. **Paragraph 1** (motivation) can mostly stay — it's still accurate as
   framing for why grey hole attacks matter.
2. **Paragraph 2** (Blockchain + LLM + FL integration): change from "the
   project integrates" (still fine) but add a sentence confirming this was
   implemented and verified (DEBSC, ZKP gate, MATD, LLM+FL fusion all have
   real code and passing unit tests per the diagnostic answers).
3. **Paragraph 3** (currently: "Simulations *will* be used to assess...")
   — replace with a summary of what was actually measured:
   - Full lightweight detection (DA4) reached MCC=0.96, very close to the
     revised theoretical ceiling of 1.0 now that attacker placement is
     mesh-reachable.
   - The 0.85 MCC target for the full system was met (DA6=0.86).
   - MATD reduced false positives by ~95% (20→1) relative to signatures
     alone.
   - The full system underperforming the lightweight-only configuration
     was identified as a specific, explained architectural gap (the
     `rcv==0` fallback path), not an unexplained regression — state this
     as a concrete, scoped item for future work rather than a weakness left
     unaddressed.
4. Add a short **Future Work** paragraph (or fold into paragraph 3) covering:
   - Fixing the `rcv==0` fallback path to close the DA6/DA4 gap.
   - Running the full drop-rate sweep (ρ∈{20,40,60,80}%) and the E1-E5
     experiment grid (Task 9/9.5/10 per `tasks.md`) if still outstanding —
     check `tasks.md` for current status before writing this, since it may
     have moved since `50_Diagnostic_Questions_Answers.md` was written.
   - Any other open items noted in `50_Diagnostic_Questions_Answers.md`'s
     "Legend/Summary Table" as ❌ Not executable (e.g. Q44/Q45 full
     experiment grid, Q38 per-round FL progression) — only include ones
     still relevant/unresolved at time of writing.

## 7. Add a Prior-Work (SOA1--SOA3) vs. SHIELD-GH comparison, using current numbers

**Why this needs its own pass.** Prior-work comparison infrastructure already
exists but is stale: it compares SOA1/SOA2 against the **old 4-node/5-node
prototype** SHIELD-GH numbers (TP=1 TN=3 FP=0 FN=0, "MCC=1.0"), not the real
DA1-DA6 (N=20, v=140 km/h) results this update is bringing into the report.
It also omits SOA3 entirely. Fix both.

**What already exists (re-use, don't re-derive):**
- [`SOA_Comparison_Report.md`](SOA_Comparison_Report.md) — full narrative
  comparison of SOA1 (Malik DPGHA, B1) and SOA2 (Alabdulatif SCBC/VCBC, B2)
  against SHIELD-GH, including a capability matrix (§C.1), a detection
  performance table (§C.2), paper-reported headline numbers (§C.3), and a
  "where SHIELD-GH advances each baseline" narrative (§C.4). This is the
  best starting draft for prose — just needs its SHIELD-GH column updated.
- [`soa1_dpgha_malik/SOA1_Sweep_Results_Report.md`](soa1_dpgha_malik/SOA1_Sweep_Results_Report.md),
  [`soa2_blockchain_scbc_vcbc/SOA2_Sweep_Results_Report.md`](soa2_blockchain_scbc_vcbc/SOA2_Sweep_Results_Report.md),
  [`State_of_Art_3/SOA3_Sweep_Results_Report.md`](State_of_Art_3/SOA3_Sweep_Results_Report.md)
  — per-baseline sweep detail (SOA3 = FL-BERT/Random Forest, B3, currently
  missing from the comparison report entirely).
- `main.tex` §4349 `\subsection{External Baselines}` already defines B1/B2/B3
  with citations — this is the right place to anchor the comparison
  narrative; §5205 `\subsection{Benchmark Experiments against
  State-of-the-Art}` (E1-E5) is the *planned* full grid comparison (200
  vehicles, not yet run) — do not confuse the two or claim E1-E5 are done.

**Steps:**

1. **Re-run or re-check the SOA1/SOA2/SOA3 sweep scripts** at the same
   configuration as the final DA1-DA6 runs where possible (N_Vehicles=20,
   attack_percentage=40, v=140 km/h), so the comparison is apples-to-apples
   rather than SHIELD-GH's N=20/v=140 numbers vs. baselines' old N=4 or
   30-node-parametric numbers. Check `soa1_dpgha_malik/dpgha_sweep_real.py`,
   `soa2_blockchain_scbc_vcbc/scbcvcbc_sweep.py`, and
   `State_of_Art_3/soa3_rf_sweep_real.py` (all modified recently per `git
   status`) for whether they already support this configuration or need a
   flag added. If an exact-match run isn't feasible, state clearly in the
   report which configuration each baseline was measured under and do not
   imply a same-configuration comparison that didn't happen.
2. **Add a new subsection under `\section{Performance Evaluation}`** (or
   directly after the new final-results section from §1/§2 above), e.g.
   `\subsection{Comparison with Prior Work (B1--B3)}`, containing:
   - The capability matrix from `SOA_Comparison_Report.md` §C.1 (SOA1/SOA2
     already there; add a SOA3 column using
     `State_of_Art_3/SOA3_Sweep_Results_Report.md` and the FL-BERT citation
     already used for B3 in main.tex line ~4365).
   - An updated detection-performance table (replacing §C.2's stale
     TP=1/TN=3 SHIELD-GH row) using the real DA-series numbers — pick the
     DA config that is the fairest match to what B1-B3 actually detect
     (e.g. DA4 "full lightweight" is the closest match to B1/B2's
     rule/blockchain-only scope; DA6 "full system" is the closest match to
     B3's ML-based scope — present both rather than cherry-picking one).
   - Carry forward the "paper-reported headline numbers" table (§C.3) as-is
     (those are fixed facts from the cited papers, not something this
     project's runs change) — but relabel the SHIELD-GH row with the
     current DA figures instead of the old prototype numbers.
   - Keep the "where SHIELD-GH advances each baseline" narrative (§C.4) but
     check every specific claim against what Fixes 1-5 actually changed —
     e.g. the MATD false-positive claim vs. VCBC's ~10% FPR is now backed by
     a concrete number (DA2's FP 20→1 reduction) rather than an assertion;
     use that.
3. **Do not merge in the E1-E5 experiment design as if it were comparison
   results** — those experiments are specified but unrun (200-vehicle grid).
   If a supervisor wants the prior-work comparison to eventually come from
   E1-E5 instead of this smaller-scale one, note that as future work
   pointing at §5205, not as something to fabricate now.
4. Add one sentence in the Conclusion (§6 above) summarizing the comparison
   outcome at a high level (e.g. "SHIELD-GH's full-lightweight configuration
   (DA4, MCC=0.96) outperforms re-implemented B1/B2 baselines on \<metric\>
   while covering 6 attack variants vs. their 2") — only state this once the
   real comparison numbers from step 2 are in hand; do not pre-write the
   conclusion sentence with placeholder metrics.

## 8. Consistency pass

After the edits above:

1. `grep -n "will be\|expected to\|scheduled for Milestone" main.tex` across
   the Results and Conclusion chapters — anything matched should be checked:
   is it still an accurate description of unfinished work, or does it now
   describe something that's done and should be past tense?
2. `grep -n "sec:expected_results\|Milestone~14\|Milestone 14"` to catch any
   remaining forward-references to the old placeholder framing or a
   milestone number that may no longer be the right one to cite.
3. Verify all new tables compile (`pdflatex`/whatever the existing build
   process is — check for a `Makefile` or build script in the repo root) and
   that no `\label{}` collides with an existing one (`grep -n "\\\\label{"
   main.tex | sort | uniq -d` on the label names).
4. Re-read the new final-results section end-to-end for the same honesty
   standard used in the diagnostic-questions files: state what was verified,
   state what wasn't, and don't smooth over the DA6<DA4 result.

---

## Quick checklist

- [ ] `Expected Results` section renamed and rewritten with real DA1-DA6 table
- [ ] Three named hypotheses stated with MET/NOT MET verdicts
- [ ] DA6-vs-DA4 root-cause subsection added
- [ ] Old `Current Simulation Results` retitled/contextualized (not deleted)
- [ ] CLI parameter delta table added near methodology or results
- [ ] Fusion weight defaults (µ1=0.65/µ2=0.20/µ3=0.15) reflected in Methodology if stated there
- [ ] Conclusion rewritten past/present tense with real measured outcomes
- [ ] Future Work paragraph added, cross-checked against current `tasks.md`
- [ ] SOA1/SOA2/SOA3 baselines re-run (or documented as-is) at a comparable config to DA1-DA6
- [ ] Prior-work comparison subsection added with updated (non-stale) SHIELD-GH numbers, incl. SOA3/B3
- [ ] Capability matrix and "where SHIELD-GH advances each baseline" narrative carried over and fact-checked against Fixes 1-5
- [ ] Cross-reference / label / "will be" consistency pass done
- [ ] Document recompiles cleanly
