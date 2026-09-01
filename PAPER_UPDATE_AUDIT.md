# Task: Paper Update After Debugging — Code vs Paper Audit

> **STATUS 2026-08-09:** All 13 supervisor patches APPLIED to `main.tex`.
> Backup of pre-patch state: `scratchpad/main.tex.pre-patch` (md5
> `b6cc53047d06187a4f8f1e6f7dbc0818`).
> **The patch set is incomplete — 19 dangling references remain, one of which
> is a hard LaTeX compile error. See "Post-Patch Fallout" at the end.**

Every item below was checked by reading the current code and the current `main.tex`.
Classification: **(a)** already in paper · **(b)** needs update · **(c)** needs new text.

---

## Part 1 — The supervisor's 13 items

| # | Item | Status | Paper location |
|---|------|--------|----------------|
| 1 | ZKP cumulative commitment | **(b)** | `main.tex:2504-2530` (eq:pedersen, eq:zkp_proof) |
| 2 | ZKP MAC tolerance ε=3 | **(c)** | after `eq:zkp_proof` (`main.tex:2526`) |
| 3 | ZKP gate on sustained path | **(b)** | DEBSC subsec + Algorithm 4 |
| 4 | Speed-scaled thresholds | **(b)** — *formula differs, see below* | `tab:sim_settings` rows S1, θ_R |
| 5 | Attacker restricted to mesh | **(c)** | `tab:sim_settings` + threat model |
| 6 | Flows = 6 | **(c)** — *no flow-count row exists at all* | `tab:sim_settings` |
| 7 | FL live integration | **(b)** | `main.tex:4268-4278`, FL rounds row `4035` |
| 8 | LLM invoked when rcv==0 (Fix C) | **(c)** | LLM-FL pipeline subsec |
| 9 | Q_i veto on sustained | **(c)** | DEBSC subsec |
| 10 | SG_SUSTAINED_ISOLATE=12 | **(c)** | `tab:sim_settings` |
| 11 | Fusion weights μ=0.65/0.20/0.15, θ_det=0.50 | **(b)** | `main.tex:2443` — currently only "optimised on the validation set", **no numbers given** |
| 12 | DA5 dual-mode necessity | **(c)** | results / dual-mode framework |
| 13 | RNG seed 42 / run 1 | **(c)** | `tab:sim_settings` |

**Zero items are already fully in the paper (a).** 5 need updating, 8 need new text.

### Code evidence

- **1** — `g_sg_zkp_cum_received/forwarded` incremented per packet at `routing.cc:120777, 120922, 122827, 122844-45`; MacRx pre-commitment confirmed. Paper still says commitment is over per-window `n_i^fwd`.
- **2** — `SG_ZKP_CUM_EPSILON = 3` at `shield_gh/blockchain/zkp_proofs.cc:45`. Paper implies strict mismatch.
- **3** — `zkp_ok_to_isolate` at `shield_gh_integration.h:1056` is ANDed into `should_isolate` (line 1106), which covers both `response==ISOLATE` and `sustained_gated`.
- **7** — `.fl_state.pkl` + `FL_ROUND_EVERY_N_WINDOWS = 10` at `ns3_infer.py:186-187`.
- **9** — `sustained_qi_ok` / `sustained_gated` at `shield_gh_integration.h:1102-1104`.
- **10** — `SG_SUSTAINED_ISOLATE = 12` at `shield_gh_integration.h:168`.
- **11** — `mu1=0.65, mu2=0.20, mu3=0.15` at `fusion.py:56-58`; `theta_det=0.50` at `fusion.py:75`.

---

## Part 2 — Corrections to the items as stated

These are places where the code does **not** do what the item describes. Flagging before
LaTeX patches are issued, so the patches don't encode something the code doesn't do.

### Item 4 — the scaling formula in the item is not the formula in the code

The item asks for `tau_f(v) = tau_f_base × (1 − ρ_ho(v))` (multiplicative). The code uses an
**additive re-anchoring** at `shield_gh/detection/lw_dp_det.cc:101`:

```
tau_f_effective = (tau_f − ρ_ho(80 km/h)) + ρ_ho(v_now)
```

θ_R is scaled too, but by a **third, different** formula — a decay-ratio form, not the
handoff-loss form (`shield_gh/blockchain/debsc.cc:57`, `EffectiveThetaR()`):

```
theta_R_effective = 1 − raw_margin × decay_ratio_i,  raw_margin = (1−θ_R_tuned)/decay_ratio(80 km/h)
```

Both reduce to the tuned value at v=80 as the item requires, but writing the multiplicative
form into the paper would misdescribe both. Also note the τ_f scaling is applied **only when
MATD is enabled** (`if (matd_enabled)`, line 96) — DA1/DA3 ablations use unmodified τ_f. That
conditionality needs to be in the text or the ablation description contradicts the method.

### Item 3 — "FAIL or ABSENT" is now FAIL-only

The item says isolation requires `zkp_proof ∈ {FAIL, ABSENT}`. Fix 2 deliberately changed this:
ABSENT now **blocks** isolation, and only a cached FAIL permits it
(`shield_gh_integration.h:1056-1057`, with the rationale in the comment at 1046-1055). Writing
`{FAIL, ABSENT}` into Algorithm 4 would document the pre-Fix-2 behaviour.

### Item 2 — the ε justification needs a number check before it goes in print

The claim "ε=3 well below minimum attacker gap (≥40 packets at drop_rate=40%)" is sound in
form, but the code's default `drop_rate = 50`, not 40 (`routing.cc:160`). The stated margin
should be recomputed at whichever drop rate the paper declares as default.

---

## Part 3 — Additional inconsistencies found (not in the 13)

Reported per the supervisor's "if you find any more, report immediately".

1. **Default drop rate: paper 40% vs code 50%.** `tab:sim_settings` declares ρ_a = 40% as "the
   canonical grey hole operating point"; `routing.cc:160` and the `--drop_rate` help text both
   default to 50.

2. **Default attacker penetration: paper 40% vs code 50%.** Same table row says p = 40%;
   `routing.cc:159` `attack_percentage = 50`.

3. **Max speed: paper 150 km/h cap vs code 80.** Table says 150 km/h cap / mean ≈21 km/h;
   `routing.cc:434` `maxspeed = 80`. This one matters beyond bookkeeping — τ_f and θ_R are both
   anchored to v=80 as the *tuned* point, and the debugging notes reference v=140 as the
   operating point. Three different speeds are in play across table, code default, and tuning
   rationale; the paper needs one coherent story.

4. **Node counts.** Table declares 264 nodes (200 vehicles + 64 RSUs). Code defaults are
   `N_Vehicles = 4` (`routing.cc:384`) and `N_RSUs = 1` (`routing.cc:383`), CLI-overridable.
   If experiments are launched with explicit flags this is harmless, but the paper should state
   that the table values are the experiment flags, not the compiled defaults — otherwise a
   reproducer running the binary bare gets a 5-node network.

5. **ZKP deadline T_zkp = 2 s is not implemented anywhere — confirmed.** My earlier report
   left this open pending a wider search. That search is now done and the parameter is
   paper-only. `grep` for `T_zkp|zkp_deadline|zkp_timeout|ZKP_DEADLINE` across the whole of
   `routing.cc` and all of `shield_gh/` returns nothing. This has three consequences that go
   beyond one table row:

   **5a. The ABSENT state is not representable in code.** `eq:zkp_state` (`main.tex:2232`)
   defines a three-state model PASS/FAIL/ABSENT, keyed on whether a proof arrives within
   `T_zkp`. `ZKPProof` (`zkp_proofs.h:26-32`) carries a single `bool valid`, and the store
   exposes only `GetProofValid()`. There is no third state and no clock, so ABSENT cannot be
   expressed. The integration layer already works around this — the comment at
   `shield_gh_integration.h:1046-1050` notes the struct "has no separate ABSENT state" and
   substitutes "no proof cached yet".

   **5b. `eq:debsc` contradicts the shipped gate.** The paper's isolation condition
   (`main.tex:2280`) is `Π_ZKP ∈ {FAIL, ABSENT}`. Fix 2 made ABSENT *block* isolation, so the
   code implements `Π_ZKP = FAIL` only. This is the same divergence as Item 3, but it lands in
   a numbered equation rather than prose — so patching Item 3's Algorithm 4 without also
   amending `eq:debsc` would leave the paper internally inconsistent. The paper's stated
   security property ("withholding a proof triggers the same isolation pathway as submitting a
   false one", `main.tex:2294-2296`) is therefore **not** what the code enforces; under Fix 2 a
   withheld proof blocks isolation instead of causing it.

   **5c. RSU-observed cross-reference (`eq:rsu_crossref`) is also unimplemented.** No match for
   `eps_obs|epsilon_obs|crossref|n_fwd_hat` in `routing.cc` or `shield_gh/`. The paper's FAIL
   state has two triggers — failed verification *or* inconsistent cross-reference — and only
   the first exists. ε_obs is likewise undefined in the settings table.

   Recommendation: these are design-claim gaps, not typos. Either implement the deadline +
   cross-reference, or scope `eq:zkp_state`/`eq:debsc` down to the two states the code actually
   has and drop the T_zkp and ε_obs rows. This is a decision for the supervisor, not something
   to patch silently — it touches a stated novelty claim (the self-reporting evasion closure).

6. **Sensitivity params that DO match** (no action): W=10, ε_f=0.20, τ_it=0.70, γ_it=1.30,
   τ_ts=0.50 — `routing.cc:236-241` all agree with the table.

---

## Recommended sequencing

Items 1-13 are all safe to patch into LaTeX once items 3, 4 and 2 above are reworded to match
actual code behaviour. Part 3 items 1-3 are the ones to resolve **before** experiments run —
they are simulation-settings mismatches, so whichever way they are resolved changes either the
runs or the table.

---

## Post-Patch Fallout — 19 dangling references the patch set did not cover

The 13 patches removed the ABSENT state, `T_zkp`, and the RSU cross-reference
(`eq:rsu_crossref`) from the method sections. Those constructs are referenced in **19 further
places** the patch set did not touch. Applied as-is, the paper does not compile cleanly and
contradicts itself.

### Tier 1 — Hard compile error (must fix before any build)

- **`eq:rsu_crossref` label deleted, still `\eqref`'d in 4 places**: lines 2805, 3557 (prose),
  4732, 5183. `\eqref` to a non-existent label renders `??` and throws
  `LaTeX Warning: Reference ... undefined`. The label was removed by Patch 1; no patch removed
  its citations.

### Tier 2 — Method-section contradictions (paper now disagrees with itself)

- **L2326** — DEBSC prose still states the gate fires on `{FAIL, ABSENT}`; `eq:debsc` two lines
  away now says `= FAIL`.
- **L3073-3074** — Algorithm (LW-DP-DET) still *calls*
  `ZKP-CROSSCHECK(v_i, t, T_zkp, ε_obs)` with the old 4-arg signature. Patch 10 changed the
  procedure definition to 3 args (`v_i, t, ε_zkp`). Call site and definition now mismatch.
- **L3077** — same algorithm still branches on `{FAIL, ABSENT}`.
- **L3554-3560** — narrative description of ZKP-Crosscheck still describes the deadline,
  ABSENT return, and RSU cross-reference step by step.
- **L4117** — `tab:sim_settings` still carries the `ZKP deadline T_zkp = 2 s` row. Patch 9b
  added new rows but no patch deleted this one, so the table now documents a parameter the
  method section no longer defines.

### Tier 3 — Results/evaluation sections built on removed functionality

This is the substantive problem, not a typo class.

- **L4706-4732 (M7 — PEDR metric)** — "ZKP Proof Evasion Detection Rate" is *defined* in terms
  of proof withholding: "withheld a proof within `T_zkp`", "(ABSENT state) — correctly flagged
  by the three-state ZKP model". The metric's definition no longer has a mechanism behind it.
- **L5015-5019 (A8 ablation, `tab:ablation_summary`)** — ablation A8 is *literally*
  "ZKP ABSENT state", ablated against "Two-state ZKP (ABSENT = undefined)", swept over
  proof-withholding fraction {0,25,50,75,100}%, measured by M7.
  **The two-state model the ablation was designed to lose against is now the shipped system.**
- **L5166-5177 (A8 prose)** — states PEDR "collapses to zero" for two-state while the proposed
  three-state "maintains high PEDR through the ABSENT-state trigger". As written, the paper now
  predicts its own system collapses to zero.
- **L5021-5025, L5179-5190 (A9 ablation)** — "RSU cross-reference", swept over fabricated-
  commitment fraction, measured by M7. Ablates a component that does not exist.
- **L5199** — A10 also consumes M7 (with M4).

### Assessment

Tier 1 and 2 are mechanical and I can fix them safely. **Tier 3 is not a patching problem —
it is a scope decision.** A8 and A9 are two of the paper's planned ablation experiments, and
their entire experimental premise is the functionality option (ii) removed. M7/PEDR exists only
to score them. Three coherent ways out:

1. **Drop A8, A9, and M7** — renumber remaining ablations, remove the M7 column from
   `tab:metric_coverage` and the ablation summary. Cleanest, costs two ablations and one metric.
2. **Implement ABSENT + cross-reference** (original option (i)) — keeps A8/A9/M7 intact and
   restores the evasion-closure novelty claim. Costs implementation work in `zkp_proofs.h/.cc`
   plus a deadline timer.
3. **Repurpose A8** — re-aim it at the cumulative-vs-per-window counter (which *is*
   implemented and is a genuine contribution: it closes the per-window reset attack). A9 still
   has to go. M7 would need redefining around cumulative-gap evasion.

I have not guessed between these. Recommendation: **option 3** if the ablation count matters
for the contribution story, **option 1** if it does not — option 2 only if the supervisor wants
the security claim back badly enough to fund the implementation.

### Verification status

No LaTeX toolchain on this machine (`pdflatex`/`latexmk` both absent), so **the patched file has
not been compile-verified**. The `eq:rsu_crossref` breakage above was found by label/reference
cross-check, not by a build. A compile check is required before submission.
