# Reply to Dr. Wijesekara

Hi Dr. Wijesekara 👋

I'll give you a paper patch now. All 13 items checked directly against the code and against
`main.tex` — not from memory. Classification below.

**Nothing is already correctly in the paper. 5 items need updating, 8 need new text.**

**(b) needs update — 5:**
- **Item 1** ZKP cumulative commitment — paper's eq:pedersen still commits per-window `n_i^fwd`
- **Item 3** ZKP gate on sustained path
- **Item 4** speed-scaled thresholds
- **Item 7** FL live integration — paper describes offline training
- **Item 11** fusion weights — paper says only "optimised on the validation set", gives no numbers

**(c) needs new text — 8:** Items 2 (ε_zkp), 5 (mesh-restricted attackers), 6 (6 flows — there
is currently no flow-count row in the table at all), 8 (Fix C), 9 (Q_i veto), 10
(SUSTAINED_ISOLATE=12), 12 (DA5 necessity), 13 (RNG seed).

---

**Three items need rewording before the patches go in — the code doesn't do what the item says:**

1. **Item 4 formula.** You specified `tau_f(v) = tau_f_base × (1 − ρ_ho(v))`. The code uses
   additive re-anchoring: `tau_f_eff = (tau_f − ρ_ho(80)) + ρ_ho(v_now)`. And θ_R is scaled by a
   *different* formula again — a decay-ratio form, not handoff-loss. Both reduce to the tuned
   value at v=80 as you intended, but the multiplicative form would misdescribe both. Also: τ_f
   scaling applies **only when MATD is on**, so DA1/DA3 use unmodified τ_f — that needs saying,
   or the ablation contradicts the method section.

2. **Item 3 gate condition.** You wrote `zkp_proof ∈ {FAIL, ABSENT}`. Fix 2 deliberately
   reversed this — ABSENT now *blocks* isolation, only a cached FAIL permits it. Writing
   {FAIL, ABSENT} into Algorithm 4 would document pre-Fix-2 behaviour.

3. **Item 2 justification.** "≥40 packets at drop_rate=40%" — the code's default drop rate is
   50%, not 40%. The margin should be recomputed at whatever rate we declare as default.

---

**Additional mismatches found (answering your second question):**

- **Drop rate:** paper 40%, code default 50%
- **Attacker penetration:** paper 40%, code default 50%
- **Max speed:** paper 150 km/h cap, code default 80, tuning rationale references 140 — three
  different speeds across table, code, and threshold anchoring. Needs one coherent story, and
  it matters because τ_f/θ_R are both anchored to v=80 as the tuned point.
- **Node counts:** table says 264 (200 vehicles + 64 RSUs); compiled defaults are 4 vehicles /
  1 RSU, CLI-overridable. Table should state these are experiment flags, not compiled defaults,
  or a reproducer running the binary bare gets a 5-node network.
- Confirmed matching, no action: W=10, ε_f=0.20, τ_it=0.70, γ_it=1.30, τ_ts=0.50.

The first three (drop rate, penetration, speed) should be resolved **before** experiments run —
whichever way they go, they change either the runs or the table.

---

**One finding needs your decision before any patch is issued — it affects two numbered
equations, not just the settings table.**

**T_zkp = 2 s is not implemented anywhere.** Confirmed by searching all of `routing.cc` and
all of `shield_gh/` — no deadline, no timer, no timeout. That has knock-on effects:

1. **ABSENT is not representable in code.** `eq:zkp_state` defines PASS/FAIL/ABSENT keyed on
   arrival within T_zkp. `ZKPProof` carries a single `bool valid` (`zkp_proofs.h:26-32`) — no
   third state, no clock. The integration layer already works around this: the comment at
   `shield_gh_integration.h:1046-1050` notes the struct "has no separate ABSENT state".

2. **`eq:debsc` contradicts the shipped gate.** The paper requires
   `Π_ZKP ∈ {FAIL, ABSENT}`; Fix 2 made ABSENT *block* isolation, so the code is FAIL-only.
   Same divergence as Item 3, but here it sits in a numbered equation — so patching Item 3's
   Algorithm 4 alone would leave the paper self-inconsistent. More importantly, the security
   property the paper claims from this ("withholding a proof triggers the same isolation
   pathway as submitting a false one") is **not** what the code does: under Fix 2 a withheld
   proof blocks isolation rather than causing it. That is a stated novelty claim, so I did not
   want to patch around it quietly.

3. **RSU cross-reference (`eq:rsu_crossref`) is also unimplemented** — no `eps_obs`/`crossref`
   anywhere. The paper's FAIL state has two triggers (failed verification *or* inconsistent
   cross-reference); only the first exists. ε_obs is undefined in the settings table too.

Two ways forward, your call: **(i)** implement the deadline + cross-reference so the code
matches the paper, or **(ii)** scope `eq:zkp_state` and `eq:debsc` down to the two states the
code actually has, and drop the T_zkp and ε_obs rows. Option (ii) is much faster but weakens
the self-reporting-evasion claim. I'd recommend deciding this before the LaTeX patches, since
Item 3's wording depends on the outcome.

Full audit with file:line evidence for every item is in `PAPER_UPDATE_AUDIT.md`.
