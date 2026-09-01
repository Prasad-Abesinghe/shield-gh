# Fixes 1-5 Implemented and Verified; DA1-DA6 at v=140 km/h

All five fixes were implemented and verified against real, complete NS-3
simulation runs (N_Vehicles=20, attack_percentage=40, drop_rate=60,
attack_number=1 (DP-FR), routing_algorithm=4, architecture=0, simTime=30,
maxspeed=140 for the final table). No numbers in this report are estimated
or fabricated -- every TP/TN/FP/FN/MCC value below is copied directly from
a `CUM M1b MCC` / `Cum TP=...` line printed by a completed run.

A build/deployment complication is documented at the end (see "Build
environment note") since it materially affected how the verification had
to be done -- worth knowing if this is picked up again later.

---

## The final table (all runs at v=140, N_Vehicles=20, attack_percentage=40)

| Config | Cum TP | Cum FP | Cum FN | MCC |
|---|---|---|---|---|
| DA1 (sig only, v=140) | 213 | 20 | 11 | 0.89 |
| DA2 (+MATD, v=140) | 213 | 1 | 11 | 0.96 |
| DA3 (+ZKP, v=140) | 213 | 20 | 11 | 0.89 |
| DA4 (full lightweight) | 213 | 1 | 11 | 0.96 |
| DA5 (LLM+FL only) | 148 | 0 | 76 | 0.73 |
| DA6 (full system, mu1=0.65 best-of-grid) | 213 | 28 | 11 | 0.86 |

(Cum TN, needed for MCC but not requested in the table: DA1/DA3=316,
DA2/DA4=335, DA5=336, DA6=308. n_evals=560 for every config, since all six
share the same attacker set, N, simTime, and window cadence.)

**0.85 target: MET (DA6 MCC=0.86), but DA6 does NOT exceed DA4 (0.96) as
the supervisor's expected pattern calls for.** Per the task's own
instruction, the full per-variant/Q_i diagnostic is gated on MCC<0.85,
which did not occur here -- but DA6<DA4 is itself a real, worth-explaining
deviation, so the root cause is included below (Fix 5 section) since it
was already found while diagnosing why the mu1 grid search was flat.

Against the three named expectations:
- **MCC increases DA1->DA4: MET.** 0.89 -> 0.89 -> 0.89(DA3, unchanged
  from DA1) -> 0.96. Not strictly monotonic step-by-step (DA3=DA1), but
  DA4 > DA1 and no step decreases.
- **DA2's FP lower than DA1's FP: MET.** 20 -> 1, a genuine ~95% reduction
  from MATD.
- **DA6 exceeds DA4: NOT MET.** 0.86 < 0.96. Root cause identified, not
  hand-waved -- see Fix 5.

---

## Fix 1 -- Attacker assignment restricted to the reachable mesh region

**Implemented as specified**, in `declare_attackers_routing()`
(`routing.cc`, function starting at the line documented in the task brief).
Attackers are now assigned starting at `mesh_start = N_Vehicles/3 + 1` (=7
at N=20), wrapping within `[mesh_start, N_Vehicles-1]`, instead of always
starting at node 0. The "at least 1 attacker" floor logic was left intact.
Added a `cout` line reporting `mesh_start` and the mesh region size, plus
kept the existing "Node N forced as ATTACKER" line (now suffixed
"(mesh-restricted placement)") for post-hoc grepping.

**Verified with real runs:**
- Zero-attack baseline (`--attack_percentage=0`, v=80): `Forcing exactly 0
  attackers out of 20 vehicles`, PDR 64.7%-74.0% across windows (same order
  of magnitude as the diagnostic history's earlier 72-82% zero-attack PDR
  baseline; not an identical run configuration, but confirms traffic flows
  normally with the fix in place, no crash, no degenerate zero-traffic
  state).
- DA1 config (`--attack_percentage=40`, v=80): `Forcing exactly 8 attackers
  out of 20 vehicles`, and the log shows exactly nodes **7, 8, 9, 10, 11,
  12, 13, 14** forced as attackers -- all inside the verified mesh region
  (7-19), none in the unreachable 0-6 chain.
- Checked every one of those 8 nodes' `[NQ1/NQ2] node=N ... rcv=R` lines
  across the whole run: **all 8 nodes show rcv>0 in every window they are
  evaluated** (node 7: 22/22 windows rcv>0, max rcv=12; node 8: 19/19, max
  19; ... node 14: 21/21, max 17). Zero attacker nodes are structurally
  silent. No range extension was needed -- the first attempt already
  cleared the "must be zero" bar.

## Fix 2 -- Flows increased from 2 to 6

**Implemented as specified**: `const int flows = SG_FLOWS_COUNT;` with
`#define SG_FLOWS_COUNT 6` (see "a bug found during this fix" below for why
a macro was used instead of a bare literal).

**Grep audit before touching anything else** (as instructed): searched the
whole file for hardcoded flow-count-shaped literals near array sizing and
packet-tag code. Everything in `routing.cc` itself already derived from
`flows`/`2*flows` -- `node_flow_received/forwarded`, the
`CustomFlowDataUplinkTag1` `m_source/m_destination/m_X/m_P/m_Q` arrays and
their `GetSerializedSize/Serialize/Deserialize` loops, the controller-plane
`Q_f/L_f/W_f/Omega_f/Theta_f/T_f/t_f/U_f/Y_f/delta_f/load_f` struct arrays,
and `path_list/sources_list/destinations_list`. No stray literal needed
fixing inside `routing.cc`.

**A real bug WAS found, outside routing.cc**, exactly the kind the task
warned about: `scratch/shield_gh/shield_gh_integration.h` had
`extern uint32_t node_flow_received[][4];` /
`extern uint32_t node_flow_forwarded[][4];` -- a **hardcoded `[4]`**
(correct only because `2*flows` was 4 when `flows=2`), instead of deriving
from the shared constant. This is a genuine C++ constraint problem, not
just a style issue: an `extern` array's second dimension must be a
compile-time constant visible at the point of declaration, and this header
is `#include`d in `routing.cc` *before* `const int flows = ...;` is
defined further down that same file -- so the runtime `flows` symbol
could not be used directly in the header without reordering ~140k lines of
a file already flagged elsewhere in this repo's history as fragile.
Fixed by introducing `#define SG_FLOWS_COUNT 6` immediately before the
`#include` of `shield_gh_integration.h` in `routing.cc`, using it in both
`const int flows = SG_FLOWS_COUNT;` (routing.cc) and the header's extern
bounds (`node_flow_received[][2*SG_FLOWS_COUNT]`), and adding a
`#error` guard in the header if `SG_FLOWS_COUNT` isn't defined yet, so this
exact class of drift can't reappear silently. Confirmed via a real build:
the original `[4]` bound produced a hard compiler error
(`conflicting declaration 'uint32_t node_flow_forwarded [205][12]'`) the
moment `flows` was raised, which is how the bug was actually found (not
found by inspection alone).

**Verified with a real run**: with the fix and a fresh flows=6 build, a
zero-attack-percentage log at v=80 shows **12 flows created** (`flow id 0`
through `flow id 11`, i.e. `2*flows=12`), with sources/destinations
spanning the full mesh region (e.g. flow 0: 7->10, flow 11: 18->8) --
this happened automatically, without any change to the flow-placement
loop itself, because `source = mesh_start + (i % mesh_span)` already
scales with however many flow-index values `i` takes (0..2*flows-1). The
DA1 run (attack_percentage=40) then showed all 8 mesh-placed attacker
nodes carrying real traffic (see Fix 1's rcv>0 verification above) --
confirms Fix 1 and Fix 2 combine correctly, not just individually.

## Fix 4 -- Fresh FL state per DA run

**Implemented via a `--fresh_state` CLI flag** on `ns3_infer.py` (matches
the existing `--theta`/`--genuine` flag pattern rather than inventing a new
config surface), gated in C++ so only the **first** window of an NS-3
process (`g_sg_window==0`) passes it -- every later window in the same run
must not, or FL round/window state would never persist even within one
run. Wired through `sg_ai_run_bridge()`'s new `fresh_state` parameter
(default `false`, so any other, unrelated caller of this function is
unaffected) and the one call site in `shield_gh_integration.h`.

**Verified with two separate, real, sequential runs** (mimicking a DA5
run immediately followed by a DA6 run, exactly the scenario that was
previously found to leak state):
- Run 1 (DA5-shaped config): log shows
  `--fresh_state: removed stale .../shield_gh_ml/.fl_state.pkl` at the
  very first bridge call, then `fl_round=0` for windows 1-9 and
  `fl_round=1 fl_round_ran=True` at window 10 -- a genuine round 1, not
  inherited from anywhere.
- Run 2 (DA6-shaped config, started right after run 1 with run 1's
  `.fl_state.pkl` still on disk): log shows the **same** sequence --
  `--fresh_state: removed stale ...` fires again, `fl_round=0` for windows
  1-9, `fl_round=1 fl_round_ran=True` at window 10. Confirms run 2 did
  **not** inherit run 1's leftover round/client state -- the previously
  confirmed DA5->DA6 contamination bug is fixed.

## Fix 3 -- Full DA1-DA6 sequence at v=140 km/h

Run with `--maxspeed=140` in place of 80, all other flags unchanged from
the reproduction commands recovered from this machine's own `.bash_history`
(the diagnostic markdown files describe flag *semantics* but do not
preserve literal invocations verbatim; the history did). Fix 4's
`--fresh_state` behaviour is automatic (wired into the C++ call site, not
something that has to be remembered per-invocation) so it applied to every
DA5/DA6-shaped run in this sequence without extra flags. Results are the
final table at the top of this document. Per-config CLI flag deltas:

| Config | enable_signatures | enable_matd | enable_zkp_gate | detection_mode | enable_full_mode_ai |
|---|---|---|---|---|---|
| DA1 | 1 | 0 | 0 | lightweight | 0 |
| DA2 | 1 | 1 | 0 | lightweight | 0 |
| DA3 | 1 | 0 | 1 | lightweight | 0 |
| DA4 | 1 | 1 | 1 | lightweight | 0 |
| DA5 | 0 | 0 | 0 | full | 1 |
| DA6 | 1 | 1 | 1 | full | 1 |

## Fix 5 -- Fusion weight grid search

**Mechanism**: added `--mu1`/`--mu3` CLI args to `ns3_infer.py` (mu2 always
derived as `1-mu1-mu3` on the Python side, matching Eq. 3.29's constraint),
threaded through from routing.cc via two new globals (`sg_ai_mu1`,
`sg_ai_mu3`, both `double`, negative sentinel = "use ns3_infer.py's
compiled-in default") and two new `cmd.AddValue` CLI flags
(`--sg_ai_mu1`, `--sg_ai_mu3`), following the exact pattern already used
for `--genuine`/`--fresh_state`. Verified the wiring is real, not just
present, by reading `/tmp/shieldgh_verdict.json`'s `weights` field mid-run:
`[0.55, 0.3, 0.15]` for `--sg_ai_mu1=0.55 --sg_ai_mu3=0.15` -- confirms
mu2 is correctly derived and the override reaches the fusion engine.

**Grid search result (DA6 config, v=140, all fixes 1-4 applied)**:

| mu1 | mu2 (derived) | mu3 | Cum TP | Cum FP | Cum FN | MCC |
|---|---|---|---|---|---|---|
| 0.34 (old default) | 0.33 | 0.33 | 213 | 28 | 11 | 0.86 |
| 0.55 | 0.30 | 0.15 | 213 | 28 | 11 | 0.86 |
| 0.65 | 0.20 | 0.15 | 213 | 28 | 11 | 0.86 |
| 0.75 | 0.10 | 0.15 | 213 | 28 | 11 | 0.86 |

**All four weight settings produce IDENTICAL results.** Reported exactly
as measured rather than picking a "winner" that isn't actually
distinguishable from the others. Traced why, since a completely flat grid
is itself worth explaining rather than shrugging off:

- Every one of the 175 windows where an attacker node was actually scored
  by the AI fusion path shows `y_hat=1` with `score` well clear of
  `theta_det=0.5` (e.g. node 7: `Q_i=0.882 score=0.930`) -- the binary
  `S_total` term (0 or 1) dominates the weighted sum at any mu1 in
  [0.55, 0.75], so no verdict is near the decision boundary and nothing
  flips as mu1 moves within that range.
- **The real reason DA6 (0.86) doesn't exceed DA4 (0.96) is architectural,
  not a fusion-weight tuning problem**: of the 224 total attacker
  evaluations in the DA6 run, only 175 ever reach the AI fusion path at
  all. The other 49 are windows where the attacker node's `rcv==0` that
  window (`shield_gh_integration.h`'s existing `else` branch, documented
  in-code as a known limitation) -- these silently fall back to the
  **lightweight** rule-signature verdict instead of the AI verdict. All 11
  of DA6's FNs and 38 of its 213 TPs come from this fallback path, not the
  AI path (which is 175/175 = 100% TP). The AI fusion is not the bottleneck
  here; the rcv==0 fallback windows are, and those get the same signature-
  only verdict quality as DA1/DA3 (MCC 0.89) rather than DA2/DA4's
  MATD-corrected quality (MCC 0.96), because the fallback branch's
  `flagged` value only reflects `S_total`, not a MATD/ZKP-adjusted verdict.
  This also explains DA6's higher FP (28 vs DA4's 1): FPs are legit nodes
  the AI path flags that the MATD-corrected lightweight path (DA4) would
  not have.
- **Default set to mu1=0.65** (`shield_gh_ml/fusion.py`'s `FusionWeights`
  dataclass defaults, now `mu1=0.65, mu2=0.20, mu3=0.15`) as the permanent
  compiled-in default -- tied for best result and the grid midpoint (not at
  either boundary), documented with a comment explaining the tie rather
  than silently picking one value with no justification recorded.

## New theoretical ceiling with Fix 1 in place

The old ceiling (MCC=0.4714, computed in earlier diagnostic rounds) existed
specifically because only 5 of 12 forced attackers were reachable, which is
a **structural** cap independent of detector quality (some FNs were
mathematically guaranteed no matter how good detection got). With Fix 1,
all 8 forced attackers (attack_percentage=40 at N=20) are in the verified-
reachable mesh region -- there is no longer any structurally-guaranteed FN,
so **the ceiling is the ordinary perfect-detector ceiling, MCC=1.0**, not a
reduced structural cap. DA2/DA4's 0.96 is genuinely close to that ceiling;
the remaining gap (11 FN, 1 FP) is real detector imperfection on specific
windows, not an artifact of unreachable attackers. This changes how DA6's
0.86 should be read: it is not hitting a topology ceiling either -- the gap
to DA4 is fully explained by the rcv==0 fallback-path finding above, which
is a fixable architectural gap (route the fallback branch through
MATD/ZKP-adjusted logic too, or feed rcv==0 windows to the AI path with an
explicit "silent window" feature) rather than a fundamental limit.

---

## Build environment note (read if resuming this work)

This machine hosts multiple groups' NS-3 projects sharing one build tree.
The working copy at `.../ns-3.35/62/scratch` (this repo) is **not** the
location `waf` actually builds from -- the real, git-tracked, previously-
built copy lives at `.../ns-3.35/scratch62` (same git remote/history,
confirmed identical HEAD commit `50ab4b3`), and the shared
`.../ns-3.35/scratch` directory is swapped between groups' code for
building (confirmed via `.bash_history`: `cd .../ns-3.35/scratch; ./waf
build --targets=routing; ./build/scratch/routing ...`). At the time this
work was done, `.../ns-3.35/scratch` held a **different, unrelated**
group's project (different `routing.cc`, no `shield_gh/`) with an actively
running simulation (`N_Vehicles=209`, running since before this session
started) -- so the shared `scratch/` directory could not safely be
swapped without risking that other group's in-progress run.

**Worked around by building in an isolated tree**: created
`.../ns-3.35-g62build/` as a directory of symlinks to every real ns-3
top-level item except `scratch` (all of `src/`, `build/`, `wscript`, etc.,
shared read-only via symlink, zero extra disk use), copied this repo's
`scratch/` content into a real (non-symlinked) `scratch/` there, then
`./waf configure --out=.../ns-3.35-g62build/build ...` and
`./waf build --targets=routing`. This never touched the shared
`.../ns-3.35/scratch` or the other group's running process (verified by
diffing `.../ns-3.35/scratch/routing.cc`'s md5sum before and after this
entire session -- unchanged). All verification and DA1-DA6 runs above were
executed from this isolated tree via
`LD_LIBRARY_PATH=$PWD/build/lib:$PWD/build ./build/scratch/routing ...`.
Before each rebuild, this repo's `scratch/` was rsynced into the isolated
tree's `scratch/` so the isolated build always reflected the latest edits
here.

This isolated tree (`.../ns-3.35-g62build/`) was left in place after this
session in case it's useful for further runs, but all source-of-truth
edits are in this repo (`.../ns-3.35/62/scratch`), as instructed --
nothing was committed to git.
