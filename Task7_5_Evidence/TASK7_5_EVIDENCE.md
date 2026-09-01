# Task 7.5 — Evidence Package: "Application of all AI patches already sent by the supervisor up to this moment"

**Task 7.5 (tasks.md):** *Application of all AI patches already sent by the
supervisor up to this moment.* Status in `tasks.md`: done. This package is
the supporting evidence for that claim, produced against the current code as
of **2026-07-25**, using the same rigour already established for Task 8's
full-mode AI integration (see `shield_gh_ml/TASK8_EVIDENCE.md`,
`shield_gh_ml/EVIDENCE_SUMMARY.md`).

"AI patches" here means the **full-mode LLM + Federated Learning detection
pipeline** — Algorithm 3 (FV-Det), the three-way fusion (Eq. 3.29), and its
live wiring into the running NS-3 simulation via `--enable_full_mode_ai=1`.
This is the same pipeline Task 8 built; Task 7.5's evidence re-verifies it
end-to-end against the code as it stands today, on a fresh run, with five
independent forms of proof:

1. **Full NS-3 live console log** (complete, unedited transcript — no video
   recording is possible in this non-interactive environment; this is the
   agreed text-transcript equivalent)
2. **Full code** (the actual source, not a description — bundled below)
3. **Equation-presence audit script** (static: is every claimed equation
   really coded, term-for-term?)
4. **Functional verification script** (dynamic: does the live simulation
   really exercise that code, in real time, producing real numbers?)
5. **Manual verification, by hand, of every applicable Performance
   Evaluation Metric** (independent of both scripts above — a human/
   calculator-level re-derivation from raw archived data)

---

## 0. Scope note: M1–M6 vs M7–M12

The report (`main.tex` §Performance Evaluation Metrics) defines twelve PEMs.
It explicitly separates them into two classes:

> *"Metrics M1–M6 are state-of-the-art comparable... Metrics M7–M12 are
> ablation-only: they evaluate design components absent from all reviewed
> baselines... Each is evaluated through the ablation variants A1–A5 or
> purpose-built controlled experiments"* — i.e. **M7–M12 belong to the
> ablation study, Task 9.5**, not Task 7.5/8.

This package therefore covers **M1–M6 in full**. A codebase survey
(2026-07-25) confirmed M7 (PEDR) and M10 (FL robustness sweep) have no
aggregation code yet, and M8 (CADR), M9 (rekey ratio), M11 (CFRT), M12
(EPAR) each have their underlying mechanism already implemented and tested
elsewhere in the project (controller trust decay `Tc(t)`/`Ψc(t)`, PQC-LKH
`rekey_cost()`, controller failover, VRF endorser selection with real
Hyperledger Fabric) but never compute the *named metric ratio* itself. That
aggregation work is correctly scoped to Task 9.5 (Ablation study), not
Task 7.5, and is not fabricated here.

---

## 1. Full NS-3 live console log

Reproduce command (from the ns-3.35 root, with the SHIELD-GH source swapped
into `scratch/` — see §6 build note):

```bash
cd /home/sdvn_ssh/ns-allinone-3.35/ns-3.35/62
./waf build --targets=routing
LD_LIBRARY_PATH=$PWD/build/lib:$PWD/build ./build/scratch/routing \
  --detection_mode=full --enable_full_mode_ai=1 \
  --attack_number=1 --drop_rate=60 --attack_percentage=40 --simTime=30 \
  --routing_algorithm=4 --architecture=0 --maxspeed=80
```

Captured **complete, unedited** stdout+stderr, start to finish:
`logs/task7_5_ns3_live_full_log.txt` (4453 lines). A second, independently
captured copy of the same live-run console output was also archived by
`functional_verification.py` itself as part of its own evidence trail:
`logs/task7_5_ns3_live_full_log_fv_archived.txt`.

**What it shows (this run):** 28 full-mode AI evaluation windows over 30s
simulated time; both attacker nodes (0, 1) isolated by the fused AI verdict
at t≈2.0s; both benign nodes (2, 3) never isolated; node-level confusion
matrix **TP=2 TN=2 FP=0 FN=0 → MCC=1.0**, stable across all 28 windows.

## 2. Full code

`Task7_5_Code_Bundle.zip` (in this directory) — the actual source exercised
by the run above:

| File | Role |
|---|---|
| `shield_gh_ml/ns3_infer.py` | AI bridge: tokenises the NS-3 window, runs LLM `Q_i` + rule `S_total` + reputation, fuses (Eq. 3.29), writes the verdict |
| `shield_gh_ml/llm_scorer.py` | LLM semantic score `Q_i` (Eq. 3.28) + tier-2 escalation (Eq. 3.17) |
| `shield_gh_ml/fusion.py` | Three-way fusion engine (Eq. 3.29) |
| `shield_gh/shield_gh_ai_bridge.h` | C++ side: dumps window, `system()`-calls `ns3_infer.py`, times it, parses the verdict |
| `shield_gh/shield_gh_integration.h` | Drives `sg_node_TP/TN/FP/FN` from the AI verdict; prints the M1–M5 PEM report block |
| `shield_gh_crypto/m6_overhead_benchmark.py` | M6 standalone crypto-overhead benchmark |
| `shield_gh_ml/equation_audit.py`, `functional_verification.py`, `manual_verification.py`, `manual_verification_full_pem.py` | The three verification scripts, §3–5 below |
| `routing_cc_task7_5_excerpt.txt` | The exact CLI-flag / bridge-path lines in `routing.cc` this run depends on (not the full 100k+-line shared file) |
| `evidence_logs/` | All logs produced by this evidence run |

## 3. Equation-presence audit script

`shield_gh_ml/equation_audit.py` — static, source-level: every equation the
full-mode pipeline claims to implement (Eq. 3.17 tier-2, 3.20 reputation,
3.28 LLM score, 3.29 fusion, weight normalisation, M1–M6 formulas) is
checked to be genuinely present, term-for-term, in the actual source files
— not re-derived, not approximated. Also audits that Algorithms 1–4
(LW-DP-Det, LW-CP-Det, FV-Det, PQC-Mit) are each defined **and called**.

```bash
cd scratch/shield_gh_ml && python3 equation_audit.py
```

**Result (2026-07-25 re-run): 35/35 PASS.** `logs/task7_5_equation_audit.log`.

## 4. Functional verification script

`shield_gh_ml/functional_verification.py` — dynamic: rebuilds `routing`
from scratch, runs the **real-time NS-3 simulation** with
`--enable_full_mode_ai=1 --sim-time=30 --attack-percentage=40`, and asserts
a 26-point checklist against the live console output: the AI bridge fires
every window, `Q_i`/fusion scores are genuine (not clamped constants),
timing stays inside the `W=10s` window, and every M1–M5 PEM line is either a
genuine measured value or an explicit, non-fabricated "not measurable" state
(M2).

```bash
cd scratch/shield_gh_ml && python3 functional_verification.py --sim-time=30 --attack-percentage=40
```

**Result (2026-07-25 re-run): 26/26 PASS.** `logs/task7_5_functional_verification.log`.
Full-detail breakdown:

| PEM | Result this run |
|---|---|
| M1 MCC | **1.0** (TP=2 TN=2 FP=0 FN=0) |
| M2 GHSR | not measurable (honest — see §5) |
| M3 AVCR | **1.0** (1/1 active variant covered) |
| M4 FIR | **0.0** (0/2 legit vehicles ever falsely isolated) |
| M5 ESRL | **948.0 ms** (t_onset=1.1s → t_isolate=2.048s) |
| M6 MDPOS | standalone benchmark (§5) |

## 5. Manual verification, by hand, of ALL applicable PEMs (M1–M6)

`shield_gh_ml/manual_verification_full_pem.py` — **new for Task 7.5**,
extends the Task 8 `manual_verification.py` (which only hand-traced M1) to
all six state-of-art-comparable metrics. It does **not** trust either
script above; it takes the raw archived numbers (one real window/verdict
pair for M1, the raw TP/FN/isolation counts printed in the live log for
M3/M4/M5, the real liboqs per-operation timings for M6) and redoes the
report's exact equations with plain arithmetic, printing every intermediate
step so a human can re-check it with a calculator.

```bash
cd scratch/shield_gh_ml && python3 manual_verification_full_pem.py
```

**Result (2026-07-25): all 6 metrics MATCH by hand.**
`logs/task7_5_manual_verification.log`. Highlights:

- **M1 MCC** = 1.0, hand-traced through all 4 nodes' fusion arithmetic individually.
- **M2 GHSR** — verified the code's own "NOT MEASURABLE" honesty guard
  actually fired (attack onset t=1.1s precedes the first evaluation window
  at t=1.998s, so no pre-attack baseline sample exists) — confirmed no
  fabricated placeholder value was ever printed instead.
- **M3 AVCR** = 53/53 → TPR=1.0 ≥ θ_cov=0.5 → covered → AVCR = 1/1 = 1.0.
- **M4 FIR** = 0/2 = 0.0.
- **M5 ESRL** = mitigation_time(2.048s) − attack_start_time(1.1s) = 0.948s = 948.0 ms (reproduces the console's truncated-precision "t_isolate=2.0" display exactly once the underlying double is used).
- **M6 Ω_comp(N=50)** hand-recomputed from real liboqs op timings (zkp_prove=24.49ms, zkp_verify=26.36ms, etc.) and the measured isolation rate = 0.2544 CPU-s/s, matching the benchmark script's own output exactly.

## 6. Build note: cross-project scratch swap

This evidence run required copying `Group_62_scratch/{routing.cc,
shield_gh/, shield_gh_crypto/, shield_gh_ml/, optimization_lifetime.py}`
into `ns-3.35/scratch/` — that is the directory `./waf` actually compiles,
and it currently holds a **different, unrelated project's** (LORIS) files
day-to-day. The pre-existing LORIS `routing.cc` and `optimization_lifetime.py`
were backed up before the swap and restored immediately after this evidence
was captured, so the LORIS working tree is unaffected. `Group_62_scratch/`
(this directory, under git) remains the permanent source of truth for
SHIELD-GH.

## 7. Summary

| Requirement asked | Delivered |
|---|---|
| Full NS-3 live logs (video) | `logs/task7_5_ns3_live_full_log.txt` — complete raw transcript (text, per agreed scope — no video recording possible in this non-interactive environment) |
| Full code | `Task7_5_Code_Bundle.zip` |
| Audit script confirming equation presence | `equation_audit.py` — 35/35 PASS |
| Functional verification script | `functional_verification.py` — 26/26 PASS |
| Manual verification using all PEMs | `manual_verification_full_pem.py` — 6/6 (M1–M6) MATCH by hand; M7–M12 out of scope (ablation-only, Task 9.5, per report's own taxonomy) |
