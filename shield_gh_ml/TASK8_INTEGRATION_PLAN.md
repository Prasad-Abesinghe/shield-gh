# Task 8 — Full-System Integration Plan (NS-3 ⟷ AI/LLM+FL)

**Task 8:** *Full system implementation evidence with correct timing and correct
coding without bypassing modeling — 1 data point of PEMs needed.*

Status: **planning only** — do not build until supervisor confirms Task 6.5.

---

## 1. What "the modeling" is (so we do NOT bypass it)

The full-mode detection pipeline the supervisor wants exercised end-to-end is
Algorithm 3 (FV-Det) in the report:

```
NS-3 forwarding logs  →  (1) tokenise window x_i^(t)        [Eq. 3.28 input]
                      →  (2) LLM scorer Q_i(t)               [Eq. 3.28]
                      →  (3) FL global model (blockchain-verified)  [Eq. 3.25/3.26/3.27]
                      →  (4) fusion ŷ_i = 1[μ1 S_total + μ2 Q_i + μ3(1−R_i) > θ_det]  [Eq. 3.29]
                      →  (5) verdict → DEBSC isolation gate  [Eq. 3.23]
```

"Without bypassing modeling" means: the LLM/FL must consume **real NS-3
forwarding data from the running simulation**, not the synthetic
`dataset.jsonl`. The verdict fed to detection must be the genuine fused output,
not a hardcoded/rule-only shortcut.

## 2. What already exists (integration is CONNECTING, not building)

Grounded in `routing.cc`:

| Piece | Where it already is in routing.cc | Reuse for Task 8 |
|---|---|---|
| Per-node forwarding counters | `node_total_forwarded[]`, `node_total_received[]` (L273, L783) | the raw data the LLM tokenises |
| Per-node PDR per window | `vcbc_window_pdr[n]` computed each window (L777–787) | the forwarding-log signal |
| Per-(node,flow) counters (S3) | L282 | per-source tokens for DP-TS |
| **NS-3 → Python bridge** | `system("...python3 ...")` — Gurobi, 4+ sites (L117766…) | **same pattern** to call the AI scorer |
| Detection metrics (the PEM) | `print_shield_gh_detection_metrics()` MCC/FPR from `sg_node_TP/TN/FP/FN` (L117149) | the M1 (MCC) PEM producer |
| shield_gh detection hooks | `shield_gh/shield_gh_integration.h` (L56) | where the AI verdict plugs in |

So the bridge pattern (C++ `system()` → Python → read result file) is **already
proven in your own code** (Gurobi). We copy it for the AI.

## 3. The bridge design (file-based, matches the Gurobi pattern)

**Per detection window (or once at t=10 s), inside routing.cc:**

1. **NS-3 writes** the current per-node forwarding window to a file, e.g.
   `/tmp/shieldgh_window.jsonl` — one line per vehicle:
   `{"node": n, "fwd": node_total_forwarded[n], "rcv": node_total_received[n],
     "per_slot": [...], "per_src": {...}, "speed": s_n}`
   (all values already in memory).

2. **NS-3 calls** the AI scorer via `system()`:
   `/home/sdvn_ssh/.pyenv/.../python3 shield_gh_ml/ns3_infer.py
      --in /tmp/shieldgh_window.jsonl --out /tmp/shieldgh_verdict.json`
   (fallback scorer = fast, CPU, no GPU crash risk — genuine Qwen optional flag).

3. **`ns3_infer.py`** (new, thin wrapper around existing `llm_scorer.py` +
   `fusion.py`): tokenise each node's window → Q_i → fuse with S_total (rule
   result NS-3 already has) and reputation → write verdict per node to
   `/tmp/shieldgh_verdict.json`: `{"node": n, "y_hat": 0/1, "q_i": ...}`.

4. **NS-3 reads** the verdict, feeds ŷ into the existing DEBSC/isolation path,
   and updates `sg_node_TP/TN/FP/FN` (compare ŷ vs ground-truth attacker) →
   `print_shield_gh_detection_metrics()` prints the **MCC PEM**.

No modeling is bypassed: real sim data in, genuine fusion verdict out, real
metric measured.

## 4. "1 data point of PEMs" — concretely

**PEM = one Performance Evaluation Metric value, measured from the integrated
run.** The cleanest single data point:

- **M1 (MCC)** at the default operating point: N vehicles, one grey-hole
  attacker (S1 or S2), `t = 10 s`, full-mode detection ON.
- Output: one line — `M1b MCC: <value>` from `print_shield_gh_detection_metrics()`
  — produced by the **integrated** NS-3+AI run (not standalone Python).

That is the "1 data point" evidence: the AI verdict drove the NS-3 detection
metric end-to-end.

## 5. "Correct timing"

- Record wall-clock time of the AI `system()` call (C++ `chrono` around the
  call), so we can report the **per-window inference latency inside the sim**
  and show it fits the window (`W = 10 s`).
- The two-tier design means the edge (fallback / small) path is used in the loop;
  genuine Qwen latency (18 ms measured) is already reported separately.
- Print: `[SHIELD-GH] full-mode AI inference: <ms> ms for <k> nodes at t=<t>s`.

## 6. Build steps (once approved)

1. `ns3_infer.py` — thin CLI wrapping `llm_scorer.py` + `fusion.py` (read
   window jsonl → write verdict json). ~40 lines, reuses tested code.
2. In `routing.cc`: add `dump_shieldgh_window()` (writes the jsonl) + a
   `system()` call to `ns3_infer.py` + `read_shieldgh_verdict()` that sets the
   detection verdict, guarded by a `--enable_full_mode_ai=1` CLI flag (off by
   default so existing runs are unaffected).
3. Wire verdict → existing `sg_node_TP/TN/FP/FN` update.
4. Time the call (chrono).
5. Run once at `t=10 s`, capture the console: MCC + latency = the Task 8 evidence.

## 7. Risks / honesty

- **GPU:** run the live loop on the **fallback scorer** (CPU, no crash); report
  genuine-Qwen numbers separately (already have MCC 0.81). Live genuine-Qwen per
  window is possible but risks the Blackwell CUDA crash mid-sim.
- **Topology:** the NS-3 prototype is a small fixed 5-node config (see memory);
  1 PEM point is achievable there; full 264-node Galle run is later (Task 10).
- Effort: ~2–3 focused days; the bridge is the proven Gurobi pattern.

## 8. Open questions for the supervisor (ask before/at start)

1. Is the **fallback scorer acceptable for the live loop** (with genuine Qwen
   numbers reported separately), or must genuine Qwen run inside the sim?
2. Which **single PEM** does he want for the 1 data point — **M1 (MCC)** (my
   default), or M4 (FIR) / M5 (latency)?
3. `t = 10 s` run on the current 5-node prototype acceptable for the "1 point",
   with the full Galle run deferred to Task 10?
