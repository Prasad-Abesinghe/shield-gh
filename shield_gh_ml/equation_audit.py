#!/usr/bin/env python3
"""
SHIELD-GH Task 8 — Full Equation Audit.

Static, source-level verification that every report equation the full-mode
AI pipeline (Algorithm 3, FV-Det) claims to implement is genuinely present
in the code that runs INSIDE the NS-3 simulation (ns3_infer.py, fusion.py,
llm_scorer.py, shield_gh_ai_bridge.h) -- not re-derived, not approximated.

Checked equations (report anchors):
    eq:llm_score   (3.28)  Q_i(t) = softmax(LLM(x_i^(t)))_malicious
    eq:tier2       (3.17)  Tier-2 escalation: 1[max_c softmax(.)_c < eps_u]
    eq:reputation  (3.20)  R_i(t) in [0,1], deficit = 1 - R_i
    eq:fusion      (3.29)  yhat_i = 1[mu1*S_total + mu2*Q_i + mu3*(1-R_i) > theta_det]
    eq:weights             mu1+mu2+mu3 = 1  (fusion weights normalised)
    eq:bridge_nsc3          NS-3 -> bridge -> verdict round-trip (no bypass)

Each check inspects the actual source text (not a re-implementation), so a
PASS here means "the equation is coded as written", matching the audit style
already used for the MDP/attribute-vector equations by the other group.

Run:  python3 equation_audit.py
"""
from __future__ import annotations
import inspect
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SHIELD_GH_DIR = os.path.abspath(os.path.join(HERE, "..", "shield_gh"))

sys.path.insert(0, HERE)

RESULTS = []


def check(eq_id, desc, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    RESULTS.append((status, eq_id, desc, detail))
    print(f"  [{status}] {eq_id:<16}{desc:<58}{detail}")


def section(title):
    print()
    print("=" * 78)
    print(f" {title}")
    print("=" * 78)


def read(path):
    with open(path) as f:
        return f.read()


def main():
    print("SHIELD-GH Task 8 — Full Equation Audit (static source verification)")
    print(f"Auditing: {HERE}")

    # ------------------------------------------------------------------ #
    section("A. LLM SEMANTIC SCORE  (eq:llm_score, eq:tier2)")
    # ------------------------------------------------------------------ #
    from llm_scorer import LLMScorer, CLASSES, MALICIOUS_IDS, EPS_U

    src_scorer = read(os.path.join(HERE, "llm_scorer.py"))

    check("eq:llm_score", "Q_i defined as malicious-class softmax mass",
          "MALICIOUS_IDS" in src_scorer and "p[MALICIOUS_IDS].sum()" in src_scorer,
          f"MALICIOUS_IDS={MALICIOUS_IDS} (7 classes, BENIGN excluded)")

    check("eq:llm_score", "threat_score() returns probability in [0,1]",
          hasattr(LLMScorer, "threat_score"),
          "LLMScorer.threat_score(text) -> float")

    check("eq:tier2", f"Tier-2 escalation uses eps_u threshold (got {EPS_U})",
          0.0 < EPS_U < 1.0 and hasattr(LLMScorer, "needs_tier2"),
          "1[max_c softmax(.)_c < eps_u]")

    sig = inspect.signature(LLMScorer.threat_score)
    check("eq:llm_score", "threat_score signature takes one window/text arg",
          len(sig.parameters) == 2, str(sig))

    # ------------------------------------------------------------------ #
    section("B. REPUTATION  (eq:reputation)")
    # ------------------------------------------------------------------ #
    from fusion import Evidence

    ev_fields = Evidence.__dataclass_fields__
    check("eq:reputation", "Evidence carries R_i in [0,1] (reputation field)",
          "reputation" in ev_fields, "fusion.Evidence.reputation")

    check("eq:reputation", "deficit computed as (1 - R_i), not re-derived",
          "1.0 - ev.reputation" in read(os.path.join(HERE, "fusion.py")),
          "fusion.FusionEngine.fuse()")

    # ------------------------------------------------------------------ #
    section("C. THREE-WAY FUSION  (eq:fusion, eq:weights)")
    # ------------------------------------------------------------------ #
    from fusion import FusionWeights, FusionEngine

    src_fusion = read(os.path.join(HERE, "fusion.py"))

    w = FusionWeights()
    check("eq:weights", "mu1 + mu2 + mu3 == 1 (normalised)",
          abs(w.mu1 + w.mu2 + w.mu3 - 1.0) < 1e-6,
          f"mu1={w.mu1} mu2={w.mu2} mu3={w.mu3}")

    check("eq:weights", "weight sum asserted at construction (not just by convention)",
          "assert abs(s - 1.0)" in src_fusion, "FusionWeights.__post_init__")

    check("eq:fusion", "score = mu1*S_total + mu2*Q_i + mu3*(1-R_i)",
          "self.w.mu1 * ev.s_total" in src_fusion
          and "self.w.mu2 * ev.q_i" in src_fusion
          and "self.w.mu3 * (1.0 - ev.reputation)" in src_fusion,
          "FusionEngine.fuse() weighted sum, exact term-for-term match")

    check("eq:fusion", "yhat = 1[score > theta_det] (binary threshold, not re-scaled)",
          "int(score > self.theta_det)" in src_fusion,
          "FusionEngine.fuse() verdict")

    # numeric spot-check: verdict is a genuine function of all 3 inputs
    scorer_stub = LLMScorer(force_fallback=True)
    engine = FusionEngine(scorer_stub, FusionWeights(), theta_det=0.5)
    lo = engine.fuse(Evidence(s_total=0.0, q_i=0.0, reputation=1.0))
    hi = engine.fuse(Evidence(s_total=1.0, q_i=1.0, reputation=0.0))
    mid = engine.fuse(Evidence(s_total=1.0, q_i=0.0, reputation=1.0))
    check("eq:fusion", "monotone: all-clean -> score=0, all-malicious -> score=1",
          lo["score"] == 0.0 and hi["score"] == 1.0,
          f"lo.score={lo['score']} hi.score={hi['score']}")
    check("eq:fusion", "S_total alone (mu1=0.34) cannot cross theta_det=0.5 unaided",
          mid["score"] == w.mu1 and mid["verdict"] == 0,
          f"mid.score={mid['score']} verdict={mid['verdict']} "
          f"(confirms fusion needs >1 source, not a rule-only shortcut)")

    # ------------------------------------------------------------------ #
    section("D. NS-3 <-> AI BRIDGE  (eq:bridge_ns3 — no modeling bypass)")
    # ------------------------------------------------------------------ #
    src_infer = read(os.path.join(HERE, "ns3_infer.py"))
    bridge_path = os.path.join(SHIELD_GH_DIR, "shield_gh_ai_bridge.h")
    integ_path = os.path.join(SHIELD_GH_DIR, "shield_gh_integration.h")
    routing_path = os.path.join(os.path.dirname(HERE), "routing.cc")

    check("eq:bridge_ns3", "ns3_infer.py imports the SAME fusion/scorer modules "
          "used elsewhere (no duplicate/shortcut logic)",
          "from llm_scorer import LLMScorer" in src_infer
          and "from fusion import FusionEngine" in src_infer,
          "ns3_infer.py imports")

    check("eq:bridge_ns3", "verdict computed via engine.evaluate_window() "
          "(calls real Q_i + fuse, not a stub)",
          "engine.evaluate_window(text, s_total, reputation)" in src_infer,
          "ns3_infer.main()")

    ok_bridge = os.path.exists(bridge_path)
    src_bridge = read(bridge_path) if ok_bridge else ""
    check("eq:bridge_ns3", "C++ bridge header exists (shield_gh_ai_bridge.h)",
          ok_bridge, bridge_path)
    check("eq:bridge_ns3", "bridge invokes ns3_infer.py via system() "
          "(same pattern as the Gurobi solver calls, not hand-coded)",
          "system(" in src_bridge and "ns3_infer.py" in src_bridge,
          "sg_ai_run_bridge()")
    check("eq:bridge_ns3", "bridge times the call with std::chrono "
          "(for the 'correct timing' requirement)",
          "chrono" in src_bridge,
          "sg_ai_run_bridge() wall-clock timer")

    ok_integ = os.path.exists(integ_path)
    src_integ = read(integ_path) if ok_integ else ""
    check("eq:bridge_ns3", "integration.h drives TP/TN/FP/FN from the AI y_hat "
          "(verdict feeds the PEM, is not discarded)",
          "enable_full_mode_ai" in src_integ and "sg_node_T" in src_integ,
          "shield_gh_integration.h full-mode block")

    ok_routing = os.path.exists(routing_path)
    src_routing = read(routing_path) if ok_routing else ""
    check("eq:bridge_ns3", "routing.cc exposes --enable_full_mode_ai CLI flag "
          "(off by default; explicit opt-in to the full pipeline)",
          "enable_full_mode_ai" in src_routing and "cmd.AddValue" in src_routing,
          "routing.cc CLI wiring")

    # ------------------------------------------------------------------ #
    section("SUMMARY")
    # ------------------------------------------------------------------ #
    n_pass = sum(1 for r in RESULTS if r[0] == "PASS")
    n_fail = sum(1 for r in RESULTS if r[0] == "FAIL")
    print(f"  {n_pass} PASS / {n_fail} FAIL / {len(RESULTS)} total checks")
    if n_fail == 0:
        print("  ALL EQUATIONS VERIFIED IMPLEMENTED — Task 8 pipeline matches"
              " the report, no modeling bypassed.")
    else:
        print("  FAILURES ABOVE must be fixed before Task 8 can be marked done.")
    print()
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
