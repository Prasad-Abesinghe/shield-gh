#!/usr/bin/env python3
"""
dpgha.py — SOA1 Malik et al. DPGHA detection logic (Python port)
================================================================
Faithful Python implementation of the paper's Eq. 13-18, byte-for-byte
equivalent to dpgha_detection.h. Used by the attacker-% sweep harness.

Malik, Khan, Qaisar, Faisal, Mehmood (2023), "An Efficient Approach for
the Detection and Prevention of Gray-Hole Attacks in VANETs", IEEE Access
vol.11, pp.46691-46706. DOI 10.1109/ACCESS.2023.3274650.

Signals per node (as stored in the RSU's Master Routing Table, Table 2):
    dp_received, dp_forwarded   -> PLR  (Eq.13-14), threshold δ = 3%
    rreq_received, rrep_generated -> RRR (Eq.15),    threshold λ = 70%
    mean_dsn                     -> μ(DSN), compared to dynamic β (Eq.16-17)

Decision (Eq.18):
    SmartGHA  if  PLR > δ      and  RRR >= λ
    SeqNoGHA  if  μ(DSN) >= β   and (PLR > δ  or  RRR >= λ)
    Normal    otherwise
"""

from dataclasses import dataclass

DELTA = 3.0    # δ — PLR threshold (%)
LAMBDA = 70.0  # λ — RRR threshold (%)


@dataclass
class NodeSignals:
    dp_received: int = 0
    dp_forwarded: int = 0
    rreq_received: int = 0
    rrep_generated: int = 0
    mean_dsn: float = 0.0
    is_attacker: bool = False
    # Data-leakage fix (2026-08-09, supervisor-flagged): rreq_received=0 (the
    # dataclass default) now means "RRR unavailable" -- see rrr()/classify()
    # below. Previously the real-run sweep (dpgha_sweep_real.py) synthesized
    # rreq_received/rrep_generated/mean_dsn by branching on the ground-truth
    # is_attacker label before this point, which let rrr_gate/dsn_gate
    # trivially separate the classes from the answer key rather than from
    # simulated behaviour. This NS-3 scenario is data-plane-only and has no
    # real RREQ/RREP/DSN control-plane counters (routing.cc:338-342 already
    # documents this), so the honest fix is PLR-only evaluation, not
    # fabricated RRR/DSN.
    rrr_available: bool = True
    dsn_available: bool = True


def plr(s: NodeSignals) -> float:
    """Eq.13-14: data Packet Loss Ratio (%)."""
    if s.dp_received == 0:
        return 0.0
    dpd = max(s.dp_received - s.dp_forwarded, 0)        # Eq.13 (DPD)
    return 100.0 * dpd / s.dp_received                  # Eq.14


def rrr(s: NodeSignals) -> float:
    """Eq.15: RREP_generated / RREQ_received (%). Guard RREQ_R > 0."""
    if s.rreq_received == 0:
        return 0.0
    return 100.0 * s.rrep_generated / s.rreq_received


def compute_beta(nodes) -> float:
    """Eq.17: dynamic β = mean of all nodes' μ(DSN), over nodes with a real
    DSN measurement only (skips dsn_available=False nodes)."""
    have_dsn = [n for n in nodes if n.dsn_available]
    if not have_dsn:
        return 0.0
    return sum(n.mean_dsn for n in have_dsn) / len(have_dsn)


def classify(s: NodeSignals, beta: float, delta=DELTA, lam=LAMBDA) -> str:
    """Eq.18: 'SmartGHA' | 'SeqNoGHA' | 'Normal'.
    When rrr_available AND dsn_available are both True (real RREQ/RREP/DSN
    counters exist), the paper's full Eq.18 conjunction applies exactly as
    specified: SmartGHA needs PLR AND RRR; SeqNoGHA needs DSN AND
    (PLR OR RRR). When this NS-3 scenario has no real RREQ/RREP/DSN
    counters at all (rrr_available=dsn_available=False), the detector
    honestly degrades to the paper's PLR sub-rule alone (Eq.13-14) rather
    than either fabricating RRR/DSN from the ground-truth label (the
    original leak) or silently going blind to every attacker because a
    3-signal AND/OR conjunction can never fire with two gates held
    permanently False (the intermediate regression this replaces)."""
    plr_gate = plr(s) > delta
    if not (s.rrr_available and s.dsn_available):
        return "SmartGHA_PLRonly" if plr_gate else "Normal"
    rrr_gate = rrr(s) >= lam
    dsn_gate = s.mean_dsn >= beta
    if plr_gate and rrr_gate:
        return "SmartGHA"
    if dsn_gate and (plr_gate or rrr_gate):
        return "SeqNoGHA"
    return "Normal"


def detect_all(nodes, delta=DELTA, lam=LAMBDA):
    """Algorithm 1 over all nodes. Returns (verdicts, beta, TP, TN, FP, FN)."""
    beta = compute_beta(nodes)
    verdicts = []
    TP = TN = FP = FN = 0
    for s in nodes:
        v = classify(s, beta, delta, lam)
        verdicts.append(v)
        detected = (v != "Normal")
        if detected and s.is_attacker:
            TP += 1
        elif detected and not s.is_attacker:
            FP += 1
        elif not detected and s.is_attacker:
            FN += 1
        else:
            TN += 1
    return verdicts, beta, TP, TN, FP, FN


# ── Self-check against paper Table 2 when run directly ──────────────────────
if __name__ == "__main__":
    rows = [  # DSN, RREQ_R, RREP_G, DP_R, DP_F, attacker
        (21, 40, 15, 550, 545, False),   # V1
        (25, 60, 25, 920, 910, False),   # V2
        (23, 50, 46, 850, 810, True),    # V3 Smart GHA
        (18, 45, 12, 640, 630, False),   # V4
        (200, 80, 75, 1400, 1370, True), # V5 Seq-No GHA
        (32, 65, 40, 960, 895, False),   # V6
        (60, 41, 25, 1620, 1590, False), # V7
        (17, 39, 19, 210, 205, False),   # V8
    ]
    nodes = [NodeSignals(dp_received=r[3], dp_forwarded=r[4],
                         rreq_received=r[1], rrep_generated=r[2],
                         mean_dsn=r[0], is_attacker=r[5]) for r in rows]
    verdicts, beta, TP, TN, FP, FN = detect_all(nodes)
    print(f"β = {beta} (paper: 49.5)")
    for i, (n, v) in enumerate(zip(nodes, verdicts), 1):
        print(f"  V{i}: PLR={plr(n):.3f}% RRR={rrr(n):.3f}% DSN={n.mean_dsn} -> {v}")
    print(f"TP={TP} TN={TN} FP={FP} FN={FN}")
    assert abs(beta - 49.5) < 1e-9
    assert verdicts[2] == "SmartGHA" and verdicts[4] == "SeqNoGHA"
    assert all(verdicts[i] == "Normal" for i in range(8) if i not in (2, 4))
    print("OK — Python port matches paper Table 2.")
