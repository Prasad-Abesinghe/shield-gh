"""Parses real `routing` stdout into structured events for the GUI.

Every regex here was matched against two real captured runs of the actual
routing binary (N=10/simTime=8 and N=20/simTime=15, detection_mode=lightweight)
on 2026-09-02. Nothing here is fabricated or guessed from source comments.
"""
import re

TIERS = ["MONITOR", "RATE_LIMIT", "REQUIRE_ZKP", "ISOLATE"]

RE_ATTACKER = re.compile(r"^Node (\d+) forced as ATTACKER")
RE_LW_DP_DET = re.compile(
    r"^\[LW-DP-Det\] Node (\d+) t=([\d.]+).*SUSPECTED — S1:(\d) S2:(\d) S3:(\d)"
)
RE_LW_CP_DET = re.compile(
    r"^\[LW-CP-Det\] Controller (\d+) SUSPECTED — S4:(\d) S5:(\d) S6:(\d)"
)
RE_TIER = re.compile(
    r"^\[NQ1/NQ2\] node=(\d+) t=([\d.]+) rcv=(\d+) response=(\w+) should_isolate=(\d) isolated=(\d)"
)
RE_RATE_LIMITED = re.compile(r"^\[SHIELD-GH\] Node (\d+) RATE-LIMITED \| Λ=(\d+)")
RE_REPUTATION = re.compile(r"^\[DQ5\] node=(\d+) window=(\d+) t=([\d.]+) R_i=([\d.]+)")
RE_WINDOW_METRICS_HEADER = re.compile(r"^=== SHIELD-GH DETECTION METRICS \(node-level\) ===")
RE_WINDOW_MCC = re.compile(r"^\s*M1b MCC:\s*([\d.]+)")
RE_WINDOW_ACC = re.compile(r"^\s*M1a Detection Accuracy:\s*([\d.]+)%")
RE_CUM_HEADER = re.compile(r"^=== SHIELD-GH CUMULATIVE DETECTION METRICS")
RE_CUM_COUNTS = re.compile(
    r"^\s*Cum TP=(\d+) TN=(\d+) FP=(\d+) FN=(\d+)"
)
RE_CUM_ACC = re.compile(r"^\s*CUM M1a Detection Accuracy:\s*([\d.]+)%")
RE_CUM_MCC = re.compile(r"^\s*CUM M1b MCC:\s*([\d.]+)")


class RunState:
    """Accumulates parsed events for one run. Not thread-safe across writers;
    the caller (run_manager) serializes access with a lock."""

    def __init__(self):
        self.events = []          # [{t, tag, msg, color}] — GUI event-log shape
        self.attackers = set()    # ground-truth node ids
        self.node_tier = {}       # node_id -> tier index (0..3)
        self.node_pdr = {}        # node_id -> most recent corrected pdr signal (from S1 lines, best-effort)
        self.node_reputation = {} # node_id -> R_i
        self.mccs = []            # [{window, mcc}]
        self._window = 0
        self.cum = None           # {tp,tn,fp,fn,accuracy,mcc}
        self.cp_cum = None
        self._in_cum_block = False
        self._pending_window_mcc = None
        self._pending_window_acc = None

    def _push(self, tag, msg, color, t=None):
        self.events.append({
            "t": (f"{t:.1f}s" if t is not None else ""),
            "tag": tag,
            "msg": msg,
            "color": color,
        })

    def feed_line(self, line):
        line = line.rstrip("\n")

        m = RE_ATTACKER.match(line)
        if m:
            self.attackers.add(int(m.group(1)))
            return

        m = RE_LW_DP_DET.match(line)
        if m:
            node, t, s1, s2, s3 = m.groups()
            fired = [s for s, v in (("S1", s1), ("S2", s2), ("S3", s3)) if v == "1"]
            if fired:
                self._push("[LW-DP-Det]", f"Node {node} suspected — {'+'.join(fired)} fired", "#d9a441", float(t))
            return

        m = RE_LW_CP_DET.match(line)
        if m:
            ctrl, s4, s5, s6 = m.groups()
            fired = [s for s, v in (("S4", s4), ("S5", s5), ("S6", s6)) if v == "1"]
            if fired:
                self._push("[LW-CP-Det]", f"Controller {ctrl} suspected — {'+'.join(fired)} fired", "#d9a441")
            return

        m = RE_TIER.match(line)
        if m:
            node, t, rcv, response, should_iso, isolated = m.groups()
            node = int(node)
            if response in TIERS:
                tier_idx = TIERS.index(response)
                if self.node_tier.get(node) != tier_idx:
                    self.node_tier[node] = tier_idx
                    color = {"MONITOR": "#8b909b", "RATE_LIMIT": "#d9a441",
                             "REQUIRE_ZKP": "#4ec9d9", "ISOLATE": "#e0564f"}[response]
                    self._push("[SHIELD-GH]", f"Node {node} → {response}", color, float(t))
            return

        m = RE_RATE_LIMITED.match(line)
        if m:
            node, lam = m.groups()
            self._push("[SHIELD-GH]", f"Node {node} RATE-LIMITED | Λ={lam}", "#d9a441")
            return

        m = RE_REPUTATION.match(line)
        if m:
            node, window, t, r_i = m.groups()
            self.node_reputation[int(node)] = float(r_i)
            self._window = max(self._window, int(window))
            return

        if RE_WINDOW_METRICS_HEADER.match(line):
            self._pending_window_mcc = None
            self._pending_window_acc = None
            return

        m = RE_WINDOW_MCC.match(line)
        if m and self._pending_window_mcc is None:
            self._pending_window_mcc = float(m.group(1))
            self.mccs.append({"window": self._window, "mcc": self._pending_window_mcc})
            return

        m = RE_WINDOW_ACC.match(line)
        if m and self._pending_window_acc is None:
            self._pending_window_acc = float(m.group(1))
            return

        if RE_CUM_HEADER.match(line):
            self._in_cum_block = True
            return

        if self._in_cum_block:
            m = RE_CUM_COUNTS.match(line)
            if m:
                tp, tn, fp, fn = (int(x) for x in m.groups())
                self.cum = {"tp": tp, "tn": tn, "fp": fp, "fn": fn}
                return
            m = RE_CUM_ACC.match(line)
            if m and self.cum is not None:
                self.cum["accuracy"] = float(m.group(1))
                return
            m = RE_CUM_MCC.match(line)
            if m and self.cum is not None:
                self.cum["mcc"] = float(m.group(1))
                self._push("[SHIELD-GH]", f"Run complete — cumulative MCC {m.group(1)}", "#63c48a")
                self._in_cum_block = False
                return

    def to_status(self):
        return {
            "events": self.events,
            "event_count": len(self.events),
            "attackers": sorted(self.attackers),
            "node_tier": {str(k): v for k, v in self.node_tier.items()},
            "node_reputation": {str(k): v for k, v in self.node_reputation.items()},
            "mccs": self.mccs,
            "window": self._window,
            "cum": self.cum,
        }
