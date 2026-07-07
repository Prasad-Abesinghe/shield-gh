"""
SHIELD-GH forwarding-log dataset generator (Task 06.01 / §3.9).

Produces the *exact* input the full-mode LLM/FL pipeline consumes: tokenised
blockchain forwarding-log windows x_i^(t) of length W (Eq. 3.28), labelled with
the ground-truth class of the vehicle that produced them.

The generator implements the three §3.9.1 data families:
  * Selective dropping  -> S1 (DP-FR) fixed-rate + S4 (CP-FR)
  * Temporal discrepancy -> S2 (DP-IT) intermittent + S5 (CP-IT)
  * Semantic / targeted  -> S3 (DP-TS) target-specific + S6 (CP-TS)
plus a BENIGN class that includes mobility-/handoff-induced loss (the false
positive trap the whole framework is built to survive).

A "token" is one per-slot forwarding record rendered as text, matching the
"Blockchain Log Tokenizer -> tokenised forwarding sequences" block of Fig 3.10.
This keeps the dataset backend-agnostic: a real BERT tokenizer, a TF-IDF
vectoriser, or a small custom transformer can all consume the same strings.

Deterministic (seeded) so the selection benchmark is fully reproducible.
"""
from __future__ import annotations
import argparse
import json
import random
from dataclasses import dataclass, asdict
from pathlib import Path

# ---- report-aligned parameters (Table 3.3 / §3.11.4) ----
W = 10                 # observation window, slots (Table 3.3: W = 10)
RHO_HANDOFF = 0.30     # rho_max handoff loss (Table 3.3)
RHO_ATTACK = 0.40      # rho_a default attacker drop (Table 3.3 sweep 20-80%)
CLASSES = ["BENIGN", "DP-FR", "DP-IT", "DP-TS", "CP-FR", "CP-IT", "CP-TS"]
LABEL2ID = {c: i for i, c in enumerate(CLASSES)}

# vocabulary of forwarding-log tokens (what the tokenizer emits per slot)
# FWD = forwarded, DRP = dropped, HOF = handoff slot (topologically-expected loss)
# each slot also carries a coarse per-source tag to expose target-specific drops
SRC_TAGS = ["s0", "s1", "s2", "s3"]   # source vehicle bucket for the packet batch


@dataclass
class Sample:
    text: str          # tokenised forwarding-log window (space-separated tokens)
    label: int
    label_name: str
    pdr: float         # window PDR (for cross-checking the rule-based detector)
    speed_kmh: float   # vehicle speed (drives MATD / handoff frequency)


def _slot(action: str, src: str) -> str:
    return f"{action}:{src}"


def _window_tokens(drop_prob, rng, *, handoff_slots=0, target_src=None,
                   intermittent=False):
    """Render one W-slot forwarding window as tokens."""
    toks = []
    duty = rng.random() < 0.5  # for intermittent: current on/off phase
    for i in range(W):
        src = rng.choice(SRC_TAGS)
        is_handoff = i < handoff_slots
        if is_handoff:
            # handoff slot: loss is topologically expected, tagged HOF
            action = "HOF" if rng.random() < RHO_HANDOFF else "FWD"
            toks.append(_slot(action, src))
            continue
        p = drop_prob
        if intermittent:
            if i % max(1, W // 4) == 0:
                duty = not duty          # flip on/off phase -> periodic pattern
            p = drop_prob if duty else 0.0
        if target_src is not None:
            # target-specific: only drop the targeted source, forward the rest
            p = drop_prob if src == target_src else 0.0
        action = "DRP" if rng.random() < p else "FWD"
        toks.append(_slot(action, src))
    fwd = sum(1 for t in toks if t.startswith("FWD"))
    non_handoff = sum(1 for t in toks if not t.startswith("HOF"))
    pdr = fwd / non_handoff if non_handoff else 1.0
    return toks, pdr


def make_sample(label_name, rng) -> Sample:
    # speed drives handoff frequency (faster -> more handoff slots -> more benign loss)
    speed = rng.uniform(20, 120)
    handoff_slots = int(round((speed / 120.0) * 3))  # 0..3 handoff slots

    if label_name == "BENIGN":
        toks, pdr = _window_tokens(0.02, rng, handoff_slots=handoff_slots)
    elif label_name in ("DP-FR", "CP-FR"):
        toks, pdr = _window_tokens(RHO_ATTACK, rng, handoff_slots=handoff_slots)
    elif label_name in ("DP-IT", "CP-IT"):
        toks, pdr = _window_tokens(RHO_ATTACK, rng, handoff_slots=handoff_slots,
                                   intermittent=True)
    elif label_name in ("DP-TS", "CP-TS"):
        tgt = rng.choice(SRC_TAGS)
        toks, pdr = _window_tokens(0.85, rng, handoff_slots=handoff_slots,
                                   target_src=tgt)
    else:
        raise ValueError(label_name)

    # controller-plane variants prepend a flow-rule descriptor token (S4-S6 look
    # at installed rules, not just PDR) -> gives the LLM a distinguishing signal
    if label_name.startswith("CP-"):
        rule = {"CP-FR": "RULE:drop_all", "CP-IT": "RULE:drop_intermittent",
                "CP-TS": "RULE:drop_match_src"}[label_name]
        toks = [rule] + toks

    return Sample(text=" ".join(toks), label=LABEL2ID[label_name],
                  label_name=label_name, pdr=round(pdr, 4),
                  speed_kmh=round(speed, 1))


def generate(n_per_class: int, seed: int):
    rng = random.Random(seed)
    samples = []
    for c in CLASSES:
        for _ in range(n_per_class):
            samples.append(make_sample(c, rng))
    rng.shuffle(samples)
    return samples


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n_per_class", type=int, default=400)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=str(Path(__file__).parent / "dataset.jsonl"))
    args = ap.parse_args()

    samples = generate(args.n_per_class, args.seed)
    with open(args.out, "w") as f:
        for s in samples:
            f.write(json.dumps(asdict(s)) + "\n")
    print(f"[gen_dataset] wrote {len(samples)} samples "
          f"({len(CLASSES)} classes x {args.n_per_class}) -> {args.out}")
    # tiny sanity print
    for s in samples[:3]:
        print("  ", s.label_name, "| pdr", s.pdr, "|", s.text[:60], "...")


if __name__ == "__main__":
    main()
