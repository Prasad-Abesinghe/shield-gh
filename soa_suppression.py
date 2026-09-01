#!/usr/bin/env python3
"""
soa_suppression.py — shared controller-suppression model for SOA1/SOA2/SOA3
===========================================================================

Models the second capability of a compromised SDN controller that the
supervisor described (2026-08-09):

  > "A compromised controller can report falsified OpenFlow counters showing
  > normal forwarding rates while the actual switching hardware enforces the
  > malicious DROP rules. The detection system receives clean-looking
  > statistics from a corrupt source... So the SOA will tell a node as an
  > attacker, but the controller will reject it when it is malicious."

i.e. a detector computes a CORRECT verdict, and the compromised controller
that mediates its evidence/reporting path prevents that verdict from becoming
an actionable result. A suppressed true positive is therefore counted as a
false negative. FP/TN are unaffected: the controller shields real attackers,
it does not fabricate accusations against benign nodes.

WHY PROBABILISTIC RATHER THAN ABSOLUTE (2026-08-11)
---------------------------------------------------
The first implementation suppressed EVERY true positive (p = 1.0). That is
arithmetically correct but models the controller as a perfect, 100%-reliable
censor, which is stronger than the threat description above and has three
undesirable consequences:

  1. It pins every controller-mediated baseline to exactly MCC = 0.00, which
     is indistinguishable from a detector that guesses at random -- even
     though these detectors are in fact scoring a RAW MCC of +1.00 and are
     simply being overruled. A reviewer reasonably reads 0.00 as "the
     baseline is broken", which is the wrong conclusion.
  2. Real controller compromise as described (falsified counters,
     SUB-THRESHOLD rule injection, deceiving voting/reputation systems) is a
     degradation of the evidence channel, not a guaranteed deletion of every
     finding. Some evidence leaks through: a detector may catch an attacker
     in a window where the falsified counters were inconsistent, or via a
     residual signal the controller did not fully mask.
  3. It removes all seed-to-seed variation from the suppression itself, so
     repeated runs cannot show a spread.

SUPPRESSION_PROB is therefore < 1.0: the controller hides MOST detections,
not all. This is a modelling parameter, not a measured quantity, and must be
reported as such (see DEFAULT_SUPPRESSION_PROB's justification below).

DETERMINISM
-----------
Suppression is seeded from (rng_run, node index) so a given --rng_run
reproduces exactly the same suppression pattern across re-runs and across all
three baselines. Varying --rng_run varies the pattern, so a multi-seed sweep
reports genuine spread rather than one arbitrary fixed sample.

REPORTING CONTRACT
------------------
Callers must report the RAW (pre-suppression) confusion matrix alongside the
suppressed one. The raw score is what the baseline's detection logic actually
achieved; the suppressed score is the actionable outcome under a compromised
controller. Reporting only the latter loses the distinction between "detected
correctly but overruled" and "failed to detect".
"""

import hashlib

# Probability that a compromised controller successfully suppresses any one
# correct detection, GIVEN that the node in question is served by a malicious
# controller.
#
# REVERTED TO 1.0 (2026-08-12, supervisor-directed). An intermediate value
# (0.75) was briefly used to avoid a uniform MCC=0.00 across all baselines.
# That was treating a symptom: the real cause was that the simulation modelled
# only ONE controller and forced it malicious every run, so EVERY node was
# always under a compromised controller and every detection was always
# suppressed.
#
# The supervisor's correction: "you are just simulating one controller, which
# is against the paper's attack model. Have 4 controllers in the network...
# Each node is assigned to exactly one controller. So, SOTA baselines will
# detect grey hole attacks under benign controllers, while it will get 0.0 MCC
# for under malicious controller."
#
# With the multi-controller model implemented (routing.cc
# declare_attackers_controller(), N_Controllers=M), a node under a malicious
# controller has its detection suppressed with certainty -- which is the
# correct semantics, since that controller fully mediates its evidence path.
# The intermediate network-wide MCC now emerges from the MIX of benign and
# malicious controller domains, i.e. from the attack model itself, rather than
# from a tuned probability. p=1.0 is therefore both correct and no longer
# produces a degenerate all-zero result.
#
# The probabilistic path is retained (set prob<1.0) only for sensitivity
# analysis; it is not used in the reported results.
DEFAULT_SUPPRESSION_PROB = 1.0


def is_suppressed(node_index, rng_run=1, prob=DEFAULT_SUPPRESSION_PROB,
                  salt="soa"):
    """Return True if this node's correct detection is suppressed.

    Deterministic in (salt, rng_run, node_index): the same arguments always
    give the same answer, so results are reproducible. `salt` lets the three
    baselines draw independent suppression patterns from the same rng_run
    (passing the same salt would make them suppress identically, which would
    understate independent variation between methods).
    """
    if prob >= 1.0:
        return True
    if prob <= 0.0:
        return False
    key = f"{salt}|{rng_run}|{node_index}".encode()
    # Uniform in [0,1) from a stable hash -- avoids depending on any global
    # RNG state that callers might reseed.
    draw = int(hashlib.sha256(key).hexdigest()[:8], 16) / 0xFFFFFFFF
    return draw < prob


def apply_suppression(per_node, rng_run=1, prob=DEFAULT_SUPPRESSION_PROB,
                      salt="soa"):
    """Apply the suppression gate to a list of (node_index, detected, is_attacker).

    Returns (raw, suppressed) confusion-matrix dicts, each with TP/TN/FP/FN.
    A suppressed true positive becomes a false negative; FP/TN are untouched.
    """
    raw = dict(TP=0, TN=0, FP=0, FN=0)
    sup = dict(TP=0, TN=0, FP=0, FN=0)
    for idx, detected, is_attacker in per_node:
        # Raw: what the detector actually concluded.
        if detected and is_attacker:
            raw["TP"] += 1
        elif detected and not is_attacker:
            raw["FP"] += 1
        elif not detected and is_attacker:
            raw["FN"] += 1
        else:
            raw["TN"] += 1

        # Suppressed: correct detections may never become actionable.
        eff = detected
        if detected and is_attacker and is_suppressed(idx, rng_run, prob, salt):
            eff = False
        if eff and is_attacker:
            sup["TP"] += 1
        elif eff and not is_attacker:
            sup["FP"] += 1
        elif not eff and is_attacker:
            sup["FN"] += 1
        else:
            sup["TN"] += 1
    return raw, sup
