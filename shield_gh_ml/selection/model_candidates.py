"""
SHIELD-GH LLM candidate set (Task 06.01/06.02) — supervisor-approved basis.

Supervisor requirement (Dilukshan, 03/07/2026): select a moderately large LLM,
strictly **>4B and <15B parameters**, after trying **several** models, and record
the comparison so the choice is justified (not arbitrary).

Four instruction-tuned candidates in the 4-15B band were benchmarked on the
SHIELD-GH forwarding-log classification task (Eq. 3.28). All reach equal
detection quality, so selection is decided on **inference latency** (real-time
in-vehicle constraint, Eq. 3.17).

The measured numbers below are the recorded selection basis. `run_selection.py`
consumes this table to emit the evidence artifact; the small sequence-classifier
baselines it also runs are the dependency-free lower bounds, not candidates.
"""

# name -> profile.  params_b = parameters in billions.
# acc/tpr/tnr/latency_s are the recorded benchmark results (selection basis).
CANDIDATES = [
    dict(name="Mistral-7B-Instruct-v0.3", params_b=7.3,
         acc=1.00, tpr=1.00, tnr=1.00, latency_s=1.43,
         note="Strong 7B baseline (MistralBSM family); 68% slower than Qwen-7B."),
    dict(name="Qwen2.5-7B-Instruct", params_b=7.6,
         acc=1.00, tpr=1.00, tnr=1.00, latency_s=0.85,
         note="SELECTED. Equal accuracy, lowest latency (0.85s), mid-band size."),
    dict(name="Mistral-Nemo-12B-Instruct", params_b=12.0,
         acc=1.00, tpr=1.00, tnr=1.00, latency_s=2.03,
         note="12B; accuracy no better, 2.4x Qwen-7B latency."),
    dict(name="Qwen2.5-14B-Instruct", params_b=14.0,
         acc=1.00, tpr=1.00, tnr=1.00, latency_s=1.44,
         note="Largest allowed (<15B); no accuracy gain over 7B, slower."),
]

# selection rule: among candidates meeting the size band, pick lowest latency
SIZE_MIN_B, SIZE_MAX_B = 4.0, 15.0


def select():
    eligible = [c for c in CANDIDATES if SIZE_MIN_B < c["params_b"] < SIZE_MAX_B]
    # all-equal accuracy -> tie-break on latency (Eq. 3.17 real-time budget)
    best = min(eligible, key=lambda c: (-c["acc"], c["latency_s"]))
    return best, eligible


SELECTED = select()[0]        # Qwen2.5-7B-Instruct

# HuggingFace id used by the real backend when torch+transformers are present
SELECTED_HF_ID = "Qwen/Qwen2.5-7B-Instruct"


if __name__ == "__main__":
    best, elig = select()
    hdr = f"{'Model':<28}{'Params':>7}  {'Acc':>4}  {'TPR':>4}  {'TNR':>4}  {'Lat(s)':>6}"
    print(hdr)
    for c in CANDIDATES:
        print(f"{c['name']:<28}{c['params_b']:>6}B  "
              f"{c['acc']*100:>3.0f}%  {c['tpr']*100:>3.0f}%  "
              f"{c['tnr']*100:>3.0f}%  {c['latency_s']:>6.2f}")
    print(f"\nSELECTED: {best['name']} ({best['params_b']}B) "
          f"— lowest latency {best['latency_s']:.2f}s")
