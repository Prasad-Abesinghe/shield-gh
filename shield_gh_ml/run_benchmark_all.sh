#!/usr/bin/env bash
# Crash-resilient launcher for the 4-candidate 7-class re-benchmark.
# benchmark_candidates.py saves results incrementally and skips completed
# candidates, so a Blackwell CUDA fault only costs the current model.
cd "$(dirname "$0")" || exit 1
PY=~/shield-ml-venv/bin/python
LOG=logs/candidate_benchmark.log
mkdir -p logs
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
export TOKENIZERS_PARALLELISM=false
# NOTE: needs network for the 3 not-yet-cached models; do NOT set HF_HUB_OFFLINE.

for attempt in $(seq 1 12); do
  echo "=== attempt $attempt $(date) ===" | tee -a "$LOG"
  $PY benchmark_candidates.py >> "$LOG" 2>&1
  rc=$?
  # done when all 4 present in the evidence file
  n=$($PY -c "import json,os;p='evidence/candidate_benchmark.json';print(len(json.load(open(p))['results']) if os.path.exists(p) else 0)" 2>/dev/null)
  echo "=== attempt $attempt exit $rc, candidates done: $n/4 ===" | tee -a "$LOG"
  [ "$n" = "4" ] && { echo "ALL DONE"; exit 0; }
  sleep 10
done
echo "gave up after 12 attempts" | tee -a "$LOG"; exit 1
