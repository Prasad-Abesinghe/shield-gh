#!/usr/bin/env bash
# Crash-resilient launcher for the Qwen2.5-7B fine-tune on the RTX 5090.
#
# The Blackwell (sm_120) + torch-cu128 stack raises intermittent
# cudaErrorLaunchFailure that can kill the process (and occasionally wedge the
# display). finetune_qwen.py checkpoints the LoRA adapter after every epoch and
# auto-resumes, so this wrapper simply relaunches until the run completes,
# picking up from the last checkpoint each time.
#
# Usage:  bash run_finetune_resilient.sh
# Stop:   touch models/qwen_ckpt/STOP   (or Ctrl-C)

cd "$(dirname "$0")" || exit 1
PY=~/shield-ml-venv/bin/python
LOG=logs/qwen_finetune_full.log
mkdir -p logs models

# GPU-stability environment (small batch is set in the python via SHIELD_BS)
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
export TOKENIZERS_PARALLELISM=false
export SHIELD_BS=4                 # small batch -> less kernel pressure
export HF_HUB_OFFLINE=1            # model already cached; no network

MAX_ATTEMPTS=8
for attempt in $(seq 1 $MAX_ATTEMPTS); do
  if [ -f models/qwen_ckpt/STOP ]; then echo "STOP file present; aborting"; exit 0; fi
  echo "=== launch attempt $attempt/$MAX_ATTEMPTS $(date) ===" | tee -a "$LOG"
  $PY finetune_qwen.py >> "$LOG" 2>&1
  rc=$?
  if [ $rc -eq 0 ] && [ -f evidence/qwen_finetune_results.json ]; then
    # confirm the results file is from THIS run (fresh)
    echo "=== SUCCESS on attempt $attempt (exit 0) ===" | tee -a "$LOG"
    exit 0
  fi
  echo "=== attempt $attempt failed (exit $rc); resuming from checkpoint ===" \
    | tee -a "$LOG"
  # let the GPU settle before relaunch
  sleep 10
done
echo "=== gave up after $MAX_ATTEMPTS attempts ===" | tee -a "$LOG"
exit 1
