#!/usr/bin/env bash
# SHIELD-GH Task 05 — one-command verification: tests + evidence.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${SHIELD_CRYPTO_PY:-$HOME/shield-crypto-venv/bin/python3}"
cd "$HERE"

echo "### 1/2  pytest (both PQC and classical-fallback backends)"
"$PY" -m pytest tests/ -q

echo
echo "### 2/3  end-to-end mitigation evidence (Fig 3.5)"
"$PY" gen_evidence.py

echo
echo "### 3/3  visual evidence figures (PNG)"
"$PY" gen_figures.py

echo
echo "### DONE — text artefacts in $HERE/vectors/, figures in $HERE/figures/"
