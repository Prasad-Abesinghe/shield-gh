#!/usr/bin/env bash
# Verify the SOA1 DPGHA detector against the paper's worked example (Table 2).
set -e
cd "$(dirname "$0")"
echo "=== C++ detector self-test (dpgha_detection.h vs paper Table 2) ==="
g++ -std=c++17 -O2 -o dpgha_selftest dpgha_selftest.cc
./dpgha_selftest
echo
echo "=== Python port self-test (dpgha.py vs paper Table 2) ==="
python3 dpgha.py
