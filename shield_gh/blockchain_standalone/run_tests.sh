#!/usr/bin/env bash
# ============================================================
# SHIELD-GH DEBSC — formal smart-contract verification (unit tests)
# Verifies functional correctness with dummy data — no running Fabric needed.
# ============================================================
set -e
cd "$(dirname "$0")/chaincode-debsc"

echo "============================================================"
echo " SHIELD-GH DEBSC — Smart Contract Formal Verification"
echo " (unit tests with dummy data)"
echo "============================================================"
echo

echo ">>> Running test suite (verbose)..."
go test -v ./...

echo
echo ">>> Coverage report (per function)..."
go test -coverprofile=/tmp/debsc_cov.out ./... >/dev/null
go tool cover -func=/tmp/debsc_cov.out

echo
# Write HTML into the project folder (snap Firefox cannot read /tmp).
HTML_OUT="$(cd .. && pwd)/debsc_coverage.html"
echo ">>> HTML coverage report -> $HTML_OUT"
go tool cover -html=/tmp/debsc_cov.out -o "$HTML_OUT"
echo "    Open in browser:  file://$HTML_OUT"

echo
echo "============================================================"
echo " VERIFICATION COMPLETE — all DEBSC functions tested:"
echo "   • CommitForwardingRecord  (reputation/ZKP/suspicion derivation)"
echo "   • EvaluateIsolation       (Eq. 3.19 dual-gate truth table)"
echo "   • false-positive guard    (low-rep but valid-ZKP -> NOT isolated)"
echo "   • ledger persistence      (isolated flag committed)"
echo "   • ReadNode / GetAllNodes / InitLedger"
echo "============================================================"
