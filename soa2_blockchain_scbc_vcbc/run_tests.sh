#!/usr/bin/env bash
# Run the SOA2 SCBC/VCBC chaincode unit tests (no running Fabric needed).
set -e
cd "$(dirname "$0")/chaincode-scbcvcbc"
echo "=== SOA2 SCBC/VCBC chaincode unit tests (Alg. 1-5) ==="
go test -mod=vendor -v -cover ./...
