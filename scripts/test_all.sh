#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LICENSING_DIR="$(cd "${ROOT_DIR}/../licensing" && pwd)"

cd "${ROOT_DIR}"
echo "[3/4] Running focused coupon tests"
go test ./... -run 'TestApplyCoupon'

echo "[4/4] Running full licensing-go test suite"
go test ./...

echo "All licensing-go tests passed using local ../licensing replace."
