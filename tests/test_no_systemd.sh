#!/usr/bin/env bash
# Manual test: statedrift on a host without systemd (container).
# Expected: services={}, no crash, collector_errors contains "services".
#
# Usage: ./tests/test_no_systemd.sh

set -euo pipefail

BINARY="$(pwd)/bin/statedrift"

if [ ! -x "$BINARY" ]; then
    echo "ERROR: $BINARY not found — run 'make build' first"
    exit 1
fi

echo "==> Running no-systemd container test"
echo "    Binary: $BINARY"
echo

docker run --rm \
    -v "$BINARY":/statedrift:ro \
    ubuntu:22.04 \
    bash << 'CONTAINERSCRIPT'
set -e
export STATEDRIFT_STORE=/tmp/statedrift-test

echo "--- init"
/statedrift init

echo "--- snap"
/statedrift snap

echo "--- checking services field"
SERVICES=$(/statedrift show HEAD --json | python3 -c "
import json, sys
snap = json.load(sys.stdin)
print(json.dumps(snap.get('services', 'MISSING'), indent=2))
")
echo "services: $SERVICES"

echo "--- checking collector_errors"
ERRORS=$(/statedrift show HEAD --json | python3 -c "
import json, sys
snap = json.load(sys.stdin)
print(json.dumps(snap.get('collector_errors'), indent=2))
")
echo "collector_errors: $ERRORS"

if [ "$SERVICES" != "{}" ]; then
    echo "FAIL: expected services={}, got: $SERVICES"
    exit 1
fi
echo "PASS: services is empty"

if echo "$ERRORS" | grep -q "services"; then
    echo "PASS: collector_errors records the systemd failure"
else
    echo "FAIL: expected collector_errors to mention services"
    exit 1
fi
CONTAINERSCRIPT

echo
echo "==> All checks passed"
