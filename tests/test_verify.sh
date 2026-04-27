#!/bin/bash
# Standalone integration test for verify.sh
# Tests that verify.sh correctly detects valid and tampered bundles.
#
# Usage:
#   ./tests/test_verify.sh
#
# Prerequisites: statedrift binary must be built (make build)
#                jq and sha256sum must be installed
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$REPO_ROOT/bin/statedrift"
WORKDIR="$(mktemp -d)"

cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

pass() { printf '\033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

# Sanity checks
if [ ! -x "$BINARY" ]; then
    echo "ERROR: $BINARY not found. Run 'make build' first."
    exit 1
fi
if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required. Install with: apt install jq / yum install jq"
    exit 1
fi
if ! command -v sha256sum &>/dev/null; then
    echo "ERROR: sha256sum is required."
    exit 1
fi

STORE_DIR="$WORKDIR/store"
BUNDLE_DIR="$WORKDIR/bundle"
BUNDLE_PATH="$WORKDIR/test-bundle.tar.gz"

echo "=== statedrift verify.sh Integration Test ==="
echo ""

# Initialize store
STATEDRIFT_STORE="$STORE_DIR" "$BINARY" init
pass "init"

# Take a few snapshots with distinct timestamps (using snap command)
for i in 1 2 3; do
    STATEDRIFT_STORE="$STORE_DIR" "$BINARY" snap
    sleep 1
done
pass "3 snapshots taken"

# Export bundle
TODAY=$(date +%Y-%m-%d)
STATEDRIFT_STORE="$STORE_DIR" "$BINARY" export --from 2000-01-01 --to 2099-12-31 -o "$BUNDLE_PATH"
pass "export"

# Extract bundle
mkdir -p "$BUNDLE_DIR"
tar xzf "$BUNDLE_PATH" -C "$BUNDLE_DIR"
BUNDLE_SUBDIR=$(ls "$BUNDLE_DIR" | head -1)

# Test 1: verify.sh on clean bundle exits 0
output=$(bash "$BUNDLE_DIR/$BUNDLE_SUBDIR/verify.sh" 2>&1)
if echo "$output" | grep -q "INTEGRITY VERIFIED"; then
    pass "verify.sh clean bundle → INTEGRITY VERIFIED"
else
    fail "verify.sh clean bundle → expected INTEGRITY VERIFIED, got: $output"
fi

# Test 2: verify.sh --quiet prints "PASS" only
quiet_out=$(bash "$BUNDLE_DIR/$BUNDLE_SUBDIR/verify.sh" --quiet 2>&1)
if [ "$(echo "$quiet_out" | tr -d '[:space:]')" = "PASS" ]; then
    pass "verify.sh --quiet → PASS"
else
    fail "verify.sh --quiet → expected 'PASS', got: $quiet_out"
fi

# Test 3: tamper with a snapshot file, verify.sh should exit 1
CHAIN_FILE=$(ls "$BUNDLE_DIR/$BUNDLE_SUBDIR/chain/"*.json | head -1)
cp "$CHAIN_FILE" "$CHAIN_FILE.bak"
# Inject a tampered value
python3 -c "
import json, sys
with open('$CHAIN_FILE') as f: d = json.load(f)
d['snapshot_id'] = 'tampered'
with open('$CHAIN_FILE', 'w') as f: json.dump(d, f)
" 2>/dev/null || \
    # Fallback: use sed if python3 not available
    sed -i 's/"snapshot_id":[^,}]*/"snapshot_id":"tampered"/' "$CHAIN_FILE"

set +e
tamper_out=$(bash "$BUNDLE_DIR/$BUNDLE_SUBDIR/verify.sh" 2>&1)
tamper_exit=$?
set -e

if [ "$tamper_exit" -eq 1 ] && echo "$tamper_out" | grep -q "INTEGRITY VIOLATION"; then
    pass "verify.sh tampered bundle → INTEGRITY VIOLATION (exit 1)"
else
    fail "verify.sh tampered bundle → expected exit 1 + INTEGRITY VIOLATION, got exit $tamper_exit: $tamper_out"
fi

# Restore
cp "$CHAIN_FILE.bak" "$CHAIN_FILE"

# Test 4: verify.sh --quiet on tampered bundle prints "FAIL"
python3 -c "
import json, sys
with open('$CHAIN_FILE') as f: d = json.load(f)
d['snapshot_id'] = 'tampered2'
with open('$CHAIN_FILE', 'w') as f: json.dump(d, f)
" 2>/dev/null || \
    sed -i 's/"snapshot_id":[^,}]*/"snapshot_id":"tampered2"/' "$CHAIN_FILE"

set +e
quiet_tamper=$(bash "$BUNDLE_DIR/$BUNDLE_SUBDIR/verify.sh" --quiet 2>&1)
quiet_tamper_exit=$?
set -e

if [ "$quiet_tamper_exit" -eq 1 ] && [ "$(echo "$quiet_tamper" | tr -d '[:space:]')" = "FAIL" ]; then
    pass "verify.sh --quiet tampered → FAIL (exit 1)"
else
    fail "verify.sh --quiet tampered → expected exit 1 + FAIL, got exit $quiet_tamper_exit: $quiet_tamper"
fi

# Test 5: statedrift verify <bundle.tar.gz> via CLI
set +e
cli_verify=$(STATEDRIFT_STORE="$STORE_DIR" "$BINARY" verify "$BUNDLE_PATH" 2>&1)
cli_exit=$?
set -e
if [ "$cli_exit" -eq 0 ] && echo "$cli_verify" | grep -q "INTEGRITY VERIFIED"; then
    pass "statedrift verify <bundle.tar.gz> → INTEGRITY VERIFIED"
else
    fail "statedrift verify <bundle.tar.gz> → exit $cli_exit: $cli_verify"
fi

echo ""
echo "All tests passed."
