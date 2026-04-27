#!/usr/bin/env bash
# Docker integration test: verify.sh works on fresh Ubuntu 24.04 with only sha256sum + jq.
#
# What this tests:
#   - verify.sh PASS on a clean bundle
#   - verify.sh FAIL on a tampered bundle
#   - No Go, no statedrift binary, no python3 inside the container
#
# Prerequisites: docker, statedrift binary built (make build)
#
# Usage:
#   ./tests/test_verify_ubuntu2404.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$REPO_ROOT/bin/statedrift"
WORKDIR="$(mktemp -d)"

cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

pass() { printf '\033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

# ── Pre-flight checks ──────────────────────────────────────────────────────────

if [ ! -x "$BINARY" ]; then
    echo "ERROR: $BINARY not found. Run 'make build' first."
    exit 1
fi

if ! command -v docker &>/dev/null; then
    echo "ERROR: docker is required."
    exit 1
fi

echo "=== statedrift verify.sh — Ubuntu 24.04 Docker Test ==="
echo ""

# ── Build a real bundle on the host ───────────────────────────────────────────

STORE_DIR="$WORKDIR/store"
BUNDLE_PATH="$WORKDIR/statedrift-test-bundle.tar.gz"

STATEDRIFT_STORE="$STORE_DIR" "$BINARY" init
for i in 1 2 3; do
    STATEDRIFT_STORE="$STORE_DIR" "$BINARY" snap
    sleep 1
done
STATEDRIFT_STORE="$STORE_DIR" "$BINARY" export --from 2000-01-01 --to 2099-12-31 -o "$BUNDLE_PATH"
pass "bundle created (3 snapshots)"

# ── Extract so we can tamper for the negative test ────────────────────────────

CLEAN_BUNDLE="$WORKDIR/clean-bundle.tar.gz"
TAMPERED_BUNDLE="$WORKDIR/tampered-bundle.tar.gz"
EXTRACT_DIR="$WORKDIR/extracted"

cp "$BUNDLE_PATH" "$CLEAN_BUNDLE"

mkdir -p "$EXTRACT_DIR"
tar xzf "$BUNDLE_PATH" -C "$EXTRACT_DIR"
BUNDLE_SUBDIR=$(ls "$EXTRACT_DIR" | head -1)

# Tamper: overwrite one field in the first chain snapshot
CHAIN_FILE=$(ls "$EXTRACT_DIR/$BUNDLE_SUBDIR/chain/"*.json | sort | head -1)
# Use only sed — no python3 on the host either (keep it honest)
sed -i 's/"snapshot_id":[^,}]*/"snapshot_id":"tampered-by-test"/' "$CHAIN_FILE"

# Re-pack the tampered bundle
tar czf "$TAMPERED_BUNDLE" -C "$EXTRACT_DIR" "$BUNDLE_SUBDIR"
pass "tampered bundle created"

# ── Helper: run verify.sh inside a minimal Ubuntu 24.04 container ─────────────
#
# The container:
#   - starts from ubuntu:24.04
#   - installs ONLY jq (sha256sum is part of coreutils, already present)
#   - has NO go, NO statedrift, NO python3
#   - mounts the bundle read-only
#   - extracts the bundle and runs verify.sh

run_in_container() {
    local label="$1"
    local bundle_host_path="$2"
    local expect_exit="$3"    # 0 or 1
    local expect_string="$4"  # string that must appear in output

    local output exit_code

    set +e
    output=$(docker run --rm \
        -v "$bundle_host_path":/bundle.tar.gz:ro \
        ubuntu:24.04 \
        bash -c '
            set -euo pipefail
            apt-get update -qq && apt-get install -y -qq jq > /dev/null 2>&1

            # Confirm the minimal-tool requirement: no go, no python3
            if command -v go &>/dev/null; then
                echo "SETUP ERROR: go is present in the container"
                exit 2
            fi
            if command -v python3 &>/dev/null; then
                echo "SETUP ERROR: python3 is present in the container"
                exit 2
            fi

            mkdir -p /verify-test
            tar xzf /bundle.tar.gz -C /verify-test
            BUNDLE_SUBDIR=$(ls /verify-test | head -1)
            bash /verify-test/"$BUNDLE_SUBDIR"/verify.sh
        ' 2>&1)
    exit_code=$?
    set -e

    if [ "$exit_code" -ne "$expect_exit" ]; then
        fail "$label — expected exit $expect_exit, got $exit_code. Output: $output"
    fi
    if ! echo "$output" | grep -q "$expect_string"; then
        fail "$label — expected '$expect_string' in output, got: $output"
    fi
    pass "$label"
}

# ── Test 1: clean bundle → INTEGRITY VERIFIED ─────────────────────────────────
run_in_container \
    "ubuntu:24.04 clean bundle → INTEGRITY VERIFIED" \
    "$CLEAN_BUNDLE" \
    0 \
    "INTEGRITY VERIFIED"

# ── Test 2: tampered bundle → INTEGRITY VIOLATION + exit 1 ───────────────────
run_in_container \
    "ubuntu:24.04 tampered bundle → INTEGRITY VIOLATION" \
    "$TAMPERED_BUNDLE" \
    1 \
    "INTEGRITY VIOLATION"

echo ""
echo "All Docker tests passed."
