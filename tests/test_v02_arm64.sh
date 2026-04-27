#!/usr/bin/env bash
# Docker integration test: statedrift v0.2 on arm64 (Ubuntu 22.04).
#
# What this tests:
#   - The arm64 binary runs correctly on linux/arm64 (via QEMU emulation or native)
#   - All core commands work: init, snap, log, diff, verify
#   - Optional collectors work on arm64 kernel (/proc paths are architecture-neutral)
#   - analyze runs cleanly
#
# Target architectures this covers:
#   - AWS Graviton 2/3 (t4g, m6g, c7g instance families)
#   - Ampere Altra (Oracle Cloud A1, Azure Cobalt)
#   - Apple M1/M2 Linux VMs
#   - Raspberry Pi 4/5 running Ubuntu 22.04
#
# Prerequisites:
#   - docker with QEMU support (or native arm64 host)
#   - arm64 binary built: make build-all  (produces bin/statedrift-linux-arm64)
#
# Enable QEMU on amd64 host (one-time setup):
#   docker run --privileged --rm tonistiigi/binfmt --install arm64
#
# Usage:
#   make build-all
#   ./tests/test_v02_arm64.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY_ARM64="$REPO_ROOT/bin/statedrift-linux-arm64"

if [ ! -x "$BINARY_ARM64" ]; then
    echo "ERROR: $BINARY_ARM64 not found."
    echo "       Run 'make build-all' to cross-compile for arm64."
    exit 1
fi
if ! command -v docker &>/dev/null; then
    echo "ERROR: docker is required."
    exit 1
fi

pass() { printf '\033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

echo "=== statedrift v0.2 — arm64 (Ubuntu 22.04, linux/arm64) ==="
echo ""

# Verify QEMU or native arm64 is available
if ! docker run --rm --platform linux/arm64 ubuntu:22.04 uname -m 2>/dev/null | grep -q "aarch64"; then
    echo "ERROR: arm64 Docker images are not runnable on this host."
    echo "       Install QEMU: docker run --privileged --rm tonistiigi/binfmt --install arm64"
    exit 1
fi
pass "arm64 Docker images available on this host"

docker run --rm \
    --platform linux/arm64 \
    --privileged \
    -v "$BINARY_ARM64":/statedrift:ro \
    ubuntu:22.04 \
    bash << 'CONTAINERSCRIPT'
set -euo pipefail

pass() { printf '\033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

# ── Confirm we are actually on arm64 ─────────────────────────────────────────

ARCH=$(uname -m)
if [ "$ARCH" != "aarch64" ]; then
    fail "Expected aarch64, got: $ARCH"
fi
pass "confirmed running on aarch64"

export STATEDRIFT_STORE=/tmp/sd-test

cat > /tmp/config-all.json << 'EOF'
{"store_path": "/tmp/sd-test", "collectors": {"all": true}}
EOF

# ── Binary executes ───────────────────────────────────────────────────────────

VERSION=$(/statedrift version 2>&1)
if echo "$VERSION" | grep -q "statedrift"; then
    pass "binary executes on arm64: $VERSION"
else
    fail "binary failed to execute or wrong version output: $VERSION"
fi

# ── Core workflow ──────────────────────────────────────────────────────────────

STATEDRIFT_CONFIG=/tmp/config-all.json /statedrift init
pass "init"

STATEDRIFT_CONFIG=/tmp/config-all.json /statedrift snap
pass "snap 1"

STATEDRIFT_CONFIG=/tmp/config-all.json /statedrift snap
pass "snap 2"

SNAP=$(/statedrift show HEAD --json)

# ── Architecture field ─────────────────────────────────────────────────────────

ARCH_FIELD=$(echo "$SNAP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['host']['arch'])" 2>/dev/null)
if [ "$ARCH_FIELD" = "arm64" ]; then
    pass "host.arch = arm64 (correctly reported)"
else
    fail "host.arch = '$ARCH_FIELD', expected 'arm64'"
fi

# ── Optional collectors on arm64 ──────────────────────────────────────────────

for field in cpu kernel_counters processes sockets; do
    if echo "$SNAP" | python3 -c "import json,sys; d=json.load(sys.stdin); exit(0 if '$field' in d else 1)" 2>/dev/null; then
        pass "$field collected on arm64"
    else
        fail "$field missing on arm64"
    fi
done

# cpu.user should be a non-negative integer
CPU_USER=$(echo "$SNAP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['cpu']['user'])" 2>/dev/null)
if [ "$CPU_USER" -ge 0 ] 2>/dev/null; then
    pass "cpu.user = $CPU_USER (valid on arm64)"
else
    fail "cpu.user invalid: $CPU_USER"
fi

# ── diff + verify ──────────────────────────────────────────────────────────────

if /statedrift diff HEAD~1 HEAD > /dev/null 2>&1; then
    pass "diff HEAD~1 HEAD exits 0"
else
    fail "diff failed on arm64"
fi

if /statedrift verify 2>&1 | grep -q "INTEGRITY VERIFIED"; then
    pass "verify: INTEGRITY VERIFIED"
else
    fail "verify failed on arm64"
fi

# ── analyze ───────────────────────────────────────────────────────────────────

STATEDRIFT_CONFIG=/tmp/config-all.json /statedrift snap
if /statedrift analyze > /dev/null 2>&1; then
    pass "analyze exits 0 on arm64"
else
    fail "analyze failed on arm64"
fi

ANALYZE_JSON=$(/statedrift analyze --json 2>&1)
if echo "$ANALYZE_JSON" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
    pass "analyze --json valid on arm64"
else
    fail "analyze --json invalid on arm64"
fi

echo ""
echo "All arm64 tests passed."
CONTAINERSCRIPT

pass "arm64 (linux/arm64) — all tests passed"
echo ""
echo "=== Done ==="
