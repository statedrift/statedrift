#!/usr/bin/env bash
# Docker integration test: v0.2 on Rocky Linux 9 (RHEL-compatible, rpm-based).
#
# What this tests:
#   - rpm package manager collection (vs dpkg on Ubuntu)
#   - Optional collectors (cpu, kernel_counters, processes, sockets) on RHEL-family
#   - analyze command on Rocky Linux 9
#   - Graceful degradation: systemd absent in container
#   - verify chain integrity across snaps
#
# Rocky Linux 9 is the primary RHEL-compatible target for enterprise consulting.
# Covers: CentOS Stream 9, AlmaLinux 9, and RHEL 9 with the same binary.
#
# Prerequisites: docker, statedrift binary built (make build)
#
# Usage:
#   ./tests/test_v02_rocky9.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$REPO_ROOT/bin/statedrift"

if [ ! -x "$BINARY" ]; then
    echo "ERROR: $BINARY not found. Run 'make build' first."
    exit 1
fi
if ! command -v docker &>/dev/null; then
    echo "ERROR: docker is required."
    exit 1
fi

pass() { printf '\033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

echo "=== statedrift v0.2 — Rocky Linux 9 (RHEL-compatible) ==="
echo ""

docker run --rm \
    --privileged \
    -v "$BINARY":/statedrift:ro \
    rockylinux:9 \
    bash << 'CONTAINERSCRIPT'
set -euo pipefail

pass() { printf '\033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; exit 1; }
skip() { printf '\033[33mSKIP\033[0m %s\n' "$1"; }

export STATEDRIFT_STORE=/tmp/sd-test

cat > /tmp/config-all.json << 'EOF'
{"store_path": "/tmp/sd-test", "collectors": {"all": true}}
EOF

# ── Package manager detection ─────────────────────────────────────────────────

if ! command -v rpm &>/dev/null; then
    fail "rpm not found in Rocky Linux 9 image (unexpected)"
fi
pass "rpm package manager available"

# ── Init and snap ─────────────────────────────────────────────────────────────

STATEDRIFT_CONFIG=/tmp/config-all.json /statedrift init
pass "init"

STATEDRIFT_CONFIG=/tmp/config-all.json /statedrift snap
pass "snap 1"

SNAP=$(/statedrift show HEAD --json)

# ── Packages collected via rpm ─────────────────────────────────────────────────

PKG_COUNT=$(echo "$SNAP" | python3 -c "
import json, sys
d = json.load(sys.stdin)
pkgs = d.get('packages', {})
print(len(pkgs))
" 2>/dev/null)

if [ "$PKG_COUNT" -gt 0 ]; then
    pass "packages collected via rpm: $PKG_COUNT packages"
else
    fail "packages: expected > 0 packages from rpm, got $PKG_COUNT"
fi

# Verify rpm package format: name → version-release
echo "$SNAP" | python3 -c "
import json, sys
d = json.load(sys.stdin)
pkgs = d.get('packages', {})
# A few packages that are always present in Rocky Linux 9
for expected in ['bash', 'glibc', 'rpm']:
    assert expected in pkgs, f'expected package {expected!r} not found'
    ver = pkgs[expected]
    assert ver, f'version empty for {expected}'
print('OK')
" 2>/dev/null && pass "core rpm packages (bash, glibc, rpm) present with versions" \
    || fail "core rpm packages missing or malformed"

# ── Optional collectors on RHEL ───────────────────────────────────────────────

for field in cpu kernel_counters processes sockets; do
    if echo "$SNAP" | python3 -c "import json,sys; d=json.load(sys.stdin); exit(0 if '$field' in d else 1)" 2>/dev/null; then
        pass "$field collected on Rocky Linux 9"
    else
        fail "$field missing from snapshot on Rocky Linux 9"
    fi
done

# ── Services: absent (no systemd in container) ────────────────────────────────

SERVICES=$(echo "$SNAP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('services', {})))" 2>/dev/null)
if [ "$SERVICES" -eq 0 ]; then
    pass "services: {} (expected — no systemd in container)"
else
    pass "services: $SERVICES units found (systemd available)"
fi

ERRORS=$(echo "$SNAP" | python3 -c "
import json, sys
d = json.load(sys.stdin)
errs = d.get('collector_errors', [])
print('\n'.join(errs))
" 2>/dev/null)
if echo "$ERRORS" | grep -qi "services\|systemd"; then
    pass "collector_errors records systemd/services failure (expected in container)"
fi

# ── Second snap + diff ────────────────────────────────────────────────────────

STATEDRIFT_CONFIG=/tmp/config-all.json /statedrift snap
pass "snap 2"

DIFF_OUT=$(/statedrift diff HEAD~1 HEAD 2>&1)
if [ $? -eq 0 ]; then
    pass "diff HEAD~1 HEAD exits 0"
else
    fail "diff HEAD~1 HEAD: non-zero exit"
fi

if echo "$DIFF_OUT" | grep -qE "[0-9]+ material changes"; then
    pass "diff output contains material change summary"
else
    fail "diff output missing summary line"
fi

# ── analyze ───────────────────────────────────────────────────────────────────

STATEDRIFT_CONFIG=/tmp/config-all.json /statedrift snap
if /statedrift analyze > /dev/null 2>&1; then
    pass "analyze exits 0"
else
    fail "analyze: non-zero exit"
fi

ANALYZE_JSON=$(/statedrift analyze --json 2>&1)
if echo "$ANALYZE_JSON" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
    pass "analyze --json produces valid JSON"
else
    fail "analyze --json: invalid JSON"
fi

# ── Chain verify ──────────────────────────────────────────────────────────────

if /statedrift verify 2>&1 | grep -q "INTEGRITY VERIFIED"; then
    pass "verify: INTEGRITY VERIFIED across all snaps"
else
    fail "verify: chain not verified"
fi

echo ""
echo "All Rocky Linux 9 tests passed."
CONTAINERSCRIPT

pass "Rocky Linux 9 — all tests passed"
echo ""
echo "=== Done ==="
