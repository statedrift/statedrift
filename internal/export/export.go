// Package export creates portable, verifiable evidence bundles.
package export

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/statedrift/statedrift/internal/collector"
	"github.com/statedrift/statedrift/internal/hasher"
	"github.com/statedrift/statedrift/internal/store"
)

// ErrManifestMismatch is returned by VerifyBundle when the recomputed first
// or last snapshot hash does not match the chain_root_hash / chain_head_hash
// recorded in manifest.json. The internal chain may still be consistent —
// this signals that the bundle as a whole has been substituted for a
// different valid chain, or the manifest was edited after creation.
var ErrManifestMismatch = errors.New("bundle manifest hash mismatch")

// Manifest describes the contents of an export bundle.
type Manifest struct {
	Version             string    `json:"version"`
	CreatedAt           time.Time `json:"created_at"`
	Hostname            string    `json:"hostname"`
	OS                  string    `json:"os"`
	Kernel              string    `json:"kernel"`
	RangeStart          time.Time `json:"range_start"`
	RangeEnd            time.Time `json:"range_end"`
	SnapshotCount       int       `json:"snapshot_count"`
	ChainRootHash       string    `json:"chain_root_hash"` // hash of first snapshot
	ChainHeadHash       string    `json:"chain_head_hash"` // hash of last snapshot
	ChainVerified       bool      `json:"chain_verified"`
	SnapshotIntervalAvg string    `json:"snapshot_interval_avg,omitempty"`
}

// Bundle creates a .tar.gz export of snapshots in the given time range.
// After writing, the bundle is self-verified; if verification fails the
// output file is removed and an error is returned.
func Bundle(s *store.Store, from, to time.Time, outputPath string) error {
	entries, err := s.List()
	if err != nil {
		return fmt.Errorf("listing snapshots: %w", err)
	}

	if len(entries) == 0 {
		return fmt.Errorf("store is empty: no snapshots to export")
	}

	// Filter to time range
	var selected []store.SnapshotEntry
	for _, e := range entries {
		t := e.Snapshot.Timestamp
		if (t.Equal(from) || t.After(from)) && (t.Equal(to) || t.Before(to)) {
			selected = append(selected, e)
		}
	}

	if len(selected) == 0 {
		return fmt.Errorf("no snapshots found in range %s to %s", from.Format("2006-01-02"), to.Format("2006-01-02"))
	}

	// Build manifest
	manifest := Manifest{
		Version:       collector.Version,
		CreatedAt:     time.Now().UTC(),
		Hostname:      selected[0].Snapshot.Host.Hostname,
		OS:            selected[0].Snapshot.Host.OS,
		Kernel:        selected[0].Snapshot.Host.Kernel,
		RangeStart:    selected[0].Snapshot.Timestamp,
		RangeEnd:      selected[len(selected)-1].Snapshot.Timestamp,
		SnapshotCount: len(selected),
		ChainRootHash: selected[0].Hash,
		ChainHeadHash: selected[len(selected)-1].Hash,
		ChainVerified: true,
	}

	if len(selected) >= 2 {
		total := selected[len(selected)-1].Snapshot.Timestamp.Sub(selected[0].Snapshot.Timestamp)
		avg := total / time.Duration(len(selected)-1)
		manifest.SnapshotIntervalAvg = avg.Round(time.Second).String()
	}

	// Create tar.gz
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}

	gzWriter := gzip.NewWriter(outFile)
	tw := tar.NewWriter(gzWriter)

	bundleName := filepath.Base(outputPath)
	bundleName = strings.TrimSuffix(bundleName, ".gz")
	bundleName = strings.TrimSuffix(bundleName, ".tar")

	// Add manifest
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	addFileToTar(tw, bundleName+"/manifest.json", manifestData)

	// Add snapshots
	for _, e := range selected {
		data, err := os.ReadFile(e.Path)
		if err != nil {
			continue
		}
		filename := e.Snapshot.Timestamp.Format("20060102-150405") + ".json"
		addFileToTar(tw, bundleName+"/chain/"+filename, data)
	}

	// Add verify.sh (Linux/macOS auditors)
	verifyScript := generateVerifyScript()
	addFileToTar(tw, bundleName+"/verify.sh", []byte(verifyScript))

	// Add verify.ps1 (Windows auditors). Mirrors verify.sh's algorithm in
	// pure PowerShell so an auditor on a locked-down Windows host can verify
	// without WSL, Git Bash, or any external tooling.
	verifyPS := generateVerifyPowerShellScript()
	addFileToTar(tw, bundleName+"/verify.ps1", []byte(verifyPS))

	// Add README
	readme := generateReadme(manifest)
	addFileToTar(tw, bundleName+"/README.txt", []byte(readme))

	// Close writers explicitly so the file is fully flushed before self-verification.
	if err := tw.Close(); err != nil {
		outFile.Close()
		os.Remove(outputPath)
		return fmt.Errorf("closing tar writer: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		outFile.Close()
		os.Remove(outputPath)
		return fmt.Errorf("closing gzip writer: %w", err)
	}
	if err := outFile.Close(); err != nil {
		os.Remove(outputPath)
		return fmt.Errorf("closing output file: %w", err)
	}

	// Self-verify the created bundle.
	_, brokenAt, err := VerifyBundle(outputPath)
	if err != nil {
		os.Remove(outputPath)
		return fmt.Errorf("bundle self-verification failed: %w", err)
	}
	if brokenAt != -1 {
		os.Remove(outputPath)
		return fmt.Errorf("bundle self-verification failed: chain broken at snapshot #%d", brokenAt)
	}

	return nil
}

// VerifyBundle reads a .tar.gz export bundle and verifies its hash chain.
// Returns the snapshot count and the index of the first broken link (-1 if
// the chain is internally consistent). Each snapshot's prev_hash must equal
// the hash of its predecessor; the first snapshot's prev_hash is not checked
// against GenesisHash, supporting partial-range exports.
//
// Additionally cross-checks manifest.json's chain_root_hash and
// chain_head_hash against the recomputed first / last snapshot hashes. On
// mismatch the returned error wraps ErrManifestMismatch — the internal
// chain may still be consistent, but the bundle as a whole no longer
// matches what its own manifest claims.
func VerifyBundle(bundlePath string) (count int, brokenAt int, err error) {
	f, err := os.Open(bundlePath)
	if err != nil {
		return 0, -1, fmt.Errorf("opening bundle: %w", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return 0, -1, fmt.Errorf("reading gzip: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	var snaps []*collector.Snapshot
	var manifest *Manifest

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, -1, fmt.Errorf("reading tar: %w", err)
		}

		isChain := strings.Contains(hdr.Name, "/chain/") && strings.HasSuffix(hdr.Name, ".json")
		isManifest := strings.HasSuffix(hdr.Name, "/manifest.json")

		if !isChain && !isManifest {
			continue
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			return 0, -1, fmt.Errorf("reading %s: %w", hdr.Name, err)
		}

		if isManifest {
			var m Manifest
			if err := json.Unmarshal(data, &m); err != nil {
				return 0, -1, fmt.Errorf("parsing manifest.json: %w", err)
			}
			manifest = &m
			continue
		}

		var snap collector.Snapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			continue
		}
		snaps = append(snaps, &snap)
	}

	if len(snaps) == 0 {
		return 0, -1, fmt.Errorf("no snapshots found in bundle")
	}

	sort.Slice(snaps, func(i, j int) bool {
		return snaps[i].Timestamp.Before(snaps[j].Timestamp)
	})

	hashes := make([]string, len(snaps))
	for i, s := range snaps {
		h, err := hasher.Hash(s)
		if err != nil {
			return 0, -1, fmt.Errorf("computing hash for snapshot %d: %w", i, err)
		}
		hashes[i] = h
	}

	// Verify internal chain consistency: each snapshot's prev_hash must equal
	// the hash of the preceding snapshot. The first snapshot's prev_hash is not
	// checked against GenesisHash to support partial-range exports.
	for i := 1; i < len(snaps); i++ {
		if snaps[i].PrevHash != hashes[i-1] {
			return len(snaps), i, nil
		}
	}

	// Cross-check manifest root/head hashes if manifest is present. Older
	// bundles may not have one; we only fail if the manifest was found and
	// its claimed hashes don't match what we computed.
	if manifest != nil {
		if manifest.ChainRootHash != "" && manifest.ChainRootHash != hashes[0] {
			return len(snaps), -1, fmt.Errorf("%w: chain_root_hash claims %s but first snapshot hashes to %s",
				ErrManifestMismatch, manifest.ChainRootHash, hashes[0])
		}
		if manifest.ChainHeadHash != "" && manifest.ChainHeadHash != hashes[len(hashes)-1] {
			return len(snaps), -1, fmt.Errorf("%w: chain_head_hash claims %s but last snapshot hashes to %s",
				ErrManifestMismatch, manifest.ChainHeadHash, hashes[len(hashes)-1])
		}
	}

	return len(snaps), -1, nil
}

func addFileToTar(tw *tar.Writer, name string, data []byte) {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0644,
		Size:    int64(len(data)),
		ModTime: time.Now(),
	}

	// Make verify.sh executable
	if filepath.Base(name) == "verify.sh" {
		hdr.Mode = 0755
	}

	tw.WriteHeader(hdr)
	tw.Write(data)
}

func generateVerifyScript() string {
	return `#!/bin/bash
# statedrift Evidence Bundle Verifier
# Independently verifies the hash chain integrity of a statedrift export bundle.
# Requirements: sha256sum, jq
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHAIN_DIR="$SCRIPT_DIR/chain"

# Parse flags
QUIET=0
VERBOSE=0
for arg in "$@"; do
    case "$arg" in
        --quiet)   QUIET=1 ;;
        --verbose) VERBOSE=1 ;;
    esac
done

# Color support: disabled if NO_COLOR is set, TERM is dumb, or stdout is not a tty
USE_COLOR=1
if [ -n "${NO_COLOR:-}" ] || [ "${TERM:-}" = "dumb" ] || [ ! -t 1 ]; then
    USE_COLOR=0
fi

_green() { [ "$USE_COLOR" -eq 1 ] && printf '\033[32m%s\033[0m' "$1" || printf '%s' "$1"; }
_red()   { [ "$USE_COLOR" -eq 1 ] && printf '\033[31m%s\033[0m' "$1" || printf '%s' "$1"; }
_dim()   { [ "$USE_COLOR" -eq 1 ] && printf '\033[2m%s\033[0m' "$1" || printf '%s' "$1"; }

# Check for jq
if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required but not installed."
    echo "Install with:"
    echo "  Ubuntu/Debian:  sudo apt install jq"
    echo "  RHEL/CentOS:    sudo yum install jq"
    echo "  macOS (Homebrew): brew install jq"
    exit 1
fi

# Read manifest
MANIFEST="$SCRIPT_DIR/manifest.json"
if [ ! -f "$MANIFEST" ]; then
    echo "ERROR: manifest.json not found"
    exit 1
fi

HOSTNAME=$(jq -r '.hostname' "$MANIFEST")
RANGE_START=$(jq -r '.range_start' "$MANIFEST")
RANGE_END=$(jq -r '.range_end' "$MANIFEST")
EXPECTED_COUNT=$(jq -r '.snapshot_count' "$MANIFEST")
MANIFEST_ROOT=$(jq -r '.chain_root_hash // ""' "$MANIFEST")
MANIFEST_HEAD=$(jq -r '.chain_head_hash // ""' "$MANIFEST")

if [ "$QUIET" -eq 0 ]; then
    echo "statedrift Evidence Bundle Verifier"
    echo "===================================="
    echo ""
    echo "Host:      $HOSTNAME"
    echo "Period:    $RANGE_START"
    echo "           $RANGE_END"
    echo "Expected:  $EXPECTED_COUNT snapshots"
    echo ""
fi

# Collect and sort snapshot files
SNAPSHOTS=($(ls "$CHAIN_DIR"/*.json 2>/dev/null | sort))
ACTUAL_COUNT=${#SNAPSHOTS[@]}

if [ "$ACTUAL_COUNT" -eq 0 ]; then
    [ "$QUIET" -eq 0 ] && echo "ERROR: No snapshot files found in chain/"
    [ "$QUIET" -eq 1 ] && echo "FAIL"
    exit 1
fi

if [ "$ACTUAL_COUNT" -ne "$EXPECTED_COUNT" ]; then
    [ "$QUIET" -eq 0 ] && echo "ERROR: manifest claims $EXPECTED_COUNT snapshots but found $ACTUAL_COUNT"
    [ "$QUIET" -eq 1 ] && echo "FAIL"
    exit 1
fi

if [ "$QUIET" -eq 0 ]; then
    echo "Found:     $ACTUAL_COUNT snapshots"
    echo ""
fi

# Verify hash chain
PREV_HASH=""
PREV_FILE=""
FIRST_HASH=""
VERIFIED=0
BROKEN=0
BROKEN_AT=""

for SNAP_FILE in "${SNAPSHOTS[@]}"; do
    FILENAME=$(basename "$SNAP_FILE")

    # Read the prev_hash from this snapshot
    SNAP_PREV_HASH=$(jq -r '.prev_hash' "$SNAP_FILE")

    # Compute this snapshot's hash (canonical JSON with sorted keys, compact,
    # no trailing newline — matches Go's hasher.CanonicalJSON output)
    CURRENT_HASH=$(jq -cS '.' "$SNAP_FILE" | tr -d '\n' | sha256sum | awk '{print $1}')

    # Check chain link (skip check for the first snapshot — partial export support)
    if [ "$VERIFIED" -gt 0 ]; then
        if [ "$SNAP_PREV_HASH" != "$PREV_HASH" ]; then
            if [ "$QUIET" -eq 0 ]; then
                echo "BREAK at $FILENAME"
                echo "  Expected prev_hash: $PREV_HASH"
                echo "  Found prev_hash:    $SNAP_PREV_HASH"
            fi
            BROKEN=1
            BROKEN_AT="$FILENAME"
            break
        fi
    else
        FIRST_HASH="$CURRENT_HASH"
    fi

    if [ "$VERBOSE" -eq 1 ] && [ "$QUIET" -eq 0 ]; then
        printf "  %s %s\n" "$(_dim "$FILENAME")" "$CURRENT_HASH"
    fi

    PREV_FILE="$FILENAME"
    PREV_HASH="$CURRENT_HASH"
    VERIFIED=$((VERIFIED + 1))
done

# Cross-check manifest root/head hashes against what we computed. This catches
# whole-bundle substitution: an internally-consistent chain with a regenerated
# manifest is detected only here, not by the chain walk above. Older bundles
# without these manifest fields are skipped.
MANIFEST_MISMATCH=""
if [ "$BROKEN" -eq 0 ]; then
    if [ -n "$MANIFEST_ROOT" ] && [ "$MANIFEST_ROOT" != "$FIRST_HASH" ]; then
        MANIFEST_MISMATCH="chain_root_hash claims $MANIFEST_ROOT but first snapshot hashes to $FIRST_HASH"
    elif [ -n "$MANIFEST_HEAD" ] && [ "$MANIFEST_HEAD" != "$PREV_HASH" ]; then
        MANIFEST_MISMATCH="chain_head_hash claims $MANIFEST_HEAD but last snapshot hashes to $PREV_HASH"
    fi
fi

echo ""
if [ "$BROKEN" -eq 1 ]; then
    if [ "$QUIET" -eq 1 ]; then
        echo "FAIL"
    else
        printf "%s\n" "$(_red "RESULT: INTEGRITY VIOLATION")"
        echo ""
        echo "  $PREV_FILE may have been modified -- its hash no longer matches"
        echo "  the prev_hash recorded in $BROKEN_AT."
        echo ""
        CLEAN=$((VERIFIED - 1))
        if [ "$CLEAN" -gt 0 ]; then
            echo "  $CLEAN of $ACTUAL_COUNT snapshot(s) verified intact (before $PREV_FILE)."
        else
            echo "  No snapshots before the break point are verified intact."
        fi
        echo "  $PREV_FILE and later cannot be trusted."
    fi
    exit 1
elif [ -n "$MANIFEST_MISMATCH" ]; then
    if [ "$QUIET" -eq 1 ]; then
        echo "FAIL"
    else
        echo "Chain:    OK ($VERIFIED snapshots internally consistent)"
        echo "Manifest: MISMATCH"
        printf "%s\n" "$(_red "RESULT: INTEGRITY VIOLATION")"
        echo ""
        echo "  The chain is internally consistent, but its first or last"
        echo "  snapshot hash no longer matches what manifest.json claims."
        echo "  The bundle as a whole has been substituted, replaced with a"
        echo "  different valid chain, or the manifest was edited after creation."
        echo ""
        echo "  detail: $MANIFEST_MISMATCH"
    fi
    exit 1
else
    if [ "$QUIET" -eq 1 ]; then
        echo "PASS"
    else
        echo "Verified: $VERIFIED snapshots"
        printf "%s\n" "$(_green "RESULT: INTEGRITY VERIFIED")"
        echo ""
        echo "All snapshots are consistent with their recorded hashes."
        echo "No tampering detected."
    fi
    exit 0
fi
`
}

// generateVerifyPowerShellScript returns the contents of verify.ps1, the
// Windows-native sibling of verify.sh. It must produce identical PASS/FAIL
// outcomes for any bundle. The canonical-JSON re-emission mirrors
// internal/hasher.CanonicalJSON exactly: keys sorted at every level,
// compact, no HTML escaping, no trailing newline.
//
// PowerShell 5.1+ compatible (Windows 10/Server 2016+ default), no
// dependencies on jq, OpenSSL, or anything outside the box.
//
// Note: this Go raw string cannot contain backticks (PowerShell's escape
// character). The script is deliberately written without backtick escapes.
func generateVerifyPowerShellScript() string {
	return `# statedrift Evidence Bundle Verifier (PowerShell)
# Independently verifies the hash chain integrity of a statedrift export bundle.
# Compatible with PowerShell 5.1+ (Windows 10/Server 2016 and later) and
# PowerShell 7+ on any platform. Uses only built-in cmdlets.
#
# Usage:
#   pwsh ./verify.ps1            # full output
#   pwsh ./verify.ps1 -Quiet     # PASS/FAIL only
#   pwsh ./verify.ps1 -Verbose   # print each snapshot's hash
[CmdletBinding()]
param(
    [switch]$Quiet
)
# Honor the common -Verbose switch from CmdletBinding so the documented
# usage line above works. PowerShell sets $VerbosePreference to 'Continue'
# in the script's scope when the caller passes -Verbose.
$VerboseOutput = $VerbosePreference -eq 'Continue'

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ChainDir = Join-Path $ScriptDir 'chain'

$UseColor = $true
if ($env:NO_COLOR) { $UseColor = $false }

function Write-Plain {
    param([string]$Text = '')
    [Console]::Out.WriteLine($Text)
}

function Write-Color {
    param([string]$Text, [string]$Color = 'red')
    if ($UseColor) {
        $esc = [char]27
        $code = if ($Color -eq 'green') { '32' } elseif ($Color -eq 'red') { '31' } else { '0' }
        [Console]::Out.WriteLine($esc + '[' + $code + 'm' + $Text + $esc + '[0m')
    } else {
        [Console]::Out.WriteLine($Text)
    }
}

# Read manifest
$ManifestPath = Join-Path $ScriptDir 'manifest.json'
if (-not (Test-Path $ManifestPath)) {
    Write-Plain 'ERROR: manifest.json not found'
    exit 1
}

$Manifest = Get-Content -Raw -Path $ManifestPath | ConvertFrom-Json

$HostName       = $Manifest.hostname
$RangeStart     = $Manifest.range_start
$RangeEnd       = $Manifest.range_end
$ExpectedCount  = [int]$Manifest.snapshot_count

$ManifestRoot = ''
$ManifestHead = ''
if ($Manifest.PSObject.Properties.Name -contains 'chain_root_hash' -and $Manifest.chain_root_hash) {
    $ManifestRoot = [string]$Manifest.chain_root_hash
}
if ($Manifest.PSObject.Properties.Name -contains 'chain_head_hash' -and $Manifest.chain_head_hash) {
    $ManifestHead = [string]$Manifest.chain_head_hash
}

if (-not $Quiet) {
    Write-Plain 'statedrift Evidence Bundle Verifier'
    Write-Plain '===================================='
    Write-Plain ''
    Write-Plain ('Host:      ' + $HostName)
    Write-Plain ('Period:    ' + $RangeStart)
    Write-Plain ('           ' + $RangeEnd)
    Write-Plain ('Expected:  ' + $ExpectedCount + ' snapshots')
    Write-Plain ''
}

# Collect snapshot files
$SnapshotFiles = @()
if (Test-Path $ChainDir) {
    $SnapshotFiles = @(Get-ChildItem -Path $ChainDir -Filter '*.json' -File | Sort-Object Name)
}
$ActualCount = $SnapshotFiles.Count

if ($ActualCount -eq 0) {
    if ($Quiet) { Write-Plain 'FAIL' } else { Write-Plain 'ERROR: No snapshot files found in chain/' }
    exit 1
}

if ($ActualCount -ne $ExpectedCount) {
    if ($Quiet) {
        Write-Plain 'FAIL'
    } else {
        Write-Plain ('ERROR: manifest claims ' + $ExpectedCount + ' snapshots but found ' + $ActualCount)
    }
    exit 1
}

if (-not $Quiet) {
    Write-Plain ('Found:     ' + $ActualCount + ' snapshots')
    Write-Plain ''
}

# Canonical JSON helpers — must produce the same byte stream as
# internal/hasher.CanonicalJSON. Keys sorted at every level, compact,
# no trailing newline, no HTML escaping. U+2028 / U+2029 pass through
# literally (matching jq and the Go hasher's post-substitution).
function ConvertTo-CanonicalJsonString {
    param([string]$Value)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int]$ch
        if ($ch -eq '"') {
            [void]$sb.Append('\"')
        } elseif ($ch -eq '\') {
            [void]$sb.Append('\\')
        } elseif ($code -eq 8)  { [void]$sb.Append('\b') }
        elseif ($code -eq 9)  { [void]$sb.Append('\t') }
        elseif ($code -eq 10) { [void]$sb.Append('\n') }
        elseif ($code -eq 12) { [void]$sb.Append('\f') }
        elseif ($code -eq 13) { [void]$sb.Append('\r') }
        elseif ($code -lt 32) {
            [void]$sb.AppendFormat('\u{0:x4}', $code)
        } else {
            [void]$sb.Append($ch)
        }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

# Iterative canonical-JSON emitter. Walks $Root using an explicit work
# stack so deeply-nested snapshots don't blow the call stack on pwsh-on-
# Linux, where each PowerShell function frame carries enough overhead to
# overflow within a few dozen levels. Frame kinds:
#   ('v', $obj)  — emit the canonical form of $obj
#   ('s', $str)  — emit a JSON-escaped string literal
#   ('l', $text) — append literal text (used for separators / closers)
# Object keys are sorted with ordinal byte comparison to match Go's
# sort.Strings and jq -cS. Sort-Object Name is culture-aware AND
# case-insensitive by default, which produces a different order on
# mixed-case keys like /proc/net/snmp's "ForwDatagrams" / "Forwarding"
# and breaks the chain hash.
function ConvertTo-CanonicalJson {
    param($Root)
    $sb = New-Object System.Text.StringBuilder
    $stack = New-Object 'System.Collections.Generic.Stack[object]'
    [void]$stack.Push(@('v', $Root))

    while ($stack.Count -gt 0) {
        $frame = $stack.Pop()
        $kind = $frame[0]

        if ($kind -eq 'l') {
            [void]$sb.Append([string]$frame[1])
            continue
        }
        if ($kind -eq 's') {
            [void]$sb.Append((ConvertTo-CanonicalJsonString -Value ([string]$frame[1])))
            continue
        }

        # kind = 'v'
        $obj = $frame[1]
        if ($null -eq $obj) {
            [void]$sb.Append('null')
        } elseif ($obj -is [bool]) {
            if ($obj) { [void]$sb.Append('true') } else { [void]$sb.Append('false') }
        } elseif ($obj -is [string]) {
            [void]$sb.Append((ConvertTo-CanonicalJsonString -Value $obj))
        } elseif ($obj -is [int] -or $obj -is [long] -or $obj -is [int16] -or $obj -is [byte] -or $obj -is [uint32] -or $obj -is [uint64]) {
            [void]$sb.Append([string]$obj)
        } elseif ($obj -is [double] -or $obj -is [single] -or $obj -is [decimal]) {
            [void]$sb.Append($obj.ToString([System.Globalization.CultureInfo]::InvariantCulture))
        } elseif ($obj -is [System.Collections.IList]) {
            [void]$sb.Append('[')
            [void]$stack.Push(@('l', ']'))
            $items = @($obj)
            for ($i = $items.Count - 1; $i -ge 0; $i--) {
                [void]$stack.Push(@('v', $items[$i]))
                if ($i -gt 0) { [void]$stack.Push(@('l', ',')) }
            }
        } else {
            [void]$sb.Append('{')
            [void]$stack.Push(@('l', '}'))
            $namesArr = [string[]]@($obj.PSObject.Properties.Name)
            [Array]::Sort($namesArr, [System.StringComparer]::Ordinal)
            for ($i = $namesArr.Count - 1; $i -ge 0; $i--) {
                $name = $namesArr[$i]
                [void]$stack.Push(@('v', $obj.$name))
                [void]$stack.Push(@('l', ':'))
                [void]$stack.Push(@('s', $name))
                if ($i -gt 0) { [void]$stack.Push(@('l', ',')) }
            }
        }
    }

    return $sb.ToString()
}

function Get-SnapshotHash {
    param([string]$JsonPath)
    $raw = Get-Content -Raw -Path $JsonPath
    $obj = $raw | ConvertFrom-Json
    $canonical = ConvertTo-CanonicalJson -Obj $obj
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonical)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha.ComputeHash($bytes)
    } finally {
        $sha.Dispose()
    }
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $hashBytes) { [void]$sb.AppendFormat('{0:x2}', $b) }
    return $sb.ToString()
}

# Verify hash chain
$PrevHash = ''
$PrevFile = ''
$FirstHash = ''
$Verified = 0
$Broken = $false
$BrokenAt = ''

foreach ($snap in $SnapshotFiles) {
    $filename = $snap.Name
    $rawJson = Get-Content -Raw -Path $snap.FullName
    $snapObj = $rawJson | ConvertFrom-Json
    $snapPrevHash = [string]$snapObj.prev_hash
    $currentHash = Get-SnapshotHash -JsonPath $snap.FullName

    if ($Verified -gt 0) {
        if ($snapPrevHash -ne $PrevHash) {
            if (-not $Quiet) {
                Write-Plain ('BREAK at ' + $filename)
                Write-Plain ('  Expected prev_hash: ' + $PrevHash)
                Write-Plain ('  Found prev_hash:    ' + $snapPrevHash)
            }
            $Broken = $true
            $BrokenAt = $filename
            break
        }
    } else {
        $FirstHash = $currentHash
    }

    if ($VerboseOutput -and -not $Quiet) {
        Write-Plain ('  ' + $filename + ' ' + $currentHash)
    }

    $PrevFile = $filename
    $PrevHash = $currentHash
    $Verified = $Verified + 1
}

# Cross-check manifest root/head hashes
$ManifestMismatch = ''
if (-not $Broken) {
    if ($ManifestRoot -and $ManifestRoot -ne $FirstHash) {
        $ManifestMismatch = 'chain_root_hash claims ' + $ManifestRoot + ' but first snapshot hashes to ' + $FirstHash
    } elseif ($ManifestHead -and $ManifestHead -ne $PrevHash) {
        $ManifestMismatch = 'chain_head_hash claims ' + $ManifestHead + ' but last snapshot hashes to ' + $PrevHash
    }
}

Write-Plain ''
if ($Broken) {
    if ($Quiet) {
        Write-Plain 'FAIL'
    } else {
        Write-Color -Text 'RESULT: INTEGRITY VIOLATION' -Color 'red'
        Write-Plain ''
        Write-Plain ('  ' + $PrevFile + ' may have been modified -- its hash no longer matches')
        Write-Plain ('  the prev_hash recorded in ' + $BrokenAt + '.')
        Write-Plain ''
        $clean = $Verified - 1
        if ($clean -gt 0) {
            Write-Plain ('  ' + $clean + ' of ' + $ActualCount + ' snapshot(s) verified intact (before ' + $PrevFile + ').')
        } else {
            Write-Plain '  No snapshots before the break point are verified intact.'
        }
        Write-Plain ('  ' + $PrevFile + ' and later cannot be trusted.')
    }
    exit 1
} elseif ($ManifestMismatch) {
    if ($Quiet) {
        Write-Plain 'FAIL'
    } else {
        Write-Plain ('Chain:    OK (' + $Verified + ' snapshots internally consistent)')
        Write-Plain 'Manifest: MISMATCH'
        Write-Color -Text 'RESULT: INTEGRITY VIOLATION' -Color 'red'
        Write-Plain ''
        Write-Plain '  The chain is internally consistent, but its first or last'
        Write-Plain '  snapshot hash no longer matches what manifest.json claims.'
        Write-Plain '  The bundle as a whole has been substituted, replaced with a'
        Write-Plain '  different valid chain, or the manifest was edited after creation.'
        Write-Plain ''
        Write-Plain ('  detail: ' + $ManifestMismatch)
    }
    exit 1
} else {
    if ($Quiet) {
        Write-Plain 'PASS'
    } else {
        Write-Plain ('Verified: ' + $Verified + ' snapshots')
        Write-Color -Text 'RESULT: INTEGRITY VERIFIED' -Color 'green'
        Write-Plain ''
        Write-Plain 'All snapshots are consistent with their recorded hashes.'
        Write-Plain 'No tampering detected.'
    }
    exit 0
}
`
}

func generateReadme(m Manifest) string {
	return fmt.Sprintf(`statedrift Evidence Bundle
==========================

This bundle contains tamper-evident infrastructure snapshots captured by
the statedrift agent. Each snapshot records the operational state of the host
at a specific point in time, and the entire chain is cryptographically
linked so that any modification is detectable.

Host:           %s
Period:         %s to %s
Snapshots:      %d
Created:        %s

How to verify
-------------
Two verifiers are included; pick the one that matches your platform.
Both produce identical PASS/FAIL outcomes for any bundle.

Linux / macOS:

    tar xzf <bundle>.tar.gz
    cd <bundle>/
    ./verify.sh

    Requires: bash, sha256sum, jq (all preinstalled on most distributions;
    on macOS install jq via Homebrew). No statedrift installation needed.

Windows (PowerShell 5.1+, ships with Windows 10 and Server 2016+):

    tar -xzf <bundle>.tar.gz
    cd <bundle>
    pwsh ./verify.ps1
    # or, on stock Windows without pwsh installed:
    powershell -ExecutionPolicy Bypass -File .\verify.ps1

    Requires: only built-in PowerShell cmdlets. No jq, OpenSSL, WSL,
    or external tools needed.

Both scripts independently recompute every snapshot hash from the canonical
JSON form and walk the prev_hash chain. They also cross-check
manifest.json's chain_root_hash / chain_head_hash, which detects
whole-bundle substitution that an internal-only chain walk would miss.

Flags (both scripts):
    --quiet / -Quiet         PASS or FAIL only, suitable for CI
    --verbose / -VerboseOutput  Print each snapshot's recomputed hash

What's captured
---------------
Each snapshot records:
- Host identity (hostname, OS, kernel version)
- Network interfaces and their addresses
- Routing table
- DNS configuration
- Selected kernel parameters (sysctl)
- Installed packages and versions
- Systemd service states
- Listening TCP ports

What's NOT captured:
- Packet payloads or traffic content
- File contents
- User data, environment variables, or secrets
- Application-level state

For more information, visit: https://github.com/statedrift/statedrift
`, m.Hostname,
		m.RangeStart.Format("2006-01-02 15:04:05 UTC"),
		m.RangeEnd.Format("2006-01-02 15:04:05 UTC"),
		m.SnapshotCount,
		m.CreatedAt.Format("2006-01-02 15:04:05 UTC"),
	)
}
