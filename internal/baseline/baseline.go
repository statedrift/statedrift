// Package baseline manages the compliance-grade pinned snapshot used by
// `statedrift baseline check`. A baseline is one snapshot, copied
// verbatim into <store>/baseline.json with a small metadata wrapper, and
// is independent of the hash chain — pinning does not append, does not
// bump head, and does not interact with `verify`.
//
// Scope is strictly compliance baselines: "different from approved
// state?" Behavioral baselines (time/load/cycle expectations) are
// deliberately deferred to v0.5+ via `when`/`expected` clauses on rules.
// See docs/V04_BASELINE_PLAN.md "Out of scope — behavioral baselines"
// for the full rationale.
package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/statedrift/statedrift/internal/collector"
	"github.com/statedrift/statedrift/internal/hasher"
)

// ErrNoBaseline is returned by Read when no baseline is pinned (the
// baseline.json file does not exist). Callers can use errors.Is to
// distinguish this from generic I/O errors and produce a clear "no
// baseline pinned — run statedrift baseline pin <ref>" message.
var ErrNoBaseline = errors.New("no baseline pinned")

// ErrCorrupt is returned by Read when the embedded snapshot's
// canonical-JSON hash does not match the recorded SnapshotHash. This
// signals tampering or filesystem corruption — the baseline file should
// be re-pinned from a known-good snapshot rather than trusted.
var ErrCorrupt = errors.New("baseline file is corrupt: snapshot hash mismatch")

// Filename is the bare basename of the baseline file. Combine with the
// store's base path via Path().
const Filename = "baseline.json"

// Pin is the on-disk representation of a pinned baseline snapshot.
// The wrapper carries pin metadata (when, by whom, by which tool
// version) alongside a verbatim snapshot copy. The snapshot is the
// authoritative reference; the wrapper exists so pin metadata does not
// pollute the chain (which would corrupt the chain hash if a wrapped
// snapshot were ever fed back into it).
type Pin struct {
	// PinnedAt is the wall-clock time the pin was created. Distinct
	// from Snapshot.Timestamp, which is when the snapshot was
	// originally captured.
	PinnedAt time.Time `json:"pinned_at"`

	// PinnedByUID is the OS uid of the process that created the pin.
	// Recorded for audit trail; not used for authorization.
	PinnedByUID int `json:"pinned_by_uid"`

	// SnapshotHash is the canonical-JSON SHA-256 of Snapshot, as
	// computed by hasher.Hash. Read() verifies this matches the
	// embedded snapshot before returning, surfacing tampering as
	// ErrCorrupt.
	SnapshotHash string `json:"snapshot_hash"`

	// ToolVersion is the statedrift binary version that created the
	// pin. Future readers can use this to detect cross-version
	// baseline use.
	ToolVersion string `json:"tool_version"`

	// Snapshot is the full pinned snapshot, copied verbatim from the
	// chain. Self-contained so the baseline survives chain GC.
	Snapshot *collector.Snapshot `json:"snapshot"`
}

// Path returns the canonical baseline file path inside the store's
// base directory.
func Path(basePath string) string {
	return filepath.Join(basePath, Filename)
}

// Exists reports whether a baseline file is present at the given path.
// Distinct from Read so callers can probe without paying the JSON parse
// + hash verification cost.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// New constructs a Pin wrapping the given snapshot, computing
// SnapshotHash from snap and stamping PinnedAt/PinnedByUID/ToolVersion
// from the current process. The returned Pin is ready to Write.
func New(snap *collector.Snapshot, toolVersion string) (*Pin, error) {
	if snap == nil {
		return nil, errors.New("baseline: nil snapshot")
	}
	h, err := hasher.Hash(snap)
	if err != nil {
		return nil, fmt.Errorf("hashing snapshot: %w", err)
	}
	return &Pin{
		PinnedAt:     time.Now().UTC(),
		PinnedByUID:  os.Getuid(),
		SnapshotHash: h,
		ToolVersion:  toolVersion,
		Snapshot:     snap,
	}, nil
}

// Read loads the baseline from path, parses it, and verifies that
// hasher.Hash(pin.Snapshot) equals pin.SnapshotHash. Returns
// ErrNoBaseline if the file does not exist, ErrCorrupt if the embedded
// snapshot's hash does not match, or a wrapped error for any other I/O
// or parse failure.
func Read(path string) (*Pin, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoBaseline
		}
		return nil, fmt.Errorf("reading baseline: %w", err)
	}
	var p Pin
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing baseline: %w", err)
	}
	if p.Snapshot == nil {
		return nil, fmt.Errorf("parsing baseline: snapshot field is missing")
	}
	got, err := hasher.Hash(p.Snapshot)
	if err != nil {
		return nil, fmt.Errorf("verifying baseline: %w", err)
	}
	if got != p.SnapshotHash {
		return nil, fmt.Errorf("%w: recorded %s, recomputed %s", ErrCorrupt, p.SnapshotHash, got)
	}
	return &p, nil
}

// Write serializes pin to path atomically: the data is written to a
// same-directory temp file and renamed into place, so a crash mid-write
// leaves either the old file intact or the new file complete — never a
// partial write at the destination.
//
// Write does NOT enforce overwrite policy — callers (cmdBaselinePin)
// own the "refuse to overwrite without --force" check. Letting Write
// always overwrite keeps the storage layer simple and matches how
// store.WriteHead behaves.
func Write(path string, pin *Pin) error {
	if pin == nil {
		return errors.New("baseline: nil pin")
	}
	data, err := json.MarshalIndent(pin, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}
	return writeFileAtomic(path, data, 0644)
}

// Remove deletes the baseline file at path. Returns ErrNoBaseline if
// the file does not exist (so callers can distinguish "nothing to
// unpin" from a real error). Other errors are wrapped and returned.
func Remove(path string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNoBaseline
		}
		return fmt.Errorf("removing baseline: %w", err)
	}
	return nil
}

// writeFileAtomic mirrors internal/store/store.go::writeFileAtomic. Kept
// local rather than exported from store to avoid an import cycle (store
// → baseline would be undesirable, and baseline doesn't otherwise need
// store).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-baseline-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
