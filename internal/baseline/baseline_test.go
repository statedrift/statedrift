package baseline

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/statedrift/statedrift/internal/collector"
	"github.com/statedrift/statedrift/internal/hasher"
)

func makeFixtureSnapshot() *collector.Snapshot {
	return &collector.Snapshot{
		SchemaVersion:  "0.4",
		Version:        "0.4.0",
		SnapshotID:     "snap-baseline-test",
		Timestamp:      time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC),
		PrevHash:       hasher.GenesisHash,
		Host:           collector.Host{Hostname: "baseline-test", OS: "Linux", Kernel: "5.15.0"},
		KernelParams:   map[string]string{"net.ipv4.ip_forward": "0"},
		Packages:       map[string]string{},
		Services:       map[string]string{},
		ListeningPorts: []collector.ListeningPort{},
		Network: collector.Network{
			Interfaces: []collector.Interface{},
			Routes:     []collector.Route{},
			DNS:        collector.DNS{},
		},
	}
}

func TestNewAndWriteRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)

	snap := makeFixtureSnapshot()
	pin, err := New(snap, "0.4.0")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if pin.SnapshotHash == "" {
		t.Fatal("SnapshotHash empty")
	}
	if pin.ToolVersion != "0.4.0" {
		t.Errorf("ToolVersion = %q, want 0.4.0", pin.ToolVersion)
	}
	if pin.PinnedAt.IsZero() {
		t.Error("PinnedAt is zero")
	}

	if err := Write(path, pin); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if got.SnapshotHash != pin.SnapshotHash {
		t.Errorf("SnapshotHash mismatch after round-trip: got %q want %q", got.SnapshotHash, pin.SnapshotHash)
	}
	if got.Snapshot.Host.Hostname != snap.Host.Hostname {
		t.Errorf("Snapshot.Host.Hostname mismatch: got %q want %q", got.Snapshot.Host.Hostname, snap.Host.Hostname)
	}
}

func TestExistsReportsCorrectly(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)

	if Exists(path) {
		t.Error("Exists should be false before any pin")
	}

	pin, err := New(makeFixtureSnapshot(), "0.4.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(path, pin); err != nil {
		t.Fatal(err)
	}

	if !Exists(path) {
		t.Error("Exists should be true after Write")
	}
}

func TestReadOnMissingFileReturnsErrNoBaseline(t *testing.T) {
	dir := t.TempDir()
	_, err := Read(Path(dir))
	if !errors.Is(err, ErrNoBaseline) {
		t.Errorf("expected ErrNoBaseline, got %v", err)
	}
}

func TestReadOnTamperedFileReturnsErrCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)

	pin, err := New(makeFixtureSnapshot(), "0.4.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(path, pin); err != nil {
		t.Fatal(err)
	}

	// Mutate the embedded snapshot's hostname and write back without
	// recomputing SnapshotHash. Read must catch the mismatch.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	rawSnap := raw["snapshot"].(map[string]interface{})
	rawHost := rawSnap["host"].(map[string]interface{})
	rawHost["hostname"] = "tampered"
	tampered, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0644); err != nil {
		t.Fatal(err)
	}

	_, err = Read(path)
	if !errors.Is(err, ErrCorrupt) {
		t.Errorf("expected ErrCorrupt, got %v", err)
	}
}

func TestReadOnInvalidJSONReturnsParseError(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)

	if err := os.WriteFile(path, []byte("not json at all"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Read(path)
	if err == nil {
		t.Fatal("expected error on invalid JSON")
	}
	// Should NOT be ErrNoBaseline (file exists) or ErrCorrupt (didn't get
	// far enough to hash-check); plain parse error is fine.
	if errors.Is(err, ErrNoBaseline) || errors.Is(err, ErrCorrupt) {
		t.Errorf("expected plain parse error, got typed error: %v", err)
	}
}

func TestWriteAtomicLeavesNoTempOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)

	pin, err := New(makeFixtureSnapshot(), "0.4.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(path, pin); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != Filename {
			t.Errorf("unexpected file in baseline dir: %q", e.Name())
		}
	}
}

func TestRemove(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)

	// Remove on missing → ErrNoBaseline
	if err := Remove(path); !errors.Is(err, ErrNoBaseline) {
		t.Errorf("Remove on missing: expected ErrNoBaseline, got %v", err)
	}

	// Pin, then remove
	pin, err := New(makeFixtureSnapshot(), "0.4.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(path, pin); err != nil {
		t.Fatal(err)
	}
	if err := Remove(path); err != nil {
		t.Errorf("Remove after pin: %v", err)
	}
	if Exists(path) {
		t.Error("file still exists after Remove")
	}

	// Remove again → ErrNoBaseline
	if err := Remove(path); !errors.Is(err, ErrNoBaseline) {
		t.Errorf("second Remove: expected ErrNoBaseline, got %v", err)
	}
}

func TestNewRejectsNilSnapshot(t *testing.T) {
	if _, err := New(nil, "0.4.0"); err == nil {
		t.Error("New(nil) should return an error")
	}
}

func TestWriteRejectsNilPin(t *testing.T) {
	dir := t.TempDir()
	if err := Write(Path(dir), nil); err == nil {
		t.Error("Write(nil pin) should return an error")
	}
}

func TestPathLayout(t *testing.T) {
	got := Path("/var/lib/statedrift")
	want := filepath.Join("/var/lib/statedrift", Filename)
	if got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
}

func TestWriteIsOverwriteByDefault(t *testing.T) {
	// Storage layer is policy-free: Write always overwrites. The
	// "refuse to overwrite without --force" rule lives in
	// cmdBaselinePin, not here. Confirms no implicit guard surprises
	// callers.
	dir := t.TempDir()
	path := Path(dir)

	pin1, err := New(makeFixtureSnapshot(), "0.4.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(path, pin1); err != nil {
		t.Fatal(err)
	}

	snap2 := makeFixtureSnapshot()
	snap2.Host.Hostname = "different"
	pin2, err := New(snap2, "0.4.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(path, pin2); err != nil {
		t.Fatalf("second Write should succeed (overwrite): %v", err)
	}

	got, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Snapshot.Host.Hostname != "different" {
		t.Errorf("expected overwritten content, got %q", got.Snapshot.Host.Hostname)
	}
}
