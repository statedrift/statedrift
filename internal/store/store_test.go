package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/statedrift/statedrift/internal/collector"
	"github.com/statedrift/statedrift/internal/hasher"
)

func makeSnap(prevHash string, ts time.Time) *collector.Snapshot {
	return &collector.Snapshot{
		Version:    "0.1.0",
		SnapshotID: "snap-" + ts.Format("20060102-150405"),
		Timestamp:  ts,
		PrevHash:   prevHash,
		Host:       collector.Host{Hostname: "testhost"},
		KernelParams: map[string]string{
			"net.ipv4.ip_forward": "0",
		},
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

func TestInitCreatesDirectoryStructure(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)

	if err := s.Init(); err != nil {
		t.Fatalf("Init() error: %v", err)
	}

	if _, err := os.Stat(s.ChainDir()); err != nil {
		t.Errorf("chain dir not created: %v", err)
	}
}

func TestInitFailsIfAlreadyInitialized(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)

	if err := s.Init(); err != nil {
		t.Fatalf("first Init() error: %v", err)
	}
	if err := s.Init(); err == nil {
		t.Error("second Init() should return error on already-initialized store")
	}
}

func TestSaveWritesFileAndUpdatesHead(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	ts := time.Date(2026, 3, 22, 10, 0, 0, 0, time.UTC)
	snap := makeSnap(hasher.GenesisHash, ts)

	hash, err := s.Save(snap)
	if err != nil {
		t.Fatalf("Save() error: %v", err)
	}
	if hash == "" {
		t.Error("Save() returned empty hash")
	}

	head := s.ReadHead()
	if head != hash {
		t.Errorf("head = %q, want %q", head, hash)
	}
}

func TestReadHeadReturnsGenesisHashForEmptyStore(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	head := s.ReadHead()
	if head != hasher.GenesisHash {
		t.Errorf("ReadHead() = %q, want GenesisHash", head)
	}
}

func TestListReturnsChronologicalOrder(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	base := time.Date(2026, 3, 22, 10, 0, 0, 0, time.UTC)

	snap1 := makeSnap(hasher.GenesisHash, base)
	h1, err := s.Save(snap1)
	if err != nil {
		t.Fatalf("Save snap1: %v", err)
	}

	snap2 := makeSnap(h1, base.Add(time.Second))
	h2, err := s.Save(snap2)
	if err != nil {
		t.Fatalf("Save snap2: %v", err)
	}

	snap3 := makeSnap(h2, base.Add(2*time.Second))
	_, err = s.Save(snap3)
	if err != nil {
		t.Fatalf("Save snap3: %v", err)
	}

	entries, err := s.List()
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("List() returned %d entries, want 3", len(entries))
	}

	for i := 1; i < len(entries); i++ {
		if !entries[i].Snapshot.Timestamp.After(entries[i-1].Snapshot.Timestamp) {
			t.Errorf("entries not in chronological order at index %d", i)
		}
	}
}

func TestFindByPrefixExactAndAmbiguous(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	base := time.Date(2026, 3, 22, 11, 0, 0, 0, time.UTC)
	snap1 := makeSnap(hasher.GenesisHash, base)
	h1, err := s.Save(snap1)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Find with full hash
	entry, err := s.FindByPrefix(h1)
	if err != nil {
		t.Fatalf("FindByPrefix full hash: %v", err)
	}
	if entry.Hash != h1 {
		t.Errorf("FindByPrefix returned hash %q, want %q", entry.Hash, h1)
	}

	// Find with a short unique prefix
	entry, err = s.FindByPrefix(h1[:8])
	if err != nil {
		t.Fatalf("FindByPrefix short prefix: %v", err)
	}
	if entry.Hash != h1 {
		t.Errorf("FindByPrefix short prefix returned wrong hash")
	}
}

func TestFindByPrefixNoMatch(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	base := time.Date(2026, 3, 22, 12, 0, 0, 0, time.UTC)
	snap := makeSnap(hasher.GenesisHash, base)
	if _, err := s.Save(snap); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, err := s.FindByPrefix("deadbeef")
	if err == nil {
		t.Error("FindByPrefix should return error for no match")
	}
}

func TestVerifyChainValid(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	base := time.Date(2026, 3, 22, 13, 0, 0, 0, time.UTC)
	h := hasher.GenesisHash

	for i := 0; i < 3; i++ {
		snap := makeSnap(h, base.Add(time.Duration(i)*time.Second))
		var err error
		h, err = s.Save(snap)
		if err != nil {
			t.Fatalf("Save snap %d: %v", i, err)
		}
	}

	_, brokenAt, err := s.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if brokenAt != -1 {
		t.Errorf("VerifyChain brokenAt = %d, want -1 (valid chain)", brokenAt)
	}
}

// TestManualTailDeletionBreaksNextSnap documents the known limitation:
// deleting snapshot files from the tail of the chain leaves the head file
// stale. The next Save() chains from the stale head hash, which no longer
// exists in the store, causing VerifyChain to break at the new snapshot.
// The fix is to run Reset()+Init() or use GC instead of manual deletion.
func TestManualTailDeletionBreaksNextSnap(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	base := time.Date(2026, 3, 22, 14, 0, 0, 0, time.UTC)

	snap1 := makeSnap(hasher.GenesisHash, base)
	h1, err := s.Save(snap1)
	if err != nil {
		t.Fatalf("Save snap1: %v", err)
	}
	snap2 := makeSnap(h1, base.Add(time.Second))
	h2, err := s.Save(snap2)
	if err != nil {
		t.Fatalf("Save snap2: %v", err)
	}
	snap3 := makeSnap(h2, base.Add(2*time.Second))
	if _, err := s.Save(snap3); err != nil {
		t.Fatalf("Save snap3: %v", err)
	}

	// Manually delete the last two snapshot files (simulates user running rm).
	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	os.Remove(entries[1].Path)
	os.Remove(entries[2].Path)

	// head still points to snap3 (the deleted file).
	// The next Save reads this stale head and chains from it.
	snap4 := makeSnap(s.ReadHead(), base.Add(3*time.Second))
	if _, err := s.Save(snap4); err != nil {
		t.Fatalf("Save snap4: %v", err)
	}

	// VerifyChain must detect the break: snap4.prev_hash references a
	// snapshot that no longer exists, so it doesn't match snap1's hash.
	_, brokenAt, err := s.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if brokenAt == -1 {
		t.Error("VerifyChain should detect break after manual tail deletion, but returned -1")
	}
}

func TestVerifyChainDetectsTamperedSnapshot(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	base := time.Date(2026, 3, 22, 14, 0, 0, 0, time.UTC)

	snap1 := makeSnap(hasher.GenesisHash, base)
	h1, err := s.Save(snap1)
	if err != nil {
		t.Fatalf("Save snap1: %v", err)
	}

	snap2 := makeSnap(h1, base.Add(time.Second))
	h2, err := s.Save(snap2)
	if err != nil {
		t.Fatalf("Save snap2: %v", err)
	}

	snap3 := makeSnap(h2, base.Add(2*time.Second))
	if _, err := s.Save(snap3); err != nil {
		t.Fatalf("Save snap3: %v", err)
	}

	// Find snapshot 2's file and tamper it
	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Tamper entry[1] (middle snapshot) — change a kernel param value
	tampered := entries[1].Snapshot
	tampered.KernelParams["net.ipv4.ip_forward"] = "TAMPERED"

	data, err := json.MarshalIndent(tampered, "", "  ")
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	if err := os.WriteFile(entries[1].Path, data, 0644); err != nil {
		t.Fatalf("write tampered file: %v", err)
	}

	// VerifyChain should detect the break
	_, brokenAt, err := s.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if brokenAt == -1 {
		t.Error("VerifyChain should have detected tampered snapshot but returned -1")
	}
}

func TestGCZeroRetentionKeepsAll(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) // old enough to be deleted by any positive retention
	snap1 := makeSnap(hasher.GenesisHash, base)
	h1, err := s.Save(snap1)
	if err != nil {
		t.Fatalf("Save snap1: %v", err)
	}
	snap2 := makeSnap(h1, base.Add(time.Second))
	if _, err := s.Save(snap2); err != nil {
		t.Fatalf("Save snap2: %v", err)
	}

	result, err := s.GC(0)
	if err != nil {
		t.Fatalf("GC(0) error: %v", err)
	}
	if result.Removed != 0 {
		t.Errorf("GC(0) removed %d snapshots, want 0 (keep-forever)", result.Removed)
	}

	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("after GC(0): %d snapshots remain, want 2", len(entries))
	}
}

func TestSaveNoCollisionSameSecond(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Two snapshots with identical second-level timestamps (differ only in nanoseconds).
	ts := time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)
	snap1 := makeSnap(hasher.GenesisHash, ts)
	h1, err := s.Save(snap1)
	if err != nil {
		t.Fatalf("Save snap1: %v", err)
	}

	ts2 := ts.Add(500 * time.Millisecond) // same second, different nanoseconds
	snap2 := makeSnap(h1, ts2)
	if _, err := s.Save(snap2); err != nil {
		t.Fatalf("Save snap2: %v", err)
	}

	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 distinct snapshots, got %d (collision?)", len(entries))
	}
}

func TestWriteFileAtomicNeverLeavesPartialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.json")

	data := []byte(`{"ok":true}`)
	if err := writeFileAtomic(path, data, 0644); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", got, data)
	}

	// No temp files should remain in the directory.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "target.json" {
			t.Errorf("unexpected file left in dir: %s", e.Name())
		}
	}
}
