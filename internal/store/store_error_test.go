package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/statedrift/statedrift/internal/hasher"
)

func TestIsInitialized(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if s.IsInitialized() {
		t.Error("IsInitialized() = true before Init()")
	}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !s.IsInitialized() {
		t.Error("IsInitialized() = false after Init()")
	}
}

func TestResetRemovesStore(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := s.Save(makeSnap(hasher.GenesisHash, time.Now())); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := s.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if s.IsInitialized() {
		t.Error("store still initialized after Reset()")
	}
	if _, err := os.Stat(s.HeadFile()); !os.IsNotExist(err) {
		t.Error("head file still present after Reset()")
	}
	// Reset on an already-clean store is a no-op, not an error.
	if err := s.Reset(); err != nil {
		t.Errorf("second Reset() errored: %v", err)
	}
}

func TestWriteHeadAndReadHead(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	want := "abc123def456"
	if err := s.WriteHead(want); err != nil {
		t.Fatalf("WriteHead: %v", err)
	}
	if got := s.ReadHead(); got != want {
		t.Errorf("ReadHead() = %q, want %q", got, want)
	}
}

func TestWriteFileAtomicFailsOnMissingDir(t *testing.T) {
	// Parent directory does not exist → CreateTemp fails, error propagates,
	// and no destination file is created.
	missing := filepath.Join(t.TempDir(), "no-such-dir", "target")
	if err := writeFileAtomic(missing, []byte("x"), 0644); err == nil {
		t.Error("writeFileAtomic to a missing directory should error")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Error("destination file should not exist after a failed atomic write")
	}
}

func TestLoadSnapshotMissingFile(t *testing.T) {
	if _, err := LoadSnapshot(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("LoadSnapshot of a missing file should error")
	}
}

func TestLoadSnapshotInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadSnapshot(path); err == nil {
		t.Error("LoadSnapshot of malformed JSON should error")
	}
}

func TestListErrorsOnUninitializedStore(t *testing.T) {
	s := New(t.TempDir()) // never Init()'d → no chain dir
	if _, err := s.List(); err == nil {
		t.Error("List() on an uninitialized store should error")
	}
}

func TestVerifyChainErrorsOnUninitializedStore(t *testing.T) {
	s := New(t.TempDir())
	if _, _, err := s.VerifyChain(); err == nil {
		t.Error("VerifyChain() on an uninitialized store should error")
	}
}

func TestGCErrorsOnUninitializedStore(t *testing.T) {
	s := New(t.TempDir())
	if _, err := s.GC(30); err == nil {
		t.Error("GC() on an uninitialized store should error")
	}
}

func TestFindByPrefixErrorsOnUninitializedStore(t *testing.T) {
	s := New(t.TempDir())
	if _, err := s.FindByPrefix("abc"); err == nil {
		t.Error("FindByPrefix() on an uninitialized store should error")
	}
}

// When the base path is a regular file, both Init and Save fail to create the
// directory structure beneath it (ENOTDIR), exercising their mkdir error paths.
func TestInitAndSaveErrorWhenBasePathIsFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s := New(f)
	if err := s.Init(); err == nil {
		t.Error("Init() should error when base path is a file")
	}
	if _, err := s.Save(makeSnap(hasher.GenesisHash, time.Now())); err == nil {
		t.Error("Save() should error when base path is a file")
	}
}

func TestFindByPrefixAmbiguous(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	base := time.Date(2026, 3, 22, 11, 0, 0, 0, time.UTC)
	h1, err := s.Save(makeSnap(hasher.GenesisHash, base))
	if err != nil {
		t.Fatalf("Save snap1: %v", err)
	}
	if _, err := s.Save(makeSnap(h1, base.Add(time.Second))); err != nil {
		t.Fatalf("Save snap2: %v", err)
	}
	// Empty prefix matches every snapshot → ambiguous.
	if _, err := s.FindByPrefix(""); err == nil {
		t.Error("FindByPrefix(\"\") should be ambiguous with multiple snapshots")
	}
}

func TestVerifyChainFirstSnapshotNotGenesis(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// A lone snapshot whose prev_hash is not the genesis hash is itself a
	// broken chain at index 0.
	if _, err := s.Save(makeSnap("not-the-genesis-hash", time.Now())); err != nil {
		t.Fatalf("Save: %v", err)
	}
	_, brokenAt, err := s.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if brokenAt != 0 {
		t.Errorf("brokenAt = %d, want 0 (first snapshot not genesis-rooted)", brokenAt)
	}
}

// saveChain saves n snapshots spaced one day apart starting at `start`,
// returning their entries via List. Each is correctly chained.
func saveChain(t *testing.T, s *Store, start time.Time, n int) {
	t.Helper()
	h := hasher.GenesisHash
	for i := 0; i < n; i++ {
		var err error
		h, err = s.Save(makeSnap(h, start.AddDate(0, 0, i)))
		if err != nil {
			t.Fatalf("Save snap %d: %v", i, err)
		}
	}
}

func TestGCDeletesOldKeepsRecent(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Three snapshots 60/59/58 days ago (deleted by a 30-day retention) and
	// two from the last couple of days (kept). Distinct calendar days, so each
	// gets its own date directory.
	now := time.Now()
	saveChain(t, s, now.AddDate(0, 0, -60), 5)
	// The last two of those five are at -56/-55 days; still old. Use an
	// explicit recent tail instead.

	// Rebuild deterministically: wipe and lay down old + recent.
	if err := s.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if err := s.Init(); err != nil {
		t.Fatalf("re-Init: %v", err)
	}
	h := hasher.GenesisHash
	times := []time.Time{
		now.AddDate(0, 0, -60),
		now.AddDate(0, 0, -45),
		now.AddDate(0, 0, -2),
		now.AddDate(0, 0, -1),
	}
	for i, ts := range times {
		var err error
		h, err = s.Save(makeSnap(h, ts))
		if err != nil {
			t.Fatalf("Save %d: %v", i, err)
		}
	}

	res, err := s.GC(30)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if res.Removed != 2 {
		t.Errorf("GC removed %d, want 2", res.Removed)
	}
	if res.Remaining != 2 {
		t.Errorf("GC remaining %d, want 2", res.Remaining)
	}

	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("after GC: %d entries, want 2", len(entries))
	}
	// Old date directories must be cleaned up (isDirEmpty path).
	for _, ts := range times[:2] {
		dayDir := filepath.Join(s.ChainDir(), ts.Format("2006-01-02"))
		if _, err := os.Stat(dayDir); !os.IsNotExist(err) {
			t.Errorf("emptied date dir %s not removed", dayDir)
		}
	}
}

func TestGCRelinkedChainStaysValid(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	now := time.Now()
	h := hasher.GenesisHash
	times := []time.Time{
		now.AddDate(0, 0, -60),
		now.AddDate(0, 0, -50),
		now.AddDate(0, 0, -3),
		now.AddDate(0, 0, -2),
		now.AddDate(0, 0, -1),
	}
	for i, ts := range times {
		var err error
		h, err = s.Save(makeSnap(h, ts))
		if err != nil {
			t.Fatalf("Save %d: %v", i, err)
		}
	}

	if _, err := s.GC(30); err != nil {
		t.Fatalf("GC: %v", err)
	}

	// After GC prunes the two oldest and re-roots the kept tail, the surviving
	// chain must still verify end to end: the oldest survivor is genesis-rooted
	// and every subsequent link matches.
	entries, brokenAt, err := s.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("after GC: %d entries, want 3", len(entries))
	}
	if brokenAt != -1 {
		t.Errorf("VerifyChain brokenAt = %d, want -1 (valid re-rooted chain)", brokenAt)
	}
	if entries[0].Snapshot.PrevHash != hasher.GenesisHash {
		t.Errorf("oldest survivor prev_hash = %q, want GenesisHash", entries[0].Snapshot.PrevHash)
	}

	// Head must point at the new (re-rooted) head hash, so a subsequent Save
	// chains cleanly and the chain still verifies.
	if got := s.ReadHead(); got != entries[len(entries)-1].Hash {
		t.Errorf("head = %q, want new head hash %q after gc", got, entries[len(entries)-1].Hash)
	}
	if _, err := s.Save(makeSnap(s.ReadHead(), now)); err != nil {
		t.Fatalf("Save after GC: %v", err)
	}
	if _, brokenAt, err := s.VerifyChain(); err != nil || brokenAt != -1 {
		t.Errorf("chain invalid after Save following GC: brokenAt=%d err=%v", brokenAt, err)
	}
}
