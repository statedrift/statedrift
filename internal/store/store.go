// Package store manages the append-only flat file snapshot store.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/statedrift/statedrift/internal/collector"
	"github.com/statedrift/statedrift/internal/hasher"
)

// Store manages snapshot storage in a date-based directory layout.
type Store struct {
	BasePath string // e.g., /var/lib/statedrift
}

// New creates a Store pointed at the given base directory.
func New(basePath string) *Store {
	return &Store{BasePath: basePath}
}

// ChainDir returns the path to the chain directory.
func (s *Store) ChainDir() string {
	return filepath.Join(s.BasePath, "chain")
}

// HeadFile returns the path to the head file (contains hash of latest snapshot).
func (s *Store) HeadFile() string {
	return filepath.Join(s.BasePath, "head")
}

// Init creates the store directory structure and returns an error if it already exists.
func (s *Store) Init() error {
	chainDir := s.ChainDir()

	if _, err := os.Stat(chainDir); err == nil {
		return fmt.Errorf("store already initialized at %s", chainDir)
	}

	if err := os.MkdirAll(chainDir, 0755); err != nil {
		return fmt.Errorf("creating chain dir: %w", err)
	}

	return nil
}

// Reset removes the chain directory and head file so Init can be called again.
func (s *Store) Reset() error {
	if err := os.RemoveAll(s.ChainDir()); err != nil {
		return fmt.Errorf("removing chain dir: %w", err)
	}
	os.Remove(s.HeadFile()) // ignore error — file may not exist
	return nil
}

// IsInitialized checks if the store has been initialized.
func (s *Store) IsInitialized() bool {
	_, err := os.Stat(s.ChainDir())
	return err == nil
}

// ReadHead returns the hash of the most recent snapshot, or GenesisHash if none exists.
func (s *Store) ReadHead() string {
	data, err := os.ReadFile(s.HeadFile())
	if err != nil {
		return hasher.GenesisHash
	}
	return strings.TrimSpace(string(data))
}

// WriteHead writes the hash of the most recent snapshot atomically.
func (s *Store) WriteHead(hash string) error {
	return writeFileAtomic(s.HeadFile(), []byte(hash+"\n"), 0644)
}

// writeFileAtomic writes data to path via a same-directory temp file and os.Rename.
// On POSIX systems, Rename within the same filesystem is atomic, so a crash
// mid-write leaves either the old file intact or the new file complete — never
// a partial write at the destination path.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
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

// Save writes a snapshot to the store and updates the head.
func (s *Store) Save(snap *collector.Snapshot) (string, error) {
	// Compute hash
	hash, err := hasher.Hash(snap)
	if err != nil {
		return "", fmt.Errorf("computing hash: %w", err)
	}

	// Create date directory
	dateDir := filepath.Join(s.ChainDir(), snap.Timestamp.Format("2006-01-02"))
	if err := os.MkdirAll(dateDir, 0755); err != nil {
		return "", fmt.Errorf("creating date dir: %w", err)
	}

	// Write snapshot file. Include nanoseconds to avoid collisions when
	// multiple snapshots are taken within the same second.
	filename := snap.Timestamp.Format("150405.000000000") + ".json"
	path := filepath.Join(dateDir, filename)

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling snapshot: %w", err)
	}

	if err := writeFileAtomic(path, data, 0644); err != nil {
		return "", fmt.Errorf("writing snapshot: %w", err)
	}

	// Update head atomically so a crash between snapshot write and head update
	// leaves head pointing at the previous snapshot rather than a partial state.
	if err := writeFileAtomic(s.HeadFile(), []byte(hash+"\n"), 0644); err != nil {
		return "", fmt.Errorf("updating head: %w", err)
	}

	// Update latest symlink
	latestLink := filepath.Join(s.ChainDir(), "latest")
	os.Remove(latestLink) // ignore error if doesn't exist
	os.Symlink(path, latestLink)

	return hash, nil
}

// SnapshotEntry is a snapshot file reference with its path and parsed data.
type SnapshotEntry struct {
	Path     string
	Snapshot *collector.Snapshot
	Hash     string
}

// List returns all snapshots in chronological order.
func (s *Store) List() ([]SnapshotEntry, error) {
	var entries []SnapshotEntry

	chainDir := s.ChainDir()

	// Walk date directories
	dateDirs, err := os.ReadDir(chainDir)
	if err != nil {
		return nil, fmt.Errorf("reading chain dir: %w", err)
	}

	for _, dateDir := range dateDirs {
		if !dateDir.IsDir() {
			continue
		}
		if dateDir.Name() == "latest" {
			continue
		}

		dayPath := filepath.Join(chainDir, dateDir.Name())
		files, err := os.ReadDir(dayPath)
		if err != nil {
			continue
		}

		for _, file := range files {
			if !strings.HasSuffix(file.Name(), ".json") {
				continue
			}

			path := filepath.Join(dayPath, file.Name())
			snap, err := LoadSnapshot(path)
			if err != nil {
				continue
			}

			hash, err := hasher.Hash(snap)
			if err != nil {
				continue
			}

			entries = append(entries, SnapshotEntry{
				Path:     path,
				Snapshot: snap,
				Hash:     hash,
			})
		}
	}

	// Sort by timestamp
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Snapshot.Timestamp.Before(entries[j].Snapshot.Timestamp)
	})

	return entries, nil
}

// LoadSnapshot reads and parses a snapshot from a JSON file.
func LoadSnapshot(path string) (*collector.Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var snap collector.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}

	return &snap, nil
}

// FindByPrefix finds a snapshot whose hash starts with the given prefix.
func (s *Store) FindByPrefix(prefix string) (*SnapshotEntry, error) {
	entries, err := s.List()
	if err != nil {
		return nil, err
	}

	prefix = strings.ToLower(prefix)
	var matches []SnapshotEntry

	for _, e := range entries {
		if strings.HasPrefix(e.Hash, prefix) {
			matches = append(matches, e)
		}
	}

	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no snapshot matching prefix %q", prefix)
	case 1:
		return &matches[0], nil
	default:
		return nil, fmt.Errorf("ambiguous prefix %q matches %d snapshots", prefix, len(matches))
	}
}

// GCResult holds a summary of what GC removed.
type GCResult struct {
	Removed   int
	Remaining int
	Before    time.Time
}

// GC removes snapshots older than retentionDays and re-links the chain.
// The oldest remaining snapshot gets its prev_hash reset to GenesisHash.
// Returns a summary of what was removed.
func (s *Store) GC(retentionDays int) (GCResult, error) {
	entries, err := s.List()
	if err != nil {
		return GCResult{}, err
	}

	// 0 means "keep forever" — nothing to remove.
	if retentionDays == 0 {
		return GCResult{Remaining: len(entries)}, nil
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	var toDelete []SnapshotEntry
	var toKeep []SnapshotEntry

	for _, e := range entries {
		if e.Snapshot.Timestamp.Before(cutoff) {
			toDelete = append(toDelete, e)
		} else {
			toKeep = append(toKeep, e)
		}
	}

	if len(toDelete) == 0 {
		return GCResult{Remaining: len(toKeep), Before: cutoff}, nil
	}

	// Delete old snapshot files and clean up empty date directories.
	for _, e := range toDelete {
		os.Remove(e.Path)
		dir := filepath.Dir(e.Path)
		// Remove date dir if now empty.
		if isEmpty, _ := isDirEmpty(dir); isEmpty {
			os.Remove(dir)
		}
	}

	// Re-link chain: oldest remaining snapshot gets prev_hash = GenesisHash.
	if len(toKeep) > 0 {
		oldest := toKeep[0]
		oldest.Snapshot.PrevHash = hasher.GenesisHash
		data, err := json.MarshalIndent(oldest.Snapshot, "", "  ")
		if err != nil {
			return GCResult{}, fmt.Errorf("marshaling snapshot: %w", err)
		}
		if err := writeFileAtomic(oldest.Path, data, 0644); err != nil {
			return GCResult{}, fmt.Errorf("rewriting oldest snapshot: %w", err)
		}
	}

	return GCResult{
		Removed:   len(toDelete),
		Remaining: len(toKeep),
		Before:    cutoff,
	}, nil
}

// isDirEmpty reports whether a directory has no entries.
func isDirEmpty(dir string) (bool, error) {
	f, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	return err != nil, nil
}

// VerifyChain walks the entire chain and checks hash integrity.
// Returns the index of the first broken link, or -1 if chain is valid.
func (s *Store) VerifyChain() (entries []SnapshotEntry, brokenAt int, err error) {
	entries, err = s.List()
	if err != nil {
		return nil, -1, err
	}

	if len(entries) == 0 {
		return entries, -1, nil
	}

	// First snapshot must have genesis prev_hash
	if entries[0].Snapshot.PrevHash != hasher.GenesisHash {
		return entries, 0, nil
	}

	// Walk the chain
	for i := 1; i < len(entries); i++ {
		expectedPrev := entries[i-1].Hash
		actualPrev := entries[i].Snapshot.PrevHash

		if actualPrev != expectedPrev {
			return entries, i, nil
		}
	}

	return entries, -1, nil
}
