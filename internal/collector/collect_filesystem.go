package collector

// collect_filesystem.go — v0.5 Phase P: recursive filesystem hash tree.
// Opt-in collector (gated by cfg.Collectors.IsEnabled("filesystem")) that walks
// a configured set of roots and records, per path, the mode / ownership / size
// and — for regular files within the size cap — a streamed SHA-256. A single
// Merkle root hash over all entries gives the quick "did anything change?"
// signal; the per-entry list drives the structural diff.
//
// Symlinks are recorded with their target and never dereferenced (avoids
// cycles and root escapes). The walk is lexical, so the entry order — and thus
// max_files truncation — is deterministic across runs.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/statedrift/statedrift/internal/config"
)

// collectFilesystem walks cfg.Filesystem.Roots (defaulting to ["/etc"]) and
// returns the hash tree. Missing roots and unreadable entries are skipped
// gracefully — they do not fail the collector. Returns a non-nil tree even
// when nothing was readable.
func collectFilesystem(cfg *config.Config) (*FilesystemTree, error) {
	roots := cfg.Filesystem.Roots
	if len(roots) == 0 {
		roots = config.FSDefaultRoots
	}
	maxFileSize := cfg.Filesystem.MaxFileSize
	if maxFileSize <= 0 {
		maxFileSize = config.FSDefaultMaxFileSize
	}
	maxFiles := cfg.Filesystem.MaxFiles
	if maxFiles <= 0 {
		maxFiles = config.FSDefaultMaxFiles
	}
	excludes := cfg.Filesystem.Excludes

	tree := &FilesystemTree{Roots: roots}

	for _, root := range roots {
		truncated := walkRoot(root, excludes, maxFileSize, maxFiles, tree)
		if truncated {
			tree.Truncated = true
			break
		}
	}

	tree.Files = len(tree.Entries)
	tree.RootHash = merkleRoot(tree.Entries)
	return tree, nil
}

// walkRoot walks a single root, appending entries to tree. It returns true if
// the max_files cap was reached (signalling the caller to stop and mark the
// tree truncated).
func walkRoot(root string, excludes []string, maxFileSize int64, maxFiles int, tree *FilesystemTree) bool {
	truncated := false
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable dir/file (permission denied, vanished mid-walk).
			// Skip its subtree if it's a directory; otherwise skip the entry.
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if matchesAny(path, excludes) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if len(tree.Entries) >= maxFiles {
			truncated = true
			return filepath.SkipAll
		}
		if e, ok := fileEntry(path, d, maxFileSize); ok {
			tree.Entries = append(tree.Entries, e)
		}
		return nil
	})
	return truncated
}

// fileEntry builds a FileEntry for one walked path. It returns ok=false only
// when the entry's metadata cannot be read (the path likely vanished mid-walk).
func fileEntry(path string, d fs.DirEntry, maxFileSize int64) (FileEntry, bool) {
	info, err := d.Info() // lstat semantics — symlinks are not followed
	if err != nil {
		return FileEntry{}, false
	}
	e := FileEntry{Path: path, Mode: info.Mode().String()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		e.UID = st.Uid
		e.GID = st.Gid
	}

	switch {
	case info.Mode()&os.ModeSymlink != 0:
		if target, err := os.Readlink(path); err == nil {
			e.Target = target
		}
	case info.Mode().IsRegular():
		e.Size = info.Size()
		if e.Size <= maxFileSize {
			if sum, err := hashFile(path); err == nil {
				e.SHA256 = sum
			}
		}
	}
	// Directories and special files: mode + ownership only, size 0, no hash.
	return e, true
}

// hashFile streams a regular file through SHA-256.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// merkleRoot computes a SHA-256 Merkle root over the entries in their given
// (lexical walk) order. The serialization is field-delimited with NUL so that
// no field value can spoof a record boundary. An empty tree hashes to "".
func merkleRoot(entries []FileEntry) string {
	if len(entries) == 0 {
		return ""
	}
	h := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(h, "%s\x00%s\x00%d\x00%d\x00%d\x00%s\x00%s\n",
			e.Path, e.Mode, e.UID, e.GID, e.Size, e.SHA256, e.Target)
	}
	return hex.EncodeToString(h.Sum(nil))
}
