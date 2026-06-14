package diff

import (
	"testing"

	"github.com/statedrift/statedrift/internal/collector"
)

func fsResult(old, new *collector.FilesystemTree) *Result {
	r := &Result{}
	diffFilesystem(old, new, r)
	return r
}

// tree builds a FilesystemTree from entries, setting a non-empty RootHash so
// the diff does not short-circuit on the unchanged-root fast path. Tests that
// want the fast path set the hash explicitly.
func tree(hash string, entries ...collector.FileEntry) *collector.FilesystemTree {
	return &collector.FilesystemTree{
		Roots:    []string{"/etc"},
		RootHash: hash,
		Files:    len(entries),
		Entries:  entries,
	}
}

func file(path, mode, sha string) collector.FileEntry {
	return collector.FileEntry{Path: path, Mode: mode, SHA256: sha}
}

func TestDiffFilesystemAddedRemoved(t *testing.T) {
	old := tree("h1", file("/etc/hosts", "-rw-r--r--", "aaa"))
	new := tree("h2",
		file("/etc/hosts", "-rw-r--r--", "aaa"),
		file("/etc/newfile", "-rw-r--r--", "bbb"),
	)
	r := fsResult(old, new)
	if !hasChange(r, "filesystem", "added", "/etc/newfile") {
		t.Error("expected /etc/newfile added")
	}
	if hasChange(r, "filesystem", "removed", "") {
		t.Error("nothing should be removed")
	}

	// Reverse: removal.
	r = fsResult(new, old)
	if !hasChange(r, "filesystem", "removed", "/etc/newfile") {
		t.Error("expected /etc/newfile removed")
	}
}

func TestDiffFilesystemModifiedAttributes(t *testing.T) {
	old := &collector.FilesystemTree{RootHash: "h1", Entries: []collector.FileEntry{
		{Path: "/etc/x", Mode: "-rw-r--r--", UID: 0, GID: 0, Size: 10, SHA256: "aaa"},
	}}
	new := &collector.FilesystemTree{RootHash: "h2", Entries: []collector.FileEntry{
		{Path: "/etc/x", Mode: "-rw-------", UID: 1000, GID: 1000, Size: 12, SHA256: "bbb"},
	}}
	r := fsResult(old, new)
	for _, attr := range []string{".mode", ".uid", ".gid", ".size", ".sha256"} {
		if !hasChange(r, "filesystem", "modified", "/etc/x"+attr) {
			t.Errorf("expected modified /etc/x%s", attr)
		}
	}
	if hasChange(r, "filesystem", "added", "") || hasChange(r, "filesystem", "removed", "") {
		t.Error("a same-path edit is modified, not add/remove")
	}
}

func TestDiffFilesystemSymlinkTarget(t *testing.T) {
	old := &collector.FilesystemTree{RootHash: "h1", Entries: []collector.FileEntry{
		{Path: "/etc/alt", Mode: "Lrwxrwxrwx", Target: "/etc/old"},
	}}
	new := &collector.FilesystemTree{RootHash: "h2", Entries: []collector.FileEntry{
		{Path: "/etc/alt", Mode: "Lrwxrwxrwx", Target: "/etc/new"},
	}}
	r := fsResult(old, new)
	if !hasChange(r, "filesystem", "modified", "/etc/alt.target") {
		t.Error("expected modified symlink target")
	}
}

func TestDiffFilesystemUnchangedRootShortCircuits(t *testing.T) {
	// Same RootHash → no per-entry walk, no changes, even if entries differ
	// (they cannot in practice, but the fast path must not emit anything).
	old := tree("same", file("/etc/a", "-rw-r--r--", "aaa"))
	new := tree("same", file("/etc/a", "-rw-r--r--", "aaa"))
	r := fsResult(old, new)
	if len(r.Changes) != 0 {
		t.Errorf("identical root hash should produce no changes, got %d", len(r.Changes))
	}
}

func TestDiffFilesystemNilTransitions(t *testing.T) {
	present := tree("h", file("/etc/a", "-rw-r--r--", "aaa"))

	// Collector toggled on: single summary "added", not per-file explosion.
	r := fsResult(nil, present)
	if !hasChange(r, "filesystem", "added", "tree") {
		t.Error("nil → present should emit a single added-tree summary")
	}
	if hasChange(r, "filesystem", "added", "/etc/a") {
		t.Error("nil → present must not explode into per-file changes")
	}

	// Collector toggled off.
	r = fsResult(present, nil)
	if !hasChange(r, "filesystem", "removed", "tree") {
		t.Error("present → nil should emit a single removed-tree summary")
	}

	r = fsResult(nil, nil)
	if len(r.Changes) != 0 {
		t.Errorf("nil/nil should produce no changes, got %d", len(r.Changes))
	}
}
