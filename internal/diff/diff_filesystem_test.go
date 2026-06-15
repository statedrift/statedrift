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

// --- v0.5 Phase Q: security signals (R34/R35) ---

func TestDiffFilesystemSetuidAdded(t *testing.T) {
	// A new setuid file appearing.
	old := tree("h1", file("/etc/a", "-rw-r--r--", "aaa"))
	new := tree("h2",
		file("/etc/a", "-rw-r--r--", "aaa"),
		file("/usr/bin/x", "urwxr-xr-x", "bbb"),
	)
	r := fsResult(old, new)
	if !hasChange(r, "filesystem", "modified", "setuid_added") {
		t.Error("expected setuid_added signal for the new setuid file")
	}
}

func TestDiffFilesystemSetgidGainedOnModify(t *testing.T) {
	// An existing file gaining the setgid bit.
	old := &collector.FilesystemTree{RootHash: "h1", Entries: []collector.FileEntry{
		{Path: "/srv/tool", Mode: "-rwxr-xr-x"},
	}}
	new := &collector.FilesystemTree{RootHash: "h2", Entries: []collector.FileEntry{
		{Path: "/srv/tool", Mode: "grwxr-xr-x"},
	}}
	r := fsResult(old, new)
	if !hasChange(r, "filesystem", "modified", "setuid_added") {
		t.Error("expected setuid_added when setgid bit is gained")
	}
}

func TestDiffFilesystemWorldWritableAdded(t *testing.T) {
	old := &collector.FilesystemTree{RootHash: "h1", Entries: []collector.FileEntry{
		{Path: "/etc/x", Mode: "-rw-r--r--"},
	}}
	new := &collector.FilesystemTree{RootHash: "h2", Entries: []collector.FileEntry{
		{Path: "/etc/x", Mode: "-rw-rw-rw-"},
	}}
	r := fsResult(old, new)
	if !hasChange(r, "filesystem", "modified", "world_writable") {
		t.Error("expected world_writable when others-write is gained")
	}
}

func TestDiffFilesystemStickyAndSymlinkNotWorldWritable(t *testing.T) {
	// A sticky world-writable dir (like /tmp) and a symlink must NOT fire R35.
	old := tree("h1")
	new := tree("h2",
		file("/data/tmp", "dtrwxrwxrwx", ""), // sticky dir
		collector.FileEntry{Path: "/etc/alt", Mode: "Lrwxrwxrwx", Target: "/x"},
	)
	r := fsResult(old, new)
	if hasChange(r, "filesystem", "modified", "world_writable") {
		t.Error("sticky dir / symlink must not fire world_writable")
	}
}

func TestDiffFilesystemPlainModeChangeNoSecuritySignal(t *testing.T) {
	// A permission tightening with no setuid/world-writable transition emits
	// only the readable .mode change — no security signal.
	old := &collector.FilesystemTree{RootHash: "h1", Entries: []collector.FileEntry{
		{Path: "/etc/x", Mode: "-rw-r--r--"},
	}}
	new := &collector.FilesystemTree{RootHash: "h2", Entries: []collector.FileEntry{
		{Path: "/etc/x", Mode: "-rw-------"},
	}}
	r := fsResult(old, new)
	if !hasChange(r, "filesystem", "modified", "/etc/x.mode") {
		t.Error("expected the readable .mode change")
	}
	if hasChange(r, "filesystem", "modified", "setuid_added") ||
		hasChange(r, "filesystem", "modified", "world_writable") {
		t.Error("a benign perm change must not fire a security signal")
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
