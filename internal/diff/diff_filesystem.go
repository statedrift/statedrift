package diff

import (
	"fmt"
	"sort"

	"github.com/statedrift/statedrift/internal/collector"
)

// diffFilesystem compares two filesystem hash trees (v0.5 Phase P).
//
// When the collector is toggled on or off, one side is nil; rather than
// exploding into one change per file, that case emits a single summary
// added/removed line (mirroring diffFirewall's nil handling). When both sides
// are present it short-circuits on an unchanged Merkle root, then emits
// per-path changes:
//
//   - "added"   — a path present in new, not old (key "<path>").
//   - "removed" — a path present in old, not new.
//   - "modified" — a path in both with a changed attribute; one change per
//     differing attribute, keyed "<path>.<attr>" (.mode/.uid/.gid/.size/
//     .sha256/.target), mirroring diffNICDrivers.
//
// Paths iterate in sorted order for deterministic output.
func diffFilesystem(old, new *collector.FilesystemTree, r *Result) {
	if old == nil && new == nil {
		return
	}
	if old == nil {
		r.Changes = append(r.Changes, Change{"filesystem", "added", "tree",
			"", fmt.Sprintf("%d files", new.Files), false})
		return
	}
	if new == nil {
		r.Changes = append(r.Changes, Change{"filesystem", "removed", "tree",
			fmt.Sprintf("%d files", old.Files), "", false})
		return
	}

	// Fast path: identical Merkle root means no content/metadata change.
	if old.RootHash == new.RootHash {
		return
	}

	oldByPath := indexEntries(old.Entries)
	newByPath := indexEntries(new.Entries)

	for _, path := range sortedPathUnion(oldByPath, newByPath) {
		oe, inOld := oldByPath[path]
		ne, inNew := newByPath[path]
		switch {
		case inOld && !inNew:
			r.Changes = append(r.Changes, Change{"filesystem", "removed", path,
				oe.Mode, "", false})
		case !inOld && inNew:
			r.Changes = append(r.Changes, Change{"filesystem", "added", path,
				"", ne.Mode, false})
		default:
			diffFileEntry(path, oe, ne, r)
		}
	}
}

// diffFileEntry emits one "modified" change per attribute that differs between
// two entries for the same path.
func diffFileEntry(path string, oe, ne collector.FileEntry, r *Result) {
	if oe.Mode != ne.Mode {
		r.Changes = append(r.Changes, Change{"filesystem", "modified", path + ".mode",
			oe.Mode, ne.Mode, false})
	}
	if oe.UID != ne.UID {
		r.Changes = append(r.Changes, Change{"filesystem", "modified", path + ".uid",
			fmt.Sprintf("%d", oe.UID), fmt.Sprintf("%d", ne.UID), false})
	}
	if oe.GID != ne.GID {
		r.Changes = append(r.Changes, Change{"filesystem", "modified", path + ".gid",
			fmt.Sprintf("%d", oe.GID), fmt.Sprintf("%d", ne.GID), false})
	}
	if oe.Size != ne.Size {
		r.Changes = append(r.Changes, Change{"filesystem", "modified", path + ".size",
			fmt.Sprintf("%d", oe.Size), fmt.Sprintf("%d", ne.Size), false})
	}
	if oe.SHA256 != ne.SHA256 {
		r.Changes = append(r.Changes, Change{"filesystem", "modified", path + ".sha256",
			oe.SHA256, ne.SHA256, false})
	}
	if oe.Target != ne.Target {
		r.Changes = append(r.Changes, Change{"filesystem", "modified", path + ".target",
			oe.Target, ne.Target, false})
	}
}

// indexEntries maps entries by path. Entry paths are unique within a tree.
func indexEntries(entries []collector.FileEntry) map[string]collector.FileEntry {
	m := make(map[string]collector.FileEntry, len(entries))
	for _, e := range entries {
		m[e.Path] = e
	}
	return m
}

// sortedPathUnion returns the sorted union of the keys of two entry maps.
func sortedPathUnion(a, b map[string]collector.FileEntry) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var paths []string
	for p := range a {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	for p := range b {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	return paths
}
