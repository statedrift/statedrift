package diff

import (
	"fmt"
	"sort"

	"github.com/statedrift/statedrift/internal/collector"
)

// diffContainers compares two container inventories (v0.6).
//
// Like diffFilesystem, a nil side (collector toggled on/off) emits a single
// summary line rather than one change per container. When both sides are
// present it keys by container ID:
//
//   - "added"    — a container present in new, not old (the security signal).
//   - "removed"  — a container gone from old.
//   - "modified" — same ID, changed attribute. Runtime/command changes are real
//     ("<id>.runtime" / "<id>.command"); the process count ("<id>.processes")
//     is volatile and marked Counter so rules ignore it.
//
// IDs iterate in sorted order for deterministic output.
func diffContainers(old, new *collector.ContainerInventory, r *Result) {
	if old == nil && new == nil {
		return
	}
	if old == nil {
		r.Changes = append(r.Changes, Change{"containers", "added", "inventory",
			"", fmt.Sprintf("%d containers", new.TotalCount), false})
		return
	}
	if new == nil {
		r.Changes = append(r.Changes, Change{"containers", "removed", "inventory",
			fmt.Sprintf("%d containers", old.TotalCount), "", false})
		return
	}

	oldByID := indexContainers(old.Containers)
	newByID := indexContainers(new.Containers)

	for _, id := range sortedIDUnion(oldByID, newByID) {
		oc, inOld := oldByID[id]
		nc, inNew := newByID[id]
		switch {
		case inOld && !inNew:
			r.Changes = append(r.Changes, Change{"containers", "removed", id,
				containerSummary(oc), "", false})
		case !inOld && inNew:
			r.Changes = append(r.Changes, Change{"containers", "added", id,
				"", containerSummary(nc), false})
		default:
			diffContainerEntry(id, oc, nc, r)
		}
	}
}

// diffContainerEntry emits one change per differing attribute for a container
// present in both snapshots.
func diffContainerEntry(id string, oc, nc collector.Container, r *Result) {
	if oc.Runtime != nc.Runtime {
		r.Changes = append(r.Changes, Change{"containers", "modified", id + ".runtime",
			oc.Runtime, nc.Runtime, false})
	}
	if oc.Command != nc.Command {
		r.Changes = append(r.Changes, Change{"containers", "modified", id + ".command",
			oc.Command, nc.Command, false})
	}
	if oc.Processes != nc.Processes {
		// Volatile process count — informational, not an anomaly.
		r.Changes = append(r.Changes, Change{"containers", "modified", id + ".processes",
			fmt.Sprintf("%d", oc.Processes), fmt.Sprintf("%d", nc.Processes), true})
	}
}

// containerSummary renders a one-line "runtime command" for added/removed lines.
func containerSummary(c collector.Container) string {
	s := c.Runtime
	if c.Command != "" {
		s += " " + c.Command
	}
	return s
}

func indexContainers(cs []collector.Container) map[string]collector.Container {
	m := make(map[string]collector.Container, len(cs))
	for _, c := range cs {
		m[c.ID] = c
	}
	return m
}

func sortedIDUnion(a, b map[string]collector.Container) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var ids []string
	for id := range a {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for id := range b {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}
