package diff

import (
	"testing"

	"github.com/statedrift/statedrift/internal/collector"
)

func ci(cs ...collector.Container) *collector.ContainerInventory {
	return &collector.ContainerInventory{TotalCount: len(cs), Containers: cs}
}

func findChange(r *Result, section, ctype, key string) *Change {
	for i := range r.Changes {
		c := &r.Changes[i]
		if c.Section == section && c.Type == ctype && c.Key == key {
			return c
		}
	}
	return nil
}

func TestDiffContainersAddedRemoved(t *testing.T) {
	old := ci(collector.Container{ID: "aaa", Runtime: "docker", Command: "nginx", Processes: 2})
	new := ci(collector.Container{ID: "bbb", Runtime: "containerd", Command: "redis", Processes: 1})

	r := &Result{}
	diffContainers(old, new, r)

	if findChange(r, "containers", "added", "bbb") == nil {
		t.Error("expected added change for bbb")
	}
	if findChange(r, "containers", "removed", "aaa") == nil {
		t.Error("expected removed change for aaa")
	}
}

func TestDiffContainersProcessCountIsCounter(t *testing.T) {
	old := ci(collector.Container{ID: "aaa", Runtime: "docker", Command: "nginx", Processes: 2})
	new := ci(collector.Container{ID: "aaa", Runtime: "docker", Command: "nginx", Processes: 5})

	r := &Result{}
	diffContainers(old, new, r)

	c := findChange(r, "containers", "modified", "aaa.processes")
	if c == nil {
		t.Fatal("expected aaa.processes change")
	}
	if !c.Counter {
		t.Error("process-count change must be marked Counter (volatile, not an anomaly)")
	}
	// No runtime/command change → only the counter change should exist.
	if findChange(r, "containers", "modified", "aaa.runtime") != nil {
		t.Error("unexpected runtime change")
	}
}

func TestDiffContainersRuntimeChangeIsReal(t *testing.T) {
	old := ci(collector.Container{ID: "aaa", Runtime: "docker", Command: "nginx", Processes: 1})
	new := ci(collector.Container{ID: "aaa", Runtime: "containerd", Command: "nginx", Processes: 1})

	r := &Result{}
	diffContainers(old, new, r)

	c := findChange(r, "containers", "modified", "aaa.runtime")
	if c == nil {
		t.Fatal("expected aaa.runtime change")
	}
	if c.Counter {
		t.Error("runtime change must not be a counter")
	}
}

func TestDiffContainersCollectorToggle(t *testing.T) {
	// Collector turned on: old nil, new present → single summary added line.
	r := &Result{}
	diffContainers(nil, ci(collector.Container{ID: "aaa", Runtime: "docker"}), r)
	if findChange(r, "containers", "added", "inventory") == nil {
		t.Error("expected single inventory-added summary when collector enabled")
	}

	// Collector turned off: old present, new nil → single summary removed line.
	r = &Result{}
	diffContainers(ci(collector.Container{ID: "aaa", Runtime: "docker"}), nil, r)
	if findChange(r, "containers", "removed", "inventory") == nil {
		t.Error("expected single inventory-removed summary when collector disabled")
	}
}

func TestDiffContainersBothNilNoChange(t *testing.T) {
	r := &Result{}
	diffContainers(nil, nil, r)
	if len(r.Changes) != 0 {
		t.Errorf("both-nil should emit no changes, got %d", len(r.Changes))
	}
}
