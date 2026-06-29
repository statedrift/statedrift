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

const (
	capDefault    = "00000000a80425fb" // docker default — no CAP_SYS_ADMIN
	capPrivileged = "0000003fffffffff" // --privileged — includes CAP_SYS_ADMIN
)

func TestDiffContainersPrivilegedAddedFiresSignal(t *testing.T) {
	old := ci() // empty inventory → "aaa" is processed as an added container
	new := ci(collector.Container{ID: "aaa", Runtime: "docker", Command: "x", CapEff: capPrivileged, Processes: 1})
	r := &Result{}
	diffContainers(old, new, r)
	if findChange(r, "containers", "modified", "privileged_container") == nil {
		t.Error("expected privileged_container signal when a privileged container appears")
	}
}

func TestDiffContainersDefaultCapsNoSignal(t *testing.T) {
	old := ci()
	new := ci(collector.Container{ID: "aaa", Runtime: "docker", Command: "x", CapEff: capDefault, Processes: 1})
	r := &Result{}
	diffContainers(old, new, r)
	if findChange(r, "containers", "modified", "privileged_container") != nil {
		t.Error("default (non-privileged) container must not fire the privileged signal")
	}
}

func TestDiffContainersGainsPrivilegeFiresSignal(t *testing.T) {
	old := ci(collector.Container{ID: "aaa", Runtime: "docker", Command: "x", CapEff: capDefault, Processes: 1})
	new := ci(collector.Container{ID: "aaa", Runtime: "docker", Command: "x", CapEff: capPrivileged, Processes: 1})
	r := &Result{}
	diffContainers(old, new, r)
	if findChange(r, "containers", "modified", "privileged_container") == nil {
		t.Error("expected privileged_container signal on a container that gains CAP_SYS_ADMIN")
	}
	// The readable .cap_eff change should also be present and not a counter.
	c := findChange(r, "containers", "modified", "aaa.cap_eff")
	if c == nil || c.Counter {
		t.Error("expected a real (non-counter) aaa.cap_eff change")
	}
}

func TestDiffContainersPrivilegedThroughoutNoSignal(t *testing.T) {
	// Already privileged in both snapshots — no *new* privilege, no signal.
	old := ci(collector.Container{ID: "aaa", Runtime: "docker", CapEff: capPrivileged, Processes: 1})
	new := ci(collector.Container{ID: "aaa", Runtime: "docker", CapEff: capPrivileged, Processes: 2})
	r := &Result{}
	diffContainers(old, new, r)
	if findChange(r, "containers", "modified", "privileged_container") != nil {
		t.Error("no signal expected when privilege did not newly appear")
	}
}

func TestDiffContainersBothNilNoChange(t *testing.T) {
	r := &Result{}
	diffContainers(nil, nil, r)
	if len(r.Changes) != 0 {
		t.Errorf("both-nil should emit no changes, got %d", len(r.Changes))
	}
}
