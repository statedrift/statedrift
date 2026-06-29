package diff

import (
	"fmt"
	"sort"

	"github.com/statedrift/statedrift/internal/collector"
)

// diffGPU compares two GPU inventories (v0.6).
//
// Like diffContainers, a nil side (collector toggled on/off, or the NVIDIA
// driver loaded/unloaded) emits a single summary line rather than one change
// per GPU. When both sides are present it reports:
//
//   - "driver_version" — host-global driver version change (R42).
//   - per-GPU, keyed by PCI bus location:
//   - "added" / "removed" — a GPU appearing/disappearing (R40 / R41).
//   - "<bus>.model" — hardware model change (informational; usually
//     accompanied by a vbios change on a card swap).
//   - "<bus>.vbios_version" — video-BIOS (firmware) change (R43).
//
// Bus locations iterate in sorted order for deterministic output.
func diffGPU(old, new *collector.GPUInventory, r *Result) {
	if old == nil && new == nil {
		return
	}
	if old == nil {
		r.Changes = append(r.Changes, Change{"gpu", "added", "inventory",
			"", fmt.Sprintf("%d GPUs", new.TotalCount), false})
		return
	}
	if new == nil {
		r.Changes = append(r.Changes, Change{"gpu", "removed", "inventory",
			fmt.Sprintf("%d GPUs", old.TotalCount), "", false})
		return
	}

	if old.DriverVersion != new.DriverVersion {
		r.Changes = append(r.Changes, Change{"gpu", "modified", "driver_version",
			old.DriverVersion, new.DriverVersion, false})
	}

	oldByBus := indexGPUs(old.GPUs)
	newByBus := indexGPUs(new.GPUs)
	for _, bus := range sortedGPUUnion(oldByBus, newByBus) {
		og, inOld := oldByBus[bus]
		ng, inNew := newByBus[bus]
		switch {
		case inOld && !inNew:
			r.Changes = append(r.Changes, Change{"gpu", "removed", bus,
				gpuSummary(og), "", false})
		case !inOld && inNew:
			r.Changes = append(r.Changes, Change{"gpu", "added", bus,
				"", gpuSummary(ng), false})
		default:
			diffGPUEntry(bus, og, ng, r)
		}
	}
}

// diffGPUEntry emits one change per differing attribute for a GPU present in
// both snapshots (same PCI bus location).
func diffGPUEntry(bus string, og, ng collector.GPU, r *Result) {
	if og.Model != ng.Model {
		r.Changes = append(r.Changes, Change{"gpu", "modified", bus + ".model",
			og.Model, ng.Model, false})
	}
	if og.VBIOSVersion != ng.VBIOSVersion {
		r.Changes = append(r.Changes, Change{"gpu", "modified", bus + ".vbios_version",
			og.VBIOSVersion, ng.VBIOSVersion, false})
	}
}

// gpuSummary renders a one-line "model vbios <v>" for added/removed lines,
// falling back to the bus location when nothing else is known.
func gpuSummary(g collector.GPU) string {
	s := g.Model
	if g.VBIOSVersion != "" {
		if s != "" {
			s += " "
		}
		s += "vbios " + g.VBIOSVersion
	}
	if s == "" {
		s = g.BusLocation
	}
	return s
}

func indexGPUs(gs []collector.GPU) map[string]collector.GPU {
	m := make(map[string]collector.GPU, len(gs))
	for _, g := range gs {
		m[g.BusLocation] = g
	}
	return m
}

func sortedGPUUnion(a, b map[string]collector.GPU) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var keys []string
	for k := range a {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range b {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}
