package diff

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/statedrift/statedrift/internal/collector"
)

// diffDataplane compares two network-dataplane inventories (v0.7).
//
// Like diffGPU, a nil side (collector toggled on/off, or the host gaining/losing
// all SR-IOV PFs and DPDK bindings) emits a single summary line rather than one
// change per device. When both sides are present it reports, keyed by PCI
// address:
//
//   - "dataplane.pf" added/removed — an SR-IOV physical function appearing or
//     disappearing (R44 / R45), plus per-PF "<pci>.num_vfs" (R46),
//     ".total_vfs", ".driver", ".interface" changes. None are counters — a VF
//     count change is a real reconfiguration.
//   - "dataplane.dpdk" added/removed — a NIC bound to / unbound from a userspace
//     poll-mode driver (R47 on add), plus "<pci>.driver" changes.
//
// The "dataplane.pf" / "dataplane.dpdk" sub-sections let the prefix-matching
// rules engine tell the two "added" kinds apart (same trick as
// "network.interfaces").
func diffDataplane(old, new *collector.NetDataplane, r *Result) {
	if old == nil && new == nil {
		return
	}
	if old == nil {
		r.Changes = append(r.Changes, Change{"dataplane", "added", "inventory",
			"", dataplaneSummary(new), false})
		return
	}
	if new == nil {
		r.Changes = append(r.Changes, Change{"dataplane", "removed", "inventory",
			dataplaneSummary(old), "", false})
		return
	}

	diffPFs(old.PFs, new.PFs, r)
	diffDPDK(old.DPDKDevices, new.DPDKDevices, r)
}

// diffPFs compares the SR-IOV physical-function lists, keyed by PCI address.
func diffPFs(old, new []collector.SRIOVPF, r *Result) {
	oldByAddr := indexPFs(old)
	newByAddr := indexPFs(new)
	for _, addr := range sortedAddrUnion(pfAddrs(oldByAddr), pfAddrs(newByAddr)) {
		op, inOld := oldByAddr[addr]
		np, inNew := newByAddr[addr]
		switch {
		case inOld && !inNew:
			r.Changes = append(r.Changes, Change{"dataplane.pf", "removed", addr,
				pfSummary(op), "", false})
		case !inOld && inNew:
			r.Changes = append(r.Changes, Change{"dataplane.pf", "added", addr,
				"", pfSummary(np), false})
		default:
			diffPFEntry(addr, op, np, r)
		}
	}
}

// diffPFEntry emits one change per differing attribute for a PF present in both
// snapshots (same PCI address).
func diffPFEntry(addr string, op, np collector.SRIOVPF, r *Result) {
	if op.NumVFs != np.NumVFs {
		r.Changes = append(r.Changes, Change{"dataplane.pf", "modified", addr + ".num_vfs",
			strconv.Itoa(op.NumVFs), strconv.Itoa(np.NumVFs), false})
	}
	if op.TotalVFs != np.TotalVFs {
		r.Changes = append(r.Changes, Change{"dataplane.pf", "modified", addr + ".total_vfs",
			strconv.Itoa(op.TotalVFs), strconv.Itoa(np.TotalVFs), false})
	}
	if op.Driver != np.Driver {
		r.Changes = append(r.Changes, Change{"dataplane.pf", "modified", addr + ".driver",
			op.Driver, np.Driver, false})
	}
	if op.Interface != np.Interface {
		r.Changes = append(r.Changes, Change{"dataplane.pf", "modified", addr + ".interface",
			op.Interface, np.Interface, false})
	}
	if op.NumaNode != np.NumaNode {
		r.Changes = append(r.Changes, Change{"dataplane.pf", "modified", addr + ".numa_node",
			strconv.Itoa(op.NumaNode), strconv.Itoa(np.NumaNode), false})
	}
}

// diffDPDK compares the DPDK-bound device lists, keyed by PCI address.
func diffDPDK(old, new []collector.DPDKDevice, r *Result) {
	oldByAddr := indexDPDK(old)
	newByAddr := indexDPDK(new)
	for _, addr := range sortedAddrUnion(dpdkAddrs(oldByAddr), dpdkAddrs(newByAddr)) {
		od, inOld := oldByAddr[addr]
		nd, inNew := newByAddr[addr]
		switch {
		case inOld && !inNew:
			r.Changes = append(r.Changes, Change{"dataplane.dpdk", "removed", addr,
				dpdkSummary(od), "", false})
		case !inOld && inNew:
			r.Changes = append(r.Changes, Change{"dataplane.dpdk", "added", addr,
				"", dpdkSummary(nd), false})
		default:
			if od.Driver != nd.Driver {
				r.Changes = append(r.Changes, Change{"dataplane.dpdk", "modified", addr + ".driver",
					od.Driver, nd.Driver, false})
			}
			if od.PhysFn != nd.PhysFn {
				r.Changes = append(r.Changes, Change{"dataplane.dpdk", "modified", addr + ".phys_fn",
					od.PhysFn, nd.PhysFn, false})
			}
			if od.NumaNode != nd.NumaNode {
				r.Changes = append(r.Changes, Change{"dataplane.dpdk", "modified", addr + ".numa_node",
					strconv.Itoa(od.NumaNode), strconv.Itoa(nd.NumaNode), false})
			}
		}
	}
}

// dataplaneSummary renders a one-line "N SR-IOV PFs, M DPDK devices" for the
// nil-side add/remove lines.
func dataplaneSummary(d *collector.NetDataplane) string {
	return fmt.Sprintf("%d SR-IOV PFs, %d DPDK devices", len(d.PFs), len(d.DPDKDevices))
}

// pfSummary renders a one-line "<driver> <num>/<total> VFs (<iface>)" for
// added/removed PF lines, falling back to the PCI address when nothing else is
// known.
func pfSummary(p collector.SRIOVPF) string {
	s := p.Driver
	if s != "" {
		s += " "
	}
	s += fmt.Sprintf("%d/%d VFs", p.NumVFs, p.TotalVFs)
	if p.Interface != "" {
		s += " (" + p.Interface + ")"
	}
	if s == "" {
		s = p.PCIAddress
	}
	return s
}

// dpdkSummary renders a one-line "<driver>" for added/removed DPDK device lines,
// noting the parent PF when the device is an SR-IOV Virtual Function.
func dpdkSummary(d collector.DPDKDevice) string {
	s := d.Driver
	if d.PhysFn != "" {
		s += " vf-of " + d.PhysFn
	}
	return s
}

func indexPFs(ps []collector.SRIOVPF) map[string]collector.SRIOVPF {
	m := make(map[string]collector.SRIOVPF, len(ps))
	for _, p := range ps {
		m[p.PCIAddress] = p
	}
	return m
}

func indexDPDK(ds []collector.DPDKDevice) map[string]collector.DPDKDevice {
	m := make(map[string]collector.DPDKDevice, len(ds))
	for _, d := range ds {
		m[d.PCIAddress] = d
	}
	return m
}

func pfAddrs(m map[string]collector.SRIOVPF) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func dpdkAddrs(m map[string]collector.DPDKDevice) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// sortedAddrUnion returns the sorted, de-duplicated union of two key slices.
func sortedAddrUnion(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var keys []string
	for _, k := range append(a, b...) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}
