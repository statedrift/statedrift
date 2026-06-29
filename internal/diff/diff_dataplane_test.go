package diff

import (
	"testing"

	"github.com/statedrift/statedrift/internal/collector"
)

func dp(pfs []collector.SRIOVPF, dpdk []collector.DPDKDevice) *collector.NetDataplane {
	return &collector.NetDataplane{PFs: pfs, DPDKDevices: dpdk}
}

func TestDiffDataplanePFAddedRemoved(t *testing.T) {
	old := dp([]collector.SRIOVPF{{PCIAddress: "0000:01:00.0", Driver: "i40e", NumVFs: 4, TotalVFs: 8}}, nil)
	new := dp([]collector.SRIOVPF{{PCIAddress: "0000:81:00.0", Driver: "mlx5_core", NumVFs: 0, TotalVFs: 16}}, nil)

	r := &Result{}
	diffDataplane(old, new, r)

	if findChange(r, "dataplane.pf", "added", "0000:81:00.0") == nil {
		t.Error("expected added change for new PF")
	}
	if findChange(r, "dataplane.pf", "removed", "0000:01:00.0") == nil {
		t.Error("expected removed change for missing PF")
	}
}

func TestDiffDataplaneVFCountChange(t *testing.T) {
	old := dp([]collector.SRIOVPF{{PCIAddress: "0000:01:00.0", Driver: "i40e", NumVFs: 0, TotalVFs: 8}}, nil)
	new := dp([]collector.SRIOVPF{{PCIAddress: "0000:01:00.0", Driver: "i40e", NumVFs: 8, TotalVFs: 8}}, nil)

	r := &Result{}
	diffDataplane(old, new, r)

	c := findChange(r, "dataplane.pf", "modified", "0000:01:00.0.num_vfs")
	if c == nil {
		t.Fatal("expected num_vfs change")
	}
	if c.Counter {
		t.Error("VF count change must not be a counter (it is a real reconfiguration)")
	}
	if c.OldValue != "0" || c.NewValue != "8" {
		t.Errorf("unexpected num_vfs values: %q -> %q", c.OldValue, c.NewValue)
	}
}

func TestDiffDataplaneDPDKBound(t *testing.T) {
	old := dp(nil, nil)
	new := dp(nil, []collector.DPDKDevice{{PCIAddress: "0000:02:00.0", Driver: "vfio-pci"}})

	r := &Result{}
	diffDataplane(old, new, r)

	if findChange(r, "dataplane.dpdk", "added", "0000:02:00.0") == nil {
		t.Error("expected added change for newly DPDK-bound NIC")
	}
}

func TestDiffDataplaneDPDKDriverChange(t *testing.T) {
	old := dp(nil, []collector.DPDKDevice{{PCIAddress: "0000:02:00.0", Driver: "igb_uio"}})
	new := dp(nil, []collector.DPDKDevice{{PCIAddress: "0000:02:00.0", Driver: "vfio-pci"}})

	r := &Result{}
	diffDataplane(old, new, r)

	if findChange(r, "dataplane.dpdk", "modified", "0000:02:00.0.driver") == nil {
		t.Error("expected driver change for rebound DPDK device")
	}
}

func TestDiffDataplanePFNumaChange(t *testing.T) {
	old := dp([]collector.SRIOVPF{{PCIAddress: "0000:01:00.0", Driver: "i40e", NumaNode: 0}}, nil)
	new := dp([]collector.SRIOVPF{{PCIAddress: "0000:01:00.0", Driver: "i40e", NumaNode: 1}}, nil)

	r := &Result{}
	diffDataplane(old, new, r)

	c := findChange(r, "dataplane.pf", "modified", "0000:01:00.0.numa_node")
	if c == nil {
		t.Fatal("expected numa_node change")
	}
	if c.OldValue != "0" || c.NewValue != "1" {
		t.Errorf("unexpected numa_node values: %q -> %q", c.OldValue, c.NewValue)
	}
}

func TestDiffDataplaneDPDKSummaryShowsParentPF(t *testing.T) {
	old := dp(nil, nil)
	new := dp(nil, []collector.DPDKDevice{{PCIAddress: "0000:01:10.0", Driver: "vfio-pci", PhysFn: "0000:01:00.0"}})

	r := &Result{}
	diffDataplane(old, new, r)

	c := findChange(r, "dataplane.dpdk", "added", "0000:01:10.0")
	if c == nil {
		t.Fatal("expected added change for DPDK-bound VF")
	}
	if c.NewValue != "vfio-pci vf-of 0000:01:00.0" {
		t.Errorf("summary should name the parent PF, got %q", c.NewValue)
	}
}

func TestDiffDataplaneCollectorToggle(t *testing.T) {
	inv := dp([]collector.SRIOVPF{{PCIAddress: "0000:01:00.0"}}, []collector.DPDKDevice{{PCIAddress: "0000:02:00.0"}})

	r := &Result{}
	diffDataplane(nil, inv, r)
	if findChange(r, "dataplane", "added", "inventory") == nil {
		t.Error("expected single inventory-added summary when collector enabled")
	}

	r = &Result{}
	diffDataplane(inv, nil, r)
	if findChange(r, "dataplane", "removed", "inventory") == nil {
		t.Error("expected single inventory-removed summary when collector disabled")
	}
}

func TestDiffDataplaneBothNilNoChange(t *testing.T) {
	r := &Result{}
	diffDataplane(nil, nil, r)
	if len(r.Changes) != 0 {
		t.Errorf("both-nil should emit no changes, got %d", len(r.Changes))
	}
}

func TestDiffDataplaneNoChange(t *testing.T) {
	inv := dp(
		[]collector.SRIOVPF{{PCIAddress: "0000:01:00.0", Driver: "i40e", NumVFs: 4, TotalVFs: 8}},
		[]collector.DPDKDevice{{PCIAddress: "0000:02:00.0", Driver: "vfio-pci"}},
	)
	r := &Result{}
	diffDataplane(inv, inv, r)
	if len(r.Changes) != 0 {
		t.Errorf("identical inventories should emit no changes, got %d", len(r.Changes))
	}
}
