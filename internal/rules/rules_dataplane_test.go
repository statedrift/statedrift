package rules

import "testing"

// v0.7 — network dataplane (SR-IOV / DPDK) anomaly rules R44–R47. The diff layer
// emits changes in the "dataplane.pf" / "dataplane.dpdk" sub-sections; these
// tests confirm the declarative rules fire on them, are free-tier, and that the
// two "added" rules do not cross-fire between sub-sections.

func TestEvaluateSRIOVPFAdded(t *testing.T) {
	changes := []Change{
		{Section: "dataplane.pf", Type: "added", Key: "0000:01:00.0", NewValue: "i40e 4/8 VFs (ens1f0)"},
	}
	if !fired(Evaluate(DefaultRules(), changes, false), "R44_SRIOV_PF_ADDED") {
		t.Error("expected R44 to fire on a new SR-IOV PF")
	}
}

func TestEvaluateSRIOVPFRemoved(t *testing.T) {
	changes := []Change{
		{Section: "dataplane.pf", Type: "removed", Key: "0000:01:00.0", OldValue: "i40e 4/8 VFs"},
	}
	if !fired(Evaluate(DefaultRules(), changes, false), "R45_SRIOV_PF_REMOVED") {
		t.Error("expected R45 to fire on a removed SR-IOV PF")
	}
}

func TestEvaluateSRIOVVFCountChanged(t *testing.T) {
	changes := []Change{
		{Section: "dataplane.pf", Type: "modified", Key: "0000:01:00.0.num_vfs", OldValue: "0", NewValue: "8"},
	}
	if !fired(Evaluate(DefaultRules(), changes, false), "R46_SRIOV_VF_COUNT_CHANGED") {
		t.Error("expected R46 to fire on a VF count change")
	}
	// The driver/interface modifications on the same sub-section must NOT trip R46.
	other := []Change{
		{Section: "dataplane.pf", Type: "modified", Key: "0000:01:00.0.driver", OldValue: "i40e", NewValue: "ice"},
	}
	if fired(Evaluate(DefaultRules(), other, false), "R46_SRIOV_VF_COUNT_CHANGED") {
		t.Error("R46 must not fire on a non-num_vfs modification")
	}
}

func TestEvaluateDPDKDeviceBound(t *testing.T) {
	changes := []Change{
		{Section: "dataplane.dpdk", Type: "added", Key: "0000:02:00.0", NewValue: "vfio-pci"},
	}
	findings := Evaluate(DefaultRules(), changes, false)
	if !fired(findings, "R47_DPDK_DEVICE_BOUND") {
		t.Error("expected R47 to fire on a newly DPDK-bound NIC")
	}
	// A DPDK add must not be mistaken for a PF add (distinct sub-sections).
	if fired(findings, "R44_SRIOV_PF_ADDED") {
		t.Error("R44 must not fire on a dataplane.dpdk change")
	}
}

func TestEvaluateDataplaneRulesAreFree(t *testing.T) {
	for _, r := range DefaultRules() {
		switch r.ID {
		case "R44_SRIOV_PF_ADDED", "R45_SRIOV_PF_REMOVED",
			"R46_SRIOV_VF_COUNT_CHANGED", "R47_DPDK_DEVICE_BOUND":
			if r.Pro {
				t.Errorf("%s must be free-tier, got Pro=true", r.ID)
			}
		}
	}
}
