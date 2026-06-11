package diff

import (
	"testing"

	"github.com/statedrift/statedrift/internal/collector"
)

// macResult runs diffMAC in isolation and returns the result.
func macResult(old, new *collector.MAC) *Result {
	r := &Result{}
	diffMAC(old, new, r)
	return r
}

// hasKey reports whether the result contains a change with the given section
// and key.
func hasKey(r *Result, section, key string) bool {
	for _, c := range r.Changes {
		if c.Section == section && c.Key == key {
			return true
		}
	}
	return false
}

func TestDiffMACSELinuxEnforcingToPermissive(t *testing.T) {
	old := &collector.MAC{System: "selinux", Mode: "enforcing", ConfigMode: "enforcing"}
	new := &collector.MAC{System: "selinux", Mode: "permissive", ConfigMode: "enforcing"}
	r := macResult(old, new)

	if !hasKey(r, "mac", "mode_degraded") {
		t.Error("expected mode_degraded (R30)")
	}
	if hasKey(r, "mac", "enforcement_disabled") {
		t.Error("permissive is not disabled — should not fire R29")
	}
	// Runtime now permissive while config still enforcing → config drift.
	if !hasKey(r, "mac", "config_drift") {
		t.Error("expected config_drift (R31)")
	}
}

func TestDiffMACSELinuxEnforcingToDisabled(t *testing.T) {
	old := &collector.MAC{System: "selinux", Mode: "enforcing", ConfigMode: "enforcing"}
	new := &collector.MAC{System: "selinux", Mode: "disabled", ConfigMode: "enforcing"}
	r := macResult(old, new)

	if !hasKey(r, "mac", "enforcement_disabled") {
		t.Error("expected enforcement_disabled (R29)")
	}
	// Full disable suppresses the weaker mode_degraded signal.
	if hasKey(r, "mac", "mode_degraded") {
		t.Error("enforcement_disabled should suppress mode_degraded")
	}
}

func TestDiffMACSELinuxToNone(t *testing.T) {
	old := &collector.MAC{System: "selinux", Mode: "enforcing", ConfigMode: "enforcing"}
	new := &collector.MAC{System: "none"}
	r := macResult(old, new)

	if !hasKey(r, "mac", "enforcement_disabled") {
		t.Error("selinux → none should fire enforcement_disabled (R29)")
	}
}

func TestDiffMACConfigDriftOnly(t *testing.T) {
	// Same enforcing runtime both snapshots, but config edited to disabled
	// (pending reboot). Runtime still enforcing, so no R29/R30, only R31.
	old := &collector.MAC{System: "selinux", Mode: "enforcing", ConfigMode: "enforcing"}
	new := &collector.MAC{System: "selinux", Mode: "enforcing", ConfigMode: "disabled"}
	r := macResult(old, new)

	if !hasKey(r, "mac", "config_drift") {
		t.Error("expected config_drift (R31)")
	}
	if hasKey(r, "mac", "enforcement_disabled") || hasKey(r, "mac", "mode_degraded") {
		t.Error("runtime unchanged — no R29/R30 expected")
	}
}

func TestDiffMACConfigDriftNoReFire(t *testing.T) {
	// Mismatch already present in old and unchanged → must NOT re-fire.
	old := &collector.MAC{System: "selinux", Mode: "permissive", ConfigMode: "enforcing"}
	new := &collector.MAC{System: "selinux", Mode: "permissive", ConfigMode: "enforcing"}
	r := macResult(old, new)

	if hasKey(r, "mac", "config_drift") {
		t.Error("standing mismatch should not re-fire config_drift")
	}
}

func TestDiffMACAppArmorEnforceDropped(t *testing.T) {
	old := &collector.MAC{System: "apparmor", Mode: "enforcing", EnforceCount: 12, ComplainCount: 1}
	new := &collector.MAC{System: "apparmor", Mode: "enforcing", EnforceCount: 8, ComplainCount: 5}
	r := macResult(old, new)

	if !hasKey(r, "mac", "mode_degraded") {
		t.Error("apparmor enforce_count drop should fire mode_degraded (R30)")
	}
	if hasKey(r, "mac", "enforcement_disabled") {
		t.Error("still enforcing — no R29")
	}
}

func TestDiffMACAppArmorDisabled(t *testing.T) {
	old := &collector.MAC{System: "apparmor", Mode: "enforcing", EnforceCount: 12}
	new := &collector.MAC{System: "apparmor", Mode: "disabled"}
	r := macResult(old, new)

	if !hasKey(r, "mac", "enforcement_disabled") {
		t.Error("apparmor enforcing → disabled should fire R29")
	}
}

func TestDiffMACNoChange(t *testing.T) {
	m1 := &collector.MAC{System: "selinux", Mode: "enforcing", ConfigMode: "enforcing", PolicyVersion: "33"}
	m2 := &collector.MAC{System: "selinux", Mode: "enforcing", ConfigMode: "enforcing", PolicyVersion: "33"}
	r := macResult(m1, m2)
	if len(r.Changes) != 0 {
		t.Errorf("identical MAC should produce no changes, got %d", len(r.Changes))
	}
}

func TestDiffMACNilTransitions(t *testing.T) {
	present := &collector.MAC{System: "selinux", Mode: "enforcing"}

	// old nil → added, no alarm.
	r := macResult(nil, present)
	if hasKey(r, "mac", "enforcement_disabled") || hasKey(r, "mac", "mode_degraded") {
		t.Error("nil→present must not raise alarms")
	}
	if !hasKey(r, "mac", "system") {
		t.Error("nil→present should record an added system change")
	}

	// new nil → removed, no alarm (absence of data is not proof of disable).
	r = macResult(present, nil)
	if hasKey(r, "mac", "enforcement_disabled") {
		t.Error("present→nil must not raise enforcement_disabled")
	}

	// both nil → nothing.
	r = macResult(nil, nil)
	if len(r.Changes) != 0 {
		t.Errorf("nil/nil should produce no changes, got %d", len(r.Changes))
	}
}

func TestDiffMACFieldChanges(t *testing.T) {
	old := &collector.MAC{System: "selinux", Mode: "enforcing", PolicyVersion: "33", PolicyType: "targeted"}
	new := &collector.MAC{System: "selinux", Mode: "enforcing", PolicyVersion: "34", PolicyType: "mls"}
	r := macResult(old, new)
	if !hasKey(r, "mac", "policy_version") {
		t.Error("policy_version change should be recorded")
	}
	if !hasKey(r, "mac", "policy_type") {
		t.Error("policy_type change should be recorded")
	}
}
