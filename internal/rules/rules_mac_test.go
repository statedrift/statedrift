package rules

import "testing"

// fired reports whether Evaluate produced a finding for the given rule ID.
func fired(findings []Finding, id string) bool {
	for _, f := range findings {
		if f.Rule.ID == id {
			return true
		}
	}
	return false
}

func TestEvaluateMACEnforcementDisabled(t *testing.T) {
	changes := []Change{
		{Section: "mac", Type: "modified", Key: "enforcement_disabled",
			OldValue: "selinux mode=enforcing", NewValue: "selinux mode=disabled"},
	}
	findings := Evaluate(DefaultRules(), changes, false)
	if !fired(findings, "R29_MAC_ENFORCEMENT_DISABLED") {
		t.Error("expected R29 to fire on enforcement_disabled key")
	}
}

func TestEvaluateMACModeDegraded(t *testing.T) {
	changes := []Change{
		{Section: "mac", Type: "modified", Key: "mode_degraded",
			OldValue: "selinux mode=enforcing", NewValue: "selinux mode=permissive"},
	}
	findings := Evaluate(DefaultRules(), changes, false)
	if !fired(findings, "R30_MAC_MODE_DEGRADED") {
		t.Error("expected R30 to fire on mode_degraded key")
	}
}

func TestEvaluateMACConfigDrift(t *testing.T) {
	changes := []Change{
		{Section: "mac", Type: "modified", Key: "config_drift",
			OldValue: "enforcing", NewValue: "permissive"},
	}
	findings := Evaluate(DefaultRules(), changes, false)
	if !fired(findings, "R31_MAC_CONFIG_DRIFT") {
		t.Error("expected R31 to fire on config_drift key")
	}
}

// A plain per-field "mode" change must not trip any MAC rule — only the
// synthetic keys are wired to rules.
func TestEvaluateMACPlainFieldNoRule(t *testing.T) {
	changes := []Change{
		{Section: "mac", Type: "modified", Key: "policy_version",
			OldValue: "33", NewValue: "34"},
	}
	findings := Evaluate(DefaultRules(), changes, false)
	if fired(findings, "R29_MAC_ENFORCEMENT_DISABLED") ||
		fired(findings, "R30_MAC_MODE_DEGRADED") ||
		fired(findings, "R31_MAC_CONFIG_DRIFT") {
		t.Error("a plain field change must not fire any MAC rule")
	}
}

// All three MAC rules are free-tier and must fire without a Pro license.
func TestMACRulesAreFreeTier(t *testing.T) {
	want := map[string]bool{
		"R29_MAC_ENFORCEMENT_DISABLED": false,
		"R30_MAC_MODE_DEGRADED":        false,
		"R31_MAC_CONFIG_DRIFT":         false,
	}
	for _, r := range DefaultRules() {
		if _, ok := want[r.ID]; ok && r.Pro {
			t.Errorf("%s should be free-tier, got Pro=true", r.ID)
		}
	}
}
