package rules

import "testing"

func TestEvaluateFirewallRulesetChanged(t *testing.T) {
	changes := []Change{
		{Section: "firewall", Type: "modified", Key: "ruleset_changed",
			OldValue: "aaa", NewValue: "bbb"},
	}
	findings := Evaluate(DefaultRules(), changes, false)
	if !fired(findings, "R32_FIREWALL_RULESET_CHANGED") {
		t.Error("expected R32 to fire on ruleset_changed key")
	}
}

func TestEvaluateFirewallFlushed(t *testing.T) {
	changes := []Change{
		{Section: "firewall", Type: "modified", Key: "flushed",
			OldValue: "20 rules", NewValue: "0 rules"},
	}
	findings := Evaluate(DefaultRules(), changes, false)
	if !fired(findings, "R33_FIREWALL_FLUSHED") {
		t.Error("expected R33 to fire on flushed key")
	}
}

// A plain ruleset_hash field change must not trip a firewall rule — only the
// synthetic keys are wired to rules.
func TestEvaluateFirewallPlainFieldNoRule(t *testing.T) {
	changes := []Change{
		{Section: "firewall", Type: "modified", Key: "ruleset_hash",
			OldValue: "aaa", NewValue: "bbb"},
	}
	findings := Evaluate(DefaultRules(), changes, false)
	if fired(findings, "R32_FIREWALL_RULESET_CHANGED") || fired(findings, "R33_FIREWALL_FLUSHED") {
		t.Error("a plain ruleset_hash field change must not fire a firewall rule")
	}
}

func TestFirewallRulesAreFreeTier(t *testing.T) {
	want := map[string]bool{
		"R32_FIREWALL_RULESET_CHANGED": false,
		"R33_FIREWALL_FLUSHED":         false,
	}
	for _, r := range DefaultRules() {
		if _, ok := want[r.ID]; ok && r.Pro {
			t.Errorf("%s should be free-tier, got Pro=true", r.ID)
		}
	}
}
