package diff

import (
	"testing"

	"github.com/statedrift/statedrift/internal/collector"
)

func fwResult(old, new *collector.Firewall) *Result {
	r := &Result{}
	diffFirewall(old, new, r)
	return r
}

func TestDiffFirewallRulesetChanged(t *testing.T) {
	old := &collector.Firewall{Backend: "nftables", RulesetHash: "aaa", Rules: 12}
	new := &collector.Firewall{Backend: "nftables", RulesetHash: "bbb", Rules: 13}
	r := fwResult(old, new)
	if !hasKey(r, "firewall", "ruleset_changed") {
		t.Error("expected ruleset_changed (R32)")
	}
	if hasKey(r, "firewall", "flushed") {
		t.Error("a one-rule addition is not a flush")
	}
}

func TestDiffFirewallFlushed(t *testing.T) {
	old := &collector.Firewall{Backend: "nftables", RulesetHash: "aaa", Rules: 20}
	new := &collector.Firewall{Backend: "nftables", RulesetHash: "", Rules: 0}
	r := fwResult(old, new)
	if !hasKey(r, "firewall", "flushed") {
		t.Error("expected flushed (R33) on populated → empty")
	}
	// Flush is dominant — must suppress the generic ruleset_changed.
	if hasKey(r, "firewall", "ruleset_changed") {
		t.Error("flushed should suppress ruleset_changed")
	}
}

func TestDiffFirewallFlushBelowThreshold(t *testing.T) {
	// Only 3 rules → emptying is not treated as a "flush of a populated
	// firewall"; it still registers as a generic change.
	old := &collector.Firewall{Backend: "nftables", RulesetHash: "aaa", Rules: 3}
	new := &collector.Firewall{Backend: "nftables", RulesetHash: "ccc", Rules: 0}
	r := fwResult(old, new)
	if hasKey(r, "firewall", "flushed") {
		t.Error("below threshold should not fire flushed")
	}
	if !hasKey(r, "firewall", "ruleset_changed") {
		t.Error("expected ruleset_changed for a sub-threshold empty")
	}
}

func TestDiffFirewallToolingVanished(t *testing.T) {
	// Backend → none (firewall tooling removed / unobservable). We must NOT
	// raise an alarm — absence of a view is not proof of a rule change.
	old := &collector.Firewall{Backend: "nftables", RulesetHash: "aaa", Rules: 20}
	new := &collector.Firewall{Backend: "none"}
	r := fwResult(old, new)
	if hasKey(r, "firewall", "flushed") || hasKey(r, "firewall", "ruleset_changed") {
		t.Error("backend → none must not raise a firewall alarm")
	}
	// The backend field change is still recorded for visibility.
	if !hasKey(r, "firewall", "backend") {
		t.Error("backend change should be recorded")
	}
}

func TestDiffFirewallEmptyToPopulated(t *testing.T) {
	old := &collector.Firewall{Backend: "nftables", RulesetHash: "", Rules: 0}
	new := &collector.Firewall{Backend: "nftables", RulesetHash: "bbb", Rules: 4}
	r := fwResult(old, new)
	if !hasKey(r, "firewall", "ruleset_changed") {
		t.Error("empty → populated is a real change (R32)")
	}
}

func TestDiffFirewallNoChange(t *testing.T) {
	f1 := &collector.Firewall{Backend: "iptables", RulesetHash: "deadbeef", Rules: 9}
	f2 := &collector.Firewall{Backend: "iptables", RulesetHash: "deadbeef", Rules: 9}
	r := fwResult(f1, f2)
	if len(r.Changes) != 0 {
		t.Errorf("identical firewall should produce no changes, got %d", len(r.Changes))
	}
}

func TestDiffFirewallNilTransitions(t *testing.T) {
	present := &collector.Firewall{Backend: "nftables", RulesetHash: "aaa", Rules: 10}

	r := fwResult(nil, present)
	if hasKey(r, "firewall", "flushed") || hasKey(r, "firewall", "ruleset_changed") {
		t.Error("nil → present must not raise alarms")
	}
	if !hasKey(r, "firewall", "backend") {
		t.Error("nil → present should record an added backend change")
	}

	r = fwResult(present, nil)
	if hasKey(r, "firewall", "flushed") || hasKey(r, "firewall", "ruleset_changed") {
		t.Error("present → nil must not raise alarms")
	}

	r = fwResult(nil, nil)
	if len(r.Changes) != 0 {
		t.Errorf("nil/nil should produce no changes, got %d", len(r.Changes))
	}
}
