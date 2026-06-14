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

// changeValue returns the new value of the first change matching
// section/type/key, and whether such a change exists.
func changeValue(r *Result, section, changeType, key string) (string, bool) {
	for _, c := range r.Changes {
		if c.Section == section && c.Type == changeType && c.Key == key {
			return c.NewValue, true
		}
	}
	return "", false
}

// --- v0.5 Phase O: per-rule diff ---

func TestDiffFirewallRuleAdded(t *testing.T) {
	old := &collector.Firewall{
		Backend: "iptables", RulesetHash: "aaa", Rules: 1,
		RuleList: []collector.FirewallRule{
			{Table: "ip4 filter", Chain: "INPUT", Rule: "-A INPUT -p tcp --dport 22 -j ACCEPT"},
		},
	}
	new := &collector.Firewall{
		Backend: "iptables", RulesetHash: "bbb", Rules: 2,
		RuleList: []collector.FirewallRule{
			{Table: "ip4 filter", Chain: "INPUT", Rule: "-A INPUT -p tcp --dport 22 -j ACCEPT"},
			{Table: "ip4 filter", Chain: "INPUT", Rule: "-A INPUT -p tcp --dport 80 -j ACCEPT"},
		},
	}
	r := fwResult(old, new)
	v, ok := changeValue(r, "firewall", "added", "ip4 filter/INPUT")
	if !ok {
		t.Fatal("expected an added firewall rule for ip4 filter/INPUT")
	}
	if v != "-A INPUT -p tcp --dport 80 -j ACCEPT" {
		t.Errorf("unexpected added rule value: %q", v)
	}
	if hasChange(r, "firewall", "removed", "") {
		t.Error("a pure addition should not produce a removed change")
	}
	// Per-rule detail present → opaque ruleset_hash field-line suppressed.
	if hasKey(r, "firewall", "ruleset_hash") {
		t.Error("ruleset_hash field-line should be suppressed when per-rule detail is available")
	}
	// R32 still fires from the hash path.
	if !hasKey(r, "firewall", "ruleset_changed") {
		t.Error("ruleset_changed (R32) should still fire")
	}
}

func TestDiffFirewallRuleRemoved(t *testing.T) {
	old := &collector.Firewall{
		Backend: "iptables", RulesetHash: "aaa", Rules: 2,
		RuleList: []collector.FirewallRule{
			{Table: "ip4 filter", Chain: "INPUT", Rule: "-A INPUT -p tcp --dport 22 -j ACCEPT"},
			{Table: "ip4 filter", Chain: "INPUT", Rule: "-A INPUT -p tcp --dport 80 -j ACCEPT"},
		},
	}
	new := &collector.Firewall{
		Backend: "iptables", RulesetHash: "bbb", Rules: 1,
		RuleList: []collector.FirewallRule{
			{Table: "ip4 filter", Chain: "INPUT", Rule: "-A INPUT -p tcp --dport 22 -j ACCEPT"},
		},
	}
	r := fwResult(old, new)
	if !hasKey(r, "firewall", "ip4 filter/INPUT") {
		t.Fatal("expected a change for ip4 filter/INPUT")
	}
	if !hasChange(r, "firewall", "removed", "ip4 filter/INPUT") {
		t.Error("expected the dropped rule to surface as removed")
	}
	if hasChange(r, "firewall", "added", "ip4 filter/INPUT") {
		t.Error("a pure removal should not produce an added change")
	}
}

func TestDiffFirewallRuleModifiedIsRemoveAdd(t *testing.T) {
	// A rule edited in place (ACCEPT → DROP) is atomic: removed + added.
	old := &collector.Firewall{
		Backend: "iptables", RulesetHash: "aaa", Rules: 1,
		RuleList: []collector.FirewallRule{
			{Table: "ip4 filter", Chain: "INPUT", Rule: "-A INPUT -p tcp --dport 22 -j ACCEPT"},
		},
	}
	new := &collector.Firewall{
		Backend: "iptables", RulesetHash: "bbb", Rules: 1,
		RuleList: []collector.FirewallRule{
			{Table: "ip4 filter", Chain: "INPUT", Rule: "-A INPUT -p tcp --dport 22 -j DROP"},
		},
	}
	r := fwResult(old, new)
	if !hasChange(r, "firewall", "removed", "ip4 filter/INPUT") {
		t.Error("expected the old ACCEPT rule removed")
	}
	if !hasChange(r, "firewall", "added", "ip4 filter/INPUT") {
		t.Error("expected the new DROP rule added")
	}
	if hasKey(r, "firewall", "ip4 filter/INPUT.reordered") {
		t.Error("a remove+add is not a reorder")
	}
}

func TestDiffFirewallRuleReordered(t *testing.T) {
	// First-match-wins: swapping a DROP above an ACCEPT changes behaviour even
	// though the set of rules is identical.
	a := collector.FirewallRule{Table: "ip4 filter", Chain: "INPUT", Rule: "-A INPUT -s 10.0.0.0/8 -j ACCEPT"}
	b := collector.FirewallRule{Table: "ip4 filter", Chain: "INPUT", Rule: "-A INPUT -s 10.0.0.5/32 -j DROP"}
	old := &collector.Firewall{
		Backend: "iptables", RulesetHash: "aaa", Rules: 2,
		RuleList: []collector.FirewallRule{a, b},
	}
	new := &collector.Firewall{
		Backend: "iptables", RulesetHash: "bbb", Rules: 2,
		RuleList: []collector.FirewallRule{b, a},
	}
	r := fwResult(old, new)
	if !hasKey(r, "firewall", "ip4 filter/INPUT.reordered") {
		t.Error("expected a reordered change for the chain")
	}
	if hasChange(r, "firewall", "added", "ip4 filter/INPUT") ||
		hasChange(r, "firewall", "removed", "ip4 filter/INPUT") {
		t.Error("a pure reorder should not add or remove rules")
	}
}

func TestDiffFirewallPerChainGrouping(t *testing.T) {
	// Changes in different chains stay distinct.
	old := &collector.Firewall{
		Backend: "iptables", RulesetHash: "aaa", Rules: 2,
		RuleList: []collector.FirewallRule{
			{Table: "ip4 filter", Chain: "INPUT", Rule: "-A INPUT -j ACCEPT"},
			{Table: "ip4 filter", Chain: "FORWARD", Rule: "-A FORWARD -j DROP"},
		},
	}
	new := &collector.Firewall{
		Backend: "iptables", RulesetHash: "bbb", Rules: 2,
		RuleList: []collector.FirewallRule{
			{Table: "ip4 filter", Chain: "INPUT", Rule: "-A INPUT -j DROP"},
			{Table: "ip4 filter", Chain: "FORWARD", Rule: "-A FORWARD -j DROP"},
		},
	}
	r := fwResult(old, new)
	if !hasChange(r, "firewall", "added", "ip4 filter/INPUT") ||
		!hasChange(r, "firewall", "removed", "ip4 filter/INPUT") {
		t.Error("INPUT chain should show the edited rule as remove+add")
	}
	if hasKey(r, "firewall", "ip4 filter/FORWARD") {
		t.Error("unchanged FORWARD chain should produce no change")
	}
}

func TestDiffFirewallHashOnlyWhenNoRuleList(t *testing.T) {
	// Pre-0.5 snapshot (or one side lacking RuleList): fall back to the Phase N
	// opaque ruleset_hash field-line; no per-rule changes.
	old := &collector.Firewall{Backend: "iptables", RulesetHash: "aaa", Rules: 2}
	new := &collector.Firewall{
		Backend: "iptables", RulesetHash: "bbb", Rules: 2,
		RuleList: []collector.FirewallRule{
			{Table: "ip4 filter", Chain: "INPUT", Rule: "-A INPUT -j DROP"},
		},
	}
	r := fwResult(old, new)
	if !hasKey(r, "firewall", "ruleset_hash") {
		t.Error("hash-only mode should still emit the ruleset_hash field-line")
	}
	if hasChange(r, "firewall", "added", "") || hasChange(r, "firewall", "removed", "") {
		t.Error("no per-rule diff when one side lacks a RuleList")
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
