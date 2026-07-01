package diff

import (
	"testing"

	"github.com/statedrift/statedrift/internal/collector"
)

// v0.8 — AI-agent-harness configuration diff. The diff emits changes under the
// harness.permissions / harness.mcp / harness.hooks / harness.model sub-sections;
// these tests confirm the semantic modelling (a grant gained — allow added OR
// deny lifted — is "added") and the element keying.

const hsrc = "/proj/.claude/settings.json"

func hc(c collector.HarnessConfig) *collector.HarnessInventory {
	c.Source = hsrc
	c.Tool = "claude-code"
	return &collector.HarnessInventory{TotalConfigs: 1, Configs: []collector.HarnessConfig{c}}
}

func TestDiffHarnessAllowAddedIsBroadening(t *testing.T) {
	old := hc(collector.HarnessConfig{Permissions: collector.HarnessPerms{Allow: []string{"Read(*)"}}})
	new := hc(collector.HarnessConfig{Permissions: collector.HarnessPerms{Allow: []string{"Read(*)", "Bash(rm *)"}}})

	r := &Result{}
	diffHarness(old, new, r)

	if findChange(r, "harness.permissions", "added", hsrc+" allow Bash(rm *)") == nil {
		t.Error("expected an added (broadening) change for the new allow pattern")
	}
}

func TestDiffHarnessDenyLiftedIsBroadening(t *testing.T) {
	old := hc(collector.HarnessConfig{Permissions: collector.HarnessPerms{Deny: []string{"Bash(rm *)"}}})
	new := hc(collector.HarnessConfig{Permissions: collector.HarnessPerms{}})

	r := &Result{}
	diffHarness(old, new, r)

	// A lifted deny is modelled as a grant *gained* → ChangeType "added".
	if findChange(r, "harness.permissions", "added", hsrc+" deny-lifted Bash(rm *)") == nil {
		t.Error("expected an added (broadening) change when a deny pattern is lifted")
	}
}

func TestDiffHarnessAllowRemovedIsNarrowing(t *testing.T) {
	old := hc(collector.HarnessConfig{Permissions: collector.HarnessPerms{Allow: []string{"Read(*)", "Bash(rm *)"}}})
	new := hc(collector.HarnessConfig{Permissions: collector.HarnessPerms{Allow: []string{"Read(*)"}}})

	r := &Result{}
	diffHarness(old, new, r)

	if findChange(r, "harness.permissions", "removed", hsrc+" allow Bash(rm *)") == nil {
		t.Error("expected a removed (narrowing) change when an allow pattern is dropped")
	}
	// Narrowing must not be reported as broadening.
	if findChange(r, "harness.permissions", "added", hsrc+" allow Bash(rm *)") != nil {
		t.Error("an allow removal must not surface as an added/broadening change")
	}
}

func TestDiffHarnessMCPServerAdded(t *testing.T) {
	old := hc(collector.HarnessConfig{})
	new := hc(collector.HarnessConfig{MCPServers: []collector.HarnessMCP{
		{Name: "github", Transport: "stdio", Fingerprint: "abc"},
	}})

	r := &Result{}
	diffHarness(old, new, r)

	c := findChange(r, "harness.mcp", "added", hsrc+" github")
	if c == nil {
		t.Fatal("expected an added change for the new MCP server")
	}
	if c.NewValue != "stdio" {
		t.Errorf("summary should be the transport, got %q", c.NewValue)
	}
}

func TestDiffHarnessMCPFingerprintChange(t *testing.T) {
	old := hc(collector.HarnessConfig{MCPServers: []collector.HarnessMCP{{Name: "github", Fingerprint: "aaa"}}})
	new := hc(collector.HarnessConfig{MCPServers: []collector.HarnessMCP{{Name: "github", Fingerprint: "bbb"}}})

	r := &Result{}
	diffHarness(old, new, r)

	if findChange(r, "harness.mcp", "modified", hsrc+" github fingerprint") == nil {
		t.Error("expected a modified change when an MCP server's fingerprint changes")
	}
}

func TestDiffHarnessHookAdded(t *testing.T) {
	old := hc(collector.HarnessConfig{})
	new := hc(collector.HarnessConfig{Hooks: []collector.HarnessHook{
		{Event: "Stop", Matcher: "", Fingerprint: "deadbeef"},
	}})

	r := &Result{}
	diffHarness(old, new, r)

	if findChange(r, "harness.hooks", "added", hsrc+" Stop") == nil {
		t.Error("expected an added change for the new hook")
	}
}

func TestDiffHarnessHookCommandChange(t *testing.T) {
	old := hc(collector.HarnessConfig{Hooks: []collector.HarnessHook{{Event: "PreToolUse", Matcher: "Bash", Fingerprint: "aaa"}}})
	new := hc(collector.HarnessConfig{Hooks: []collector.HarnessHook{{Event: "PreToolUse", Matcher: "Bash", Fingerprint: "bbb"}}})

	r := &Result{}
	diffHarness(old, new, r)

	if findChange(r, "harness.hooks", "modified", hsrc+" PreToolUse/Bash fingerprint") == nil {
		t.Error("expected a modified change when a hook's command fingerprint changes")
	}
}

func TestDiffHarnessModelChange(t *testing.T) {
	old := hc(collector.HarnessConfig{Model: "claude-a"})
	new := hc(collector.HarnessConfig{Model: "claude-b"})

	r := &Result{}
	diffHarness(old, new, r)

	c := findChange(r, "harness.model", "modified", hsrc+" model")
	if c == nil {
		t.Fatal("expected a model change")
	}
	if c.OldValue != "claude-a" || c.NewValue != "claude-b" {
		t.Errorf("unexpected model values: %q -> %q", c.OldValue, c.NewValue)
	}
}

func TestDiffHarnessCollectorToggle(t *testing.T) {
	inv := hc(collector.HarnessConfig{Model: "claude-a"})

	r := &Result{}
	diffHarness(nil, inv, r)
	if findChange(r, "harness", "added", "inventory") == nil {
		t.Error("expected a single inventory-added summary when collector enabled")
	}

	r = &Result{}
	diffHarness(inv, nil, r)
	if findChange(r, "harness", "removed", "inventory") == nil {
		t.Error("expected a single inventory-removed summary when collector disabled")
	}
}

func TestDiffHarnessBothNilNoChange(t *testing.T) {
	r := &Result{}
	diffHarness(nil, nil, r)
	if len(r.Changes) != 0 {
		t.Errorf("both-nil should emit no changes, got %d", len(r.Changes))
	}
}

func TestDiffHarnessIdenticalNoChange(t *testing.T) {
	inv := hc(collector.HarnessConfig{
		Model:       "claude-a",
		Permissions: collector.HarnessPerms{Allow: []string{"Read(*)"}, Deny: []string{"Bash(rm *)"}},
		MCPServers:  []collector.HarnessMCP{{Name: "github", Fingerprint: "abc"}},
		Hooks:       []collector.HarnessHook{{Event: "Stop", Fingerprint: "def"}},
	})
	r := &Result{}
	diffHarness(inv, inv, r)
	if len(r.Changes) != 0 {
		t.Errorf("identical inventories should emit no changes, got %d", len(r.Changes))
	}
}
