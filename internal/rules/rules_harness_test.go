package rules

import "testing"

// v0.8 — AI-agent-harness configuration rules R49–R54. The diff layer emits
// changes under the harness.permissions / harness.mcp / harness.hooks /
// harness.model sub-sections; these tests confirm the declarative rules fire on
// them, are free-tier, and do not cross-fire between element kinds.

func TestEvaluateHarnessPermissionBroadened(t *testing.T) {
	changes := []Change{
		{Section: "harness.permissions", Type: "added", Key: "/p/settings.json allow Bash(rm *)", NewValue: "Bash(rm *)"},
	}
	if !fired(Evaluate(DefaultRules(), changes, false), "R49_HARNESS_PERMISSION_BROADENED") {
		t.Error("expected R49 to fire on a broadened permission")
	}
	// A narrowing (removed) must not trip R49.
	narrow := []Change{
		{Section: "harness.permissions", Type: "removed", Key: "/p/settings.json allow Bash(rm *)", OldValue: "Bash(rm *)"},
	}
	if fired(Evaluate(DefaultRules(), narrow, false), "R49_HARNESS_PERMISSION_BROADENED") {
		t.Error("R49 must not fire when a permission is narrowed")
	}
}

func TestEvaluateHarnessMCPServerAdded(t *testing.T) {
	changes := []Change{
		{Section: "harness.mcp", Type: "added", Key: "/p/.mcp.json github", NewValue: "stdio"},
	}
	findings := Evaluate(DefaultRules(), changes, false)
	if !fired(findings, "R50_HARNESS_MCP_SERVER_ADDED") {
		t.Error("expected R50 to fire on a newly added MCP server")
	}
	// An MCP add must not be mistaken for a hook add (distinct sub-sections).
	if fired(findings, "R51_HARNESS_HOOK_ADDED") {
		t.Error("R51 must not fire on a harness.mcp change")
	}
}

func TestEvaluateHarnessHookAdded(t *testing.T) {
	changes := []Change{
		{Section: "harness.hooks", Type: "added", Key: "/p/settings.json Stop", NewValue: "deadbeef"},
	}
	if !fired(Evaluate(DefaultRules(), changes, false), "R51_HARNESS_HOOK_ADDED") {
		t.Error("expected R51 to fire on a newly added hook")
	}
}

func TestEvaluateHarnessMCPServerChanged(t *testing.T) {
	changes := []Change{
		{Section: "harness.mcp", Type: "modified", Key: "/p/.mcp.json github fingerprint", OldValue: "aaa", NewValue: "bbb"},
	}
	if !fired(Evaluate(DefaultRules(), changes, false), "R52_HARNESS_MCP_SERVER_CHANGED") {
		t.Error("expected R52 to fire on an MCP server fingerprint change")
	}
}

func TestEvaluateHarnessHookChanged(t *testing.T) {
	changes := []Change{
		{Section: "harness.hooks", Type: "modified", Key: "/p/settings.json PreToolUse/Bash fingerprint", OldValue: "aaa", NewValue: "bbb"},
	}
	if !fired(Evaluate(DefaultRules(), changes, false), "R53_HARNESS_HOOK_CHANGED") {
		t.Error("expected R53 to fire on a hook command change")
	}
}

func TestEvaluateHarnessModelChanged(t *testing.T) {
	changes := []Change{
		{Section: "harness.model", Type: "modified", Key: "/p/settings.json model", OldValue: "claude-a", NewValue: "claude-b"},
	}
	if !fired(Evaluate(DefaultRules(), changes, false), "R54_HARNESS_MODEL_CHANGED") {
		t.Error("expected R54 to fire on a model change")
	}
}

func TestEvaluateHarnessRulesAreFree(t *testing.T) {
	want := map[string]bool{
		"R49_HARNESS_PERMISSION_BROADENED": false,
		"R50_HARNESS_MCP_SERVER_ADDED":     false,
		"R51_HARNESS_HOOK_ADDED":           false,
		"R52_HARNESS_MCP_SERVER_CHANGED":   false,
		"R53_HARNESS_HOOK_CHANGED":         false,
		"R54_HARNESS_MODEL_CHANGED":        false,
	}
	for _, r := range DefaultRules() {
		if _, ok := want[r.ID]; ok {
			want[r.ID] = true
			if r.Pro {
				t.Errorf("%s must be free-tier, got Pro=true", r.ID)
			}
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("expected rule %s to be present in DefaultRules", id)
		}
	}
}
