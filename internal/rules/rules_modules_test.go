package rules

import "testing"

// v0.7 — kernel-module integrity rule R48. The diff layer emits a module size
// change as a "modules"/"modified" change keyed "<name>.size". R48 gives that
// the rootkit-replacement severity R17/R18 (load/unload) cannot provide. These
// tests confirm it fires on a size change, is free-tier, and does not fire on
// the other module modifications (dependency-graph changes) sharing the section.

func TestEvaluateModuleReplaced(t *testing.T) {
	changes := []Change{
		{Section: "modules", Type: "modified", Key: "nf_tables.size", OldValue: "200704", NewValue: "204800"},
	}
	if !fired(Evaluate(DefaultRules(), changes, false), "R48_MODULE_REPLACED") {
		t.Error("expected R48 to fire on an in-place module size change")
	}
}

func TestEvaluateModuleReplacedIgnoresDependencies(t *testing.T) {
	// A dependency-graph change is a distinct (lower) signal; R48 keys on size
	// only, so it must not fire on a "<name>.dependencies" modification.
	changes := []Change{
		{Section: "modules", Type: "modified", Key: "nf_tables.dependencies", OldValue: "nf_nat", NewValue: "nf_nat,nf_conntrack"},
	}
	if fired(Evaluate(DefaultRules(), changes, false), "R48_MODULE_REPLACED") {
		t.Error("R48 must not fire on a non-size module modification")
	}
}

func TestEvaluateModuleReplacedDistinctFromLoadUnload(t *testing.T) {
	// An in-place replacement is neither a load nor an unload: R17/R18 must stay
	// silent on a size change so the replacement is not misreported.
	changes := []Change{
		{Section: "modules", Type: "modified", Key: "nf_tables.size", OldValue: "200704", NewValue: "204800"},
	}
	findings := Evaluate(DefaultRules(), changes, false)
	if fired(findings, "R17_MODULE_LOADED") {
		t.Error("R17 must not fire on an in-place module replacement")
	}
	if fired(findings, "R18_MODULE_REMOVED") {
		t.Error("R18 must not fire on an in-place module replacement")
	}
}

func TestEvaluateModuleReplacedIsFree(t *testing.T) {
	for _, r := range DefaultRules() {
		if r.ID == "R48_MODULE_REPLACED" && r.Pro {
			t.Error("R48 must be free-tier, got Pro=true")
		}
	}
}
