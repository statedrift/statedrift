package rules

import "testing"

// v0.5 Phase Q — filesystem + firewall anomaly rules R34–R36. The diff layer
// emits bare synthetic keys; these tests confirm the thin declarative rules
// fire on them, are free-tier, and do not fire on the raw per-file changes.

func TestEvaluateFSSetuidAdded(t *testing.T) {
	changes := []Change{
		{Section: "filesystem", Type: "modified", Key: "setuid_added", NewValue: "/usr/bin/x"},
	}
	if !fired(Evaluate(DefaultRules(), changes, false), "R34_FS_SETUID_ADDED") {
		t.Error("expected R34 to fire on setuid_added")
	}
}

func TestEvaluateFSWorldWritable(t *testing.T) {
	changes := []Change{
		{Section: "filesystem", Type: "modified", Key: "world_writable", NewValue: "/etc/x"},
	}
	if !fired(Evaluate(DefaultRules(), changes, false), "R35_FS_WORLD_WRITABLE") {
		t.Error("expected R35 to fire on world_writable")
	}
}

func TestEvaluateFWWorldOpen(t *testing.T) {
	changes := []Change{
		{Section: "firewall", Type: "modified", Key: "world_open", NewValue: "-A INPUT -p tcp --dport 22 -j ACCEPT"},
	}
	if !fired(Evaluate(DefaultRules(), changes, false), "R36_FW_WORLD_OPEN_SENSITIVE") {
		t.Error("expected R36 to fire on world_open")
	}
}

// The raw per-file mode/content changes carry path-bearing keys (with '/'),
// which the bare-key rules must not match.
func TestEvaluatePerFileChangeDoesNotFireSecurityRules(t *testing.T) {
	changes := []Change{
		{Section: "filesystem", Type: "modified", Key: "/etc/passwd.mode", OldValue: "-rw-r--r--", NewValue: "-rw-rw-rw-"},
		{Section: "filesystem", Type: "modified", Key: "/etc/passwd.sha256", OldValue: "a", NewValue: "b"},
	}
	findings := Evaluate(DefaultRules(), changes, false)
	if fired(findings, "R34_FS_SETUID_ADDED") || fired(findings, "R35_FS_WORLD_WRITABLE") {
		t.Error("path-keyed per-file changes must not fire the bare-key security rules")
	}
}

func TestPhaseQRulesAreFreeTier(t *testing.T) {
	want := map[string]bool{
		"R34_FS_SETUID_ADDED":         false,
		"R35_FS_WORLD_WRITABLE":       false,
		"R36_FW_WORLD_OPEN_SENSITIVE": false,
	}
	for _, r := range DefaultRules() {
		if _, ok := want[r.ID]; ok && r.Pro {
			t.Errorf("%s should be free-tier, got Pro=true", r.ID)
		}
	}
}
