package collector

import (
	"os"
	"path/filepath"
	"testing"
)

// mkUnitLink creates dir/name as a symlink to dest. The target need not exist —
// systemd enablement links routinely point at unit files this test does not
// create, and the collector must never follow them.
func mkUnitLink(t *testing.T, dir, name, dest string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.Symlink(dest, filepath.Join(dir, name)); err != nil {
		t.Fatalf("symlink %s/%s: %v", dir, name, err)
	}
}

// unitTree builds a systemd-like pair of roots covering every shape the
// collector recognizes, and returns (persistent, runtime).
func unitTree(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	etc := filepath.Join(base, "etc")
	run := filepath.Join(base, "run")

	// Enabled, and wanted by two targets — the value must be deterministic.
	mkUnitLink(t, filepath.Join(etc, "multi-user.target.wants"), "auditd.service",
		"/usr/lib/systemd/system/auditd.service")
	mkUnitLink(t, filepath.Join(etc, "graphical.target.wants"), "auditd.service",
		"/usr/lib/systemd/system/auditd.service")
	// Wanted by both .wants and .requires of the same target — one target, once.
	mkUnitLink(t, filepath.Join(etc, "multi-user.target.wants"), "firewalld.service",
		"/usr/lib/systemd/system/firewalld.service")
	mkUnitLink(t, filepath.Join(etc, "multi-user.target.requires"), "firewalld.service",
		"/usr/lib/systemd/system/firewalld.service")
	// Masked, and aliased.
	mkUnitLink(t, etc, "rsyslog.service", os.DevNull)
	mkUnitLink(t, etc, "display-manager.service", "/usr/lib/systemd/system/gdm.service")
	// Noise that must be ignored: a drop-in directory, a non-service link, a
	// plain file, and a nested directory that is not a .wants/.requires.
	if err := os.MkdirAll(filepath.Join(etc, "sshd.service.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	mkUnitLink(t, filepath.Join(etc, "multi-user.target.wants"), "chronyd.timer",
		"/usr/lib/systemd/system/chronyd.timer")
	if err := os.WriteFile(filepath.Join(etc, "README"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Runtime-only enablement and a runtime mask.
	mkUnitLink(t, filepath.Join(run, "multi-user.target.wants"), "telegraf.service",
		"/usr/lib/systemd/system/telegraf.service")
	mkUnitLink(t, run, "netdata.service", os.DevNull)

	return etc, run
}

func TestCollectServiceEnablement(t *testing.T) {
	etc, run := unitTree(t)
	got, err := collectServiceEnablementFrom(etc, run)
	if err != nil {
		t.Fatalf("collectServiceEnablementFrom: %v", err)
	}

	want := map[string]string{
		"auditd.service":          "enabled:graphical.target,multi-user.target",
		"firewalld.service":       "enabled:multi-user.target",
		"rsyslog.service":         "masked",
		"display-manager.service": "alias:gdm.service",
		"telegraf.service":        "enabled-runtime:multi-user.target",
		"netdata.service":         "masked-runtime",
	}
	for unit, wantState := range want {
		if got[unit] != wantState {
			t.Errorf("%s: got %q, want %q", unit, got[unit], wantState)
		}
	}
	if len(got) != len(want) {
		t.Errorf("collected %d units, want %d: %v", len(got), len(want), got)
	}
	if _, ok := got["chronyd.timer"]; ok {
		t.Error("a .timer unit was collected; this collector covers services only")
	}
}

// A masked unit cannot start even if a stale .wants symlink still points at it,
// so the mask must win inside a single root.
func TestServiceEnablementMaskBeatsStaleWantsLink(t *testing.T) {
	etc := filepath.Join(t.TempDir(), "etc")
	mkUnitLink(t, filepath.Join(etc, "multi-user.target.wants"), "auditd.service",
		"/usr/lib/systemd/system/auditd.service")
	mkUnitLink(t, etc, "auditd.service", os.DevNull)

	got, err := collectServiceEnablementFrom(etc, filepath.Join(etc, "does-not-exist"))
	if err != nil {
		t.Fatalf("collectServiceEnablementFrom: %v", err)
	}
	if got["auditd.service"] != "masked" {
		t.Errorf("auditd.service: got %q, want %q", got["auditd.service"], "masked")
	}
}

// A unit enabled in both layers is reported by its persistent state, which is
// the fact that survives a reboot.
func TestServiceEnablementPersistentBeatsRuntime(t *testing.T) {
	base := t.TempDir()
	etc, run := filepath.Join(base, "etc"), filepath.Join(base, "run")
	mkUnitLink(t, filepath.Join(etc, "multi-user.target.wants"), "auditd.service", "/x")
	mkUnitLink(t, filepath.Join(run, "multi-user.target.wants"), "auditd.service", "/x")

	got, err := collectServiceEnablementFrom(etc, run)
	if err != nil {
		t.Fatalf("collectServiceEnablementFrom: %v", err)
	}
	if got["auditd.service"] != "enabled:multi-user.target" {
		t.Errorf("auditd.service: got %q, want persistent state", got["auditd.service"])
	}
}

// A host with no /etc/systemd/system at all (a container, a non-systemd image)
// is "nothing decided", not a collection failure.
func TestServiceEnablementMissingRootsIsNotAnError(t *testing.T) {
	base := t.TempDir()
	got, err := collectServiceEnablementFrom(filepath.Join(base, "nope"), filepath.Join(base, "nah"))
	if err != nil {
		t.Fatalf("missing roots should not error, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected an empty map, got %v", got)
	}
}

// An unreadable root MUST error rather than return an empty map: an empty map
// would diff against the previous snapshot as "every protective service on the
// host was disabled at once" and fire R55/R57/R60 across the board.
func TestServiceEnablementUnreadableRootErrors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not restrict reads")
	}
	etc := filepath.Join(t.TempDir(), "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(etc, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(etc, 0o755) // let t.TempDir clean up

	got, err := collectServiceEnablementFrom(etc, filepath.Join(etc, "run"))
	if err == nil {
		t.Fatal("expected an error for an unreadable root")
	}
	if got != nil {
		t.Errorf("expected a nil map alongside the error, got %v", got)
	}
}
