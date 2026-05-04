package collector

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReadTimerUnitFileBasic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dnf-makecache.timer")
	content := `[Unit]
Description=dnf makecache --timer
ConditionKernelCommandLine=!rd.live.image

[Timer]
OnBootSec=10min
OnUnitInactiveSec=1h
RandomizedDelaySec=60m
Unit=dnf-makecache.service

[Install]
WantedBy=timers.target
`
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	timer, err := readTimerUnitFile(p)
	if err != nil {
		t.Fatalf("readTimerUnitFile: %v", err)
	}
	if timer == nil {
		t.Fatalf("nil timer")
	}
	if timer.UnitFile != p {
		t.Errorf("UnitFile = %q, want %q", timer.UnitFile, p)
	}
	if timer.Description != "dnf makecache --timer" {
		t.Errorf("Description = %q", timer.Description)
	}
	if timer.OnBootSec != "10min" {
		t.Errorf("OnBootSec = %q", timer.OnBootSec)
	}
	if timer.OnUnitInactiveSec != "1h" {
		t.Errorf("OnUnitInactiveSec = %q", timer.OnUnitInactiveSec)
	}
	if timer.Unit != "dnf-makecache.service" {
		t.Errorf("Unit = %q", timer.Unit)
	}
	if timer.RandomizedDelaySec != "60m" {
		t.Errorf("RandomizedDelaySec = %q", timer.RandomizedDelaySec)
	}
	if timer.OnCalendar != "" {
		t.Errorf("OnCalendar should be empty, got %q", timer.OnCalendar)
	}
}

func TestReadTimerUnitFileOnCalendar(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fstrim.timer")
	content := `[Unit]
Description=Discard unused blocks once a week

[Timer]
OnCalendar=weekly
AccuracySec=1h
Persistent=true

[Install]
WantedBy=timers.target
`
	os.WriteFile(p, []byte(content), 0644)

	timer, err := readTimerUnitFile(p)
	if err != nil || timer == nil {
		t.Fatalf("got %v, %v", timer, err)
	}
	if timer.OnCalendar != "weekly" {
		t.Errorf("OnCalendar = %q, want 'weekly'", timer.OnCalendar)
	}
}

func TestReadTimerUnitFileNoTimerSection(t *testing.T) {
	// A file in *.timer glob that lacks [Timer] (broken or wrong-extension).
	dir := t.TempDir()
	p := filepath.Join(dir, "weird.timer")
	os.WriteFile(p, []byte("[Unit]\nDescription=oops\n"), 0644)

	timer, err := readTimerUnitFile(p)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if timer != nil {
		t.Errorf("expected nil for file with no [Timer] section, got %+v", timer)
	}
}

func TestReadTimerUnitFileIgnoresCommentsAndUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.timer")
	content := `# top comment
; semicolon comment
[Timer]
# inside-section comment
OnCalendar=daily
SomeNewSystemdKey=value
Unit=x.service
`
	os.WriteFile(p, []byte(content), 0644)

	timer, err := readTimerUnitFile(p)
	if err != nil || timer == nil {
		t.Fatalf("got %v, %v", timer, err)
	}
	if timer.OnCalendar != "daily" {
		t.Errorf("OnCalendar = %q", timer.OnCalendar)
	}
	if timer.Unit != "x.service" {
		t.Errorf("Unit = %q", timer.Unit)
	}
}

func TestReadTimersFromOverrideOrder(t *testing.T) {
	dir := t.TempDir()
	libDir := filepath.Join(dir, "lib")
	etcDir := filepath.Join(dir, "etc")
	os.MkdirAll(libDir, 0755)
	os.MkdirAll(etcDir, 0755)

	// Same-named timer in both — etc must win.
	libContent := `[Timer]
OnCalendar=hourly
Unit=foo.service
`
	etcContent := `[Timer]
OnCalendar=daily
Unit=foo.service
`
	os.WriteFile(filepath.Join(libDir, "foo.timer"), []byte(libContent), 0644)
	os.WriteFile(filepath.Join(etcDir, "foo.timer"), []byte(etcContent), 0644)

	// Lib-only timer.
	os.WriteFile(filepath.Join(libDir, "bar.timer"), []byte("[Timer]\nOnCalendar=weekly\n"), 0644)

	timers, err := readTimersFrom(filepath.Join(etcDir, "*.timer"), filepath.Join(libDir, "*.timer"))
	if err != nil {
		t.Fatalf("readTimersFrom: %v", err)
	}
	if len(timers) != 2 {
		t.Fatalf("got %d timers, want 2", len(timers))
	}

	// Sorted by basename — bar.timer first, foo.timer second.
	wantBases := []string{"bar.timer", "foo.timer"}
	gotBases := []string{filepath.Base(timers[0].UnitFile), filepath.Base(timers[1].UnitFile)}
	if !reflect.DeepEqual(gotBases, wantBases) {
		t.Errorf("basenames = %v, want %v", gotBases, wantBases)
	}

	// foo.timer must be the etc version (daily, not hourly).
	for _, ti := range timers {
		if filepath.Base(ti.UnitFile) == "foo.timer" {
			if ti.OnCalendar != "daily" {
				t.Errorf("foo.timer OnCalendar = %q, want 'daily' (etc must override lib)", ti.OnCalendar)
			}
			if filepath.Dir(ti.UnitFile) != etcDir {
				t.Errorf("foo.timer path = %q, want it from %q", ti.UnitFile, etcDir)
			}
		}
	}
}

func TestReadTimersFromSkipsBackups(t *testing.T) {
	dir := t.TempDir()
	libDir := filepath.Join(dir, "lib")
	os.MkdirAll(libDir, 0755)

	os.WriteFile(filepath.Join(libDir, "real.timer"), []byte("[Timer]\nOnCalendar=daily\n"), 0644)
	os.WriteFile(filepath.Join(libDir, "real.timer~"), []byte("[Timer]\nOnCalendar=hourly\n"), 0644)
	os.WriteFile(filepath.Join(libDir, "real.timer.rpmnew"), []byte("[Timer]\nOnCalendar=hourly\n"), 0644)

	timers, err := readTimersFrom("/dev/null/none/*.timer", filepath.Join(libDir, "*.timer*"))
	if err != nil {
		t.Fatalf("readTimersFrom: %v", err)
	}
	for _, ti := range timers {
		base := filepath.Base(ti.UnitFile)
		if base != "real.timer" {
			t.Errorf("backup file slipped through: %q", base)
		}
	}
}

func TestShouldSkipUnitFile(t *testing.T) {
	cases := []struct {
		name string
		skip bool
	}{
		{"foo.timer", false},
		{"foo@.timer", false}, // template instance — keep
		{"", true},
		{".hidden.timer", true},
		{"foo.timer~", true},
		{"foo.timer.rpmnew", true},
		{"foo.timer.dpkg-old", true},
		{"foo.timer.rpmsave", true},
	}
	for _, c := range cases {
		got := shouldSkipUnitFile(c.name)
		if got != c.skip {
			t.Errorf("shouldSkipUnitFile(%q) = %v, want %v", c.name, got, c.skip)
		}
	}
}
