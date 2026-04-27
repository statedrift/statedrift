package daemon

import (
	"strings"
	"testing"
	"time"
)

func TestParseIntervalValid(t *testing.T) {
	cases := []struct {
		input string
		want  time.Duration
	}{
		{"1h", time.Hour},
		{"15m", 15 * time.Minute},
		{"30s", 30 * time.Second},
		{"24h", 24 * time.Hour},
		{"1h30m", 90 * time.Minute},
	}
	for _, tc := range cases {
		d, err := ParseInterval(tc.input)
		if err != nil {
			t.Errorf("ParseInterval(%q) error: %v", tc.input, err)
			continue
		}
		if d != tc.want {
			t.Errorf("ParseInterval(%q) = %v, want %v", tc.input, d, tc.want)
		}
	}
}

func TestParseIntervalInvalid(t *testing.T) {
	cases := []string{"", "not-a-duration", "0s", "-1h", "0"}
	for _, input := range cases {
		_, err := ParseInterval(input)
		if err == nil {
			t.Errorf("ParseInterval(%q) should return error but did not", input)
		}
	}
}

func TestSystemdUnitContainsRequiredFields(t *testing.T) {
	unit := SystemdUnit("/usr/local/bin/statedrift", "/var/lib/statedrift", "")

	checks := []string{
		"[Unit]",
		"[Service]",
		"[Install]",
		"ExecStart=/usr/local/bin/statedrift daemon",
		"STATEDRIFT_STORE=/var/lib/statedrift",
		"Restart=on-failure",
		"User=root",
		"WantedBy=multi-user.target",
	}
	for _, want := range checks {
		if !strings.Contains(unit, want) {
			t.Errorf("SystemdUnit missing %q", want)
		}
	}
}

func TestSystemdUnitCustomPaths(t *testing.T) {
	unit := SystemdUnit("/opt/bin/statedrift", "/data/statedrift", "")
	if !strings.Contains(unit, "ExecStart=/opt/bin/statedrift daemon") {
		t.Error("custom binary path not reflected in ExecStart")
	}
	if !strings.Contains(unit, "STATEDRIFT_STORE=/data/statedrift") {
		t.Error("custom store path not reflected in Environment")
	}
}

func TestSystemdUnitWithInterval(t *testing.T) {
	unit := SystemdUnit("/usr/local/bin/statedrift", "/var/lib/statedrift", "30s")
	if !strings.Contains(unit, "ExecStart=/usr/local/bin/statedrift daemon --interval 30s") {
		t.Errorf("SystemdUnit interval not embedded in ExecStart, got:\n%s", unit)
	}
}

func TestSystemdUnitNoIntervalWhenEmpty(t *testing.T) {
	unit := SystemdUnit("/usr/local/bin/statedrift", "/var/lib/statedrift", "")
	if strings.Contains(unit, "--interval") {
		t.Errorf("SystemdUnit should not contain --interval when interval is empty, got:\n%s", unit)
	}
}
