package config

import (
	"os"
	"testing"
	"time"
)

func TestSectionIntervalUsesOverride(t *testing.T) {
	cfg := Default()
	cfg.SectionIntervals = map[string]string{"packages": "6h"}
	got := cfg.SectionInterval("packages", 5*time.Minute)
	if got != 6*time.Hour {
		t.Errorf("SectionInterval(packages) = %v, want 6h", got)
	}
}

func TestSectionIntervalFallsBackToBase(t *testing.T) {
	cfg := Default()
	cfg.SectionIntervals = map[string]string{"packages": "6h"}
	got := cfg.SectionInterval("network", 5*time.Minute)
	if got != 5*time.Minute {
		t.Errorf("SectionInterval(network) = %v, want 5m", got)
	}
}

func TestMinTickIntervalReturnsMinimum(t *testing.T) {
	cfg := Default()
	cfg.SectionIntervals = map[string]string{
		"packages":    "6h",
		"connections": "1m",
	}
	got := cfg.MinTickInterval(5 * time.Minute)
	if got != time.Minute {
		t.Errorf("MinTickInterval = %v, want 1m", got)
	}
}

func TestMinTickIntervalNoOverrides(t *testing.T) {
	cfg := Default()
	got := cfg.MinTickInterval(5 * time.Minute)
	if got != 5*time.Minute {
		t.Errorf("MinTickInterval with no overrides = %v, want 5m", got)
	}
}

func TestValidateSectionIntervalUnknownSection(t *testing.T) {
	cfg := Default()
	cfg.SectionIntervals = map[string]string{"invalid_section": "1m"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for unknown section in section_intervals")
	}
}

func TestValidateSectionIntervalBadDuration(t *testing.T) {
	cfg := Default()
	cfg.SectionIntervals = map[string]string{"packages": "6x"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for bad duration in section_intervals")
	}
}

func TestValidateSectionIntervalTooShort(t *testing.T) {
	cfg := Default()
	cfg.SectionIntervals = map[string]string{"packages": "30s"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for section_interval < 1m")
	}
}

func TestValidateSectionIntervalValid(t *testing.T) {
	cfg := Default()
	cfg.SectionIntervals = map[string]string{
		"packages":    "6h",
		"services":    "1h",
		"connections": "1m",
		"processes":   "5m",
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid section_intervals should not error: %v", err)
	}
}

func TestValidateDefault(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Errorf("Default config should be valid: %v", err)
	}
}

func TestValidateBadInterval(t *testing.T) {
	cfg := Default()
	cfg.Interval = "1x"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for bad interval")
	}
}

func TestValidateIntervalTooShort(t *testing.T) {
	cfg := Default()
	cfg.Interval = "30s"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for interval < 1m")
	}
}

func TestValidateNegativeRetention(t *testing.T) {
	cfg := Default()
	cfg.RetentionDays = -1
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for negative retention_days")
	}
}

func TestValidateZeroRetentionAllowed(t *testing.T) {
	cfg := Default()
	cfg.RetentionDays = 0
	if err := cfg.Validate(); err != nil {
		t.Errorf("retention_days=0 (keep forever) should be valid: %v", err)
	}
}

func TestValidateUnknownCaptureSection(t *testing.T) {
	cfg := Default()
	cfg.Capture = []string{"host", "listening_port"} // typo: missing 's'
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for unknown capture section")
	}
}

func TestValidateBadGlobInterface(t *testing.T) {
	cfg := Default()
	cfg.Ignore.Interfaces = []string{"[bad"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid glob in ignore.interfaces")
	}
}

func TestValidateBadGlobPackage(t *testing.T) {
	cfg := Default()
	cfg.Ignore.Packages = []string{"[bad"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid glob in ignore.packages")
	}
}

func TestDefaultValues(t *testing.T) {
	cfg := Default()
	if cfg.StorePath != "/var/lib/statedrift" {
		t.Errorf("StorePath = %q, want /var/lib/statedrift", cfg.StorePath)
	}
	if cfg.Interval != "1h" {
		t.Errorf("Interval = %q, want 1h", cfg.Interval)
	}
	if cfg.RetentionDays != 365 {
		t.Errorf("RetentionDays = %d, want 365", cfg.RetentionDays)
	}
	if len(cfg.Capture) == 0 {
		t.Error("Capture should have defaults")
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	t.Setenv("STATEDRIFT_CONFIG", "/nonexistent/path/config.json")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // isolate from real user config
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.StorePath != "/var/lib/statedrift" {
		t.Errorf("expected default store path, got %q", cfg.StorePath)
	}
}

func TestLoadFromEnvPath(t *testing.T) {
	f, err := os.CreateTemp("", "statedrift-config-*.json")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	content := `{
		"store_path": "/tmp/mystore",
		"interval": "15m",
		"retention_days": 90,
		"ignore": {
			"interfaces": ["veth*", "docker0"]
		}
	}`
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	f.Close()

	t.Setenv("STATEDRIFT_CONFIG", f.Name())

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.StorePath != "/tmp/mystore" {
		t.Errorf("StorePath = %q, want /tmp/mystore", cfg.StorePath)
	}
	if cfg.Interval != "15m" {
		t.Errorf("Interval = %q, want 15m", cfg.Interval)
	}
	if cfg.RetentionDays != 90 {
		t.Errorf("RetentionDays = %d, want 90", cfg.RetentionDays)
	}
	if len(cfg.Ignore.Interfaces) != 2 {
		t.Errorf("Ignore.Interfaces len = %d, want 2", len(cfg.Ignore.Interfaces))
	}
}

func TestLoadInvalidJSONReturnsError(t *testing.T) {
	f, err := os.CreateTemp("", "statedrift-config-*.json")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())
	f.WriteString("{not valid json")
	f.Close()

	t.Setenv("STATEDRIFT_CONFIG", f.Name())
	_, err = Load()
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestCollectorsIsEnabledAll(t *testing.T) {
	c := Collectors{All: true}
	for _, name := range []string{"cpu", "kernel_counters", "processes", "sockets", "nic_drivers", "connections"} {
		if !c.IsEnabled(name) {
			t.Errorf("All=true: IsEnabled(%q) should be true", name)
		}
	}
}

func TestCollectorsIsEnabledIndividual(t *testing.T) {
	c := Collectors{CPU: true}
	if !c.IsEnabled("cpu") {
		t.Error("CPU=true: IsEnabled(cpu) should be true")
	}
	if c.IsEnabled("processes") {
		t.Error("CPU=true: IsEnabled(processes) should be false")
	}
}

func TestCollectorsIsEnabledConnections(t *testing.T) {
	c := Collectors{Connections: true}
	if !c.IsEnabled("connections") {
		t.Error("Connections=true: IsEnabled(connections) should be true")
	}
	if c.IsEnabled("cpu") {
		t.Error("Connections=true: IsEnabled(cpu) should be false")
	}
}

func TestCollectorsDefaultAllOff(t *testing.T) {
	cfg := Default()
	for _, name := range []string{"cpu", "kernel_counters", "processes", "sockets", "nic_drivers", "connections"} {
		if cfg.Collectors.IsEnabled(name) {
			t.Errorf("default config: IsEnabled(%q) should be false", name)
		}
	}
}

func TestLoadCollectorsFromConfig(t *testing.T) {
	f, err := os.CreateTemp("", "statedrift-config-*.json")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	content := `{"collectors": {"cpu": true, "processes": true}}`
	f.WriteString(content)
	f.Close()

	t.Setenv("STATEDRIFT_CONFIG", f.Name())
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !cfg.Collectors.CPU {
		t.Error("CPU should be true from config")
	}
	if !cfg.Collectors.Processes {
		t.Error("Processes should be true from config")
	}
	if cfg.Collectors.Sockets {
		t.Error("Sockets should still be false")
	}
}

func TestLoadCollectorsAll(t *testing.T) {
	f, err := os.CreateTemp("", "statedrift-config-*.json")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	f.WriteString(`{"collectors": {"all": true}}`)
	f.Close()

	t.Setenv("STATEDRIFT_CONFIG", f.Name())
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	for _, name := range []string{"cpu", "kernel_counters", "processes", "sockets", "nic_drivers"} {
		if !cfg.Collectors.IsEnabled(name) {
			t.Errorf("all=true: IsEnabled(%q) should be true", name)
		}
	}
}

func TestLoadCustomKernelParams(t *testing.T) {
	f, err := os.CreateTemp("", "statedrift-config-*.json")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	content := `{"kernel_params": ["net.ipv4.ip_forward", "vm.swappiness"]}`
	f.WriteString(content)
	f.Close()

	t.Setenv("STATEDRIFT_CONFIG", f.Name())
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.KernelParams) != 2 {
		t.Errorf("KernelParams len = %d, want 2", len(cfg.KernelParams))
	}
}
