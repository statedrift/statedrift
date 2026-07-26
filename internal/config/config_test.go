package config

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	for _, name := range []string{"cpu", "kernel_counters", "processes", "sockets", "nic_drivers", "connections", "filesystem"} {
		if !c.IsEnabled(name) {
			t.Errorf("All=true: IsEnabled(%q) should be true", name)
		}
	}
}

func TestCollectorsIsEnabledFilesystem(t *testing.T) {
	c := Collectors{Filesystem: true}
	if !c.IsEnabled("filesystem") {
		t.Error("Filesystem=true: IsEnabled(filesystem) should be true")
	}
	if c.IsEnabled("cpu") {
		t.Error("Filesystem=true: IsEnabled(cpu) should be false")
	}
}

func TestValidateSectionIntervalFilesystem(t *testing.T) {
	cfg := Default()
	cfg.SectionIntervals = map[string]string{"filesystem": "6h"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("filesystem should be a valid section_intervals key: %v", err)
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

func TestExampleJSONRoundTrips(t *testing.T) {
	data, err := ExampleJSON()
	if err != nil {
		t.Fatalf("ExampleJSON: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("example output is not valid JSON: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("example config does not validate: %v", err)
	}
	// Saving the example unchanged must not alter behavior: scalar values
	// must equal the built-in defaults.
	def := Default()
	if cfg.StorePath != def.StorePath || cfg.Interval != def.Interval ||
		cfg.RetentionDays != def.RetentionDays || cfg.DisplayTZ != def.DisplayTZ {
		t.Errorf("example scalars diverge from defaults: %+v vs %+v", cfg, def)
	}
	if cfg.Filesystem.MaxFileSize != FSDefaultMaxFileSize || cfg.Filesystem.MaxFiles != FSDefaultMaxFiles {
		t.Errorf("example filesystem limits = %d/%d, want defaults %d/%d",
			cfg.Filesystem.MaxFileSize, cfg.Filesystem.MaxFiles, FSDefaultMaxFileSize, FSDefaultMaxFiles)
	}
	if cfg.Collectors.All || cfg.Collectors.Harness {
		t.Errorf("example must ship with all collectors off")
	}
	// Every collector switch must be spelled out in the JSON so the file is
	// self-documenting.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	var collectors map[string]bool
	if err := json.Unmarshal(raw["collectors"], &collectors); err != nil {
		t.Fatalf("unmarshal collectors: %v", err)
	}
	for _, name := range KnownCollectors {
		if _, ok := collectors[name]; !ok {
			t.Errorf("example collectors block missing %q", name)
		}
	}
}

func TestSetCollectorCreatesUserConfig(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("STATEDRIFT_CONFIG", "/nonexistent/system-config.json")

	path, err := SetCollector("harness", true)
	if err != nil {
		t.Fatalf("SetCollector: %v", err)
	}
	if path != UserConfigPath() {
		t.Errorf("wrote to %s, want %s", path, UserConfigPath())
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load after SetCollector: %v", err)
	}
	if !cfg.Collectors.IsEnabled("harness") {
		t.Errorf("harness not enabled after SetCollector")
	}
	if cfg.Collectors.IsEnabled("gpu") {
		t.Errorf("gpu enabled as a side effect")
	}
}

func TestSetCollectorPreservesOtherKeys(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("STATEDRIFT_CONFIG", "/nonexistent/system-config.json")

	// Seed a user config the way init does, plus a hand-set collector.
	if err := SaveUserStorePath("/data/statedrift"); err != nil {
		t.Fatalf("SaveUserStorePath: %v", err)
	}
	if _, err := SetCollector("gpu", true); err != nil {
		t.Fatalf("SetCollector gpu: %v", err)
	}

	if _, err := SetCollector("harness", true); err != nil {
		t.Fatalf("SetCollector harness: %v", err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.StorePath != "/data/statedrift" {
		t.Errorf("store_path clobbered: %q", cfg.StorePath)
	}
	if !cfg.Collectors.GPU || !cfg.Collectors.Harness {
		t.Errorf("expected gpu and harness both enabled, got %+v", cfg.Collectors)
	}
	// retention_days etc. must still fall back to built-in defaults — the
	// merge must not have persisted zero values.
	if cfg.RetentionDays != 365 {
		t.Errorf("RetentionDays = %d, want default 365", cfg.RetentionDays)
	}

	if _, err := SetCollector("gpu", false); err != nil {
		t.Fatalf("SetCollector disable gpu: %v", err)
	}
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Collectors.GPU {
		t.Errorf("gpu still enabled after disable")
	}
	if !cfg.Collectors.Harness {
		t.Errorf("harness disabled as a side effect")
	}
}

func TestSetCollectorUnknownName(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if _, err := SetCollector("bogus", true); err == nil {
		t.Fatal("expected error for unknown collector name")
	}
}

func TestSetCollectorAll(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("STATEDRIFT_CONFIG", "/nonexistent/system-config.json")
	if _, err := SetCollector("all", true); err != nil {
		t.Fatalf("SetCollector all: %v", err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Collectors.IsEnabled("dataplane") {
		t.Errorf(`"all": true does not enable dataplane via IsEnabled`)
	}
}

func TestSetCollectorRejectsMalformedUserConfig(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	upath := UserConfigPath()
	if err := os.MkdirAll(filepath.Dir(upath), 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(upath, []byte("{not json"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := SetCollector("harness", true); err == nil {
		t.Fatal("expected error on malformed user config, got nil (would have clobbered the file)")
	}
	// The broken file must be left untouched for the user to inspect.
	data, err := os.ReadFile(upath)
	if err != nil || string(data) != "{not json" {
		t.Errorf("malformed config was modified: %q, %v", data, err)
	}
}
