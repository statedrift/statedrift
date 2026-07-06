// Package config loads statedrift configuration from a JSON file.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config holds all runtime configuration for statedrift.
type Config struct {
	StorePath        string            `json:"store_path"`
	Interval         string            `json:"interval"`
	RetentionDays    int               `json:"retention_days"`
	KernelParams     []string          `json:"kernel_params"`
	Capture          []string          `json:"capture"`
	SectionIntervals map[string]string `json:"section_intervals"`
	Ignore           Ignore            `json:"ignore"`
	Collectors       Collectors        `json:"collectors"`
	Filesystem       Filesystem        `json:"filesystem"`
	Dataplane        Dataplane         `json:"dataplane"`
	Harness          Harness           `json:"harness"`
	LicensePath      string            `json:"license_path"`
	// DisplayTZ controls CLI output formatting and parsing of operator-typed
	// dates (--since, --until, --from, --to). Storage timestamps are always
	// UTC regardless of this setting. Special values: "" or "UTC" → UTC,
	// "Local" → host zone. Otherwise an IANA name like "America/Los_Angeles".
	// Overridden by $STATEDRIFT_TZ.
	DisplayTZ string `json:"display_tz"`
}

// Ignore holds glob patterns for filtering collected data.
type Ignore struct {
	Interfaces []string `json:"interfaces"`
	Packages   []string `json:"packages"`
}

// Collectors gates the optional collectors added in v0.2 (and the v0.5
// filesystem collector). All default to false (opt-in). Set All to true to
// enable every optional collector.
type Collectors struct {
	All            bool `json:"all"`
	CPU            bool `json:"cpu"`
	KernelCounters bool `json:"kernel_counters"`
	Processes      bool `json:"processes"`
	Sockets        bool `json:"sockets"`
	NICDrivers     bool `json:"nic_drivers"`
	Connections    bool `json:"connections"`
	Filesystem     bool `json:"filesystem"`
	Containers     bool `json:"containers"`
	GPU            bool `json:"gpu"`
	Dataplane      bool `json:"dataplane"`
	Harness        bool `json:"harness"`
}

// Filesystem configures the v0.5 Phase P filesystem hash-tree collector
// (gated by Collectors.Filesystem). Roots defaults to ["/etc"] when empty;
// MaxFileSize and MaxFiles fall back to FSDefaultMaxFileSize / FSDefaultMaxFiles
// when zero. Excludes are glob patterns matched against the full path.
type Filesystem struct {
	Roots       []string `json:"roots"`
	Excludes    []string `json:"excludes"`
	MaxFileSize int64    `json:"max_file_size"` // bytes; 0 → FSDefaultMaxFileSize
	MaxFiles    int      `json:"max_files"`     // 0 → FSDefaultMaxFiles
}

// Dataplane configures the v0.7 network-dataplane collector (gated by
// Collectors.Dataplane). DPDKDrivers lists additional userspace poll-mode
// driver names to treat as DPDK-bound, on top of the built-in defaults
// (vfio-pci, uio_pci_generic, igb_uio). It is additive — supplying it never
// disables detection of the standard drivers — for vendor or out-of-tree UIO
// drivers. Empty (the default) means built-in drivers only.
type Dataplane struct {
	DPDKDrivers []string `json:"dpdk_drivers"`
}

// Harness configures the v0.8 AI-agent-harness collector (gated by
// Collectors.Harness). Roots lists additional directories to scan for harness
// config files (settings.json, settings.local.json, .mcp.json) on top of the
// daemon user's ~/.claude, which is always scanned. Point Roots at project
// .claude directories (and project roots holding a .mcp.json) that the daemon
// user should watch. Empty (the default) means ~/.claude only.
type Harness struct {
	Roots []string `json:"roots"`
}

// Filesystem collector defaults, applied when the corresponding field is the
// zero value. Kept here (not in the collector) so they are visible to config
// validation and documentation.
const (
	FSDefaultMaxFileSize = 50 << 20 // 50 MiB — larger files are recorded but not hashed
	FSDefaultMaxFiles    = 50000    // walk stops here and marks the tree truncated
)

// FSDefaultRoots is the default watched set when Filesystem.Roots is empty:
// /etc only (config / credential / unit drift — high value, modest size).
var FSDefaultRoots = []string{"/etc"}

// IsEnabled returns true if the named optional collector should run.
// Name must be one of: "cpu", "kernel_counters", "processes", "sockets", "nic_drivers".
func (c Collectors) IsEnabled(name string) bool {
	if c.All {
		return true
	}
	switch name {
	case "cpu":
		return c.CPU
	case "kernel_counters":
		return c.KernelCounters
	case "processes":
		return c.Processes
	case "sockets":
		return c.Sockets
	case "nic_drivers":
		return c.NICDrivers
	case "connections":
		return c.Connections
	case "filesystem":
		return c.Filesystem
	case "containers":
		return c.Containers
	case "gpu":
		return c.GPU
	case "dataplane":
		return c.Dataplane
	case "harness":
		return c.Harness
	}
	return false
}

// Default returns a Config populated with sensible defaults.
func Default() *Config {
	return &Config{
		StorePath:     "/var/lib/statedrift",
		Interval:      "1h",
		RetentionDays: 365,
		Capture: []string{
			"host", "network", "kernel_params",
			"packages", "services", "listening_ports", "multicast",
			"users", "groups", "sudoers", "mounts", "modules",
			"cron", "timers", "ssh_keys", "mac", "firewall",
		},
		DisplayTZ: "UTC",
	}
}

// UserConfigPath returns the path to the user-level config file.
// Respects $XDG_CONFIG_HOME; falls back to ~/.config per the XDG Base Directory spec.
// Written by "statedrift init" to persist the chosen store path.
func UserConfigPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "statedrift", "config.json")
}

// Load reads config using a layered approach (lowest to highest priority):
//  1. Built-in defaults
//  2. User config (~/.config/statedrift/config.json) — written by init
//  3. System config (/etc/statedrift/config.json, or $STATEDRIFT_CONFIG)
//
// Missing files are silently skipped. Fields present in a higher-priority
// file override those from lower-priority ones.
func Load() (*Config, error) {
	cfg := Default()

	// Layer 1: user config (written by init).
	if upath := UserConfigPath(); upath != "" {
		if err := loadFile(cfg, upath); err != nil {
			return nil, err
		}
	}

	// Layer 2: system config (highest priority among files).
	spath := os.Getenv("STATEDRIFT_CONFIG")
	if spath == "" {
		spath = "/etc/statedrift/config.json"
	}
	if err := loadFile(cfg, spath); err != nil {
		return nil, err
	}

	// Layer 3: STATEDRIFT_TZ env var (highest priority for display_tz).
	if tz := os.Getenv("STATEDRIFT_TZ"); tz != "" {
		cfg.DisplayTZ = tz
	}

	return cfg, nil
}

// loadFile overlays a JSON config file onto cfg. Missing files are silently skipped.
func loadFile(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(data, cfg)
}

// knownCaptureSections is the set of valid values for the capture field.
var knownCaptureSections = map[string]bool{
	"host": true, "network": true, "kernel_params": true,
	"packages": true, "services": true, "listening_ports": true, "multicast": true,
	"users": true, "groups": true, "sudoers": true, "mounts": true, "modules": true,
	"cron": true, "timers": true, "ssh_keys": true, "mac": true, "firewall": true,
}

// knownSectionNames is the set of valid keys for section_intervals.
// Includes both capture sections and optional collector names.
var knownSectionNames = map[string]bool{
	"host": true, "network": true, "kernel_params": true,
	"packages": true, "services": true, "listening_ports": true, "multicast": true,
	"users": true, "groups": true, "sudoers": true, "mounts": true, "modules": true,
	"cron": true, "timers": true, "ssh_keys": true, "mac": true, "firewall": true,
	"cpu": true, "kernel_counters": true, "processes": true,
	"sockets": true, "nic_drivers": true, "connections": true,
	"filesystem": true, "containers": true, "gpu": true, "dataplane": true,
	"harness": true,
}

// SectionInterval returns the effective collection interval for a named section.
// It returns the section-specific override from SectionIntervals if present,
// otherwise it returns base (which the caller resolves from Interval + CLI flags).
func (c *Config) SectionInterval(section string, base time.Duration) time.Duration {
	if c.SectionIntervals != nil {
		if s, ok := c.SectionIntervals[section]; ok {
			if d, err := time.ParseDuration(s); err == nil {
				return d
			}
		}
	}
	return base
}

// MinTickInterval returns the minimum across all section intervals and base.
// This is the rate at which the watch ticker must fire to honour all schedules.
func (c *Config) MinTickInterval(base time.Duration) time.Duration {
	min := base
	for _, durStr := range c.SectionIntervals {
		if d, err := time.ParseDuration(durStr); err == nil && d < min {
			min = d
		}
	}
	return min
}

// Validate checks all config fields for obvious misconfigurations.
// Returns a descriptive error on the first problem found.
func (c *Config) Validate() error {
	if c.Interval != "" {
		d, err := time.ParseDuration(c.Interval)
		if err != nil {
			return fmt.Errorf("interval %q is not a valid duration (e.g. 30s, 15m, 1h): %w", c.Interval, err)
		}
		if d < time.Minute {
			return fmt.Errorf("interval %q is too short (minimum 1m)", c.Interval)
		}
	}

	if c.RetentionDays < 0 {
		return fmt.Errorf("retention_days %d must be 0 (keep forever) or a positive number", c.RetentionDays)
	}

	for _, s := range c.Capture {
		if !knownCaptureSections[s] {
			return fmt.Errorf("capture: unknown section %q (valid: host, network, kernel_params, packages, services, listening_ports, multicast)", s)
		}
	}

	for section, durStr := range c.SectionIntervals {
		if !knownSectionNames[section] {
			return fmt.Errorf("section_intervals: unknown section %q", section)
		}
		d, err := time.ParseDuration(durStr)
		if err != nil {
			return fmt.Errorf("section_intervals[%q]: %q is not a valid duration (e.g. 30s, 15m, 1h): %w", section, durStr, err)
		}
		if d < time.Minute {
			return fmt.Errorf("section_intervals[%q]: %q is too short (minimum 1m)", section, durStr)
		}
	}

	for _, pat := range c.Ignore.Interfaces {
		if _, err := filepath.Match(pat, ""); err != nil {
			return fmt.Errorf("ignore.interfaces: %q is not a valid glob pattern: %w", pat, err)
		}
	}
	for _, pat := range c.Ignore.Packages {
		if _, err := filepath.Match(pat, ""); err != nil {
			return fmt.Errorf("ignore.packages: %q is not a valid glob pattern: %w", pat, err)
		}
	}

	if c.DisplayTZ != "" {
		if _, err := time.LoadLocation(c.DisplayTZ); err != nil {
			return fmt.Errorf("display_tz %q is not a valid IANA zone: %w (try \"UTC\", \"Local\", or e.g. \"America/Los_Angeles\")", c.DisplayTZ, err)
		}
	}

	return nil
}

// SaveUserStorePath writes the store path to the user config so subsequent
// commands find it without needing STATEDRIFT_STORE set.
func SaveUserStorePath(storePath string) error {
	upath := UserConfigPath()
	if upath == "" {
		return nil // can't determine home dir; not fatal
	}

	if err := os.MkdirAll(filepath.Dir(upath), 0755); err != nil {
		return err
	}

	// Merge at the raw-JSON level: only store_path is managed here. Marshaling
	// the whole Config struct would persist zero values ("retention_days": 0,
	// "interval": "") that override the built-in defaults at load time.
	raw := map[string]json.RawMessage{}
	if data, err := os.ReadFile(upath); err == nil {
		_ = json.Unmarshal(data, &raw) // ignore parse errors — start fresh
	}
	sp, err := json.Marshal(storePath)
	if err != nil {
		return err
	}
	raw["store_path"] = sp

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(upath, append(data, '\n'), 0644)
}
