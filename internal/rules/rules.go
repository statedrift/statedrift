// Package rules defines anomaly detection rules and evaluates them against a diff result.
//
// Rules are loaded from two sources, merged in this order:
//  1. Built-in defaults (bundled in the binary via DefaultRules).
//  2. User-supplied file (e.g., /etc/statedrift/rules.json), which can add rules or
//     override defaults by matching ID.
//
// Pro rules (Rule.Pro == true) are silently skipped when no valid license is present.
// This allows the same rules file to serve both free and Pro tiers.
package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Severity levels, ordered from most to least severe.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Rule defines a single anomaly detection condition evaluated against a diff.
type Rule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`    // "critical", "high", "medium", "low"
	Section     string `json:"section"`     // matches Change.Section prefix (e.g., "packages")
	ChangeType  string `json:"change_type"` // "added", "removed", "modified", "any"
	KeyPattern  string `json:"key_pattern"` // glob on Change.Key; "" matches everything
	Pro         bool   `json:"pro"`         // true = requires Pro license
}

// Finding is a rule that matched one or more changes in a diff.
type Finding struct {
	Rule    Rule
	Matches int // number of changes that triggered this rule
}

// SeverityRank returns a numeric rank for sorting (lower = more severe).
func SeverityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	}
	return 4
}

// Evaluate applies rules to a diff result. Rules with Pro=true are skipped when
// hasPro is false. Returns findings sorted by severity (critical first).
func Evaluate(ruleSet []Rule, changes []Change, hasPro bool) []Finding {
	var findings []Finding

	for _, rule := range ruleSet {
		if rule.Pro && !hasPro {
			continue
		}
		count := 0
		for _, c := range changes {
			if matchesRule(rule, c) {
				count++
			}
		}
		if count > 0 {
			findings = append(findings, Finding{Rule: rule, Matches: count})
		}
	}

	// Sort by severity
	sortFindings(findings)
	return findings
}

// Change is a minimal view of diff.Change used by this package to avoid
// import cycles (rules is imported by main, which also imports diff).
type Change struct {
	Section  string
	Type     string
	Key      string
	OldValue string
	NewValue string
	Counter  bool
}

func matchesRule(rule Rule, c Change) bool {
	// Counter-only changes never trigger rules (they are not anomalies, just stats)
	if c.Counter {
		return false
	}

	// Section must match as a prefix
	if rule.Section != "" {
		matched := false
		for i := 0; i <= len(c.Section)-len(rule.Section); i++ {
			if c.Section[:len(rule.Section)] == rule.Section {
				matched = true
				break
			}
			break
		}
		if !matched {
			return false
		}
	}

	// Change type
	if rule.ChangeType != "any" && rule.ChangeType != "" && c.Type != rule.ChangeType {
		return false
	}

	// Key pattern
	if rule.KeyPattern != "" {
		matched, _ := filepath.Match(rule.KeyPattern, c.Key)
		if !matched {
			return false
		}
	}

	return true
}

func sortFindings(findings []Finding) {
	// Simple insertion sort — finding counts are small
	for i := 1; i < len(findings); i++ {
		for j := i; j > 0 && SeverityRank(findings[j].Rule.Severity) < SeverityRank(findings[j-1].Rule.Severity); j-- {
			findings[j], findings[j-1] = findings[j-1], findings[j]
		}
	}
}

// DefaultRules returns the built-in ruleset.
// These rules cover common infrastructure anomalies and require no license.
// Pro-tier rules (Pro: true) require a valid Pro license to evaluate.
func DefaultRules() []Rule {
	return []Rule{
		{
			ID:          "R01_NEW_LISTEN_PORT",
			Name:        "New listening port appeared",
			Description: "A port that was not listening before is now accepting connections.",
			Severity:    SeverityHigh,
			Section:     "listening_ports",
			ChangeType:  "added",
		},
		{
			ID:          "R02_PORT_CLOSED",
			Name:        "Listening port closed",
			Description: "A previously listening port is no longer accepting connections.",
			Severity:    SeverityMedium,
			Section:     "listening_ports",
			ChangeType:  "removed",
		},
		{
			ID:          "R03_PACKAGE_ADDED",
			Name:        "Package installed",
			Description: "A software package was installed outside of a change window.",
			Severity:    SeverityHigh,
			Section:     "packages",
			ChangeType:  "added",
		},
		{
			ID:          "R04_PACKAGE_REMOVED",
			Name:        "Package removed",
			Description: "A software package was uninstalled.",
			Severity:    SeverityMedium,
			Section:     "packages",
			ChangeType:  "removed",
		},
		{
			ID:          "R05_PACKAGE_UPGRADED",
			Name:        "Package version changed",
			Description: "A package was upgraded or downgraded.",
			Severity:    SeverityLow,
			Section:     "packages",
			ChangeType:  "modified",
		},
		{
			ID:          "R06_SERVICE_STATE_CHANGE",
			Name:        "Service state changed",
			Description: "A systemd service changed its active/sub state.",
			Severity:    SeverityMedium,
			Section:     "services",
			ChangeType:  "modified",
		},
		{
			ID:          "R07_SERVICE_ADDED",
			Name:        "New service unit appeared",
			Description: "A systemd service unit was added to the system.",
			Severity:    SeverityHigh,
			Section:     "services",
			ChangeType:  "added",
		},
		{
			ID:          "R08_KERNEL_PARAM_CHANGED",
			Name:        "Kernel parameter changed",
			Description: "A sysctl value was changed. Security-relevant params (ip_forward, rp_filter) are high severity.",
			Severity:    SeverityHigh,
			Section:     "kernel_params",
			ChangeType:  "modified",
		},
		{
			ID:          "R09_NETWORK_INTERFACE_CHANGE",
			Name:        "Network interface state changed",
			Description: "An interface went up/down or its IP address changed.",
			Severity:    SeverityMedium,
			Section:     "network.interfaces",
			ChangeType:  "modified",
		},
		{
			ID:          "R10_HOST_REBOOTED",
			Name:        "Host rebooted",
			Description: "Boot ID changed, indicating the host was rebooted between snapshots.",
			Severity:    SeverityCritical,
			Section:     "host",
			ChangeType:  "modified",
			KeyPattern:  "boot_id",
		},
		// v0.3 Phase A — security signals (free tier)
		{
			ID:          "R14_USER_ADDED",
			Name:        "New user account",
			Description: "A new entry was added to /etc/passwd. New accounts created outside a change window may be backdoors.",
			Severity:    SeverityHigh,
			Section:     "users",
			ChangeType:  "added",
		},
		{
			ID:          "R15_USER_MODIFIED",
			Name:        "User account modified",
			Description: "A user's UID, GID, GECOS, home directory, or login shell changed. Privilege-escalation-specific rules are deferred to a follow-up; this is the catch-all.",
			Severity:    SeverityMedium,
			Section:     "users",
			ChangeType:  "modified",
		},
		{
			ID:          "R16_SUDOERS_MODIFIED",
			Name:        "Sudoers configuration changed",
			Description: "A line was added or removed in /etc/sudoers or /etc/sudoers.d/. Sudoers controls privilege escalation; any change is high-signal.",
			Severity:    SeverityCritical,
			Section:     "sudoers",
			ChangeType:  "any",
		},
		// v0.3 Phase D — cron + systemd timers (free tier)
		{
			ID:          "R21_CRON_MODIFIED",
			Name:        "Cron job changed",
			Description: "A cron entry was added, removed, or replaced in /etc/crontab, /etc/cron.d/, or /var/spool/cron/. Cron jobs run arbitrary commands, often as root; any change is high-signal.",
			Severity:    SeverityHigh,
			Section:     "cron",
			ChangeType:  "any",
		},
		{
			ID:          "R22_TIMER_MODIFIED",
			Name:        "Systemd timer changed",
			Description: "A .timer unit file was added, removed, or modified in /etc/systemd/system or /usr/lib/systemd/system. Timers schedule arbitrary services; any change is high-signal.",
			Severity:    SeverityHigh,
			Section:     "timers",
			ChangeType:  "any",
		},
		// v0.3 Phase B — kernel modules (free tier)
		{
			ID:          "R17_MODULE_LOADED",
			Name:        "Kernel module loaded",
			Description: "A new entry appeared in /proc/modules. New kernel modules can install rootkits, hook syscalls, or modify kernel behavior; loads outside a change window are high-signal.",
			Severity:    SeverityHigh,
			Section:     "modules",
			ChangeType:  "added",
		},
		{
			ID:          "R18_MODULE_REMOVED",
			Name:        "Kernel module unloaded",
			Description: "A module disappeared from /proc/modules. Benign on shutdown or driver swap; suspicious during steady-state operation.",
			Severity:    SeverityMedium,
			Section:     "modules",
			ChangeType:  "removed",
		},
		// v0.3 Phase E — mounts (free tier)
		{
			ID:          "R23_MOUNT_ADDED",
			Name:        "New filesystem mount",
			Description: "A new entry appeared in /proc/self/mountinfo. New mounts can introduce data-exfiltration channels (CIFS/NFS to external hosts) or write paths around hardening.",
			Severity:    SeverityHigh,
			Section:     "mounts",
			ChangeType:  "added",
		},
		{
			ID:          "R24_MOUNT_REMOVED",
			Name:        "Filesystem unmounted",
			Description: "A mount disappeared from /proc/self/mountinfo. Benign on shutdown; suspicious during steady-state operation.",
			Severity:    SeverityMedium,
			Section:     "mounts",
			ChangeType:  "removed",
		},
		{
			ID:          "R25_MOUNT_OPTIONS_CHANGED",
			Name:        "Mount options changed",
			Description: "Mount options or super-block options changed (e.g. ro→rw, dropping nosuid/nodev/noexec). Security-relevant flips are exactly what this rule flags.",
			Severity:    SeverityHigh,
			Section:     "mounts",
			ChangeType:  "modified",
		},
		// Pro rules
		{
			ID:          "R11_NIC_FIRMWARE_CHANGED",
			Name:        "NIC firmware version changed",
			Description: "Network interface firmware was updated or rolled back.",
			Severity:    SeverityHigh,
			Section:     "nic_drivers",
			ChangeType:  "modified",
			KeyPattern:  "*.fw_version",
			Pro:         true,
		},
		{
			ID:          "R12_LARGE_PROCESS_RSS_GROWTH",
			Name:        "Process memory growth",
			Description: "A process in the top-N by RSS grew significantly between snapshots.",
			Severity:    SeverityMedium,
			Section:     "processes",
			ChangeType:  "modified",
			KeyPattern:  "*.rss_kb",
			Pro:         true,
		},
		{
			ID:          "R13_NEW_HIGH_SOCKET_PROCESS",
			Name:        "New high-socket-count process",
			Description: "A process with many open sockets appeared in the top-N.",
			Severity:    SeverityMedium,
			Section:     "sockets",
			ChangeType:  "added",
			Pro:         true,
		},
	}
}

// Load reads rules from path, merges them with DefaultRules, and returns the combined set.
// File rules with matching IDs override the built-in defaults.
// If path does not exist, returns defaults only (not an error).
func Load(path string) ([]Rule, error) {
	defaults := DefaultRules()

	if path == "" {
		path = "/etc/statedrift/rules.json"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaults, nil
		}
		return nil, err
	}

	var fileRules []Rule
	if err := json.Unmarshal(data, &fileRules); err != nil {
		return nil, err
	}

	// Build index of defaults by ID
	byID := make(map[string]int, len(defaults))
	merged := make([]Rule, len(defaults))
	copy(merged, defaults)
	for i, r := range merged {
		byID[r.ID] = i
	}

	// Apply file rules: override existing by ID, append new ones
	for _, fr := range fileRules {
		if idx, exists := byID[fr.ID]; exists {
			merged[idx] = fr
		} else {
			merged = append(merged, fr)
		}
	}

	return merged, nil
}
