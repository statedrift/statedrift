package collector

// collect_mac.go — v0.4 Phase M: Mandatory Access Control (SELinux/AppArmor)
// enforcement state. Always-on when the capture allowlist permits.
//
// All reads are from /sys and /etc; no external commands (no getenforce,
// no aa-status). A host runs at most one MAC system, so detection has a
// fixed precedence: SELinux (selinuxfs present) → AppArmor (module enabled)
// → none.

import (
	"bufio"
	"io"
	"os"
	"strings"
)

const (
	defaultSELinuxDir       = "/sys/fs/selinux"
	defaultSELinuxConfig    = "/etc/selinux/config"
	defaultAppArmorEnabled  = "/sys/module/apparmor/parameters/enabled"
	defaultAppArmorProfiles = "/sys/kernel/security/apparmor/profiles"
)

// collectMAC reports the host's Mandatory Access Control enforcement state.
// It never returns a nil *MAC without an error: when neither SELinux nor
// AppArmor is active it returns System "none".
func collectMAC() (*MAC, error) {
	return collectMACFrom(defaultSELinuxDir, defaultSELinuxConfig,
		defaultAppArmorEnabled, defaultAppArmorProfiles)
}

// collectMACFrom is the testable core. Detection precedence: SELinux is
// reported when either selinuxfs is mounted or /etc/selinux/config exists;
// otherwise AppArmor when its module is enabled; otherwise "none".
func collectMACFrom(selinuxDir, selinuxConfig, apparmorEnabled, apparmorProfiles string) (*MAC, error) {
	// SELinux: selinuxfs mounted, or a config file present (covers the
	// SELINUX=disabled-at-boot case where selinuxfs is never mounted).
	_, enforceErr := os.Stat(selinuxDir + "/enforce")
	_, configErr := os.Stat(selinuxConfig)
	if enforceErr == nil || configErr == nil {
		return readSELinuxFrom(selinuxDir, selinuxConfig)
	}

	// AppArmor: module loaded and enabled.
	if apparmorIsEnabled(apparmorEnabled) {
		return readAppArmorFrom(apparmorProfiles)
	}

	return &MAC{System: "none"}, nil
}

// readSELinuxFrom builds the SELinux MAC view. Runtime mode comes from
// <dir>/enforce (1=enforcing, 0=permissive); when selinuxfs is absent the
// runtime mode falls back to the persisted config value. Policy version and
// the config-file SELINUX=/SELINUXTYPE= settings are read when available.
func readSELinuxFrom(selinuxDir, selinuxConfig string) (*MAC, error) {
	m := &MAC{System: "selinux"}

	configMode, policyType := parseSELinuxConfig(selinuxConfig)
	m.ConfigMode = configMode
	m.PolicyType = policyType

	if b, err := os.ReadFile(selinuxDir + "/enforce"); err == nil {
		switch strings.TrimSpace(string(b)) {
		case "1":
			m.Mode = "enforcing"
		case "0":
			m.Mode = "permissive"
		}
	}
	// selinuxfs not mounted (SELINUX=disabled at boot): the persisted config
	// is the only available signal for the runtime mode.
	if m.Mode == "" {
		if configMode == "disabled" {
			m.Mode = "disabled"
		} else {
			// Config says enabled but selinuxfs is missing — treat as disabled
			// at runtime, which is the observable reality.
			m.Mode = "disabled"
		}
	}

	if b, err := os.ReadFile(selinuxDir + "/policyvers"); err == nil {
		m.PolicyVersion = strings.TrimSpace(string(b))
	}

	return m, nil
}

// parseSELinuxConfig reads SELINUX= and SELINUXTYPE= from /etc/selinux/config.
// Missing file or keys yield empty strings (non-fatal). Returns (mode, type).
func parseSELinuxConfig(path string) (mode, policyType string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch key {
		case "SELINUX":
			mode = val
		case "SELINUXTYPE":
			policyType = val
		}
	}
	return mode, policyType
}

// apparmorIsEnabled reports whether the AppArmor LSM module is loaded and
// enabled, per /sys/module/apparmor/parameters/enabled (contains "Y").
func apparmorIsEnabled(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "Y"
}

// readAppArmorFrom tallies loaded AppArmor profiles by mode. Mode is a
// roll-up: "enforcing" when at least one profile is in enforce mode,
// otherwise "permissive" (profiles loaded but all complain) — or "disabled"
// when the profiles file is unreadable despite the module being enabled.
func readAppArmorFrom(profilesPath string) (*MAC, error) {
	m := &MAC{System: "apparmor"}

	f, err := os.Open(profilesPath)
	if err != nil {
		// Module enabled but securityfs not mounted / profiles unreadable.
		m.Mode = "disabled"
		return m, nil
	}
	defer f.Close()

	enforce, complain := parseAppArmorProfiles(f)
	m.EnforceCount = enforce
	m.ComplainCount = complain
	switch {
	case enforce > 0:
		m.Mode = "enforcing"
	case complain > 0:
		m.Mode = "permissive"
	default:
		m.Mode = "disabled"
	}
	return m, nil
}

// parseAppArmorProfiles counts profiles by mode from the apparmor profiles
// file. Each line is "<profile name> (<mode>)"; recognized modes are
// "enforce" and "complain". Unparseable or unknown-mode lines are ignored.
func parseAppArmorProfiles(r io.Reader) (enforce, complain int) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Mode is the parenthesized token at the end of the line.
		openIdx := strings.LastIndexByte(line, '(')
		closeIdx := strings.LastIndexByte(line, ')')
		if openIdx < 0 || closeIdx < openIdx {
			continue
		}
		switch strings.TrimSpace(line[openIdx+1 : closeIdx]) {
		case "enforce":
			enforce++
		case "complain":
			complain++
		}
	}
	return enforce, complain
}
