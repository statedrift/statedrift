package collector

// collect_timers.go — v0.3 Phase D systemd-timers collector.
//
// Reads .timer unit files from the two standard system unit directories:
//   - /etc/systemd/system/*.timer  (admin-installed, takes precedence)
//   - /usr/lib/systemd/system/*.timer  (package-installed)
//
// We deliberately do NOT shell out to `systemctl list-timers` because the
// output includes NEXT and LAST run timestamps that change every snapshot
// and would dominate the diff with operationally-meaningless churn. The
// static configuration (OnCalendar, Unit, etc.) is what carries the drift
// signal; that lives in the unit file itself.
//
// Same-name unit in /etc/systemd/system overrides /usr/lib/systemd/system —
// systemd's documented ordering. We replicate that behavior so the snapshot
// reflects the unit that systemd would actually run.

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	defaultTimerEtcDirGlob = "/etc/systemd/system/*.timer"
	defaultTimerLibDirGlob = "/usr/lib/systemd/system/*.timer"
)

// collectTimers reads all systemd .timer unit files in standard system locations.
func collectTimers() ([]SystemdTimer, error) {
	return readTimersFrom(defaultTimerEtcDirGlob, defaultTimerLibDirGlob)
}

// readTimersFrom is the test-friendly form. Files matched by etcGlob override
// same-named files matched by libGlob (systemd unit-file precedence).
func readTimersFrom(etcGlob, libGlob string) ([]SystemdTimer, error) {
	byBasename := make(map[string]string) // basename -> chosen path

	// Lib units first.
	libMatches, err := filepath.Glob(libGlob)
	if err != nil {
		return nil, err
	}
	for _, p := range libMatches {
		base := filepath.Base(p)
		if shouldSkipUnitFile(base) {
			continue
		}
		byBasename[base] = p
	}

	// Etc units second — overrides lib.
	etcMatches, err := filepath.Glob(etcGlob)
	if err != nil {
		return nil, err
	}
	for _, p := range etcMatches {
		base := filepath.Base(p)
		if shouldSkipUnitFile(base) {
			continue
		}
		byBasename[base] = p
	}

	var bases []string
	for b := range byBasename {
		bases = append(bases, b)
	}
	sort.Strings(bases)

	var timers []SystemdTimer
	for _, b := range bases {
		p := byBasename[b]
		info, err := os.Stat(p)
		if err != nil || info.IsDir() {
			continue
		}
		t, err := readTimerUnitFile(p)
		if err != nil {
			return nil, err
		}
		if t != nil {
			timers = append(timers, *t)
		}
	}
	return timers, nil
}

// readTimerUnitFile parses a single .timer unit file. Returns nil for files
// without a [Timer] section (defensive — symlinks pointing nowhere etc.).
func readTimerUnitFile(path string) (*SystemdTimer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	t := &SystemdTimer{UnitFile: path}
	var section string
	var sawTimer bool

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == "Timer" {
				sawTimer = true
			}
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])

		switch section {
		case "Unit":
			if key == "Description" {
				t.Description = val
			}
		case "Timer":
			switch key {
			case "OnCalendar":
				t.OnCalendar = val
			case "OnBootSec":
				t.OnBootSec = val
			case "OnUnitActiveSec":
				t.OnUnitActiveSec = val
			case "OnUnitInactiveSec":
				t.OnUnitInactiveSec = val
			case "Unit":
				t.Unit = val
			case "RandomizedDelaySec":
				t.RandomizedDelaySec = val
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !sawTimer {
		return nil, nil
	}
	return t, nil
}

// shouldSkipUnitFile filters editor-backups and instance-template glob
// artifacts (foo@.timer is a template; we still capture it — but not
// foo@.timer.dpkg-old etc.).
func shouldSkipUnitFile(name string) bool {
	if name == "" {
		return true
	}
	if strings.HasPrefix(name, ".") {
		return true
	}
	if strings.HasSuffix(name, "~") {
		return true
	}
	if strings.HasSuffix(name, ".dpkg-old") ||
		strings.HasSuffix(name, ".dpkg-new") ||
		strings.HasSuffix(name, ".dpkg-dist") ||
		strings.HasSuffix(name, ".rpmnew") ||
		strings.HasSuffix(name, ".rpmsave") ||
		strings.HasSuffix(name, ".rpmorig") {
		return true
	}
	return false
}
