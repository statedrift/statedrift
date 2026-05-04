package collector

// collect_cron.go — v0.3 Phase D cron collector.
//
// Reads system-wide and per-user crontabs:
//   - /etc/crontab            (system-wide, with user field)
//   - /etc/cron.d/*           (drop-ins, with user field)
//   - /var/spool/cron/*       (per-user; RHEL/Fedora layout)
//   - /var/spool/cron/crontabs/* (per-user; Debian/Ubuntu layout)
//
// /etc/cron.{daily,hourly,weekly,monthly}/ are deliberately not collected:
// those are script directories run by anacron / run-parts, the schedule is
// implicit by the directory name, and the script contents are tracked by the
// package manager via the `packages` collector. See docs/V03_PLAN.md
// "Phase D — known limitations".
//
// Variable assignments inside crontab files (SHELL=, MAILTO=, PATH=) are
// skipped — they are not jobs, and noisy MAILTO churn would dominate the
// diff. Documented as a known limitation.

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	defaultCrontabPath           = "/etc/crontab"
	defaultCronDDirGlob          = "/etc/cron.d/*"
	defaultUserCronDirRHEL       = "/var/spool/cron"
	defaultUserCronDirDebianGlob = "/var/spool/cron/crontabs/*"
)

// collectCron reads all standard crontab locations.
func collectCron() ([]CronJob, error) {
	return readCronFrom(
		defaultCrontabPath,
		defaultCronDDirGlob,
		defaultUserCronDirRHEL,
		defaultUserCronDirDebianGlob,
	)
}

// readCronFrom is the test-friendly form: callers pass in the paths and
// globs to read. Each source is best-effort — per-source permission and
// not-exist errors are silently skipped so e.g. an unreadable
// /var/spool/cron (mode 0700 on RHEL) doesn't wipe out the readable
// /etc/cron.d/* entries collected alongside it. Production deployments
// run snapshots as root and see everything; dev runs as non-root still
// get the world-readable subset. Truly unexpected errors (read failures
// mid-file, glob syntax errors) still propagate.
func readCronFrom(crontabPath, cronDGlob, userCronDir, userCronDebianGlob string) ([]CronJob, error) {
	var jobs []CronJob

	// /etc/crontab (system-wide, has user field).
	if es, err := readCrontabFile(crontabPath, "", true); err != nil {
		if !isExpectedFSAccessError(err) {
			return nil, err
		}
	} else {
		jobs = append(jobs, es...)
	}

	// /etc/cron.d/* (drop-ins, have user field).
	if cronDGlob != "" {
		matches, err := filepath.Glob(cronDGlob)
		if err != nil {
			return nil, err
		}
		sort.Strings(matches)
		for _, p := range matches {
			base := filepath.Base(p)
			if shouldSkipCronInclude(base) {
				continue
			}
			info, err := os.Stat(p)
			if err != nil || info.IsDir() {
				continue
			}
			es, err := readCrontabFile(p, "", true)
			if err != nil {
				if isExpectedFSAccessError(err) {
					continue
				}
				return nil, err
			}
			jobs = append(jobs, es...)
		}
	}

	// /var/spool/cron/<user> (RHEL): user is the file basename, no user field
	// in the line itself.
	if userCronDir != "" {
		entries, err := os.ReadDir(userCronDir)
		if err != nil {
			if !isExpectedFSAccessError(err) {
				return nil, err
			}
			entries = nil
		}
		var names []string
		for _, e := range entries {
			if e.IsDir() {
				continue // /var/spool/cron/crontabs is a dir on Debian
			}
			names = append(names, e.Name())
		}
		sort.Strings(names)
		for _, n := range names {
			p := filepath.Join(userCronDir, n)
			es, err := readCrontabFile(p, n, false)
			if err != nil {
				if isExpectedFSAccessError(err) {
					continue
				}
				return nil, err
			}
			jobs = append(jobs, es...)
		}
	}

	// /var/spool/cron/crontabs/* (Debian): user is the file basename.
	if userCronDebianGlob != "" {
		matches, err := filepath.Glob(userCronDebianGlob)
		if err != nil {
			return nil, err
		}
		sort.Strings(matches)
		for _, p := range matches {
			info, err := os.Stat(p)
			if err != nil || info.IsDir() {
				continue
			}
			es, err := readCrontabFile(p, filepath.Base(p), false)
			if err != nil {
				if isExpectedFSAccessError(err) {
					continue
				}
				return nil, err
			}
			jobs = append(jobs, es...)
		}
	}

	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].Source != jobs[j].Source {
			return jobs[i].Source < jobs[j].Source
		}
		if jobs[i].User != jobs[j].User {
			return jobs[i].User < jobs[j].User
		}
		if jobs[i].Schedule != jobs[j].Schedule {
			return jobs[i].Schedule < jobs[j].Schedule
		}
		return jobs[i].Command < jobs[j].Command
	})
	return jobs, nil
}

// readCrontabFile parses one crontab-format file. If hasUserField is true the
// line is expected to have a user field after the schedule (system crontabs).
// Otherwise the file's owning user is passed in fixedUser (per-user crontabs).
func readCrontabFile(path, fixedUser string, hasUserField bool) ([]CronJob, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var jobs []CronJob
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Variable assignments (SHELL=, MAILTO=, PATH=) — skipped, see header.
		if isCronEnvAssignment(line) {
			continue
		}

		schedule, user, command := parseCronLine(line, hasUserField)
		if schedule == "" || command == "" {
			continue
		}
		if !hasUserField {
			user = fixedUser
		}
		jobs = append(jobs, CronJob{
			Source:   path,
			User:     user,
			Schedule: schedule,
			Command:  redactSecrets(command),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return jobs, nil
}

// parseCronLine splits a non-comment cron line into (schedule, user, command).
// hasUserField determines whether the line carries a user field after the
// schedule. Returns empty strings for any malformed input.
//
// Schedule formats:
//   - five fields separated by whitespace: "m h dom mon dow"
//   - "@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily",
//     "@midnight", "@hourly" (single token)
func parseCronLine(line string, hasUserField bool) (schedule, user, command string) {
	if strings.HasPrefix(line, "@") {
		// Shortcut form: one field for schedule.
		idx := strings.IndexAny(line, " \t")
		if idx < 0 {
			return "", "", ""
		}
		schedule = line[:idx]
		rest := strings.TrimLeft(line[idx:], " \t")
		if hasUserField {
			user, command = splitFirstField(rest)
		} else {
			command = rest
		}
		return schedule, user, command
	}

	// Standard form: 5 schedule fields, then optional user, then command.
	fields := splitFields(line, 5)
	if len(fields) < 5 {
		return "", "", ""
	}
	schedule = strings.Join(fields[:5], " ")
	rest := ""
	if len(fields) > 5 {
		rest = strings.TrimLeft(fields[5], " \t")
	}
	if hasUserField {
		user, command = splitFirstField(rest)
	} else {
		command = rest
	}
	return schedule, user, command
}

// splitFields splits s into up to n+1 tokens on whitespace; the (n+1)th token
// (if present) is the entire remainder of the string with leading whitespace
// preserved relative to the previous token boundary. Returns nil if s has
// fewer than n whitespace-separated tokens.
func splitFields(s string, n int) []string {
	fields := make([]string, 0, n+1)
	i := 0
	for f := 0; f < n; f++ {
		// Skip leading whitespace.
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			return nil
		}
		start := i
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		fields = append(fields, s[start:i])
	}
	// Skip whitespace between schedule and remainder.
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i < len(s) {
		fields = append(fields, s[i:])
	}
	return fields
}

// splitFirstField returns the first whitespace-delimited token of s and the
// remainder with leading whitespace trimmed.
func splitFirstField(s string) (first, rest string) {
	i := 0
	for i < len(s) && s[i] != ' ' && s[i] != '\t' {
		i++
	}
	first = s[:i]
	rest = strings.TrimLeft(s[i:], " \t")
	return first, rest
}

// isCronEnvAssignment reports whether line is a `KEY=value` assignment that
// crond would treat as an environment variable rather than a job.
//
// Rule: the first whitespace-or-`=` character is `=`, and what's before it is
// a valid env-var name (letter/digit/underscore, must start with non-digit).
func isCronEnvAssignment(line string) bool {
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '=' {
			if i == 0 {
				return false
			}
			name := line[:i]
			return validEnvName(name)
		}
		if c == ' ' || c == '\t' {
			return false
		}
	}
	return false
}

// validEnvName reports whether name is a syntactically valid env-var name.
func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		isLetter := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'
		isDigit := c >= '0' && c <= '9'
		if i == 0 && !isLetter {
			return false
		}
		if !isLetter && !isDigit {
			return false
		}
	}
	return true
}

// isExpectedFSAccessError reports whether err is a routine filesystem error
// that should be tolerated during best-effort multi-source reads (e.g.
// /var/spool/cron is mode 0700 on RHEL and unreadable as non-root, but we
// still want world-readable /etc/crontab and /etc/cron.d/* entries to land
// in the snapshot).
func isExpectedFSAccessError(err error) bool {
	return os.IsNotExist(err) || os.IsPermission(err)
}

// shouldSkipCronInclude mirrors the same hidden / editor-backup / dotted-name
// filter sudo's visudo applies to /etc/sudoers.d. cron drop-in dirs follow the
// same convention to avoid loading editor-saved temp copies.
func shouldSkipCronInclude(name string) bool {
	if name == "" {
		return true
	}
	if strings.HasPrefix(name, ".") {
		return true
	}
	if strings.HasSuffix(name, "~") {
		return true
	}
	if strings.Contains(name, ".") {
		return true
	}
	return false
}
