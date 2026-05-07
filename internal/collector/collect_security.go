package collector

// collect_security.go — v0.3 Phase A security-signal collectors: users, groups, sudoers.
// Always-on when the capture allowlist permits. All reads are from /etc; no external commands.
//
// Files /etc/passwd and /etc/group are world-readable. /etc/sudoers and /etc/sudoers.d/*
// are mode 0440 root:root and require root; statedrift snap runs as root by design.

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	defaultPasswdPath     = "/etc/passwd"
	defaultGroupPath      = "/etc/group"
	defaultSudoersPath    = "/etc/sudoers"
	defaultSudoersDirGlob = "/etc/sudoers.d/*"
)

// collectUsers reads /etc/passwd. NSS-only users (LDAP etc.) are not included.
func collectUsers() ([]User, error) {
	return readPasswdFrom(defaultPasswdPath)
}

// readPasswdFrom parses an /etc/passwd-format file. Blank and comment lines
// are skipped. Output is sorted by name for deterministic hashing.
func readPasswdFrom(path string) ([]User, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var users []User
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// passwd format: name:x:uid:gid:gecos:home:shell (7 fields, colon-separated).
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		gid, err := strconv.Atoi(parts[3])
		if err != nil {
			continue
		}
		users = append(users, User{
			Name:  parts[0],
			UID:   uid,
			GID:   gid,
			GECOS: parts[4],
			Home:  parts[5],
			Shell: parts[6],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	return users, nil
}

// collectGroups reads /etc/group.
func collectGroups() ([]Group, error) {
	return readGroupFrom(defaultGroupPath)
}

// readGroupFrom parses an /etc/group-format file. Members are sorted within
// each group; groups themselves are sorted by name. Blank and comment lines
// are skipped.
func readGroupFrom(path string) ([]Group, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var groups []Group
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// group format: name:x:gid:member1,member2,...
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		gid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		var members []string
		if parts[3] != "" {
			members = strings.Split(parts[3], ",")
			for i, m := range members {
				members[i] = strings.TrimSpace(m)
			}
			sort.Strings(members)
		}
		groups = append(groups, Group{
			Name:    parts[0],
			GID:     gid,
			Members: members,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	return groups, nil
}

// collectSudoers reads /etc/sudoers and all eligible files under /etc/sudoers.d/.
func collectSudoers() ([]SudoEntry, error) {
	return readSudoersFrom(defaultSudoersPath, defaultSudoersDirGlob)
}

// readSudoersFrom reads the main sudoers file plus all files matching dirGlob,
// returning one SudoEntry per non-comment logical line. A logical line folds
// backslash-newline continuations and collapses internal whitespace.
//
// Files in the include directory whose names match common editor-backup or
// hidden-file patterns are skipped, mirroring sudo's own visudo behavior.
func readSudoersFrom(mainPath, dirGlob string) ([]SudoEntry, error) {
	var entries []SudoEntry

	// Main sudoers file. Missing is non-fatal — some systems put everything in
	// /etc/sudoers.d. Other errors (permission denied, IO) propagate so the
	// caller can record them in CollectorErrors.
	es, err := readSudoersFile(mainPath, mainPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	entries = append(entries, es...)

	// Include-directory files.
	if dirGlob != "" {
		matches, err := filepath.Glob(dirGlob)
		if err != nil {
			return nil, err
		}
		sort.Strings(matches)
		for _, p := range matches {
			base := filepath.Base(p)
			if shouldSkipSudoersInclude(base) {
				continue
			}
			info, err := os.Stat(p)
			if err != nil || info.IsDir() {
				continue
			}
			es, err := readSudoersFile(p, p)
			if err != nil {
				return nil, err
			}
			entries = append(entries, es...)
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Source != entries[j].Source {
			return entries[i].Source < entries[j].Source
		}
		return entries[i].Line < entries[j].Line
	})
	return entries, nil
}

// readSudoersFile parses a single sudoers-format file into SudoEntry values
// tagged with the given source label.
func readSudoersFile(path, sourceLabel string) ([]SudoEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []SudoEntry
	scanner := bufio.NewScanner(f)
	var pending strings.Builder
	for scanner.Scan() {
		raw := scanner.Text()
		// Backslash-newline continuation: a logical line continues to the next
		// physical line when the line ends with a single backslash.
		trimmedRight := strings.TrimRight(raw, " \t")
		if strings.HasSuffix(trimmedRight, "\\") {
			pending.WriteString(strings.TrimSuffix(trimmedRight, "\\"))
			pending.WriteByte(' ')
			continue
		}
		pending.WriteString(raw)
		line := normalizeSudoersLine(pending.String())
		pending.Reset()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, SudoEntry{Source: sourceLabel, Line: line})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	// Trailing pending content with no terminating non-continuation line.
	if pending.Len() > 0 {
		line := normalizeSudoersLine(pending.String())
		if line != "" && !strings.HasPrefix(line, "#") {
			entries = append(entries, SudoEntry{Source: sourceLabel, Line: line})
		}
	}
	return entries, nil
}

// normalizeSudoersLine trims the line and collapses internal runs of whitespace
// (spaces and tabs) into a single space, so cosmetic whitespace edits don't
// register as drift.
func normalizeSudoersLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	return b.String()
}

// shouldSkipSudoersInclude reports whether a basename in /etc/sudoers.d/ should
// be ignored. Mirrors the patterns visudo skips: dotfiles, editor backups
// (~ suffix), package-manager artifacts (.rpmnew, .rpmsave, .dpkg-*), and
// names containing a literal dot (other than the package-manager extensions
// already covered) — sudo itself skips files whose names contain a `.` to
// avoid loading editor-saved temp copies.
func shouldSkipSudoersInclude(name string) bool {
	if name == "" {
		return true
	}
	if strings.HasPrefix(name, ".") {
		return true
	}
	if strings.HasSuffix(name, "~") {
		return true
	}
	// sudo's own rule: skip filenames containing `.` so editor-saved copies
	// like `myrules.bak` or `.swp` don't get loaded.
	if strings.Contains(name, ".") {
		return true
	}
	return false
}

// Note: secret-pattern redaction is NOT applied to SudoEntry.Line in Phase A.
// Sudoers commands are typically binary paths (/usr/bin/systemctl restart nginx),
// not credential-bearing shell commands. See docs/V03_PLAN.md "Phase A — known
// limitations" for rationale and the planned re-evaluation when the cron
// pattern-redactor lands in Phase D.

// SchemaVersionV04 is the value written into Snapshot.SchemaVersion by v0.4+
// binaries. Bumped when the schema changes in a way callers should notice.
// v0.3 wrote "0.3"; v0.4 added Process tick fields, Threads, and start_ticks.
const SchemaVersionV04 = "0.4"
