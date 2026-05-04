package collector

// collect_mounts.go — v0.3 Phase E mounts collector.
// Reads /proc/self/mountinfo, the kernel's authoritative view of currently-
// mounted filesystems. Strips credential-bearing option keys at collect time
// per the project redaction policy.

import (
	"bufio"
	"os"
	"sort"
	"strings"
)

const defaultMountinfoPath = "/proc/self/mountinfo"

// credentialOptionKeys is the set of option keys whose values must never be
// recorded in a snapshot. Drop the entire key=value pair at collect time.
// Keys are matched case-insensitively.
var credentialOptionKeys = map[string]bool{
	"password":    true,
	"credentials": true,
	"cred":        true,
}

// collectMounts reads /proc/self/mountinfo.
func collectMounts() ([]Mount, error) {
	return readMountinfoFrom(defaultMountinfoPath)
}

// readMountinfoFrom parses a mountinfo-format file. Output is sorted by
// mount point so the snapshot hashes deterministically across reads.
func readMountinfoFrom(path string) ([]Mount, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var mounts []Mount
	scanner := bufio.NewScanner(f)
	// mountinfo lines can be long when many options are present; raise the
	// per-line buffer limit above the bufio default of 64 KiB.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if m := parseMountinfoLine(line); m != nil {
			mounts = append(mounts, *m)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(mounts, func(i, j int) bool {
		if mounts[i].MountPoint != mounts[j].MountPoint {
			return mounts[i].MountPoint < mounts[j].MountPoint
		}
		// Multiple bind mounts can target the same mount point; break ties on source.
		return mounts[i].Source < mounts[j].Source
	})
	return mounts, nil
}

// parseMountinfoLine parses a single mountinfo line. Returns nil for lines
// that don't have the expected shape (kernel hands us well-formed data, but
// being permissive lets us survive future format additions).
//
// Format (kernel docs, proc(5)):
//
//	mount_id parent_id major:minor root mount_point mount_opts [optional...] - fs_type source super_opts
//
// The optional-fields block has a variable count and is terminated by a
// literal " - " token. We find that separator to know where fs_type starts.
func parseMountinfoLine(line string) *Mount {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return nil
	}

	// Locate the " - " separator after the mount-options field (index 5).
	sepIdx := -1
	for i := 6; i < len(fields); i++ {
		if fields[i] == "-" {
			sepIdx = i
			break
		}
	}
	// Need fs_type, source, super_opts after the separator.
	if sepIdx < 0 || sepIdx+3 >= len(fields) {
		return nil
	}

	mountPoint := unescapeMountField(fields[4])
	mountOpts := fields[5]
	fsType := fields[sepIdx+1]
	source := unescapeMountField(fields[sepIdx+2])
	superOpts := fields[sepIdx+3]

	return &Mount{
		Source:       source,
		MountPoint:   mountPoint,
		FSType:       fsType,
		MountOptions: redactAndSortOptions(mountOpts),
		SuperOptions: redactAndSortOptions(superOpts),
	}
}

// redactAndSortOptions drops credential-bearing key=value pairs and returns
// a comma-joined, alphabetically-sorted options string. Sorting stabilizes
// hashing across kernel versions that may emit options in different orders.
func redactAndSortOptions(opts string) string {
	if opts == "" {
		return ""
	}
	parts := strings.Split(opts, ",")
	out := parts[:0]
	for _, p := range parts {
		var key string
		if eq := strings.Index(p, "="); eq >= 0 {
			key = strings.ToLower(p[:eq])
		} else {
			key = strings.ToLower(p)
		}
		if credentialOptionKeys[key] {
			continue
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// unescapeMountField decodes mountinfo's octal escapes for whitespace and
// backslash characters in path-like fields. Order is irrelevant because
// mountinfo encoding is unambiguous (every backslash starts an escape).
func unescapeMountField(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	s = strings.ReplaceAll(s, `\040`, " ")
	s = strings.ReplaceAll(s, `\011`, "\t")
	s = strings.ReplaceAll(s, `\012`, "\n")
	s = strings.ReplaceAll(s, `\134`, `\`)
	return s
}
