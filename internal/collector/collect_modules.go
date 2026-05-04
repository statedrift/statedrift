package collector

// collect_modules.go — v0.3 Phase B kernel-modules collector.
// Reads /proc/modules, the kernel's authoritative list of loaded modules.
// World-readable, no root needed. No external commands invoked: modinfo
// signature collection is deferred (see types.go Module doc).

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"
)

const defaultModulesPath = "/proc/modules"

// collectModules reads /proc/modules.
func collectModules() ([]Module, error) {
	return readModulesFrom(defaultModulesPath)
}

// readModulesFrom parses a /proc/modules-format file. Output is sorted by
// module name so the snapshot hashes deterministically across reads.
//
// Format (one module per line):
//
//	name size refcount [deps] state addr
//
// where deps is a comma-separated list of dependent module names ending in
// a trailing comma, or a literal "-" if there are no dependencies.
func readModulesFrom(path string) ([]Module, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var modules []Module
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if m := parseModulesLine(line); m != nil {
			modules = append(modules, *m)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Name < modules[j].Name })
	return modules, nil
}

// parseModulesLine parses a single /proc/modules line. Returns nil for
// malformed lines (defensive against future kernel format additions).
func parseModulesLine(line string) *Module {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return nil
	}

	size, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return nil
	}

	return &Module{
		Name:         fields[0],
		Size:         size,
		Dependencies: parseModuleDeps(fields[3]),
	}
}

// parseModuleDeps converts the dependency field into a sorted slice.
// "-" means no dependencies; otherwise the field is a comma-separated list
// with a trailing comma (e.g. "nf_nat_tftp,").
func parseModuleDeps(field string) []string {
	if field == "-" || field == "" {
		return nil
	}
	parts := strings.Split(field, ",")
	deps := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		deps = append(deps, p)
	}
	if len(deps) == 0 {
		return nil
	}
	sort.Strings(deps)
	return deps
}
