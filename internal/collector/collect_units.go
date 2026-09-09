package collector

// collect_units.go — v0.9 systemd service *enablement* (the admin decision layer).
//
// The existing services collector reads `systemctl list-units`, i.e. runtime
// state: a unit going inactive is a reboot, a deploy, or a maintenance stop.
// This collector reads the orthogonal fact — whether a unit is wired to start
// at all — because that is the one an operator (or an intruder) changes
// deliberately, and it survives a reboot.
//
// It is read straight from the filesystem rather than from
// `systemctl list-unit-files`: that command stats every unit file across the
// whole search path and costs ~1s on a normal host (~40% of a full snapshot),
// returning several hundred `static` units that carry no enablement decision.
// The admin decisions all live as symlinks under two directories:
//
//   - <root>/<target>.wants/<unit>  and  <root>/<target>.requires/<unit>
//     — what `systemctl enable` writes.
//   - <root>/<unit> → /dev/null — what `systemctl mask` writes.
//   - <root>/<unit> → <other unit> — an alias (the [Install] Alias= form).
//
// with <root> = /etc/systemd/system (persistent) or /run/systemd/system
// (`--runtime`). Reading them is a handful of readdirs, no os/exec, and yields
// only units somebody decided something about.
//
// Trade-off, recorded deliberately: units enabled by a vendor preset shipped
// under /usr/lib are not visible here, and a plain disable is observed as the
// unit leaving the map (a "removed" change) rather than an explicit "disabled"
// value. Both are acceptable — the protective-control rules key on "a unit
// that was enabled no longer is", which covers disable and uninstall alike.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Roots of systemd's admin layer. /etc holds persistent decisions, /run holds
// `--runtime` ones that do not survive a reboot.
const (
	systemdPersistentRoot = "/etc/systemd/system"
	systemdRuntimeRoot    = "/run/systemd/system"
)

// collectServiceEnablement reads the host's systemd admin layer.
func collectServiceEnablement() (map[string]string, error) {
	return collectServiceEnablementFrom(systemdPersistentRoot, systemdRuntimeRoot)
}

// collectServiceEnablementFrom is the testable variant pointed at systemd-like
// roots. A missing root is "nothing decided here", not an error (a container
// may have no /etc/systemd/system at all). Any other read failure IS an error:
// silently returning an empty map would make the next diff look like every
// service on the host was disabled at once, which is precisely what the
// protective-control rules alarm on.
func collectServiceEnablementFrom(persistentRoot, runtimeRoot string) (map[string]string, error) {
	out := make(map[string]string)
	// Runtime first, persistent second: a unit decided in both places is
	// reported by its persistent state, which is the durable fact.
	if err := scanUnitRoot(runtimeRoot, "-runtime", out); err != nil {
		return nil, err
	}
	if err := scanUnitRoot(persistentRoot, "", out); err != nil {
		return nil, err
	}
	return out, nil
}

// scanUnitRoot records every enablement decision found under one systemd root,
// writing into out. kind is "" for persistent roots and "-runtime" for /run.
func scanUnitRoot(root, kind string, out map[string]string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	// Collected separately so precedence can be applied in one place below.
	wants := make(map[string][]string) // unit → targets wanting it
	special := make(map[string]string) // unit → "masked" / "alias:<unit>"

	for _, e := range entries {
		name := e.Name()
		switch {
		case e.IsDir() && (strings.HasSuffix(name, ".wants") || strings.HasSuffix(name, ".requires")):
			target := strings.TrimSuffix(strings.TrimSuffix(name, ".wants"), ".requires")
			for _, unit := range serviceLinksIn(filepath.Join(root, name)) {
				wants[unit] = append(wants[unit], target)
			}
		case strings.HasSuffix(name, ".service") && e.Type()&os.ModeSymlink != 0:
			dest, err := os.Readlink(filepath.Join(root, name))
			if err != nil {
				continue // raced with a concurrent systemctl; skip rather than fail the snapshot
			}
			if dest == os.DevNull {
				special[name] = "masked" + kind
			} else {
				special[name] = "alias" + kind + ":" + filepath.Base(dest)
			}
		}
	}

	for unit, targets := range wants {
		out[unit] = "enabled" + kind + ":" + strings.Join(sortedUnique(targets), ",")
	}
	// Masks and aliases are applied last: a masked unit cannot start even if a
	// stale .wants symlink still points at it, so the mask is the true state.
	for unit, state := range special {
		out[unit] = state
	}
	return nil
}

// serviceLinksIn returns the .service unit names inside one .wants/.requires
// directory. systemd honors both symlinks and real files there, so entry type
// is not filtered — only the .service suffix is.
func serviceLinksIn(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var units []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".service") {
			units = append(units, e.Name())
		}
	}
	return units
}

// sortedUnique sorts and de-duplicates. A unit listed in both foo.target.wants
// and foo.target.requires would otherwise record its target twice, making the
// value depend on directory read order.
func sortedUnique(vals []string) []string {
	sort.Strings(vals)
	out := make([]string, 0, len(vals))
	for i, v := range vals {
		if i == 0 || v != vals[i-1] {
			out = append(out, v)
		}
	}
	return out
}
