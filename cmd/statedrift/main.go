// statedrift — git log for your infrastructure.
// A tamper-evident infrastructure snapshot agent.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/statedrift/statedrift/internal/collector"
	"github.com/statedrift/statedrift/internal/config"
	"github.com/statedrift/statedrift/internal/daemon"
	"github.com/statedrift/statedrift/internal/diff"
	"github.com/statedrift/statedrift/internal/export"
	"github.com/statedrift/statedrift/internal/hasher"
	"github.com/statedrift/statedrift/internal/license"
	"github.com/statedrift/statedrift/internal/rules"
	"github.com/statedrift/statedrift/internal/store"
	"github.com/statedrift/statedrift/internal/timefmt"
)

// tf is the process-wide time formatter, initialised in main() from
// cfg.DisplayTZ. Storage timestamps are always UTC; tf controls only how
// times are rendered to the user and how operator-typed dates are parsed.
var tf = timefmt.MustNew("UTC")

// isTerminal returns true when stdout is a character device (interactive terminal).
func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ANSI color codes for inline diff output in cmdSnap.
const (
	ansiReset  = "\033[0m"
	ansiGreen  = "\033[32m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
)

const defaultStorePath = "/var/lib/statedrift"

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "statedrift: warning: config load error: %v\n", err)
		cfg = config.Default()
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "statedrift: invalid config: %v\n", err)
		os.Exit(1)
	}

	if f, err := timefmt.New(cfg.DisplayTZ); err != nil {
		fmt.Fprintf(os.Stderr, "statedrift: %v\n", err)
		os.Exit(1)
	} else {
		tf = f
	}

	storePath := envOr("STATEDRIFT_STORE", cfg.StorePath)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	s := store.New(storePath)

	switch os.Args[1] {
	case "init":
		cmdInit(s, cfg)
	case "snap":
		cmdSnap(s, cfg)
	case "log":
		cmdLog(s)
	case "show":
		cmdShow(s)
	case "diff":
		cmdDiff(s)
	case "verify":
		cmdVerify(s)
	case "export":
		cmdExport(s)
	case "daemon":
		cmdDaemon(s, cfg)
	case "gc":
		cmdGC(s)
	case "watch":
		cmdWatch(s, cfg)
	case "analyze":
		cmdAnalyze(s, cfg)
	case "version":
		fmt.Printf("statedrift %s (built %s)\n", collector.Version, collector.BuildDate)
	case "help", "--help", "-h":
		if len(os.Args) >= 3 {
			printCommandHelp(os.Args[2])
		} else {
			printUsage()
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`statedrift — git log for your infrastructure

Usage:
  statedrift <command> [flags]

Commands:
  init         Initialize the snapshot store
  snap         Take an on-demand snapshot
  log          Show snapshot history
  show <ref>   Display a specific snapshot (hash prefix, HEAD, HEAD~N)
  diff <a> <b> Compare two snapshots
  verify       Validate hash chain integrity
  export       Create a verifiable evidence bundle
  daemon       Run continuous snapshot collection
  watch        Continuously snap and alert on material changes
  analyze      Evaluate anomaly rules against latest diff  [free/Pro]
  gc           Remove snapshots older than retention_days
  version      Print version info
  help <cmd>   Show detailed help for a command

Environment:
  STATEDRIFT_STORE   Path to snapshot store (default: /var/lib/statedrift)
  STATEDRIFT_CONFIG  Path to config file (default: /etc/statedrift/config.json)
  STATEDRIFT_TZ      IANA zone for CLI output and date parsing
                     (overrides display_tz; default UTC; "Local" for host zone)
  XDG_CONFIG_HOME    Base for user config (default: ~/.config)
  NO_COLOR           Set to disable ANSI colors

Store path resolution (highest to lowest priority):
  1. $STATEDRIFT_STORE environment variable
  2. store_path in /etc/statedrift/config.json  (system config, requires root)
  3. store_path in $XDG_CONFIG_HOME/statedrift/config.json  (written by init)
  4. /var/lib/statedrift  (built-in default, requires root)

Examples:
  sudo statedrift init
  sudo statedrift snap
  statedrift log --since 2026-03-01
  statedrift diff HEAD~1 HEAD
  statedrift verify
  statedrift export --from 2026-03-01 --to 2026-03-22 -o audit.tar.gz
  sudo statedrift daemon --interval 1h
  sudo statedrift daemon --install
  sudo statedrift watch --interval 5m --webhook https://hooks.slack.com/...
  statedrift analyze
  statedrift help diff

Build: ` + collector.Version + ` (` + collector.BuildDate + `)`)

}

func printCommandHelp(cmd string) {
	helps := map[string]string{
		"init": `statedrift init — Initialize the snapshot store

Usage:
  sudo statedrift init
  STATEDRIFT_STORE=$HOME/.statedrift statedrift init

Creates the store directory and records a genesis snapshot of current host state.
Must be run once before any other command.

The chosen store path is saved to $XDG_CONFIG_HOME/statedrift/config.json so
subsequent commands find it automatically — no env var needed after init.

Store path resolution (highest to lowest priority):
  1. $STATEDRIFT_STORE environment variable
  2. store_path in /etc/statedrift/config.json       (system config, requires root)
  3. store_path in $XDG_CONFIG_HOME/statedrift/config.json  (written by init)
  4. /var/lib/statedrift                             (built-in default, requires root)

Flags:
  --force   Wipe and reinitialize an existing store

Examples:
  sudo statedrift init
  STATEDRIFT_STORE=$HOME/.statedrift statedrift init
  STATEDRIFT_STORE=$HOME/.statedrift statedrift init --force`,

		"snap": `statedrift snap — Take an on-demand snapshot

Usage:
  sudo statedrift snap

Collects the current host state, links it to the previous snapshot
via SHA-256 hash chain, and writes it to the store.

After saving, prints a brief inline diff from the previous snapshot
showing material changes (network, kernel params, packages, services).

Examples:
  sudo statedrift snap`,

		"log": `statedrift log — Show snapshot history

Usage:
  statedrift log [--since DATE] [--until DATE] [--json]

Flags:
  --since YYYY-MM-DD   Show snapshots on or after this date
  --until YYYY-MM-DD   Show snapshots on or before this date
  --json               Output as JSON array

Dates resolve to midnight in display_tz (default UTC; see STATEDRIFT_TZ).

Examples:
  statedrift log
  statedrift log --since 2026-03-01
  statedrift log --since 2026-03-01 --until 2026-03-22
  statedrift log --json | jq '.[].hash'`,

		"show": `statedrift show — Display a specific snapshot

Usage:
  statedrift show <ref> [--json]

Arguments:
  ref   Hash prefix, "HEAD", or "HEAD~N" (N snapshots before latest)

Flags:
  --json   Output raw snapshot JSON (pretty-printed)

Examples:
  statedrift show HEAD
  statedrift show HEAD~1
  statedrift show a3f8c1d2
  statedrift show HEAD --json | jq .kernel_params`,

		"diff": `statedrift diff — Compare two snapshots

Usage:
  statedrift diff <a> <b> [--section SECTION] [--material-only] [--json] [--no-color]

Arguments:
  a, b   Hash prefixes or HEAD/HEAD~N references

Flags:
  --section SECTION    Limit output to one section:
                       network, kernel_params, packages,
                       services, listening_ports, host
  --material-only      Hide counter-type changes (packet counts, etc.)
  --json               Output diff result as JSON
  --no-color           Disable ANSI color output

Output symbols:
  +   added
  -   removed
  ~   modified
  (dim) counter change (not counted as material)

Examples:
  statedrift diff HEAD~1 HEAD
  statedrift diff HEAD~1 HEAD --section kernel_params
  statedrift diff HEAD~1 HEAD --material-only
  statedrift diff a3f8 f7a2 --json | jq .changes`,

		"verify": `statedrift verify — Validate hash chain integrity

Usage:
  statedrift verify [bundle.tar.gz]

Without arguments, verifies the local store at $STATEDRIFT_STORE.
With a bundle path, extracts and verifies the exported bundle.

Exit code 0 = INTEGRITY VERIFIED
Exit code 1 = INTEGRITY VIOLATION detected

Examples:
  statedrift verify
  statedrift verify audit-2026-03.tar.gz`,

		"export": `statedrift export — Create a verifiable evidence bundle

Usage:
  statedrift export --from YYYY-MM-DD --to YYYY-MM-DD [-o output.tar.gz]

Flags:
  --from YYYY-MM-DD    Start date (inclusive, required)
  --to YYYY-MM-DD      End date (inclusive, required)
  -o, --output FILE    Output filename
                       (default: statedrift-export-FROM-TO.tar.gz)

Dates are interpreted as midnight in display_tz (default: UTC; override
with display_tz in /etc/statedrift/config.json or STATEDRIFT_TZ env var).
--from is inclusive at 00:00:00, --to is inclusive through 23:59:59.
Snapshot timestamps inside the bundle remain UTC regardless.

The bundle contains:
  - All snapshot JSON files for the date range
  - manifest.json with metadata and chain verification status
  - verify.sh  — self-contained verifier for Linux / macOS auditors
  - verify.ps1 — self-contained verifier for Windows auditors (PowerShell 5.1 or 7.5+)
  - README.txt — auditor instructions

A Linux/macOS auditor needs only sha256sum and jq. A Windows auditor needs
nothing beyond the PowerShell that ships with the OS — no jq, no WSL, no
external tools. No Go toolchain or statedrift binary required either way.

Examples:
  statedrift export --from 2026-03-01 --to 2026-03-22 -o audit.tar.gz
  tar xzf audit.tar.gz && cd audit && ./verify.sh`,

		"daemon": `statedrift daemon — Run continuous snapshot collection

Usage:
  sudo statedrift daemon [--interval DURATION] [--install] [--uninstall]

Flags:
  --interval DURATION   Snapshot interval, e.g. 30s, 15m, 1h
                        (default: from config or 1h; sub-minute intervals
                        are allowed for testing — use watch for alerting
                        workloads, which enforces a 1m floor)
  --install             Write /etc/systemd/system/statedrift.service
                        and print activation instructions.
                        If --interval is given, it is embedded in the unit file.
  --uninstall           Stop, disable, and remove the systemd service unit

Handles SIGTERM and SIGINT gracefully (stops the ticker, exits).
Logs one line per snapshot: timestamp and hash prefix.

Examples:
  sudo statedrift daemon
  sudo statedrift daemon --interval 15m
  sudo statedrift daemon --install
  sudo statedrift daemon --install --interval 30s
  sudo systemctl enable --now statedrift   # after --install
  sudo statedrift daemon --uninstall`,

		"gc": `statedrift gc — Remove old snapshots (garbage collect)

Usage:
  sudo statedrift gc

Deletes snapshots older than retention_days (from config, default 365).
Re-links the hash chain so verify still passes on remaining snapshots.
Prints a summary of removed snapshots.

Configure retention in /etc/statedrift/config.json:
  { "retention_days": 90 }

Examples:
  sudo statedrift gc`,

		"watch": `statedrift watch — Continuously snap and alert on material changes

Usage:
  statedrift watch [--interval DURATION] [--webhook URL] [--material-only] [--json]

Flags:
  --interval DURATION   Snapshot interval (default: 5m, minimum: 1m)
  --webhook URL         HTTP POST material changes as JSON to this URL
  --material-only       Suppress counter-only changes in output
  --json                Output diff events as JSON

Takes a snapshot every interval, diffs against the previous, and prints any
material changes to stdout. When --webhook is set, also POSTs the JSON diff
to the URL (useful for Slack incoming webhooks or custom alerting).

Disk usage: watch automatically enforces the retention_days policy from
config after every snapshot, so the store does not grow unboundedly.
At the default 5m interval that is ~288 snapshots/day; with 365-day retention
the store stabilises at ~105,000 snapshots. Set retention_days in
/etc/statedrift/config.json to control this:
  { "retention_days": 7 }
The retention period and a gc log line are printed on startup and whenever
old snapshots are removed.

Requires write access to the snapshot store. If the store is at the default
path (/var/lib/statedrift) run with sudo. If you initialized with a non-root
path (STATEDRIFT_STORE=$HOME/.statedrift statedrift init), no sudo needed.
watch will tell you immediately on startup if it cannot write to the store.

Handles SIGTERM and SIGINT gracefully.

Examples:
  sudo statedrift watch                                    # default store (root)
  statedrift watch                                         # non-root store via user config
  statedrift watch --interval 5m
  statedrift watch --interval 5m --webhook https://hooks.slack.com/services/...
  statedrift watch --material-only --json`,

		"analyze": `statedrift analyze — Evaluate anomaly rules against the latest diff

Usage:
  statedrift analyze [ref] [--rules FILE] [--json]

Arguments:
  ref   Optional: diff this snapshot against its predecessor.
        Accepts HEAD (default), HEAD~N, or a hash prefix.

Flags:
  --rules FILE   Path to rules JSON file (default: /etc/statedrift/rules.json,
                 falls back to built-in rules if file is absent)
  --json         Output findings as JSON

Evaluates the diff between ref and ref~1 against the configured rule set.
Rules are sorted by severity: critical > high > medium > low.

Pro rules (marked [PRO]) require a valid license at /etc/statedrift/license.json.
Free tier evaluates R01–R10 (core infrastructure rules).

Examples:
  statedrift analyze
  statedrift analyze HEAD~3
  statedrift analyze --rules /etc/statedrift/rules.json
  statedrift analyze --json | jq '.[] | select(.rule.severity=="critical")'`,

		"version": `statedrift version — Print version information

Usage:
  statedrift version

Examples:
  statedrift version`,
	}

	h, ok := helps[cmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "statedrift: unknown command %q\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
	fmt.Println(h)
}

// --- Commands ---

func cmdInit(s *store.Store, cfg *config.Config) {
	force := false
	for _, arg := range os.Args[2:] {
		if arg == "--force" {
			force = true
		}
	}

	if force {
		if err := s.Reset(); err != nil {
			fatal("reset failed: %v", err)
		}
		fmt.Println("Store reset.")
	} else if err := s.Init(); err != nil {
		if errors.Is(err, fs.ErrPermission) {
			fatal("init failed: %v\n(hint: run with sudo, or use a writable path:\n         STATEDRIFT_STORE=$HOME/.statedrift statedrift init)", err)
		}
		fatal("init failed: %v\n(hint: use --force to wipe and reinitialize)", err)
	}

	// Take genesis snapshot
	snap, err := collector.Collect(hasher.GenesisHash, cfg)
	if err != nil {
		fatal("genesis snapshot failed: %v", err)
	}

	hash, err := s.Save(snap)
	if err != nil {
		fatal("saving genesis snapshot: %v", err)
	}

	// Persist the chosen store path to the user config so subsequent commands
	// find it without STATEDRIFT_STORE being set in the environment.
	if err := config.SaveUserStorePath(s.BasePath); err != nil {
		fmt.Fprintf(os.Stderr, "statedrift: warning: could not save user config: %v\n", err)
	}

	fmt.Println("✓ Store initialized at", s.ChainDir())
	fmt.Println("✓ Genesis snapshot recorded")
	fmt.Printf("  Host:    %s\n", snap.Host.Hostname)
	fmt.Printf("  Time:    %s\n", tf.RFC3339(snap.Timestamp))
	fmt.Printf("  Hash:    %s\n", hash[:16]+"...")
	fmt.Println("✓ Run 'statedrift snap' to take more snapshots.")
}

func cmdSnap(s *store.Store, cfg *config.Config) {
	requireInit(s)

	prevHash := s.ReadHead()
	snap, err := collector.Collect(prevHash, cfg)
	if err != nil {
		fatal("snapshot failed: %v", err)
	}

	hash, err := s.Save(snap)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			fatal("saving snapshot: %v\n(hint: run with sudo)", err)
		}
		fatal("saving snapshot: %v", err)
	}

	fmt.Println("✓ Snapshot recorded")
	fmt.Printf("  Time:    %s\n", tf.RFC3339(snap.Timestamp))
	fmt.Printf("  Hash:    %s\n", hash[:16]+"...")
	fmt.Printf("  Prev:    %s\n", snap.PrevHash[:16]+"...")

	// Show quick diff from previous if available
	entries, err := s.List()
	if err == nil && len(entries) >= 2 {
		prev := entries[len(entries)-2].Snapshot
		result := diff.Compare(prev, snap)
		if result.Material > 0 || result.Counters > 0 {
			fmt.Printf("  Changes: %d material, %d counters\n", result.Material, result.Counters)
			// Show material changes inline
			for _, c := range result.Changes {
				if c.Counter {
					continue
				}
				color := isTerminal()
				switch c.Type {
				case "added":
					if color {
						fmt.Printf("%s    + %s.%s: %s%s\n", ansiGreen, c.Section, c.Key, c.NewValue, ansiReset)
					} else {
						fmt.Printf("    + %s.%s: %s\n", c.Section, c.Key, c.NewValue)
					}
				case "removed":
					if color {
						fmt.Printf("%s    - %s.%s: %s%s\n", ansiRed, c.Section, c.Key, c.OldValue, ansiReset)
					} else {
						fmt.Printf("    - %s.%s: %s\n", c.Section, c.Key, c.OldValue)
					}
				case "modified":
					if color {
						fmt.Printf("%s    ~ %s.%s: %q → %q%s\n", ansiYellow, c.Section, c.Key, c.OldValue, c.NewValue, ansiReset)
					} else {
						fmt.Printf("    ~ %s.%s: %q → %q\n", c.Section, c.Key, c.OldValue, c.NewValue)
					}
				}
			}
		} else {
			fmt.Println("  Changes: (none)")
		}
	}
}

func cmdLog(s *store.Store) {
	requireInit(s)

	var sinceStr, untilStr string
	var jsonOut bool
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--since":
			if i+1 < len(os.Args) {
				sinceStr = os.Args[i+1]
				i++
			}
		case "--until":
			if i+1 < len(os.Args) {
				untilStr = os.Args[i+1]
				i++
			}
		case "--json":
			jsonOut = true
		}
	}

	var since, until time.Time
	if sinceStr != "" {
		t, err := tf.ParseDate(sinceStr)
		if err != nil {
			fatal("invalid --since date: %v", err)
		}
		since = t
	}
	if untilStr != "" {
		t, err := tf.ParseDate(untilStr)
		if err != nil {
			fatal("invalid --until date: %v", err)
		}
		until = t.Add(24*time.Hour - time.Second)
	}

	entries, err := s.List()
	if err != nil {
		fatal("listing snapshots: %v", err)
	}

	if !since.IsZero() || !until.IsZero() {
		var filtered []store.SnapshotEntry
		for _, e := range entries {
			t := e.Snapshot.Timestamp
			if !since.IsZero() && t.Before(since) {
				continue
			}
			if !until.IsZero() && t.After(until) {
				continue
			}
			filtered = append(filtered, e)
		}
		entries = filtered
	}

	if len(entries) == 0 {
		fmt.Println("No snapshots found.")
		return
	}

	type logEntry struct {
		Hash      string `json:"hash"`
		Time      string `json:"time"`
		Changes   int    `json:"changes"`
		Counters  int    `json:"counters"`
		IsGenesis bool   `json:"is_genesis"`
		IsHead    bool   `json:"is_head"`
	}

	if jsonOut {
		out := make([]logEntry, 0, len(entries))
		for i := len(entries) - 1; i >= 0; i-- {
			e := entries[i]
			// JSON output stays UTC regardless of display_tz: machine consumers
			// (jq pipelines, scripts) expect a stable wire format.
			le := logEntry{
				Hash:      e.Hash,
				Time:      e.Snapshot.Timestamp.UTC().Format(time.RFC3339),
				IsGenesis: i == 0,
				IsHead:    i == len(entries)-1,
			}
			if i > 0 {
				result := diff.Compare(entries[i-1].Snapshot, e.Snapshot)
				le.Changes = result.Material
				le.Counters = result.Counters
			}
			out = append(out, le)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fatal("encoding JSON: %v", err)
		}
		return
	}

	fmt.Printf("%-10s  %-20s  %s\n", "hash", "time", "changes")
	fmt.Println(strings.Repeat("─", 56))

	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		changes := "-"
		if i > 0 {
			result := diff.Compare(entries[i-1].Snapshot, e.Snapshot)
			changes = fmt.Sprintf("%d", result.Material)
			if result.Counters > 0 {
				changes += fmt.Sprintf(" (+%d counters)", result.Counters)
			}
		} else {
			changes = "genesis"
		}

		note := ""
		if i == len(entries)-1 {
			note = " (HEAD)"
		}

		fmt.Printf("%-10s  %-24s  %s%s\n",
			e.Hash[:8],
			tf.Short(e.Snapshot.Timestamp),
			changes,
			note,
		)
	}

	fmt.Printf("\n%d snapshots total\n", len(entries))
}

func cmdShow(s *store.Store) {
	requireInit(s)

	if len(os.Args) < 3 {
		fatal("usage: statedrift show <ref>\n  ref: HEAD, HEAD~N, or a hash prefix (run 'statedrift log' to list snapshots)")
	}

	jsonOut := false
	for _, arg := range os.Args[3:] {
		if arg == "--json" {
			jsonOut = true
		}
	}

	snap, err := resolveRef(s, os.Args[2])
	if err != nil {
		fatal("%v", err)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(snap); err != nil {
			fatal("encoding JSON: %v", err)
		}
		return
	}

	// Resolve hash for display.
	entries, _ := s.List()
	hash := ""
	for _, e := range entries {
		if e.Snapshot == snap {
			hash = e.Hash
			break
		}
	}
	if len(hash) >= 16 {
		fmt.Printf("Snapshot %s\n", hash[:16]+"...")
	} else {
		fmt.Printf("Snapshot %s\n", hash)
	}
	fmt.Printf("Time:    %s\n", tf.RFC3339(snap.Timestamp))
	fmt.Printf("Host:    %s (%s, kernel %s)\n\n", snap.Host.Hostname, snap.Host.OS, snap.Host.Kernel)

	// Network interfaces
	fmt.Println("Network Interfaces:")
	for _, iface := range snap.Network.Interfaces {
		addrs := strings.Join(iface.Addresses, ", ")
		fmt.Printf("  %-10s %-4s %-24s MTU %d\n", iface.Name, iface.State, addrs, iface.MTU)
	}

	// Routes
	fmt.Println("\nRoutes:")
	for _, r := range snap.Network.Routes {
		line := "  " + r.Destination
		if r.Gateway != "" {
			line += " via " + r.Gateway
		}
		line += " dev " + r.Device
		if r.Metric > 0 {
			line += fmt.Sprintf(" metric %d", r.Metric)
		}
		fmt.Println(line)
	}

	// Kernel params
	fmt.Println("\nKernel Parameters:")
	for k, v := range snap.KernelParams {
		fmt.Printf("  %s = %s\n", k, v)
	}

	// Listening ports
	fmt.Println("\nListening Ports:")
	for _, p := range snap.ListeningPorts {
		proc := p.Process
		if proc == "" {
			proc = "-"
		}
		fmt.Printf("  %d/%s  %-16s %s\n", p.Port, p.Protocol, p.Address, proc)
	}

	// Package count (don't print all — too noisy)
	fmt.Printf("\nPackages: %d installed\n", len(snap.Packages))

	// Services
	fmt.Println("\nServices:")
	for name, state := range snap.Services {
		fmt.Printf("  %-40s %s\n", name, state)
	}

	// Users — count only; full list available via `show --json | jq .users`.
	fmt.Printf("\nUsers: %d in /etc/passwd\n", len(snap.Users))

	// Groups — count + the subset with non-empty member lists, since member
	// composition (especially of privileged groups) is the audit-relevant signal.
	fmt.Printf("\nGroups: %d in /etc/group\n", len(snap.Groups))
	for _, g := range snap.Groups {
		if len(g.Members) > 0 {
			fmt.Printf("  %-20s gid=%-6d members=%s\n", g.Name, g.GID, strings.Join(g.Members, ","))
		}
	}

	// Sudoers — full dump. Small, security-critical.
	if len(snap.Sudoers) == 0 {
		fmt.Println("\nSudoers: (none collected — requires root, see collector_errors)")
	} else {
		fmt.Printf("\nSudoers: %d entries\n", len(snap.Sudoers))
		for _, e := range snap.Sudoers {
			fmt.Printf("  [%s] %s\n", e.Source, e.Line)
		}
	}

	// Mounts — count all, but only enumerate real-storage and network mounts.
	// Virtual filesystems (tmpfs, proc, sysfs, overlay, cgroup, etc.) are
	// signaled by source == fstype and are usually noise for audit purposes.
	fmt.Printf("\nMounts: %d entries\n", len(snap.Mounts))
	for _, m := range snap.Mounts {
		if m.Source == m.FSType {
			continue
		}
		fmt.Printf("  %-32s %-10s %-32s %s\n", m.MountPoint, m.FSType, m.Source, m.MountOptions)
	}

	// Surface non-fatal collector errors so users notice missing sections.
	if len(snap.CollectorErrors) > 0 {
		fmt.Println("\nCollector errors:")
		for _, e := range snap.CollectorErrors {
			fmt.Printf("  %s\n", e)
		}
	}
}

func cmdDiff(s *store.Store) {
	requireInit(s)

	if len(os.Args) < 4 {
		fatal("usage: statedrift diff <hash-prefix-a> <hash-prefix-b>")
	}

	snapA, err := resolveRef(s, os.Args[2])
	if err != nil {
		fatal("snapshot A: %v", err)
	}
	snapB, err := resolveRef(s, os.Args[3])
	if err != nil {
		fatal("snapshot B: %v", err)
	}

	materialOnly := false
	sectionFilter := ""
	jsonOut := false
	args := os.Args[4:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--material-only":
			materialOnly = true
		case "--json":
			jsonOut = true
		case "--section":
			if i+1 < len(args) {
				sectionFilter = args[i+1]
				i++
			}
		}
	}

	result := diff.Compare(snapA, snapB)
	if sectionFilter != "" {
		result = diff.FilterSection(result, sectionFilter)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fatal("encoding JSON: %v", err)
		}
		return
	}

	fmt.Printf("Comparing %s → %s\n\n",
		tf.Short(snapA.Timestamp),
		tf.Short(snapB.Timestamp),
	)
	fmt.Print(diff.Format(result, materialOnly, isTerminal()))
}

func cmdVerify(s *store.Store) {
	// If a bundle path is given, verify the bundle instead of the local store.
	if len(os.Args) >= 3 && !strings.HasPrefix(os.Args[2], "--") {
		cmdVerifyBundle(os.Args[2])
		return
	}

	requireInit(s)

	fmt.Println("Verifying chain integrity...")

	// Scan every .json file in the chain directory directly, before relying
	// on store.List() (which silently skips unreadable/unparseable files,
	// per DEFERRED #1). Any failure here is an integrity violation: a
	// corrupt snapshot must not be hidden by appearing as "no snapshots".
	corrupt, scanErr := scanChainCorruption(s)
	if scanErr != nil {
		fatal("scanning chain dir: %v", scanErr)
	}
	if len(corrupt) > 0 {
		fmt.Printf("  Chain:      ✗ %d unreadable or unparseable file(s)\n", len(corrupt))
		fmt.Println("  Result:     INTEGRITY VIOLATION")
		fmt.Println()
		fmt.Println("WARNING: The following snapshot files could not be read or parsed.")
		fmt.Println("         A corrupt snapshot file means the chain may be incomplete")
		fmt.Println("         or has been tampered with.")
		for _, c := range corrupt {
			fmt.Printf("  %s: %v\n", c.path, c.err)
		}
		os.Exit(1)
	}

	entries, brokenAt, err := s.VerifyChain()
	if err != nil {
		fatal("verification error: %v", err)
	}

	if len(entries) == 0 {
		fmt.Println("  No snapshots found.")
		return
	}

	fmt.Printf("  Snapshots:  %d\n", len(entries))
	fmt.Printf("  First:      %s\n", tf.RFC3339(entries[0].Snapshot.Timestamp))
	fmt.Printf("  Last:       %s\n", tf.RFC3339(entries[len(entries)-1].Snapshot.Timestamp))

	if brokenAt == -1 {
		// Cross-check the last snapshot's hash against the head file.
		// This catches modifications to the last snapshot, which have no
		// successor link to detect them through the chain alone.
		headHash := s.ReadHead()
		lastHash := entries[len(entries)-1].Hash
		if headHash != lastHash {
			fmt.Printf("  Chain:      ✓ all %d links valid\n", len(entries))
			fmt.Printf("  Head:       ✗ MISMATCH\n")
			fmt.Println("  Result:     INTEGRITY VIOLATION")
			fmt.Println()
			fmt.Printf("WARNING: The last snapshot (%s) may have been modified.\n",
				tf.RFC3339(entries[len(entries)-1].Snapshot.Timestamp))
			fmt.Printf("         head file records: %s\n", headHash[:16]+"...")
			fmt.Printf("         last snapshot hash: %s\n", lastHash[:16]+"...")
			fmt.Printf("Snapshots #0-%d are verified intact.\n", len(entries)-2)
			fmt.Printf("Snapshot #%d (last) cannot be trusted.\n", len(entries)-1)
			os.Exit(1)
		}
		fmt.Printf("  Chain:      ✓ all %d hashes valid\n", len(entries))
		fmt.Printf("  Head:       ✓ matches last snapshot\n")
		fmt.Println("  Result:     INTEGRITY VERIFIED")
		fmt.Println()
		fmt.Println("No tampering detected. All snapshots are consistent with their recorded hashes.")
	} else {
		fmt.Printf("  Chain:      ✗ BREAK at snapshot #%d (%s)\n",
			brokenAt, tf.RFC3339(entries[brokenAt].Snapshot.Timestamp))

		if brokenAt > 0 {
			fmt.Printf("              Expected prev_hash: %s\n", entries[brokenAt-1].Hash[:16]+"...")
		}
		fmt.Printf("              Found prev_hash:    %s\n", entries[brokenAt].Snapshot.PrevHash[:16]+"...")
		fmt.Println("  Result:     INTEGRITY VIOLATION")
		fmt.Println()
		if brokenAt == 0 {
			fmt.Println("WARNING: The first snapshot does not start from genesis.")
			fmt.Printf("         prev_hash: %s\n", entries[0].Snapshot.PrevHash[:16]+"...")
			fmt.Println("         This usually means snapshot files were deleted manually,")
			fmt.Println("         leaving the store in an inconsistent state.")
			fmt.Println("         Use 'statedrift gc' to remove old snapshots safely,")
			fmt.Println("         or 'statedrift init' to start a fresh chain.")
			fmt.Println("No snapshots are verified intact.")
		} else {
			fmt.Printf("WARNING: Snapshot #%d (%s) may have been modified.\n",
				brokenAt-1, tf.RFC3339(entries[brokenAt-1].Snapshot.Timestamp))
			fmt.Printf("         Its hash no longer matches the prev_hash recorded in snapshot #%d.\n", brokenAt)
			if brokenAt-1 > 0 {
				fmt.Printf("Snapshots #0-%d are verified intact.\n", brokenAt-2)
			} else {
				fmt.Println("No snapshots before the suspect are verified intact.")
			}
			fmt.Printf("Snapshot #%d and later cannot be trusted.\n", brokenAt-1)
		}
		os.Exit(1)
	}
}

func cmdExport(s *store.Store) {
	requireInit(s)

	var fromStr, toStr, output string

	for i := 2; i < len(os.Args)-1; i++ {
		switch os.Args[i] {
		case "--from":
			fromStr = os.Args[i+1]
		case "--to":
			toStr = os.Args[i+1]
		case "-o", "--output":
			output = os.Args[i+1]
		}
	}

	if fromStr == "" || toStr == "" {
		fatal("usage: statedrift export --from YYYY-MM-DD --to YYYY-MM-DD -o output.tar.gz")
	}

	from, err := tf.ParseDate(fromStr)
	if err != nil {
		fatal("invalid --from date: %v", err)
	}
	to, err := tf.ParseDate(toStr)
	if err != nil {
		fatal("invalid --to date: %v", err)
	}
	// Include the entire "to" day
	to = to.Add(24*time.Hour - time.Second)

	if output == "" {
		output = fmt.Sprintf("statedrift-export-%s-%s.tar.gz", fromStr, toStr)
	}

	// Verify chain before exporting
	fmt.Println("Verifying chain before export...")
	_, brokenAt, err := s.VerifyChain()
	if err != nil {
		fatal("chain verification failed: %v", err)
	}
	if brokenAt != -1 {
		fatal("chain integrity violation detected at snapshot #%d. Fix before exporting.", brokenAt)
	}
	fmt.Println("  Chain: ✓ verified")

	fmt.Println("Exporting snapshots...")
	if err := export.Bundle(s, from, to, output); err != nil {
		fatal("export failed: %v", err)
	}
	fmt.Println("  Bundle verified ✓")

	fmt.Printf("\nCreated: %s\n", output)
	fmt.Println("\nAn auditor can verify this bundle by running:")
	fmt.Printf("  tar xzf %s && cd %s && ./verify.sh\n",
		output, strings.TrimSuffix(output, ".tar.gz"))
}

// corruptFile records a snapshot file that could not be read or parsed.
type corruptFile struct {
	path string
	err  error
}

// scanChainCorruption walks the chain directory and returns every .json file
// that cannot be read or parsed as a snapshot. Used by cmdVerify to surface
// corruption that store.List() would silently skip.
func scanChainCorruption(s *store.Store) ([]corruptFile, error) {
	var corrupt []corruptFile
	chainDir := s.ChainDir()

	err := filepath.WalkDir(chainDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// A directory we cannot read counts as corruption — note it and continue.
			if d != nil && d.IsDir() {
				corrupt = append(corrupt, corruptFile{path: path, err: walkErr})
				return fs.SkipDir
			}
			corrupt = append(corrupt, corruptFile{path: path, err: walkErr})
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			corrupt = append(corrupt, corruptFile{path: path, err: err})
			return nil
		}
		var snap collector.Snapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			corrupt = append(corrupt, corruptFile{path: path, err: err})
		}
		return nil
	})
	if err != nil {
		return corrupt, err
	}
	return corrupt, nil
}

func cmdVerifyBundle(path string) {
	fmt.Printf("Verifying bundle: %s\n", path)
	fmt.Println()

	count, brokenAt, err := export.VerifyBundle(path)
	if errors.Is(err, export.ErrManifestMismatch) {
		fmt.Printf("  Snapshots:  %d\n", count)
		fmt.Printf("  Chain:      ✓ all %d hashes valid\n", count)
		fmt.Printf("  Manifest:   ✗ MISMATCH\n")
		fmt.Println("  Result:     INTEGRITY VIOLATION")
		fmt.Println()
		fmt.Println("WARNING: The chain is internally consistent, but its first or last")
		fmt.Println("         snapshot hash no longer matches what manifest.json claims.")
		fmt.Println("         The bundle as a whole has been substituted, replaced with a")
		fmt.Println("         different valid chain, or the manifest was edited after creation.")
		fmt.Printf("  detail: %v\n", err)
		os.Exit(1)
	}
	if err != nil {
		fatal("verification error: %v", err)
	}

	fmt.Printf("  Snapshots:  %d\n", count)

	if brokenAt == -1 {
		fmt.Printf("  Chain:      ✓ all %d hashes valid\n", count)
		fmt.Println("  Result:     INTEGRITY VERIFIED")
		fmt.Println()
		fmt.Println("No tampering detected. All snapshots are consistent with their recorded hashes.")
	} else {
		fmt.Printf("  Chain:      ✗ BREAK at snapshot #%d\n", brokenAt)
		fmt.Println("  Result:     INTEGRITY VIOLATION")
		fmt.Println()
		if brokenAt == 0 {
			fmt.Println("WARNING: The first snapshot has an invalid prev_hash.")
			fmt.Println("No snapshots are verified intact.")
		} else {
			fmt.Printf("WARNING: Snapshot #%d may have been modified.\n", brokenAt-1)
			fmt.Printf("         Its hash no longer matches the prev_hash recorded in snapshot #%d.\n", brokenAt)
			if brokenAt-1 > 0 {
				fmt.Printf("Snapshots #0-%d are verified intact.\n", brokenAt-2)
			} else {
				fmt.Println("No snapshots before the suspect are verified intact.")
			}
			fmt.Printf("Snapshot #%d and later cannot be trusted.\n", brokenAt-1)
		}
		os.Exit(1)
	}
}

func cmdDaemon(s *store.Store, cfg *config.Config) {
	install := false
	uninstall := false
	intervalStr := cfg.Interval
	if intervalStr == "" {
		intervalStr = "1h"
	}
	intervalExplicit := ""

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--install":
			install = true
		case "--uninstall":
			uninstall = true
		case "--interval":
			if i+1 < len(os.Args) {
				intervalStr = os.Args[i+1]
				intervalExplicit = os.Args[i+1]
				i++
			}
		}
	}

	if uninstall {
		cmdDaemonUninstall()
		return
	}

	if install {
		cmdDaemonInstall(s, intervalExplicit)
		return
	}

	requireInit(s)

	interval, err := daemon.ParseInterval(intervalStr)
	if err != nil {
		fatal("invalid interval: %v", err)
	}

	fmt.Println("statedrift daemon started")
	fmt.Printf("  Store:    %s\n", s.BasePath)
	fmt.Printf("  Interval: %s\n", interval)
	fmt.Printf("  Next snap: %s\n\n", tf.RFC3339(time.Now().Add(interval)))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Take first snapshot immediately on start.
	daemonSnap(s, cfg)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			daemonSnap(s, cfg)
		case sig := <-sigCh:
			fmt.Printf("\nReceived %s. Shutting down cleanly.\n", sig)
			return
		}
	}
}

func daemonSnap(s *store.Store, cfg *config.Config) {
	prevHash := s.ReadHead()
	snap, err := collector.Collect(prevHash, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "statedrift: snapshot error: %v\n", err)
		return
	}
	hash, err := s.Save(snap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "statedrift: save error: %v\n", err)
		return
	}
	fmt.Printf("[%s] ✓ hash: %s\n", tf.RFC3339(snap.Timestamp), hash[:16]+"...")
}

func cmdGC(s *store.Store) {
	requireInit(s)

	cfg, err := config.Load()
	if err != nil {
		cfg = config.Default()
	}

	retentionDays := cfg.RetentionDays
	// Override with --days flag if provided.
	for i := 2; i < len(os.Args)-1; i++ {
		if os.Args[i] == "--days" {
			var n int
			if _, err := fmt.Sscanf(os.Args[i+1], "%d", &n); err == nil && n >= 0 {
				retentionDays = n
			}
		}
	}

	fmt.Printf("Removing snapshots older than %d days...\n", retentionDays)

	result, err := s.GC(retentionDays)
	if err != nil {
		fatal("gc failed: %v", err)
	}

	if result.Removed == 0 {
		fmt.Println("Nothing to remove.")
		return
	}

	fmt.Printf("Removed %d snapshot(s) older than %s\n",
		result.Removed, tf.Date(result.Before))
	fmt.Printf("Remaining: %d snapshot(s)\n", result.Remaining)
	fmt.Println("Chain re-linked. Run 'statedrift verify' to confirm.")
}

const installedBinaryPath = "/usr/local/bin/statedrift"

func cmdDaemonInstall(s *store.Store, interval string) {
	srcPath, err := os.Executable()
	if err != nil {
		fatal("resolving binary path: %v", err)
	}

	if err := copyFile(srcPath, installedBinaryPath, 0755); err != nil {
		fatal("copying binary to %s: %v\n(hint: run with sudo)", installedBinaryPath, err)
	}
	fmt.Printf("Copied binary to %s\n", installedBinaryPath)

	unitPath := "/etc/systemd/system/statedrift.service"
	content := daemon.SystemdUnit(installedBinaryPath, s.BasePath, interval)

	if err := os.WriteFile(unitPath, []byte(content), 0644); err != nil {
		fatal("writing service file: %v\n(hint: run with sudo)", err)
	}

	fmt.Printf("Created %s\n", unitPath)
	if interval != "" {
		fmt.Printf("Interval: %s\n", interval)
	}
	fmt.Println("\nTo enable and start:")
	fmt.Println("  sudo systemctl daemon-reload")
	fmt.Println("  sudo systemctl enable --now statedrift")
	fmt.Println("\nTo check status:")
	fmt.Println("  sudo systemctl status statedrift")
	fmt.Println("  sudo journalctl -u statedrift -f")
	fmt.Println("\nTo stop:")
	fmt.Println("  sudo systemctl stop statedrift")
	fmt.Println("\nTo uninstall:")
	fmt.Println("  sudo /usr/local/bin/statedrift daemon --uninstall")
}

// copyFile copies src to dst with the given permissions, overwriting dst if it exists.
func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func cmdDaemonUninstall() {
	unitPath := "/etc/systemd/system/statedrift.service"

	// Stop and disable — ignore errors if already stopped/disabled.
	for _, args := range [][]string{
		{"systemctl", "stop", "statedrift"},
		{"systemctl", "disable", "statedrift"},
	} {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
	}

	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		fatal("removing %s: %v", unitPath, err)
	}

	cmd := exec.Command("systemctl", "daemon-reload")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fatal("systemctl daemon-reload: %v", err)
	}

	fmt.Printf("Removed %s\n", unitPath)

	if _, err := os.Stat(installedBinaryPath); err == nil {
		fmt.Printf("Remove %s? [y/N] ", installedBinaryPath)
		var answer string
		fmt.Fscan(os.Stdin, &answer)
		if answer == "y" || answer == "Y" {
			if err := os.Remove(installedBinaryPath); err != nil {
				fatal("removing %s: %v", installedBinaryPath, err)
			}
			fmt.Printf("Removed %s\n", installedBinaryPath)
		}
	}

	fmt.Println("statedrift service uninstalled.")
}

// checkStoreWritable verifies the store directory is writable by creating and
// immediately removing a temp file. Called before entering long-running loops
// so permission problems surface immediately rather than silently.
func checkStoreWritable(s *store.Store) error {
	tmp, err := os.CreateTemp(s.ChainDir(), ".write-check-*")
	if err != nil {
		return err
	}
	tmp.Close()
	os.Remove(tmp.Name())
	return nil
}

// allWatchSections is the ordered list of every section name tracked by the
// per-section scheduler. Order is cosmetic (startup banner only).
var allWatchSections = []string{
	"host", "network", "kernel_params", "packages", "services",
	"listening_ports", "multicast",
	"cpu", "kernel_counters", "processes", "sockets", "nic_drivers", "connections",
}

func cmdWatch(s *store.Store, cfg *config.Config) {
	requireInit(s)

	if err := checkStoreWritable(s); err != nil {
		if errors.Is(err, fs.ErrPermission) {
			fatal("watch: cannot write to store at %s: permission denied.\n"+
				"  Run with sudo, or use a non-root store:\n"+
				"    STATEDRIFT_STORE=$HOME/.statedrift statedrift watch",
				s.BasePath)
		}
		fatal("watch: cannot write to store at %s: %v", s.BasePath, err)
	}

	// Resolve base interval: config default → 5m fallback, then CLI override.
	// cfg.Interval was already validated by cfg.Validate() in main().
	const watchDefault = 5 * time.Minute
	baseInterval := watchDefault
	if cfg.Interval != "" {
		if d, _ := time.ParseDuration(cfg.Interval); d >= time.Minute {
			baseInterval = d
		}
	}

	var webhookURL string
	materialOnly := false
	jsonOut := false

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--interval":
			if i+1 < len(os.Args) {
				d, err := time.ParseDuration(os.Args[i+1])
				if err != nil {
					fatal("invalid --interval: %v", err)
				}
				if d < time.Minute {
					fatal("--interval must be at least 1m")
				}
				// CLI --interval overrides the base; section-specific overrides
				// in cfg.SectionIntervals are still honoured on top of this.
				baseInterval = d
				i++
			}
		case "--webhook":
			if i+1 < len(os.Args) {
				webhookURL = os.Args[i+1]
				i++
			}
		case "--material-only":
			materialOnly = true
		case "--json":
			jsonOut = true
		}
	}

	// Build per-section schedules. Each section fires at its own interval;
	// the ticker fires at the minimum across all of them.
	type sectionSchedule struct {
		interval time.Duration
		nextDue  time.Time
	}
	now := time.Now()
	schedules := make(map[string]*sectionSchedule, len(allWatchSections))
	for _, sec := range allWatchSections {
		schedules[sec] = &sectionSchedule{
			interval: cfg.SectionInterval(sec, baseInterval),
			nextDue:  now, // all sections due on the first tick
		}
	}
	tickInterval := cfg.MinTickInterval(baseInterval)

	useColor := isTerminal() && !jsonOut && os.Getenv("NO_COLOR") == ""

	fmt.Printf("statedrift watch — base: %s, tick: %s, retention: %d days",
		baseInterval, tickInterval, cfg.RetentionDays)
	if webhookURL != "" {
		fmt.Printf(", webhook: %s", webhookURL)
	}
	fmt.Println()
	if len(cfg.SectionIntervals) > 0 {
		fmt.Printf("  section overrides:")
		for _, sec := range allWatchSections {
			if override, ok := cfg.SectionIntervals[sec]; ok {
				fmt.Printf(" %s=%s", sec, override)
			}
		}
		fmt.Println()
	}
	fmt.Println("Press Ctrl-C to stop.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sig:
			fmt.Println("\nstatedrift watch: stopped.")
			return
		case t := <-ticker.C:
			// Determine which sections are due on this tick.
			due := make(map[string]bool, len(allWatchSections))
			for _, sec := range allWatchSections {
				if !t.Before(schedules[sec].nextDue) {
					due[sec] = true
				}
			}

			// Load the most recent snapshot from the store — used both as the
			// carry-forward base for CollectPartial and as the "previous" for
			// the diff. One s.List() call serves both purposes.
			prevHash := s.ReadHead()
			entries, listErr := s.List()

			var snap *collector.Snapshot
			var err error
			if listErr == nil && len(entries) > 0 {
				prevSnap := entries[len(entries)-1].Snapshot
				snap, err = collector.CollectPartial(prevSnap, due, prevHash, cfg)
			} else {
				// No previous snapshot yet: full collect.
				snap, err = collector.Collect(prevHash, cfg)
			}

			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s] snap error: %v\n", tf.RFC3339(t), err)
				continue
			}

			// Advance schedules for sections that fired this tick.
			for _, sec := range allWatchSections {
				if due[sec] {
					schedules[sec].nextDue = t.Add(schedules[sec].interval)
				}
			}

			hash, err := s.Save(snap)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s] ERROR: could not save snapshot to %s: %v — no diff computed\n",
					tf.RFC3339(t), s.BasePath, err)
				continue
			}

			// Enforce retention policy after every save so the store does not
			// grow unboundedly.
			if cfg.RetentionDays > 0 {
				if gc, err := s.GC(cfg.RetentionDays); err != nil {
					fmt.Fprintf(os.Stderr, "[%s] gc warning: %v\n", tf.RFC3339(t), err)
				} else if gc.Removed > 0 {
					fmt.Printf("[%s] gc: removed %d snapshot(s) older than %d days\n",
						tf.RFC3339(t), gc.Removed, cfg.RetentionDays)
				}
			}

			// Diff against the snapshot that was most recent before this save.
			if listErr != nil || len(entries) < 1 {
				fmt.Printf("[%s] snap %s — no previous snapshot to diff\n", tf.RFC3339(t), hash[:12])
				continue
			}

			prev := entries[len(entries)-1].Snapshot
			result := diff.Compare(prev, snap)

			if result.Material == 0 && (materialOnly || result.Counters == 0) {
				fmt.Printf("[%s] snap %s — no changes\n", tf.RFC3339(t), hash[:12])
				continue
			}

			fmt.Printf("[%s] snap %s — %d material, %d counters\n",
				tf.RFC3339(t), hash[:12], result.Material, result.Counters)

			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				_ = enc.Encode(result)
			} else {
				fmt.Print(diff.Format(result, materialOnly, useColor))
			}

			if webhookURL != "" && result.Material > 0 {
				postWebhook(webhookURL, snap, result)
			}
		}
	}
}

// postWebhook POSTs a JSON diff payload to the webhook URL.
func postWebhook(url string, snap *collector.Snapshot, result *diff.Result) {
	// Webhook payload stays UTC regardless of display_tz: receivers expect
	// a stable wire format independent of the agent's display config.
	payload := map[string]interface{}{
		"host":      snap.Host.Hostname,
		"timestamp": snap.Timestamp.UTC().Format(time.RFC3339),
		"material":  result.Material,
		"counters":  result.Counters,
		"changes":   result.Changes,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "webhook: marshal error: %v\n", err)
		return
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(data)) //nolint:noctx
	if err != nil {
		fmt.Fprintf(os.Stderr, "webhook: POST error: %v\n", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "webhook: HTTP %d\n", resp.StatusCode)
	}
}

func cmdAnalyze(s *store.Store, cfg *config.Config) {
	requireInit(s)

	var ref string
	var rulesPath string
	jsonOut := false

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--rules":
			if i+1 < len(os.Args) {
				rulesPath = os.Args[i+1]
				i++
			}
		case "--json":
			jsonOut = true
		default:
			if !strings.HasPrefix(os.Args[i], "--") {
				ref = os.Args[i]
			}
		}
	}

	if ref == "" {
		ref = "HEAD"
	}

	// Resolve the two snapshots to compare
	entries, err := s.List()
	if err != nil {
		fatal("listing snapshots: %v", err)
	}
	if len(entries) < 2 {
		if len(entries) == 0 {
			fatal("no snapshots found; run 'statedrift init' then 'statedrift snap'")
		}
		fatal("need at least 2 snapshots to diff; run 'statedrift snap' to record another")
	}

	newSnap, err := resolveRef(s, ref)
	if err != nil {
		fatal("resolving %q: %v", ref, err)
	}
	oldSnap, err := resolveRef(s, ref+"~1")
	if err != nil {
		// Fallback: if ref is already HEAD, use the second-to-last entry
		if len(entries) >= 2 {
			oldSnap = entries[len(entries)-2].Snapshot
		} else {
			fatal("resolving predecessor of %q: %v", ref, err)
		}
	}

	result := diff.Compare(oldSnap, newSnap)

	// Check license for Pro rules
	lic, licErr := license.Check(cfg.LicensePath)
	if licErr != nil {
		fmt.Fprintf(os.Stderr, "statedrift: license warning: %v\n", licErr)
	}
	hasPro := license.HasFeature(lic, license.FeatureAnalyze)

	// Load rules (file override + defaults)
	ruleSet, err := rules.Load(rulesPath)
	if err != nil {
		fatal("loading rules: %v", err)
	}

	// Convert diff.Changes to rules.Changes
	var ruleChanges []rules.Change
	for _, c := range result.Changes {
		ruleChanges = append(ruleChanges, rules.Change{
			Section:  c.Section,
			Type:     c.Type,
			Key:      c.Key,
			OldValue: c.OldValue,
			NewValue: c.NewValue,
			Counter:  c.Counter,
		})
	}

	findings := rules.Evaluate(ruleSet, ruleChanges, hasPro)

	if jsonOut {
		type jsonFinding struct {
			RuleID   string `json:"rule_id"`
			Name     string `json:"name"`
			Severity string `json:"severity"`
			Matches  int    `json:"matches"`
			Pro      bool   `json:"pro"`
		}
		out := make([]jsonFinding, 0, len(findings))
		for _, f := range findings {
			out = append(out, jsonFinding{
				RuleID:   f.Rule.ID,
				Name:     f.Rule.Name,
				Severity: f.Rule.Severity,
				Matches:  f.Matches,
				Pro:      f.Rule.Pro,
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}

	fmt.Printf("statedrift analyze — %s → %s\n",
		tf.RFC3339(oldSnap.Timestamp), tf.RFC3339(newSnap.Timestamp))
	fmt.Printf("  %d material changes, %d rules evaluated\n\n", result.Material, len(ruleSet))

	if len(findings) == 0 {
		fmt.Println("  No rule matches. Infrastructure looks clean.")
		return
	}

	useColor := isTerminal() && os.Getenv("NO_COLOR") == ""

	severityColor := map[string]string{
		"critical": "\033[31;1m", // bold red
		"high":     "\033[31m",   // red
		"medium":   "\033[33m",   // yellow
		"low":      "\033[0m",    // no color
	}

	for _, f := range findings {
		proTag := ""
		if f.Rule.Pro {
			proTag = " [PRO]"
		}
		label := fmt.Sprintf("  [%s]%s %s (%d match", strings.ToUpper(f.Rule.Severity), proTag, f.Rule.Name, f.Matches)
		if f.Matches != 1 {
			label += "es"
		}
		label += ")"
		if useColor {
			color := severityColor[f.Rule.Severity]
			fmt.Printf("%s%s\033[0m\n", color, label)
		} else {
			fmt.Println(label)
		}
		fmt.Printf("    %s\n", f.Rule.Description)
	}

	fmt.Printf("\n%d finding(s). Run 'statedrift diff HEAD~1 HEAD' for full details.\n", len(findings))
	if !hasPro {
		fmt.Println("  Pro rules skipped (no license). See 'statedrift help analyze'.")
	}
}

// resolveRef resolves a snapshot reference (HEAD, HEAD~N, hash prefix) to a Snapshot.
// This duplicates the resolution logic from cmdShow/cmdDiff; a future refactor can unify them.
func resolveRef(s *store.Store, ref string) (*collector.Snapshot, error) {
	entries, err := s.List()
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no snapshots in store")
	}

	if ref == "HEAD" {
		return entries[len(entries)-1].Snapshot, nil
	}

	if strings.HasPrefix(ref, "HEAD~") {
		nStr := strings.TrimPrefix(ref, "HEAD~")
		n := 0
		for _, ch := range nStr {
			if ch < '0' || ch > '9' {
				return nil, fmt.Errorf("invalid HEAD~N: %q", ref)
			}
			n = n*10 + int(ch-'0')
		}
		idx := len(entries) - 1 - n
		if idx < 0 {
			return nil, fmt.Errorf("HEAD~%d: only %d snapshots available", n, len(entries))
		}
		return entries[idx].Snapshot, nil
	}

	// Hash prefix
	for _, e := range entries {
		if strings.HasPrefix(e.Hash, ref) {
			return e.Snapshot, nil
		}
	}
	return nil, fmt.Errorf("no snapshot matching %q", ref)
}

// --- Helpers ---

func requireInit(s *store.Store) {
	_, err := os.Stat(s.ChainDir())
	if err == nil {
		return
	}
	if errors.Is(err, fs.ErrPermission) {
		fatal("permission denied accessing store at %s.\n"+
			"  Run with sudo, or initialize a non-root store:\n"+
			"    STATEDRIFT_STORE=$HOME/.statedrift statedrift init",
			s.BasePath)
	}
	if s.BasePath == defaultStorePath {
		fatal("store not initialized at %s.\n"+
			"  To use the default path:  sudo statedrift init\n"+
			"  To use a non-root path:   STATEDRIFT_STORE=$HOME/.statedrift statedrift init",
			s.BasePath)
	}
	fatal("store not initialized at %s.\n"+
		"  Run 'statedrift init', or check that STATEDRIFT_STORE matches the path used at init time.",
		s.BasePath)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "statedrift: "+format+"\n", args...)
	os.Exit(1)
}

func envOr(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
