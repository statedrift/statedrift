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
	"regexp"
	"strconv"
	"strings"
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

	// Match is an optional list of value conditions, all of which must hold
	// for the rule to fire (logical AND). It runs after the Section /
	// ChangeType / KeyPattern gates and can only narrow a match, never broaden
	// it. Empty (the default) imposes no value constraint, so rules authored
	// before this field — and every built-in rule — behave unchanged.
	Match []Condition `json:"match,omitempty"`
}

// Condition is a single value test applied to a change. It lets a user-authored
// policy rule inspect the change's value (not just its section/key), e.g. "fire
// only when net.ipv4.ip_forward becomes 1".
type Condition struct {
	// Field selects the string under test: "new" (default/empty) → NewValue,
	// "old" → OldValue, "key" → Key.
	Field string `json:"field"`
	// Op is the comparison operator. Supported: eq, ne, contains, prefix,
	// suffix, regex, gt, lt, gte, lte, changed. An unknown operator never
	// matches (fail-closed, so a typo cannot silently fire a rule).
	Op string `json:"op"`
	// Value is the comparand. Ignored by "changed".
	Value string `json:"value"`
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

	// Value conditions (all must hold). Narrows the match only.
	for _, cond := range rule.Match {
		if !matchCondition(cond, c) {
			return false
		}
	}

	return true
}

// matchCondition evaluates a single value condition against a change. An
// unknown operator, an invalid regex, or a non-numeric operand on a numeric
// operator all return false (fail-closed).
func matchCondition(cond Condition, c Change) bool {
	field := fieldValue(cond.Field, c)

	switch cond.Op {
	case "eq":
		return field == cond.Value
	case "ne":
		return field != cond.Value
	case "contains":
		return strings.Contains(field, cond.Value)
	case "prefix":
		return strings.HasPrefix(field, cond.Value)
	case "suffix":
		return strings.HasSuffix(field, cond.Value)
	case "regex":
		matched, err := regexp.MatchString(cond.Value, field)
		return err == nil && matched
	case "gt", "lt", "gte", "lte":
		return matchNumeric(cond.Op, field, cond.Value)
	case "changed":
		return c.OldValue != c.NewValue
	}
	return false // unknown operator
}

// fieldValue returns the change string selected by a condition's Field.
func fieldValue(field string, c Change) string {
	switch field {
	case "old":
		return c.OldValue
	case "key":
		return c.Key
	default: // "new" or empty
		return c.NewValue
	}
}

// matchNumeric parses both operands as floats and compares them. A non-numeric
// operand returns false.
func matchNumeric(op, field, value string) bool {
	a, err1 := strconv.ParseFloat(field, 64)
	b, err2 := strconv.ParseFloat(value, 64)
	if err1 != nil || err2 != nil {
		return false
	}
	switch op {
	case "gt":
		return a > b
	case "lt":
		return a < b
	case "gte":
		return a >= b
	case "lte":
		return a <= b
	}
	return false
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
		// v0.3 Phase C — SSH authorized_keys (free tier)
		{
			ID:          "R19_SSH_KEY_ADDED",
			Name:        "New SSH authorized key",
			Description: "A new entry appeared in some user's ~/.ssh/authorized_keys. SSH keys grant remote login as that user — a new key out of a change window may indicate post-exploitation persistence.",
			Severity:    SeverityCritical,
			Section:     "ssh_keys",
			ChangeType:  "added",
		},
		{
			ID:          "R20_SSH_KEY_REMOVED",
			Name:        "SSH authorized key removed",
			Description: "An entry was removed from a user's ~/.ssh/authorized_keys. Benign during offboarding or key rotation; suspicious if unexplained (could be an attacker covering tracks).",
			Severity:    SeverityMedium,
			Section:     "ssh_keys",
			ChangeType:  "removed",
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
		// v0.4 Phase F — process forensics
		{
			ID:          "R26_PROCESS_REPARENTED",
			Name:        "Process reparented",
			Description: "A long-running process changed parents between snapshots. Reparenting to PID 1 is normal after the original parent exits, but unexpected reparenting on a service process can indicate a parent crash, daemon restart, or PR_SET_CHILD_SUBREAPER manipulation.",
			Severity:    SeverityMedium,
			Section:     "processes",
			ChangeType:  "modified",
			KeyPattern:  "*.ppid",
		},
		{
			ID:          "R27_PROCESS_ZOMBIE",
			Name:        "Process became zombie",
			Description: "A process transitioned into the zombie (Z) state — it exited but its parent has not reaped it. Persistent zombies indicate a parent process that is buggy or hung.",
			Severity:    SeverityLow,
			Section:     "processes",
			ChangeType:  "modified",
			KeyPattern:  "*.zombie",
		},
		{
			ID:          "R28_PROCESS_THREAD_EXPLOSION",
			Name:        "Process thread explosion",
			Description: "A process spawned a large number of threads in one collection interval (delta ≥ 100 and new ≥ 2× old). Tuned to catch sudden growth (e.g. fork bombs, thread leaks), not normal high-thread workloads like JVMs.",
			Severity:    SeverityMedium,
			Section:     "processes",
			ChangeType:  "modified",
			KeyPattern:  "*.thread_explosion",
		},
		// v0.4 Phase M — MAC enforcement (SELinux/AppArmor)
		{
			ID:          "R29_MAC_ENFORCEMENT_DISABLED",
			Name:        "MAC enforcement disabled",
			Description: "The host's Mandatory Access Control system (SELinux or AppArmor) went from actively enforcing/permissive to disabled or absent. Disabling MAC removes a major exploit-containment layer and is a common post-compromise hardening rollback (e.g. `setenforce 0`, `SELINUX=disabled`, or unloading AppArmor).",
			Severity:    SeverityHigh,
			Section:     "mac",
			ChangeType:  "modified",
			KeyPattern:  "enforcement_disabled",
		},
		{
			ID:          "R30_MAC_MODE_DEGRADED",
			Name:        "MAC enforcement degraded",
			Description: "MAC enforcement weakened without being fully disabled: SELinux dropped from enforcing to permissive (denials logged but not blocked), or the count of AppArmor profiles in enforce mode decreased. Both leave the system observably less constrained.",
			Severity:    SeverityHigh,
			Section:     "mac",
			ChangeType:  "modified",
			KeyPattern:  "mode_degraded",
		},
		{
			ID:          "R31_MAC_CONFIG_DRIFT",
			Name:        "SELinux runtime/config mismatch",
			Description: "The SELinux runtime mode no longer matches the persisted /etc/selinux/config value — typically a live `setenforce` that was not written to config (will revert on reboot) or a config edit not yet applied. Either way the running state and the documented intent disagree.",
			Severity:    SeverityMedium,
			Section:     "mac",
			ChangeType:  "modified",
			KeyPattern:  "config_drift",
		},
		// v0.4 Phase N — firewall ruleset identity (iptables/nftables)
		{
			ID:          "R32_FIREWALL_RULESET_CHANGED",
			Name:        "Firewall ruleset changed",
			Description: "The SHA-256 of the canonicalized firewall ruleset changed between snapshots (volatile packet/byte counters are excluded, so this is a real rule change, not traffic). Could be a legitimate deployment or an attacker opening a port or weakening a policy — worth a look either way.",
			Severity:    SeverityMedium,
			Section:     "firewall",
			ChangeType:  "modified",
			KeyPattern:  "ruleset_changed",
		},
		{
			ID:          "R33_FIREWALL_FLUSHED",
			Name:        "Firewall flushed",
			Description: "The firewall ruleset went from populated to empty while the packet-filter engine is still present — the signature of `iptables -F` / `nft flush ruleset`. Flushing the firewall removes all filtering in one step and is a common early move in a host compromise.",
			Severity:    SeverityHigh,
			Section:     "firewall",
			ChangeType:  "modified",
			KeyPattern:  "flushed",
		},
		// v0.5 Phase Q — anomaly rules over the filesystem tree (Phase P) and
		// firewall rules (Phase O). All free.
		{
			ID:          "R34_FS_SETUID_ADDED",
			Name:        "Setuid/setgid file appeared",
			Description: "A watched file gained the setuid or setgid bit, or a new setuid/setgid file appeared under a watched root. Setuid binaries run with the file owner's privileges (often root) regardless of who executes them — a classic privilege-escalation foothold, so an unexpected one is worth immediate review.",
			Severity:    SeverityHigh,
			Section:     "filesystem",
			ChangeType:  "modified",
			KeyPattern:  "setuid_added",
		},
		{
			ID:          "R35_FS_WORLD_WRITABLE",
			Name:        "World-writable file appeared",
			Description: "A watched file or directory became writable by any user (others-write) without the sticky bit, or a new world-writable path appeared under a watched root. Anyone on the host can now overwrite it — a tampering and persistence vector, especially for config files and binaries.",
			Severity:    SeverityHigh,
			Section:     "filesystem",
			ChangeType:  "modified",
			KeyPattern:  "world_writable",
		},
		{
			ID:          "R36_FW_WORLD_OPEN_SENSITIVE",
			Name:        "Sensitive port opened to the world",
			Description: "A new firewall INPUT rule accepts a sensitive service port (SSH, RDP, database, container API, …) from any source address. Exposing these to 0.0.0.0/0 is a common misconfiguration and a frequent breach entry point — worth confirming it was intentional and scoped.",
			Severity:    SeverityHigh,
			Section:     "firewall",
			ChangeType:  "modified",
			KeyPattern:  "world_open",
		},
		// v0.6 — container runtime inventory (free).
		{
			ID:          "R37_CONTAINER_STARTED",
			Name:        "Container started",
			Description: "A new container appeared in the running inventory (detected from /proc cgroup membership). Containers launched outside a change window are a common foothold for cryptominers, reverse shells, and lateral movement — worth confirming the image and who started it.",
			Severity:    SeverityMedium,
			Section:     "containers",
			ChangeType:  "added",
		},
		{
			ID:          "R38_CONTAINER_STOPPED",
			Name:        "Container stopped",
			Description: "A container disappeared from the running inventory. Benign on a normal deploy or scale-down; suspicious if unexplained — an attacker may be tearing down a short-lived payload to cover tracks.",
			Severity:    SeverityLow,
			Section:     "containers",
			ChangeType:  "removed",
		},
		{
			ID:          "R39_PRIVILEGED_CONTAINER",
			Name:        "Privileged container appeared",
			Description: "A container whose init process holds CAP_SYS_ADMIN appeared, or an existing container gained it. CAP_SYS_ADMIN is dropped by the default container capability set and grants mount, namespace, and BPF operations — the classic container-escape primitive. It is set by `--privileged` or `--cap-add=SYS_ADMIN`, so an unexpected one is high-signal.",
			Severity:    SeverityHigh,
			Section:     "containers",
			ChangeType:  "modified",
			KeyPattern:  "privileged_container",
		},
		// v0.6 — GPU / accelerator inventory (free).
		{
			ID:          "R40_GPU_ADDED",
			Name:        "GPU appeared",
			Description: "A GPU/accelerator appeared in the inventory (read from the NVIDIA driver's /proc interface). GPUs do not hot-add on a stable host, so one appearing means a hardware change or a VM passthrough reconfiguration — worth confirming it was intentional.",
			Severity:    SeverityLow,
			Section:     "gpu",
			ChangeType:  "added",
		},
		{
			ID:          "R41_GPU_REMOVED",
			Name:        "GPU disappeared",
			Description: "A GPU/accelerator disappeared from the inventory. On AI/ML hosts this is high-signal: the card may have fallen off the PCI bus (Xid/hardware fault), been physically removed, or dropped from a VM's passthrough set — all of which silently degrade or halt workloads.",
			Severity:    SeverityMedium,
			Section:     "gpu",
			ChangeType:  "removed",
		},
		{
			ID:          "R42_GPU_DRIVER_CHANGED",
			Name:        "GPU driver version changed",
			Description: "The NVIDIA kernel driver version changed. Benign on a planned upgrade, but a downgrade can reintroduce known-vulnerable driver code and any unscheduled change is worth confirming against the change record.",
			Severity:    SeverityMedium,
			Section:     "gpu",
			ChangeType:  "modified",
			KeyPattern:  "driver_version",
		},
		{
			ID:          "R43_GPU_VBIOS_CHANGED",
			Name:        "GPU VBIOS version changed",
			Description: "A GPU's video BIOS (firmware) version changed. A VBIOS reflash is firmware-level modification — legitimate for an approved vendor update, but also a stealthy persistence vector that survives OS reinstalls. Confirm it matches a sanctioned firmware rollout.",
			Severity:    SeverityHigh,
			Section:     "gpu",
			ChangeType:  "modified",
			KeyPattern:  "*.vbios_version",
		},
		// v0.7 — network dataplane (SR-IOV / DPDK) (free).
		{
			ID:          "R44_SRIOV_PF_ADDED",
			Name:        "SR-IOV physical function appeared",
			Description: "A new SR-IOV physical function appeared in the dataplane inventory. PFs do not hot-add on a stable host, so one appearing means a NIC came online or a VM passthrough reconfiguration — worth confirming it was intentional.",
			Severity:    SeverityLow,
			Section:     "dataplane.pf",
			ChangeType:  "added",
		},
		{
			ID:          "R45_SRIOV_PF_REMOVED",
			Name:        "SR-IOV physical function disappeared",
			Description: "An SR-IOV physical function disappeared from the dataplane inventory. The NIC may have fallen off the PCI bus (hardware fault), been physically removed, or dropped from a VM's passthrough set — all of which silently degrade or halt fast-path networking.",
			Severity:    SeverityMedium,
			Section:     "dataplane.pf",
			ChangeType:  "removed",
		},
		{
			ID:          "R46_SRIOV_VF_COUNT_CHANGED",
			Name:        "SR-IOV VF count changed",
			Description: "The number of enabled SR-IOV Virtual Functions on a physical function changed. Enabling VFs carves a NIC into slices that can be handed directly to VMs or containers, bypassing the host networking stack — a reconfiguration worth confirming against the change record.",
			Severity:    SeverityMedium,
			Section:     "dataplane.pf",
			ChangeType:  "modified",
			KeyPattern:  "*.num_vfs",
		},
		{
			ID:          "R47_DPDK_DEVICE_BOUND",
			Name:        "NIC bound to userspace DPDK driver",
			Description: "A network device was bound to a userspace poll-mode driver (vfio-pci, uio_pci_generic, or igb_uio). The kernel networking stack — and its firewall — no longer sees that NIC, so traffic on it is invisible to host-level controls. Legitimate on a DPDK appliance, high-signal if unplanned.",
			Severity:    SeverityMedium,
			Section:     "dataplane.dpdk",
			ChangeType:  "added",
		},
		// v0.7 — kernel-module integrity (free). Complements R17/R18, which only
		// fire on a module appearing or disappearing. R48 catches the in-place
		// swap: a module whose name stays loaded but whose backing .ko changed
		// size — the classic way a rootkit replaces a legitimate module without
		// tripping a load/unload signal. The diff already emits <module>.size as
		// a "modified" change; this rule gives it a severity.
		{
			ID:          "R48_MODULE_REPLACED",
			Name:        "Kernel module replaced in place",
			Description: "A loaded kernel module kept its name but its size changed, meaning the underlying .ko was swapped without an unload/reload. Module code does not change under a stable kernel, so an in-place size change points to a tampered or recompiled module — a rootkit-replacement signal that R17/R18 (load/unload) cannot see.",
			Severity:    SeverityHigh,
			Section:     "modules",
			ChangeType:  "modified",
			KeyPattern:  "*.size",
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
