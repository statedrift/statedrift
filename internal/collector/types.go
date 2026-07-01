// Package collector reads host operational state and produces snapshots.
package collector

import "time"

// Snapshot is a point-in-time record of host operational state.
// Every field is deterministic and read-only — we observe, never modify.
//
// Optional collectors (CPU, KernelCounters, Processes, Sockets, NICDrivers) are nil
// when not enabled in config. Old snapshots without these fields deserialize cleanly.
type Snapshot struct {
	// SchemaVersion is set on snapshots produced by v0.3+ binaries.
	// Defensive metadata so future schema changes can be detected without
	// guessing from the presence of fields.
	SchemaVersion string `json:"schema_version,omitempty"`

	Version    string    `json:"version"`
	SnapshotID string    `json:"snapshot_id"`
	Timestamp  time.Time `json:"timestamp"`
	PrevHash   string    `json:"prev_hash"`

	Host           Host              `json:"host"`
	Network        Network           `json:"network"`
	KernelParams   map[string]string `json:"kernel_params"`
	Packages       map[string]string `json:"packages"`
	Services       map[string]string `json:"services"`
	ListeningPorts []ListeningPort   `json:"listening_ports"`

	MulticastGroups []MulticastGroup `json:"multicast_groups,omitempty"`
	Connections     []Connection     `json:"connections,omitempty"`

	// v0.3 security signals (Phases A, B, C, D, E). Always-on when capture allowlist permits.
	// omitempty for backward compatibility with v0.1/v0.2 snapshots that lack these fields.
	Users    []User         `json:"users,omitempty"`
	Groups   []Group        `json:"groups,omitempty"`
	Sudoers  []SudoEntry    `json:"sudoers,omitempty"`
	Mounts   []Mount        `json:"mounts,omitempty"`
	Modules  []Module       `json:"modules,omitempty"`
	CronJobs []CronJob      `json:"cron_jobs,omitempty"`
	Timers   []SystemdTimer `json:"systemd_timers,omitempty"`
	SSHKeys  []SSHKey       `json:"ssh_keys,omitempty"`

	// v0.4 Phase M — Mandatory Access Control enforcement state (SELinux/AppArmor).
	// nil on pre-0.4 snapshots and when the "mac" capture section is disabled.
	MAC *MAC `json:"mac,omitempty"`

	// v0.4 Phase N — firewall ruleset identity (iptables/nftables hash).
	// nil on pre-0.4 snapshots and when the "firewall" capture section is disabled.
	Firewall *Firewall `json:"firewall,omitempty"`

	// v0.5 Phase P — recursive filesystem hash tree over configured roots.
	// nil on pre-Phase-P snapshots and when the "filesystem" collector is
	// disabled.
	Filesystem *FilesystemTree `json:"filesystem,omitempty"`

	// v0.6 — running container inventory derived from /proc cgroup membership.
	// nil on pre-v0.6 snapshots and when the "containers" collector is disabled.
	Containers *ContainerInventory `json:"containers,omitempty"`

	// v0.6 — GPU / accelerator inventory from the NVIDIA driver procfs tree.
	// nil on pre-v0.6 snapshots, when the "gpu" collector is disabled, or when
	// no NVIDIA driver is loaded.
	GPU *GPUInventory `json:"gpu,omitempty"`

	// v0.7 — network dataplane wiring (SR-IOV PFs + DPDK-bound NICs) from /sys.
	// nil on pre-v0.7 snapshots, when the "dataplane" collector is disabled, or
	// when the host has neither SR-IOV physical functions nor DPDK-bound NICs.
	Dataplane *NetDataplane `json:"dataplane,omitempty"`

	// v0.8 — AI-agent-harness configuration inventory (permissions, MCP servers,
	// hooks, model) parsed from harness JSON config files. nil on pre-v0.8
	// snapshots, when the "harness" collector is disabled, or when no harness
	// config is discovered.
	Harness *HarnessInventory `json:"harness,omitempty"`

	// Optional collectors — nil when not enabled in config.
	CPU            *CPUStats            `json:"cpu,omitempty"`
	KernelCounters *KernelCounters      `json:"kernel_counters,omitempty"`
	Processes      *ProcessInventory    `json:"processes,omitempty"`
	Sockets        *SocketInventory     `json:"sockets,omitempty"`
	NICDrivers     map[string]NICDriver `json:"nic_drivers,omitempty"`

	// CollectorErrors records non-fatal errors encountered during collection.
	// A non-empty list means some data was unavailable but collection continued.
	CollectorErrors []string `json:"collector_errors,omitempty"`
}

// Host identifies the machine.
type Host struct {
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Kernel    string `json:"kernel"`
	Arch      string `json:"arch"`
	BootID    string `json:"boot_id"`
	MachineID string `json:"machine_id"`
}

// Network captures interface and routing state.
type Network struct {
	Interfaces []Interface `json:"interfaces"`
	Routes     []Route     `json:"routes"`
	DNS        DNS         `json:"dns"`
}

// Interface is a single network interface with its addresses and counters.
type Interface struct {
	Name      string         `json:"name"`
	State     string         `json:"state"`
	MTU       int            `json:"mtu"`
	MAC       string         `json:"mac"`
	Addresses []string       `json:"addresses"`
	Stats     InterfaceStats `json:"stats"`
}

// InterfaceStats are packet/byte counters from /sys/class/net/<iface>/statistics/.
type InterfaceStats struct {
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxDropped uint64 `json:"tx_dropped"`
}

// Route is a single routing table entry.
type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Device      string `json:"device"`
	Metric      int    `json:"metric"`
	Protocol    string `json:"protocol"`
}

// DNS captures resolver configuration.
type DNS struct {
	Nameservers   []string `json:"nameservers"`
	SearchDomains []string `json:"search_domains"`
}

// ListeningPort is a socket in LISTEN state.
type ListeningPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Process  string `json:"process"`
}

// CPUStats captures cumulative CPU mode ticks from /proc/stat (first "cpu" line).
// These are counters — diff output marks them accordingly.
type CPUStats struct {
	User      uint64 `json:"user"`
	Nice      uint64 `json:"nice"`
	System    uint64 `json:"system"`
	Idle      uint64 `json:"idle"`
	IOWait    uint64 `json:"iowait"`
	IRQ       uint64 `json:"irq"`
	SoftIRQ   uint64 `json:"softirq"`
	Steal     uint64 `json:"steal"`
	Guest     uint64 `json:"guest"`
	GuestNice uint64 `json:"guest_nice"`
}

// KernelCounters captures protocol-level counters from /proc/net/snmp.
// Keys match the field names in the snmp file (e.g., "InReceives", "OutRequests").
// All values are counters — diff output marks them accordingly.
type KernelCounters struct {
	IP  map[string]uint64 `json:"ip"`
	TCP map[string]uint64 `json:"tcp"`
	UDP map[string]uint64 `json:"udp"`
}

// ProcessInventory captures a summary of running processes from /proc.
type ProcessInventory struct {
	TotalCount int       `json:"total_count"`
	TopByRSS   []Process `json:"top_by_rss"` // sorted descending by RSS
}

// Process is a single process entry from /proc/<pid>/status and /proc/<pid>/stat.
//
// v0.4 adds Threads, UTimeTicks, STimeTicks, StartTicks. Tick fields are
// cumulative since process start (UTime, STime) or since boot (StartTicks),
// expressed in clock ticks (typically 100 Hz on Linux). CPU% is computed at
// diff time from the delta of (UTimeTicks+STimeTicks) divided by wall-clock
// elapsed seconds. StartTicks is used to detect PID reuse across snapshots:
// same PID with different StartTicks means the original process exited and a
// new one took its slot.
type Process struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	Comm       string `json:"comm"`
	State      string `json:"state"`
	RSSKB      uint64 `json:"rss_kb"`
	VMSKB      uint64 `json:"vms_kb"`
	Threads    int    `json:"threads,omitempty"`
	UTimeTicks uint64 `json:"utime_ticks,omitempty"`
	STimeTicks uint64 `json:"stime_ticks,omitempty"`
	StartTicks uint64 `json:"start_ticks,omitempty"`
}

// ContainerInventory is the set of running containers detected from /proc
// cgroup membership (v0.6). Daemon-free and runtime-agnostic.
type ContainerInventory struct {
	TotalCount int         `json:"total_count"`
	Containers []Container `json:"containers"` // sorted by ID for canonical output
}

// Container is one running container, identified by the ID embedded in its
// processes' cgroup paths. Command is the comm of the lowest-PID process in the
// container (a stable representative of what it runs). Processes is the live
// process count — volatile, so the diff treats <id>.processes as a counter.
type Container struct {
	ID      string `json:"id"`                // short (12-char) container id
	Runtime string `json:"runtime"`           // docker|containerd|cri-o|podman|unknown
	Command string `json:"command,omitempty"` // representative process name
	// CapEff is the effective-capability bitmask (hex, as in /proc/[pid]/status)
	// of the container's representative process. Stored as a raw fact; the diff
	// derives the "privileged" security signal from it (mirrors how file modes
	// are stored and setuid is derived at diff time).
	CapEff    string `json:"cap_eff,omitempty"`
	Processes int    `json:"processes"`
}

// GPUInventory is the set of GPUs/accelerators detected from the NVIDIA kernel
// driver's procfs interface (/proc/driver/nvidia) in v0.6. Daemon-free: no
// nvidia-smi, no os/exec, no extra privilege beyond reading /proc. DriverVersion
// is host-global (one loaded driver); the per-GPU detail drives the structural
// diff. nil when the "gpu" collector is disabled or no NVIDIA driver is loaded.
type GPUInventory struct {
	DriverVersion string `json:"driver_version,omitempty"`
	TotalCount    int    `json:"total_count"`
	GPUs          []GPU  `json:"gpus"` // sorted by bus location for canonical output
}

// GPU is one accelerator. BusLocation (PCI address, e.g. "0000:01:00.0") is the
// stable identity key — the diff groups by it. Model is the marketing name;
// VBIOSVersion is the video-BIOS firmware string, so a reflash is firmware-level
// drift. None of these is a Category B identifier (hardware model, PCI address,
// and version strings — like firewall backend or filesystem paths), so the
// section is not subject to export-time redaction. GPU UUID is deliberately not
// collected (it is a stable per-device identifier that would pull in Cat B
// handling; deferred).
type GPU struct {
	BusLocation  string `json:"bus_location"`
	Model        string `json:"model,omitempty"`
	VBIOSVersion string `json:"vbios_version,omitempty"`
}

// NetDataplane is the v0.7 network-dataplane inventory: how the host's NICs are
// wired into the fast path. Two daemon-free facts read from /sys (regular files
// only): SR-IOV physical functions (PFs that expose Virtual Functions) and
// DPDK-bound devices (network PCI devices handed to a userspace poll-mode driver,
// so the kernel netdev — and its firewall — no longer sees them). nil when the
// "dataplane" collector is disabled or the host has neither.
//
// None of the fields (PCI addresses, driver names, kernel netdev names, VF
// counts) is a Category B identifier — same call as the gpu section — so this
// section is not subject to export-time redaction.
type NetDataplane struct {
	PFs         []SRIOVPF    `json:"pfs"`          // SR-IOV physical functions, sorted by pci_address
	DPDKDevices []DPDKDevice `json:"dpdk_devices"` // network PCI devices bound to a userspace driver, sorted by pci_address
}

// SRIOVPF is one SR-IOV physical function. PCIAddress (e.g. "0000:01:00.0") is
// the stable identity key — the diff groups by it. NumVFs is the count of
// Virtual Functions currently enabled (a real reconfiguration when it changes,
// not a counter); TotalVFs is the hardware maximum. Interface is the kernel
// netdev name and Driver its PF kernel driver (e.g. "i40e", "mlx5_core"), both
// read from .../device/uevent. NumaNode is the NUMA node the card is attached to
// (-1 when the host is not NUMA or the attribute is unavailable) — placement
// locality that matters for dataplane performance; a change implies a topology
// move.
type SRIOVPF struct {
	PCIAddress string `json:"pci_address"`
	Interface  string `json:"interface,omitempty"`
	Driver     string `json:"driver,omitempty"`
	NumVFs     int    `json:"num_vfs"`
	TotalVFs   int    `json:"total_vfs"`
	NumaNode   int    `json:"numa_node"`
}

// DPDKDevice is a network-class PCI device bound to a userspace poll-mode driver
// (vfio-pci, uio_pci_generic, or igb_uio) instead of its kernel netdev driver.
// PCIAddress is the identity key. A device appearing here means the kernel
// networking stack no longer handles it — high-signal when unplanned. PhysFn is
// the parent PF's PCI address when this device is an SR-IOV Virtual Function
// (empty for a bare PCI device), so "a slice of PF X went to userspace" is
// visible at a glance. NumaNode is the card's NUMA node (-1 when not NUMA).
type DPDKDevice struct {
	PCIAddress string `json:"pci_address"`
	Driver     string `json:"driver"`
	PhysFn     string `json:"phys_fn,omitempty"`
	NumaNode   int    `json:"numa_node"`
}

// HarnessInventory is the v0.8 AI-agent-harness configuration inventory: the
// security-relevant settings of coding/ops agents installed on the host, parsed
// from their JSON config files (Claude Code's settings.json hierarchy and
// .mcp.json in v1). Daemon-free — regular file reads only, never talking to a
// running agent. nil when the "harness" collector is disabled or no harness
// config is discovered.
//
// The agent's own configuration is host attack surface: which tools it may run
// (permissions), which MCP servers it reaches (egress + new tools), and which
// hooks fire automatically (persistent code execution). This section maps those
// onto the same drift primitives statedrift already watches for sudoers, mounts,
// and cron.
type HarnessInventory struct {
	TotalConfigs int             `json:"total_configs"`
	Configs      []HarnessConfig `json:"configs"` // sorted by Source for canonical output
}

// HarnessConfig is one parsed harness config file, located by Source (its path,
// the provenance key — like SudoEntry.Source). Tool names the harness
// ("claude-code" in v1). Only the security-relevant fields are extracted, never
// the whole document.
type HarnessConfig struct {
	Source      string        `json:"source"`
	Tool        string        `json:"tool"`
	Model       string        `json:"model,omitempty"`
	Permissions HarnessPerms  `json:"permissions"`
	MCPServers  []HarnessMCP  `json:"mcp_servers,omitempty"` // sorted by Name
	Hooks       []HarnessHook `json:"hooks,omitempty"`       // sorted by Event, then Matcher, then Fingerprint
}

// HarnessPerms is the tool-permission boundary: allow/deny patterns (tool globs
// like "Bash(npm run *)") and the default mode. A broadened allow-list or a
// lifted deny is a privilege-escalation signal — the sudoers analogue. Allow and
// Deny are sorted for stable hashing.
type HarnessPerms struct {
	DefaultMode string   `json:"default_mode,omitempty"`
	Allow       []string `json:"allow,omitempty"`
	Deny        []string `json:"deny,omitempty"`
}

// HarnessMCP is one configured MCP (Model Context Protocol) server — an external
// endpoint the agent can call for tools/data, so a new one is new egress plus new
// capability. Name is the identity key within a config. Transport is
// stdio/sse/http. EnvKeys is the sorted list of environment variable *names* the
// server definition sets — values are secrets (API keys) and are NEVER stored.
// Fingerprint is a SHA-256 over the redacted command/args/url/env-key-names, so a
// wiring change (new command, new endpoint, added env key) changes it while the
// secret values themselves never enter the chain in any form.
type HarnessMCP struct {
	Name        string   `json:"name"`
	Transport   string   `json:"transport,omitempty"`
	EnvKeys     []string `json:"env_keys,omitempty"`
	Fingerprint string   `json:"fingerprint"`
}

// HarnessHook is one automatically-fired hook: a command run by the agent on an
// event (PreToolUse/PostToolUse/Stop/…), optionally scoped by Matcher. This is
// persistent code execution — the cron/systemd-timer analogue — so a new or
// changed hook is high-signal. The command can embed credentials, so it is not
// stored: Fingerprint is a SHA-256 over the redacted command.
type HarnessHook struct {
	Event       string `json:"event"`
	Matcher     string `json:"matcher,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

// SocketInventory captures socket counts per process from /proc/net/tcp and /proc/net/udp.
type SocketInventory struct {
	TotalTCP    int             `json:"total_tcp"`
	TotalUDP    int             `json:"total_udp"`
	TotalListen int             `json:"total_listen"`
	TopByCount  []SocketProcess `json:"top_by_count"` // sorted descending by total socket count
}

// SocketProcess is a process with its socket counts.
type SocketProcess struct {
	PID      int    `json:"pid"`
	Comm     string `json:"comm"`
	TCPCount int    `json:"tcp_count"`
	UDPCount int    `json:"udp_count"`
}

// NICDriver captures driver and firmware information for a network interface.
// Collected via ethtool -i <ifname>.
type NICDriver struct {
	Driver          string `json:"driver"`
	Version         string `json:"version"`
	FirmwareVersion string `json:"fw_version"`
}

// MulticastGroup is a single IGMP/MLD group membership on an interface.
type MulticastGroup struct {
	Interface string `json:"interface"`
	Group     string `json:"group"` // human-readable IP address (IPv4 or IPv6)
}

// User is an entry from /etc/passwd. The password hash field (`x` placeholder)
// is intentionally not collected — we never read /etc/shadow.
// GECOS is Category B PII (kept verbatim in the chain, redactable at export
// via planned v0.4 flags).
type User struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	GECOS string `json:"gecos"`
	Home  string `json:"home"`
	Shell string `json:"shell"`
}

// Group is an entry from /etc/group. Members is sorted for stable hashing.
type Group struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members"`
}

// SudoEntry is a single non-comment, non-blank line from a sudoers file with
// provenance. Line is normalized: leading/trailing whitespace trimmed, internal
// runs collapsed to single spaces, and backslash-newline continuations folded.
type SudoEntry struct {
	Source string `json:"source"` // "/etc/sudoers" or "/etc/sudoers.d/<name>"
	Line   string `json:"line"`
}

// MAC captures Mandatory Access Control enforcement state — SELinux or
// AppArmor, whichever the host runs. A host runs at most one, so System is
// the discriminator and only the relevant sub-fields are populated.
//
// SELinux fields (Mode, ConfigMode, PolicyType, PolicyVersion) come from
// /sys/fs/selinux and /etc/selinux/config. AppArmor is enforced per-profile
// with no global mode, so its signal is the enforce/complain profile counts;
// Mode is a roll-up ("enforcing" if any profile is in enforce mode).
//
// No field is a Category B identifier (no IPs, hostnames, user names, or
// paths), so the section is not subject to export-time redaction.
type MAC struct {
	System        string `json:"system"`                   // "selinux" | "apparmor" | "none"
	Mode          string `json:"mode,omitempty"`           // enforcing | permissive | disabled
	ConfigMode    string `json:"config_mode,omitempty"`    // selinux: /etc/selinux/config SELINUX=
	PolicyType    string `json:"policy_type,omitempty"`    // selinux: SELINUXTYPE=
	PolicyVersion string `json:"policy_version,omitempty"` // selinux: /sys/fs/selinux/policyvers
	EnforceCount  int    `json:"enforce_count,omitempty"`  // apparmor: profiles in enforce mode
	ComplainCount int    `json:"complain_count,omitempty"` // apparmor: profiles in complain mode
}

// Firewall captures the *identity* of the host's packet-filter ruleset, not
// its contents. The canonicalized ruleset (volatile packet/byte counters and
// the iptables-save timestamp stripped) is hashed with SHA-256; only that
// hash and a rule count are stored.
//
// The v0.4 hash (RulesetHash) and rule count are retained so R32/R33 keep
// working. v0.5 Phase O adds RuleList — the parsed rules — enabling per-rule
// diff. Firewall rules embed IPs/CIDRs/ports (Category B), so with RuleList
// present the section IS subject to export-time redaction (--redact-network
// hashes each rule whole, sudoers-style), bringing it in line with the
// connections/listening_ports collectors.
type Firewall struct {
	Backend     string `json:"backend"`                // "nftables" | "iptables" | "none"
	RulesetHash string `json:"ruleset_hash,omitempty"` // SHA-256 hex of canonicalized ruleset
	Rules       int    `json:"rules,omitempty"`        // canonical rule-line count (flush signal)

	// RuleList is the parsed, ordered ruleset (v0.5 Phase O). nil on
	// pre-0.5 snapshots and when the backend is "none". Order is the on-host
	// rule order — significant, since firewalls are first-match-wins.
	RuleList []FirewallRule `json:"rule_list,omitempty"`
}

// FirewallRule is one parsed packet-filter rule, located by table and chain.
// Rule is the canonical rule text with volatile counters stripped (matching
// the ruleset hash). Position within Firewall.RuleList is the on-host order.
type FirewallRule struct {
	Table string `json:"table"` // "filter", "inet filter", "ip4 filter", "ip6 nat", ...
	Chain string `json:"chain"` // "INPUT", "input", "FORWARD", custom chains
	Rule  string `json:"rule"`  // canonical rule text, counters stripped
}

// FilesystemTree is the v0.5 Phase P recursive hash tree over a set of
// configured roots. RootHash is a Merkle root over all Entries (in lexical
// walk order), giving a single "did anything change?" signal; Entries carry
// the per-file detail that drives the structural diff. Truncated is set when
// the walk stopped at the configured max_files cap.
//
// Paths, modes, ownership, and content hashes are not Category B identifiers
// (default roots are system config paths; see DESIGN §4.5), so this section is
// not redacted at export.
type FilesystemTree struct {
	Roots     []string    `json:"roots"`               // roots actually scanned
	RootHash  string      `json:"root_hash"`           // SHA-256 Merkle root over Entries
	Files     int         `json:"files"`               // entry count
	Truncated bool        `json:"truncated,omitempty"` // hit max_files
	Entries   []FileEntry `json:"entries,omitempty"`   // lexical order
}

// FileEntry is one path in a FilesystemTree. SHA256 is set only for regular
// files within the size cap; it is empty for directories, symlinks, special
// files, and oversized files. Target is set only for symlinks. Size is 0 for
// non-regular entries (directory size is volatile and carries no signal).
type FileEntry struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"` // os.FileMode string, e.g. "-rw-r--r--", "drwxr-xr-x", "Lrwxrwxrwx"
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
	Target string `json:"target,omitempty"`
}

// Mount is a single entry from /proc/self/mountinfo. Options carry the
// security-relevant flags (rw/ro, nosuid, nodev, noexec). Credential-bearing
// option keys (password, credentials, cred) are stripped at collect time per
// the project redaction policy; remote-mount sources (server:/share) are
// kept verbatim as Category B identifiers (redactable at export in v0.4).
type Mount struct {
	Source       string `json:"source"`        // /dev/sda1, tmpfs, server:/share, etc.
	MountPoint   string `json:"mount_point"`   // /, /home, /mnt/foo
	FSType       string `json:"fs_type"`       // ext4, tmpfs, cifs, overlay
	MountOptions string `json:"mount_options"` // sorted, comma-joined; credentials stripped
	SuperOptions string `json:"super_options"` // sorted, comma-joined; credentials stripped
}

// Module is a single loaded kernel module from /proc/modules.
// We deliberately drop RefCount (varies constantly with kernel activity),
// State (almost always "Live"), and the load address (zeros to non-root
// readers under kASLR). Size is retained because an unchanged Name with
// changed Size indicates the underlying .ko file was replaced — a useful
// rootkit signal. Dependencies is sorted for stable hashing.
//
// Module signatures (modinfo -F signature) are not collected in v0.3:
// always-on snapshotting would spawn one modinfo process per loaded
// module (typically 100+). See docs/V03_PLAN.md "Phase B — known
// limitations" for v0.4 follow-up.
type Module struct {
	Name         string   `json:"name"`
	Size         uint64   `json:"size"`
	Dependencies []string `json:"dependencies"`
}

// CronJob is a single non-comment, non-blank line from a cron tab with
// provenance. Command is run through redactSecrets at collect time, so
// inline credentials (PASSWORD=foo, AKIA tokens, Bearer xxx) never enter
// the snapshot. User is the runtime identity: pulled from the line itself
// for /etc/crontab and /etc/cron.d/* (which carry a user field), and from
// the file basename for /var/spool/cron/<user>.
type CronJob struct {
	Source   string `json:"source"`   // e.g. "/etc/crontab" or "/etc/cron.d/raid-check"
	User     string `json:"user"`     // runtime user ("" for malformed lines)
	Schedule string `json:"schedule"` // "m h dom mon dow" or "@reboot"/"@daily"/etc.
	Command  string `json:"command"`  // redacted
}

// SystemdTimer is the static configuration of a systemd timer unit, parsed
// directly from the unit file (not from `systemctl list-timers`, which
// includes last/next-run timestamps that change every snapshot and would
// dominate the diff). Fields not set in the unit are returned as empty
// strings.
type SystemdTimer struct {
	UnitFile           string `json:"unit_file"`             // e.g. "/etc/systemd/system/foo.timer"
	Description        string `json:"description,omitempty"` // [Unit] Description=
	OnCalendar         string `json:"on_calendar,omitempty"`
	OnBootSec          string `json:"on_boot_sec,omitempty"`
	OnUnitActiveSec    string `json:"on_unit_active_sec,omitempty"`
	OnUnitInactiveSec  string `json:"on_unit_inactive_sec,omitempty"`
	Unit               string `json:"unit,omitempty"` // [Timer] Unit= (target service); empty implies foo.service for foo.timer
	RandomizedDelaySec string `json:"randomized_delay_sec,omitempty"`
}

// SSHKey is a single line from a user's authorized_keys file, captured as
// metadata only. The base64-encoded public-key body is NEVER stored in the
// chain — we record only what's needed to identify the key (fingerprint),
// classify it (type), label it (comment), and assess restrictions
// (options). Per docs/V03_PLAN.md "PII / secrets redaction policy" Cat A:
// key material is dropped at collection time, not at export time.
//
// Fingerprint is the standard SHA256-of-public-key in OpenSSH form
// ("SHA256:" + base64-no-padding), exactly matching `ssh-keygen -lf`.
//
// Options carries the comma-separated forced-command / source-restriction /
// no-pty / etc. prefix. Pass through redactSecrets at collect time so
// inline credentials in `command="bash -c '... TOKEN=xxx ...'"` never enter
// the chain.
//
// Identity for diff purposes is (User, Type, Fingerprint). Re-keying the
// same human user produces a remove + add (a fingerprint change is a
// genuine identity change, which is what an auditor wants to see).
type SSHKey struct {
	User        string `json:"user"`              // login name (from /etc/passwd, or "root")
	Source      string `json:"source"`            // file path (e.g., "/root/.ssh/authorized_keys")
	Type        string `json:"type"`              // "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", etc.
	Fingerprint string `json:"fingerprint"`       // "SHA256:base64nopad"
	Comment     string `json:"comment,omitempty"` // free-form label (often user@host)
	Options     string `json:"options,omitempty"` // comma-joined options prefix; redacted
}

// Connection is an established or outbound-pending TCP connection.
// Keyed by process+remote endpoint in diffs, so ephemeral local port changes
// between snapshots do not generate noise.
type Connection struct {
	Protocol   string `json:"protocol"` // "tcp"
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`   // "established" or "syn_sent"
	Process    string `json:"process"` // empty if unknown or no permission
}
