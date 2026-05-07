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
