// Package collector reads host operational state and produces snapshots.
package collector

import "time"

// Snapshot is a point-in-time record of host operational state.
// Every field is deterministic and read-only — we observe, never modify.
//
// Optional collectors (CPU, KernelCounters, Processes, Sockets, NICDrivers) are nil
// when not enabled in config. Old snapshots without these fields deserialize cleanly.
type Snapshot struct {
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

// Process is a single process entry from /proc/<pid>/status and /proc/<pid>/statm.
type Process struct {
	PID   int    `json:"pid"`
	PPID  int    `json:"ppid"`
	Comm  string `json:"comm"`
	State string `json:"state"`
	RSSKB uint64 `json:"rss_kb"`
	VMSKB uint64 `json:"vms_kb"`
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
