package collector

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/statedrift/statedrift/internal/config"
)

var Version = "0.2.0"

// BuildDate is injected at build time via ldflags.
var BuildDate = "unknown"

// defaultKernelParams is used when the config does not specify a custom list.
var defaultKernelParams = []string{
	"net.ipv4.ip_forward",
	"net.ipv4.tcp_syncookies",
	"net.core.somaxconn",
	"vm.swappiness",
	"fs.file-max",
	"net.ipv4.conf.all.rp_filter",
	"net.ipv4.conf.default.rp_filter",
	"net.ipv4.icmp_echo_ignore_broadcasts",
	"net.ipv4.tcp_max_syn_backlog",
	"kernel.randomize_va_space",
	// Additional commonly-tuned params
	"net.core.rmem_default",
	"net.core.rmem_max",
	"net.core.wmem_default",
	"net.core.wmem_max",
	"net.ipv4.tcp_fin_timeout",
	"net.ipv4.tcp_keepalive_time",
	"net.ipv4.tcp_tw_reuse",
	"net.ipv6.conf.all.forwarding",
	"kernel.pid_max",
	"kernel.shmmax",
	"kernel.shmall",
}

// Collect gathers a full snapshot of current host state.
// prevHash is the hash of the previous snapshot (or all zeros for genesis).
// cfg controls which sections to collect and what to ignore. Pass nil to use defaults.
func Collect(prevHash string, cfg *config.Config) (*Snapshot, error) {
	if cfg == nil {
		cfg = config.Default()
	}

	now := time.Now().UTC()

	snap := &Snapshot{
		SchemaVersion: SchemaVersionV03,
		Version:       Version,
		SnapshotID:    fmt.Sprintf("snap-%s-%s-%s", now.Format("20060102"), now.Format("150405"), randomHex(3)),
		Timestamp:     now,
		PrevHash:      prevHash,
	}

	var collectorErrors []string

	var err error

	if captures(cfg, "host") {
		snap.Host, err = collectHost()
		if err != nil {
			return nil, fmt.Errorf("collecting host info: %w", err)
		}
	}

	if captures(cfg, "network") {
		snap.Network, err = collectNetwork(cfg.Ignore.Interfaces)
		if err != nil {
			// Non-fatal: network collection may fail in restricted environments
			snap.Network = Network{Interfaces: []Interface{}, Routes: []Route{}, DNS: DNS{}}
			collectorErrors = append(collectorErrors, fmt.Sprintf("network: %v", err))
		}
	}

	if captures(cfg, "kernel_params") {
		kernelParams := cfg.KernelParams
		if len(kernelParams) == 0 {
			kernelParams = defaultKernelParams
		}
		snap.KernelParams, err = collectKernelParams(kernelParams)
		if err != nil {
			snap.KernelParams = map[string]string{}
			collectorErrors = append(collectorErrors, fmt.Sprintf("kernel_params: %v", err))
		}
	}

	if captures(cfg, "packages") {
		snap.Packages, err = collectPackages(cfg.Ignore.Packages)
		if err != nil {
			snap.Packages = map[string]string{}
			collectorErrors = append(collectorErrors, fmt.Sprintf("packages: %v", err))
		}
	}

	if captures(cfg, "services") {
		snap.Services, err = collectServices()
		if err != nil {
			snap.Services = map[string]string{}
			collectorErrors = append(collectorErrors, fmt.Sprintf("services: %v", err))
		}
	}

	// Build inode→process map once; shared by listening_ports and connections collectors.
	var inodes map[uint64]string
	if captures(cfg, "listening_ports") || cfg.Collectors.IsEnabled("connections") {
		inodes = buildInodeProcessMap()
	}

	if captures(cfg, "listening_ports") {
		snap.ListeningPorts, err = collectListeningPorts(inodes)
		if err != nil {
			snap.ListeningPorts = []ListeningPort{}
			collectorErrors = append(collectorErrors, fmt.Sprintf("listening_ports: %v", err))
		}
	}

	if captures(cfg, "multicast") {
		snap.MulticastGroups, err = collectMulticastGroups()
		if err != nil {
			snap.MulticastGroups = []MulticastGroup{}
			collectorErrors = append(collectorErrors, fmt.Sprintf("multicast: %v", err))
		}
	}

	// v0.3 Phase A security signals — always-on when capture allowlist permits.
	if captures(cfg, "users") {
		snap.Users, err = collectUsers()
		if err != nil {
			snap.Users = nil
			collectorErrors = append(collectorErrors, fmt.Sprintf("users: %v", err))
		}
	}

	if captures(cfg, "groups") {
		snap.Groups, err = collectGroups()
		if err != nil {
			snap.Groups = nil
			collectorErrors = append(collectorErrors, fmt.Sprintf("groups: %v", err))
		}
	}

	if captures(cfg, "sudoers") {
		snap.Sudoers, err = collectSudoers()
		if err != nil {
			snap.Sudoers = nil
			collectorErrors = append(collectorErrors, fmt.Sprintf("sudoers: %v", err))
		}
	}

	// Optional collectors — only run when enabled in config.
	if cfg.Collectors.IsEnabled("cpu") {
		snap.CPU, err = collectCPU()
		if err != nil {
			collectorErrors = append(collectorErrors, fmt.Sprintf("cpu: %v", err))
		}
	}

	if cfg.Collectors.IsEnabled("kernel_counters") {
		snap.KernelCounters, err = collectKernelCounters()
		if err != nil {
			collectorErrors = append(collectorErrors, fmt.Sprintf("kernel_counters: %v", err))
		}
	}

	if cfg.Collectors.IsEnabled("processes") {
		snap.Processes, err = collectProcesses(20)
		if err != nil {
			collectorErrors = append(collectorErrors, fmt.Sprintf("processes: %v", err))
		}
	}

	if cfg.Collectors.IsEnabled("sockets") {
		snap.Sockets, err = collectSockets(20)
		if err != nil {
			collectorErrors = append(collectorErrors, fmt.Sprintf("sockets: %v", err))
		}
	}

	if cfg.Collectors.IsEnabled("nic_drivers") {
		snap.NICDrivers, err = collectNICDrivers(cfg.Ignore.Interfaces)
		if err != nil {
			collectorErrors = append(collectorErrors, fmt.Sprintf("nic_drivers: %v", err))
		}
	}

	if cfg.Collectors.IsEnabled("connections") {
		snap.Connections, err = collectConnections(inodes)
		if err != nil {
			collectorErrors = append(collectorErrors, fmt.Sprintf("connections: %v", err))
		}
	}

	if len(collectorErrors) > 0 {
		snap.CollectorErrors = collectorErrors
	}

	return snap, nil
}

// CollectPartial collects only the sections listed in due, carrying forward all
// other fields verbatim from prevSnap. Every returned snapshot is a complete
// document — the store, hash chain, and diff engine see no difference from a
// full Collect() call.
//
// Use this in the watch loop when different sections have different intervals:
// only the due sections are re-read from the host; the rest keep their
// previous values, so expensive collectors (packages, nic_drivers, processes)
// are not invoked on every fast tick.
//
// The inode→process map is built only when listening_ports or connections is
// in due, avoiding the expensive /proc/[pid]/fd walk on non-due ticks.
func CollectPartial(prevSnap *Snapshot, due map[string]bool, prevHash string, cfg *config.Config) (*Snapshot, error) {
	if cfg == nil {
		cfg = config.Default()
	}

	now := time.Now().UTC()

	// Shallow-copy prevSnap so non-due sections carry forward automatically.
	// Fields are only ever reassigned (never mutated in-place), so sharing
	// the underlying backing arrays with prevSnap is safe.
	snap := *prevSnap
	snap.SchemaVersion = SchemaVersionV03
	snap.Version = Version
	snap.SnapshotID = fmt.Sprintf("snap-%s-%s-%s", now.Format("20060102"), now.Format("150405"), randomHex(3))
	snap.Timestamp = now
	snap.PrevHash = prevHash
	snap.CollectorErrors = nil

	var collectorErrors []string
	var err error

	if due["host"] && captures(cfg, "host") {
		snap.Host, err = collectHost()
		if err != nil {
			return nil, fmt.Errorf("collecting host info: %w", err)
		}
	}

	if due["network"] && captures(cfg, "network") {
		snap.Network, err = collectNetwork(cfg.Ignore.Interfaces)
		if err != nil {
			snap.Network = Network{Interfaces: []Interface{}, Routes: []Route{}, DNS: DNS{}}
			collectorErrors = append(collectorErrors, fmt.Sprintf("network: %v", err))
		}
	}

	if due["kernel_params"] && captures(cfg, "kernel_params") {
		kernelParams := cfg.KernelParams
		if len(kernelParams) == 0 {
			kernelParams = defaultKernelParams
		}
		snap.KernelParams, err = collectKernelParams(kernelParams)
		if err != nil {
			snap.KernelParams = map[string]string{}
			collectorErrors = append(collectorErrors, fmt.Sprintf("kernel_params: %v", err))
		}
	}

	if due["packages"] && captures(cfg, "packages") {
		snap.Packages, err = collectPackages(cfg.Ignore.Packages)
		if err != nil {
			snap.Packages = map[string]string{}
			collectorErrors = append(collectorErrors, fmt.Sprintf("packages: %v", err))
		}
	}

	if due["services"] && captures(cfg, "services") {
		snap.Services, err = collectServices()
		if err != nil {
			snap.Services = map[string]string{}
			collectorErrors = append(collectorErrors, fmt.Sprintf("services: %v", err))
		}
	}

	// Build inode→process map only when a section that needs it is due.
	var inodes map[uint64]string
	needInodes := (due["listening_ports"] && captures(cfg, "listening_ports")) ||
		(due["connections"] && cfg.Collectors.IsEnabled("connections"))
	if needInodes {
		inodes = buildInodeProcessMap()
	}

	if due["listening_ports"] && captures(cfg, "listening_ports") {
		snap.ListeningPorts, err = collectListeningPorts(inodes)
		if err != nil {
			snap.ListeningPorts = []ListeningPort{}
			collectorErrors = append(collectorErrors, fmt.Sprintf("listening_ports: %v", err))
		}
	}

	if due["multicast"] && captures(cfg, "multicast") {
		snap.MulticastGroups, err = collectMulticastGroups()
		if err != nil {
			snap.MulticastGroups = []MulticastGroup{}
			collectorErrors = append(collectorErrors, fmt.Sprintf("multicast: %v", err))
		}
	}

	if due["users"] && captures(cfg, "users") {
		snap.Users, err = collectUsers()
		if err != nil {
			snap.Users = nil
			collectorErrors = append(collectorErrors, fmt.Sprintf("users: %v", err))
		}
	}

	if due["groups"] && captures(cfg, "groups") {
		snap.Groups, err = collectGroups()
		if err != nil {
			snap.Groups = nil
			collectorErrors = append(collectorErrors, fmt.Sprintf("groups: %v", err))
		}
	}

	if due["sudoers"] && captures(cfg, "sudoers") {
		snap.Sudoers, err = collectSudoers()
		if err != nil {
			snap.Sudoers = nil
			collectorErrors = append(collectorErrors, fmt.Sprintf("sudoers: %v", err))
		}
	}

	if due["cpu"] && cfg.Collectors.IsEnabled("cpu") {
		snap.CPU, err = collectCPU()
		if err != nil {
			collectorErrors = append(collectorErrors, fmt.Sprintf("cpu: %v", err))
		}
	}

	if due["kernel_counters"] && cfg.Collectors.IsEnabled("kernel_counters") {
		snap.KernelCounters, err = collectKernelCounters()
		if err != nil {
			collectorErrors = append(collectorErrors, fmt.Sprintf("kernel_counters: %v", err))
		}
	}

	if due["processes"] && cfg.Collectors.IsEnabled("processes") {
		snap.Processes, err = collectProcesses(20)
		if err != nil {
			collectorErrors = append(collectorErrors, fmt.Sprintf("processes: %v", err))
		}
	}

	if due["sockets"] && cfg.Collectors.IsEnabled("sockets") {
		snap.Sockets, err = collectSockets(20)
		if err != nil {
			collectorErrors = append(collectorErrors, fmt.Sprintf("sockets: %v", err))
		}
	}

	if due["nic_drivers"] && cfg.Collectors.IsEnabled("nic_drivers") {
		snap.NICDrivers, err = collectNICDrivers(cfg.Ignore.Interfaces)
		if err != nil {
			collectorErrors = append(collectorErrors, fmt.Sprintf("nic_drivers: %v", err))
		}
	}

	if due["connections"] && cfg.Collectors.IsEnabled("connections") {
		snap.Connections, err = collectConnections(inodes)
		if err != nil {
			collectorErrors = append(collectorErrors, fmt.Sprintf("connections: %v", err))
		}
	}

	if len(collectorErrors) > 0 {
		snap.CollectorErrors = collectorErrors
	}

	return &snap, nil
}

// randomHex returns n*2 random hex characters.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use timestamp nanoseconds if rand fails
		return fmt.Sprintf("%06x", time.Now().UnixNano()&0xffffff)
	}
	return hex.EncodeToString(b)
}

// collectHost reads machine identity from /etc and /proc.
func collectHost() (Host, error) {
	h := Host{
		Arch: runtime.GOARCH,
	}

	hostname, err := os.Hostname()
	if err != nil {
		return h, err
	}
	h.Hostname = hostname

	h.OS = readOSRelease()

	if data, err := os.ReadFile("/proc/version"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) >= 3 {
			h.Kernel = parts[2]
		}
	}

	if data, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		h.BootID = strings.TrimSpace(string(data))
	}

	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		h.MachineID = strings.TrimSpace(string(data))
	}

	return h, nil
}

// readOSRelease parses PRETTY_NAME from /etc/os-release.
func readOSRelease() string {
	return readOSReleaseFrom("/etc/os-release")
}

// readOSReleaseFrom parses PRETTY_NAME from the given os-release file path.
func readOSReleaseFrom(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "unknown"
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			val := strings.TrimPrefix(line, "PRETTY_NAME=")
			return strings.Trim(val, "\"")
		}
	}
	return "unknown"
}

// collectNetwork reads interfaces, routes, and DNS config.
// ignorePatterns is a list of glob patterns for interface names to skip.
func collectNetwork(ignorePatterns []string) (Network, error) {
	n := Network{
		Interfaces: []Interface{},
		Routes:     []Route{},
	}

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		// Graceful degradation: /sys/class/net may not exist in some containers
		n.Routes = collectRoutes()
		n.DNS = collectDNS()
		return n, nil
	}

	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue // always skip loopback
		}
		if matchesAny(name, ignorePatterns) {
			continue
		}

		iface := Interface{Name: name}
		base := filepath.Join("/sys/class/net", name)

		if data, err := os.ReadFile(filepath.Join(base, "operstate")); err == nil {
			iface.State = strings.TrimSpace(string(data))
		}

		if data, err := os.ReadFile(filepath.Join(base, "mtu")); err == nil {
			if mtu, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				iface.MTU = mtu
			}
		}

		if data, err := os.ReadFile(filepath.Join(base, "address")); err == nil {
			iface.MAC = strings.TrimSpace(string(data))
		}

		if netIface, err := net.InterfaceByName(name); err == nil {
			if addrs, err := netIface.Addrs(); err == nil {
				for _, addr := range addrs {
					iface.Addresses = append(iface.Addresses, addr.String())
				}
			}
		}

		statsBase := filepath.Join(base, "statistics")
		iface.Stats = InterfaceStats{
			RxBytes:   readUint64(filepath.Join(statsBase, "rx_bytes")),
			TxBytes:   readUint64(filepath.Join(statsBase, "tx_bytes")),
			RxPackets: readUint64(filepath.Join(statsBase, "rx_packets")),
			TxPackets: readUint64(filepath.Join(statsBase, "tx_packets")),
			RxErrors:  readUint64(filepath.Join(statsBase, "rx_errors")),
			TxErrors:  readUint64(filepath.Join(statsBase, "tx_errors")),
			RxDropped: readUint64(filepath.Join(statsBase, "rx_dropped")),
			TxDropped: readUint64(filepath.Join(statsBase, "tx_dropped")),
		}

		n.Interfaces = append(n.Interfaces, iface)
	}

	n.Routes = collectRoutes()
	n.DNS = collectDNS()

	return n, nil
}

// captures reports whether section should be collected according to cfg.Capture.
// An empty or nil Capture list means collect everything (the default).
func captures(cfg *config.Config, section string) bool {
	if len(cfg.Capture) == 0 {
		return true
	}
	for _, s := range cfg.Capture {
		if s == section {
			return true
		}
	}
	return false
}

// matchesAny returns true if name matches any of the glob patterns.
func matchesAny(name string, patterns []string) bool {
	for _, pat := range patterns {
		if matched, _ := filepath.Match(pat, name); matched {
			return true
		}
	}
	return false
}

// collectRoutes parses the routing table.
func collectRoutes() []Route {
	var routes []Route

	out, err := exec.Command("ip", "route", "show").Output()
	if err != nil {
		return routes
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		r := parseRouteLine(line)
		if r != nil {
			routes = append(routes, *r)
		}
	}
	return routes
}

// parseRouteLine parses a single line of `ip route show` output.
// Example: "default via 10.0.1.1 dev eth0 proto dhcp metric 100"
// Example: "10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.15"
func parseRouteLine(line string) *Route {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil
	}

	r := &Route{}

	r.Destination = fields[0]
	if r.Destination == "default" {
		r.Destination = "0.0.0.0/0"
	}

	for i := 1; i < len(fields)-1; i++ {
		switch fields[i] {
		case "via":
			r.Gateway = fields[i+1]
		case "dev":
			r.Device = fields[i+1]
		case "proto":
			r.Protocol = fields[i+1]
		case "metric":
			if m, err := strconv.Atoi(fields[i+1]); err == nil {
				r.Metric = m
			}
		}
	}

	return r
}

// collectDNS reads /etc/resolv.conf.
func collectDNS() DNS {
	dns := DNS{}

	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return dns
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			dns.Nameservers = append(dns.Nameservers, fields[1])
		case "search":
			dns.SearchDomains = append(dns.SearchDomains, fields[1:]...)
		}
	}
	return dns
}

// collectKernelParams reads selected sysctl values from /proc/sys/.
func collectKernelParams(params []string) (map[string]string, error) {
	result := make(map[string]string)

	for _, param := range params {
		// Convert dot notation to path: net.ipv4.ip_forward -> /proc/sys/net/ipv4/ip_forward
		path := "/proc/sys/" + strings.ReplaceAll(param, ".", "/")
		if data, err := os.ReadFile(path); err == nil {
			result[param] = strings.TrimSpace(string(data))
		}
	}

	return result, nil
}

// collectPackages queries the system package manager and filters out any package
// whose name matches a pattern in ignorePatterns (exact name match or glob).
func collectPackages(ignorePatterns []string) (map[string]string, error) {
	packages := make(map[string]string)

	// Try dpkg first (Debian/Ubuntu)
	out, err := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\n").Output()
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			parts := strings.SplitN(scanner.Text(), "\t", 2)
			if len(parts) == 2 && !matchesAny(parts[0], ignorePatterns) {
				packages[parts[0]] = parts[1]
			}
		}
		return packages, nil
	}

	// Try rpm (RHEL/CentOS/Rocky)
	out, err = exec.Command("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n").Output()
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			parts := strings.SplitN(scanner.Text(), "\t", 2)
			if len(parts) == 2 && !matchesAny(parts[0], ignorePatterns) {
				packages[parts[0]] = parts[1]
			}
		}
		return packages, nil
	}

	return packages, fmt.Errorf("no supported package manager found (tried dpkg-query, rpm)")
}

// parseRPMOutput parses rpm -qa --queryformat output into a name→version map.
// Exported for testing.
func parseRPMOutput(output string) map[string]string {
	packages := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "\t", 2)
		if len(parts) == 2 {
			packages[parts[0]] = parts[1]
		}
	}
	return packages
}

// collectServices reads systemd service states.
func collectServices() (map[string]string, error) {
	services := make(map[string]string)

	out, err := exec.Command("systemctl", "list-units", "--type=service",
		"--no-pager", "--no-legend", "--plain").Output()
	if err != nil {
		return services, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 {
			name := fields[0]
			active := fields[2]
			sub := fields[3]
			services[name] = fmt.Sprintf("%s (%s)", active, sub)
		}
	}

	return services, nil
}

// procProto describes a /proc/net file and the attributes needed to parse it.
type procProto struct {
	file        string // filename under /proc/net
	protocol    string // "tcp" or "udp"
	listenState string // hex state value that means "listening/bound"
}

// collectListeningPorts reads TCP LISTEN and bound UDP sockets from /proc/net.
// TCP: state 0A (LISTEN). UDP: state 07 (CLOSE, meaning bound/listening for UDP).
// inodes maps socket inodes to process names; pass nil to skip process association.
func collectListeningPorts(inodes map[uint64]string) ([]ListeningPort, error) {
	var ports []ListeningPort

	protos := []procProto{
		{"tcp", "tcp", "0A"},
		{"tcp6", "tcp", "0A"},
		{"udp", "udp", "07"},
		{"udp6", "udp", "07"},
	}

	for _, ps := range protos {
		f, err := os.Open(filepath.Join("/proc/net", ps.file))
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header line

		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}
			if fields[3] != ps.listenState {
				continue
			}
			addr, port, err := parseHexAddrPort(fields[1])
			if err != nil {
				continue
			}
			lp := ListeningPort{
				Port:     port,
				Protocol: ps.protocol,
				Address:  addr,
			}
			// /proc/net/{tcp,udp} field[9] is the socket inode number.
			if inodes != nil && len(fields) > 9 {
				if inode, err := strconv.ParseUint(fields[9], 10, 64); err == nil {
					lp.Process = inodes[inode]
				}
			}
			ports = append(ports, lp)
		}
		f.Close()
	}

	return ports, nil
}

// buildInodeProcessMap walks /proc/[pid]/fd/ symlinks to build a map from
// socket inode numbers to process comm names. Called at most once per Collect()
// and shared across collectors that need process attribution.
func buildInodeProcessMap() map[uint64]string {
	inodes := make(map[uint64]string)

	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return inodes
	}

	for _, d := range dirs {
		if !d.IsDir() || !isDecimal(d.Name()) {
			continue
		}
		pid := d.Name()

		commData, err := os.ReadFile("/proc/" + pid + "/comm")
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(commData))

		fdDir := "/proc/" + pid + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			// Symlink target is "socket:[inode]" for socket fds.
			if !strings.HasPrefix(link, "socket:[") || link[len(link)-1] != ']' {
				continue
			}
			inodeStr := link[len("socket:[") : len(link)-1]
			inode, err := strconv.ParseUint(inodeStr, 10, 64)
			if err != nil {
				continue
			}
			if _, exists := inodes[inode]; !exists {
				inodes[inode] = comm
			}
		}
	}
	return inodes
}

// collectConnections reads ESTABLISHED and SYN_SENT TCP connections from /proc/net.
// The diff key is protocol/process/remote_addr:remote_port — local (ephemeral) port
// is recorded but not used for keying, to avoid noise from port recycling.
func collectConnections(inodes map[uint64]string) ([]Connection, error) {
	var conns []Connection
	seen := make(map[string]struct{})

	stateNames := map[string]string{
		"01": "established",
		"02": "syn_sent",
	}

	for _, file := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join("/proc/net", file))
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header

		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}
			stateName, ok := stateNames[fields[3]]
			if !ok {
				continue
			}
			localAddr, localPort, err := parseHexAddrPort(fields[1])
			if err != nil {
				continue
			}
			remoteAddr, remotePort, err := parseHexAddrPort(fields[2])
			if err != nil {
				continue
			}

			process := ""
			if inodes != nil {
				if inode, err := strconv.ParseUint(fields[9], 10, 64); err == nil {
					process = inodes[inode]
				}
			}

			// Dedup by remote endpoint + process (not local ephemeral port).
			dedupKey := fmt.Sprintf("%s/%s/%s:%d", stateName, process, remoteAddr, remotePort)
			if _, dup := seen[dedupKey]; dup {
				continue
			}
			seen[dedupKey] = struct{}{}

			conns = append(conns, Connection{
				Protocol:   "tcp",
				LocalAddr:  localAddr,
				LocalPort:  localPort,
				RemoteAddr: remoteAddr,
				RemotePort: remotePort,
				State:      stateName,
				Process:    process,
			})
		}
		f.Close()
	}

	sort.Slice(conns, func(i, j int) bool {
		ki := conns[i].Process + "/" + conns[i].RemoteAddr + ":" + strconv.Itoa(conns[i].RemotePort)
		kj := conns[j].Process + "/" + conns[j].RemoteAddr + ":" + strconv.Itoa(conns[j].RemotePort)
		return ki < kj
	})

	return conns, nil
}

// collectMulticastGroups reads IGMP (IPv4) and MLD (IPv6) group memberships.
func collectMulticastGroups() ([]MulticastGroup, error) {
	var groups []MulticastGroup
	groups = append(groups, collectIGMP()...)
	groups = append(groups, collectIGMP6()...)
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Interface != groups[j].Interface {
			return groups[i].Interface < groups[j].Interface
		}
		return groups[i].Group < groups[j].Group
	})
	return groups, nil
}

// collectIGMP reads IPv4 multicast group memberships from /proc/net/igmp.
func collectIGMP() []MulticastGroup {
	f, err := os.Open("/proc/net/igmp")
	if err != nil {
		return nil
	}
	defer f.Close()

	var groups []MulticastGroup
	var currentIface string

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		// Interface line: first field is a decimal index, second is the name.
		if isDecimal(fields[0]) {
			currentIface = fields[1]
			continue
		}
		// Group line: first field is an 8-char little-endian hex IPv4 address.
		if len(fields[0]) == 8 && currentIface != "" {
			if addr := parseIGMPv4Addr(fields[0]); addr != "" {
				groups = append(groups, MulticastGroup{Interface: currentIface, Group: addr})
			}
		}
	}
	return groups
}

// collectIGMP6 reads IPv6 multicast group memberships from /proc/net/igmp6.
func collectIGMP6() []MulticastGroup {
	f, err := os.Open("/proc/net/igmp6")
	if err != nil {
		return nil
	}
	defer f.Close()

	var groups []MulticastGroup
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Format: idx iface group_hex users flags timer
		if len(fields) < 3 || len(fields[2]) != 32 {
			continue
		}
		if addr := parseIGMPv6Addr(fields[2]); addr != "" {
			groups = append(groups, MulticastGroup{Interface: fields[1], Group: addr})
		}
	}
	return groups
}

// parseIGMPv4Addr converts a little-endian 8-char hex string to a dotted IPv4 address.
// Example: "010000E0" → "224.0.0.1"
func parseIGMPv4Addr(h string) string {
	if len(h) != 8 {
		return ""
	}
	b := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
		if err != nil {
			return ""
		}
		b[3-i] = byte(v) // reverse: little-endian to big-endian
	}
	return b.String()
}

// parseIGMPv6Addr converts a 32-char big-endian hex string to an IPv6 address.
// Example: "ff020000000000000000000000000001" → "ff02::1"
func parseIGMPv6Addr(h string) string {
	if len(h) != 32 {
		return ""
	}
	b := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
		if err != nil {
			return ""
		}
		b[i] = byte(v)
	}
	return b.String()
}

// isDecimal reports whether s contains only ASCII decimal digits.
func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// parseHexAddrPort parses "0100007F:0035" into ("127.0.0.1", 53).
func parseHexAddrPort(s string) (string, int, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid addr:port %q", s)
	}

	port64, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, err
	}

	hexAddr := parts[0]
	var addr string

	switch len(hexAddr) {
	case 8: // IPv4
		b0, _ := strconv.ParseUint(hexAddr[6:8], 16, 8)
		b1, _ := strconv.ParseUint(hexAddr[4:6], 16, 8)
		b2, _ := strconv.ParseUint(hexAddr[2:4], 16, 8)
		b3, _ := strconv.ParseUint(hexAddr[0:2], 16, 8)
		addr = fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3)
	case 32: // IPv6 — simplified: show :: for all zeros
		if hexAddr == "00000000000000000000000000000000" {
			addr = "::"
		} else if hexAddr == "00000000000000000000000001000000" {
			addr = "::1"
		} else {
			addr = hexAddr // fallback: raw hex
		}
	default:
		addr = hexAddr
	}

	return addr, int(port64), nil
}

// readUint64 reads a single uint64 from a file (e.g., /sys/class/net/eth0/statistics/rx_bytes).
func readUint64(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	val, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return val
}
