package collector

// collect_optional.go — optional v0.2 collectors: CPU, KernelCounters, Processes, Sockets, NICDrivers.
// Each collector is gated by cfg.Collectors.IsEnabled("name").
// All reads are from /proc or /sys; no external commands except ethtool for NIC drivers.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// collectCPU reads the first "cpu" line from /proc/stat.
// Returns cumulative ticks in each CPU mode. All values are counters.
func collectCPU() (*CPUStats, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			return parseCPUStat(line)
		}
	}
	return nil, fmt.Errorf("/proc/stat: no cpu line found")
}

// parseCPUStat parses a single "cpu ..." line from /proc/stat.
// Exported for testing.
func parseCPUStat(line string) (*CPUStats, error) {
	fields := strings.Fields(line)
	// fields[0] = "cpu", then user nice system idle iowait irq softirq steal guest guest_nice
	if len(fields) < 5 {
		return nil, fmt.Errorf("/proc/stat cpu line too short: %q", line)
	}
	get := func(i int) uint64 {
		if i >= len(fields) {
			return 0
		}
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		return v
	}
	return &CPUStats{
		User:      get(1),
		Nice:      get(2),
		System:    get(3),
		Idle:      get(4),
		IOWait:    get(5),
		IRQ:       get(6),
		SoftIRQ:   get(7),
		Steal:     get(8),
		Guest:     get(9),
		GuestNice: get(10),
	}, nil
}

// collectKernelCounters parses /proc/net/snmp for IP, TCP, and UDP protocol counters.
func collectKernelCounters() (*KernelCounters, error) {
	f, err := os.Open("/proc/net/snmp")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseKernelCounterLines(f)
}

// parseKernelCounterLines parses the alternating header/values format of /proc/net/snmp.
// Exported for testing.
func parseKernelCounterLines(r io.Reader) (*KernelCounters, error) {
	kc := &KernelCounters{
		IP:  make(map[string]uint64),
		TCP: make(map[string]uint64),
		UDP: make(map[string]uint64),
	}

	scanner := bufio.NewScanner(r)
	var lastHeader []string
	var lastProto string

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		proto := strings.TrimSuffix(fields[0], ":")

		if lastProto == proto && lastHeader != nil {
			// Values line matching the previous header
			var target map[string]uint64
			switch strings.ToUpper(proto) {
			case "IP":
				target = kc.IP
			case "TCP":
				target = kc.TCP
			case "UDP":
				target = kc.UDP
			}
			if target != nil {
				for i, key := range lastHeader {
					valIdx := i + 1 // skip the "Proto:" prefix field
					if valIdx < len(fields) {
						v, _ := strconv.ParseUint(fields[valIdx], 10, 64)
						target[key] = v
					}
				}
			}
			lastHeader = nil
			lastProto = ""
		} else {
			// Header line: "Ip: Forwarding DefaultTTL InReceives ..."
			lastHeader = fields[1:]
			lastProto = proto
		}
	}
	return kc, scanner.Err()
}

// collectProcesses reads /proc/[pid]/status for all running processes
// and returns the top topN by RSS, plus total count.
func collectProcesses(topN int) (*ProcessInventory, error) {
	if topN <= 0 {
		topN = 20
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var procs []Process
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID directory
		}
		p, err := readProcStatus(pid)
		if err != nil {
			continue // process may have exited; skip gracefully
		}
		procs = append(procs, p)
	}

	total := len(procs)

	// Sort descending by RSS
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].RSSKB > procs[j].RSSKB
	})

	if len(procs) > topN {
		procs = procs[:topN]
	}

	return &ProcessInventory{
		TotalCount: total,
		TopByRSS:   procs,
	}, nil
}

// readProcStatus parses /proc/<pid>/status into a Process struct.
func readProcStatus(pid int) (Process, error) {
	path := fmt.Sprintf("/proc/%d/status", pid)
	return readProcStatusFrom(path, pid)
}

// readProcStatusFrom parses a status file at the given path for the given PID.
// Exported for testing.
func readProcStatusFrom(path string, pid int) (Process, error) {
	f, err := os.Open(path)
	if err != nil {
		return Process{}, err
	}
	defer f.Close()

	p := Process{PID: pid}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "Name":
			p.Comm = val
		case "State":
			// "R (running)" — take just the letter
			if len(val) > 0 {
				p.State = string(val[0])
			}
		case "PPid":
			p.PPID, _ = strconv.Atoi(val)
		case "VmRSS":
			// "1234 kB"
			fields := strings.Fields(val)
			if len(fields) >= 1 {
				p.RSSKB, _ = strconv.ParseUint(fields[0], 10, 64)
			}
		case "VmSize":
			fields := strings.Fields(val)
			if len(fields) >= 1 {
				p.VMSKB, _ = strconv.ParseUint(fields[0], 10, 64)
			}
		}
	}
	if p.Comm == "" {
		return p, fmt.Errorf("pid %d: no Name in status", pid)
	}
	return p, nil
}

// collectSockets reads /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6
// to count sockets, then maps inode→pid to attribute sockets to processes.
func collectSockets(topN int) (*SocketInventory, error) {
	if topN <= 0 {
		topN = 20
	}

	type socketEntry struct {
		proto string
		state string // hex state code
		inode uint64
	}

	var sockets []socketEntry

	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		path := filepath.Join("/proc/net", proto)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			// Fields: sl local_addr rem_addr state tx_queue:rx_queue tr:tm-when retransmit uid timeout inode
			if len(fields) < 10 {
				continue
			}
			inode, err := strconv.ParseUint(fields[9], 10, 64)
			if err != nil || inode == 0 {
				continue
			}
			sockets = append(sockets, socketEntry{
				proto: strings.TrimSuffix(proto, "6"), // normalize tcp6→tcp
				state: fields[3],
				inode: inode,
			})
		}
		f.Close()
	}

	// Count totals
	inv := &SocketInventory{}
	for _, s := range sockets {
		switch s.proto {
		case "tcp":
			inv.TotalTCP++
			if s.state == "0A" { // LISTEN
				inv.TotalListen++
			}
		case "udp":
			inv.TotalUDP++
		}
	}

	// Build inode→pid map by scanning /proc/[pid]/fd/
	inodeToPID := buildInodePIDMap()

	// Build inode→comm map (need pid→comm)
	pidToComm := buildPIDCommMap()

	// Count per PID
	type pidCounts struct {
		comm     string
		tcpCount int
		udpCount int
	}
	perPID := make(map[int]*pidCounts)
	for _, s := range sockets {
		pid, ok := inodeToPID[s.inode]
		if !ok {
			continue
		}
		if _, exists := perPID[pid]; !exists {
			perPID[pid] = &pidCounts{comm: pidToComm[pid]}
		}
		switch s.proto {
		case "tcp":
			perPID[pid].tcpCount++
		case "udp":
			perPID[pid].udpCount++
		}
	}

	// Convert to slice and sort by total socket count
	var procs []SocketProcess
	for pid, counts := range perPID {
		procs = append(procs, SocketProcess{
			PID:      pid,
			Comm:     counts.comm,
			TCPCount: counts.tcpCount,
			UDPCount: counts.udpCount,
		})
	}
	sort.Slice(procs, func(i, j int) bool {
		ti := procs[i].TCPCount + procs[i].UDPCount
		tj := procs[j].TCPCount + procs[j].UDPCount
		return ti > tj
	})
	if len(procs) > topN {
		procs = procs[:topN]
	}
	inv.TopByCount = procs

	return inv, nil
}

// buildInodePIDMap scans /proc/[pid]/fd/ symlinks to map socket inodes to PIDs.
// Gracefully skips PIDs that exit or that we lack permission to read.
func buildInodePIDMap() map[uint64]int {
	m := make(map[uint64]int)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return m
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			// Socket symlinks look like "socket:[1234567]"
			if !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inodeStr := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			inode, err := strconv.ParseUint(inodeStr, 10, 64)
			if err != nil {
				continue
			}
			m[inode] = pid
		}
	}
	return m
}

// buildPIDCommMap reads Name from /proc/[pid]/status for all PIDs.
func buildPIDCommMap() map[int]string {
	m := make(map[int]string)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return m
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Name:") {
				m[pid] = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
				break
			}
		}
	}
	return m
}

// collectNICDrivers runs `ethtool -i <ifname>` for each interface and captures
// driver, version, and firmware version. Gracefully skips if ethtool is absent.
func collectNICDrivers(ignorePatterns []string) (map[string]NICDriver, error) {
	result := make(map[string]NICDriver)

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}

	for _, e := range entries {
		name := e.Name()
		if name == "lo" || matchesAny(name, ignorePatterns) {
			continue
		}

		out, err := exec.Command("ethtool", "-i", name).Output()
		if err != nil {
			continue // ethtool missing or interface doesn't support it
		}

		d := NICDriver{}
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			switch key {
			case "driver":
				d.Driver = val
			case "version":
				d.Version = val
			case "firmware-version":
				d.FirmwareVersion = val
			}
		}
		if d.Driver != "" {
			result[name] = d
		}
	}
	return result, nil
}
