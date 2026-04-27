// Package diff computes human-readable differences between two snapshots.
package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/statedrift/statedrift/internal/collector"
)

// Change represents a single difference between two snapshots.
type Change struct {
	Section  string // e.g., "kernel_params", "packages", "listening_ports"
	Type     string // "added", "removed", "modified"
	Key      string // e.g., "net.core.somaxconn", "nginx", "80/tcp"
	OldValue string // empty for additions
	NewValue string // empty for removals
	Counter  bool   // true if this is a counter increment (stats), not a material change
}

// Result holds the complete diff between two snapshots.
type Result struct {
	Changes  []Change
	Material int // count of non-counter changes
	Counters int // count of counter-only changes
}

// Compare computes the diff between two snapshots.
func Compare(old, new *collector.Snapshot) *Result {
	r := &Result{}

	// Host changes
	diffHost(old.Host, new.Host, r)

	// Kernel params
	diffMap("kernel_params", old.KernelParams, new.KernelParams, r, false)

	// Packages
	diffMap("packages", old.Packages, new.Packages, r, false)

	// Services
	diffMap("services", old.Services, new.Services, r, false)

	// Network interfaces
	diffInterfaces(old.Network.Interfaces, new.Network.Interfaces, r)

	// Routes
	diffRoutes(old.Network.Routes, new.Network.Routes, r)

	// DNS
	diffDNS(old.Network.DNS, new.Network.DNS, r)

	// Listening ports
	diffPorts(old.ListeningPorts, new.ListeningPorts, r)

	// Multicast groups
	diffMulticastGroups(old.MulticastGroups, new.MulticastGroups, r)

	// Optional collectors — only diffed when at least one snapshot has the data.
	if old.CPU != nil || new.CPU != nil {
		diffCPU(old.CPU, new.CPU, r)
	}
	if old.KernelCounters != nil || new.KernelCounters != nil {
		diffKernelCounters(old.KernelCounters, new.KernelCounters, r)
	}
	if old.Processes != nil || new.Processes != nil {
		diffProcesses(old.Processes, new.Processes, r)
	}
	if old.Sockets != nil || new.Sockets != nil {
		diffSockets(old.Sockets, new.Sockets, r)
	}
	if old.NICDrivers != nil || new.NICDrivers != nil {
		diffNICDrivers(old.NICDrivers, new.NICDrivers, r)
	}
	if old.Connections != nil || new.Connections != nil {
		diffConnections(old.Connections, new.Connections, r)
	}

	// Count material vs counter changes
	for _, c := range r.Changes {
		if c.Counter {
			r.Counters++
		} else {
			r.Material++
		}
	}

	return r
}

func diffHost(old, new collector.Host, r *Result) {
	if old.Hostname != new.Hostname {
		r.Changes = append(r.Changes, Change{"host", "modified", "hostname", old.Hostname, new.Hostname, false})
	}
	if old.Kernel != new.Kernel {
		r.Changes = append(r.Changes, Change{"host", "modified", "kernel", old.Kernel, new.Kernel, false})
	}
	if old.BootID != new.BootID {
		r.Changes = append(r.Changes, Change{"host", "modified", "boot_id", old.BootID, new.BootID, false})
	}
}

// diffMap compares two string->string maps (kernel_params, packages, services).
func diffMap(section string, old, new map[string]string, r *Result, isCounter bool) {
	// Find removed and modified
	for k, oldVal := range old {
		if newVal, ok := new[k]; ok {
			if oldVal != newVal {
				r.Changes = append(r.Changes, Change{section, "modified", k, oldVal, newVal, isCounter})
			}
		} else {
			r.Changes = append(r.Changes, Change{section, "removed", k, oldVal, "", isCounter})
		}
	}

	// Find added
	for k, newVal := range new {
		if _, ok := old[k]; !ok {
			r.Changes = append(r.Changes, Change{section, "added", k, "", newVal, isCounter})
		}
	}
}

func diffInterfaces(old, new []collector.Interface, r *Result) {
	oldMap := make(map[string]collector.Interface)
	for _, iface := range old {
		oldMap[iface.Name] = iface
	}
	newMap := make(map[string]collector.Interface)
	for _, iface := range new {
		newMap[iface.Name] = iface
	}

	// Check all old interfaces
	for name, oldIf := range oldMap {
		newIf, exists := newMap[name]
		if !exists {
			r.Changes = append(r.Changes, Change{"network.interfaces", "removed", name, oldIf.State, "", false})
			continue
		}

		// Compare material properties
		if oldIf.State != newIf.State {
			r.Changes = append(r.Changes, Change{"network.interfaces", "modified",
				name + ".state", oldIf.State, newIf.State, false})
		}
		if oldIf.MTU != newIf.MTU {
			r.Changes = append(r.Changes, Change{"network.interfaces", "modified",
				name + ".mtu", fmt.Sprintf("%d", oldIf.MTU), fmt.Sprintf("%d", newIf.MTU), false})
		}

		// Compare addresses
		oldAddrs := strings.Join(oldIf.Addresses, ",")
		newAddrs := strings.Join(newIf.Addresses, ",")
		if oldAddrs != newAddrs {
			r.Changes = append(r.Changes, Change{"network.interfaces", "modified",
				name + ".addresses", oldAddrs, newAddrs, false})
		}

		// Compare stats (these are counters)
		diffStat := func(field string, oldVal, newVal uint64) {
			if oldVal != newVal {
				delta := int64(newVal) - int64(oldVal)
				r.Changes = append(r.Changes, Change{"network.interfaces", "modified",
					name + ".stats." + field,
					fmt.Sprintf("%d", oldVal),
					fmt.Sprintf("%d (delta: %+d)", newVal, delta),
					true}) // counter = true
			}
		}
		diffStat("rx_bytes", oldIf.Stats.RxBytes, newIf.Stats.RxBytes)
		diffStat("tx_bytes", oldIf.Stats.TxBytes, newIf.Stats.TxBytes)
		diffStat("rx_packets", oldIf.Stats.RxPackets, newIf.Stats.RxPackets)
		diffStat("tx_packets", oldIf.Stats.TxPackets, newIf.Stats.TxPackets)
		diffStat("rx_errors", oldIf.Stats.RxErrors, newIf.Stats.RxErrors)
		diffStat("tx_errors", oldIf.Stats.TxErrors, newIf.Stats.TxErrors)
		diffStat("rx_dropped", oldIf.Stats.RxDropped, newIf.Stats.RxDropped)
		diffStat("tx_dropped", oldIf.Stats.TxDropped, newIf.Stats.TxDropped)
	}

	// Check for new interfaces
	for name := range newMap {
		if _, exists := oldMap[name]; !exists {
			r.Changes = append(r.Changes, Change{"network.interfaces", "added", name, "", newMap[name].State, false})
		}
	}
}

func diffRoutes(old, new []collector.Route, r *Result) {
	oldSet := make(map[string]collector.Route)
	for _, route := range old {
		key := route.Destination + " dev " + route.Device
		oldSet[key] = route
	}
	newSet := make(map[string]collector.Route)
	for _, route := range new {
		key := route.Destination + " dev " + route.Device
		newSet[key] = route
	}

	for key := range oldSet {
		if _, exists := newSet[key]; !exists {
			r.Changes = append(r.Changes, Change{"network.routes", "removed", key, formatRoute(oldSet[key]), "", false})
		}
	}
	for key := range newSet {
		if _, exists := oldSet[key]; !exists {
			r.Changes = append(r.Changes, Change{"network.routes", "added", key, "", formatRoute(newSet[key]), false})
		}
	}
}

func formatRoute(route collector.Route) string {
	s := route.Destination
	if route.Gateway != "" {
		s += " via " + route.Gateway
	}
	s += " dev " + route.Device
	return s
}

func diffDNS(old, new collector.DNS, r *Result) {
	oldNS := strings.Join(old.Nameservers, ",")
	newNS := strings.Join(new.Nameservers, ",")
	if oldNS != newNS {
		r.Changes = append(r.Changes, Change{"network.dns", "modified", "nameservers", oldNS, newNS, false})
	}

	oldSearch := strings.Join(old.SearchDomains, ",")
	newSearch := strings.Join(new.SearchDomains, ",")
	if oldSearch != newSearch {
		r.Changes = append(r.Changes, Change{"network.dns", "modified", "search_domains", oldSearch, newSearch, false})
	}
}

func diffPorts(old, new []collector.ListeningPort, r *Result) {
	oldSet := make(map[string]collector.ListeningPort)
	for _, p := range old {
		key := fmt.Sprintf("%d/%s %s", p.Port, p.Protocol, p.Address)
		oldSet[key] = p
	}
	newSet := make(map[string]collector.ListeningPort)
	for _, p := range new {
		key := fmt.Sprintf("%d/%s %s", p.Port, p.Protocol, p.Address)
		newSet[key] = p
	}

	for key, p := range oldSet {
		if _, exists := newSet[key]; !exists {
			label := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
			if p.Process != "" {
				label += " " + p.Process
			}
			r.Changes = append(r.Changes, Change{"listening_ports", "removed", key, label, "", false})
		}
	}
	for key, p := range newSet {
		if _, exists := oldSet[key]; !exists {
			label := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
			if p.Process != "" {
				label += " " + p.Process
			}
			r.Changes = append(r.Changes, Change{"listening_ports", "added", key, "", label, false})
		}
	}
}

func diffMulticastGroups(old, new []collector.MulticastGroup, r *Result) {
	oldSet := make(map[string]struct{})
	for _, g := range old {
		oldSet[g.Interface+"/"+g.Group] = struct{}{}
	}
	newSet := make(map[string]struct{})
	for _, g := range new {
		newSet[g.Interface+"/"+g.Group] = struct{}{}
	}
	for key := range oldSet {
		if _, exists := newSet[key]; !exists {
			r.Changes = append(r.Changes, Change{"multicast_groups", "removed", key, key, "", false})
		}
	}
	for key := range newSet {
		if _, exists := oldSet[key]; !exists {
			r.Changes = append(r.Changes, Change{"multicast_groups", "added", key, "", key, false})
		}
	}
}

// FilterSection returns a new Result containing only changes whose Section has the given prefix.
func FilterSection(r *Result, section string) *Result {
	filtered := &Result{}
	for _, c := range r.Changes {
		if strings.HasPrefix(c.Section, section) {
			filtered.Changes = append(filtered.Changes, c)
			if c.Counter {
				filtered.Counters++
			} else {
				filtered.Material++
			}
		}
	}
	return filtered
}

// Format produces a human-readable diff string.
// If useColor is true, ANSI terminal colors are applied (green=added, red=removed, yellow=modified).
func Format(r *Result, materialOnly bool, useColor bool) string {
	if len(r.Changes) == 0 {
		return "  (no changes)\n"
	}

	const (
		reset  = "\033[0m"
		green  = "\033[32m"
		red    = "\033[31m"
		yellow = "\033[33m"
	)

	var b strings.Builder

	// Group by section
	sections := make(map[string][]Change)
	var sectionOrder []string
	for _, c := range r.Changes {
		if materialOnly && c.Counter {
			continue
		}
		if _, seen := sections[c.Section]; !seen {
			sectionOrder = append(sectionOrder, c.Section)
		}
		sections[c.Section] = append(sections[c.Section], c)
	}

	sort.Strings(sectionOrder)

	for _, section := range sectionOrder {
		changes := sections[section]
		b.WriteString(fmt.Sprintf("  %s:\n", section))

		for _, c := range changes {
			switch c.Type {
			case "added":
				if useColor {
					b.WriteString(fmt.Sprintf("%s  + %s: %s%s\n", green, c.Key, c.NewValue, reset))
				} else {
					b.WriteString(fmt.Sprintf("  + %s: %s\n", c.Key, c.NewValue))
				}
			case "removed":
				if useColor {
					b.WriteString(fmt.Sprintf("%s  - %s: %s%s\n", red, c.Key, c.OldValue, reset))
				} else {
					b.WriteString(fmt.Sprintf("  - %s: %s\n", c.Key, c.OldValue))
				}
			case "modified":
				if useColor {
					b.WriteString(fmt.Sprintf("%s  ~ %s: %q → %q%s\n", yellow, c.Key, c.OldValue, c.NewValue, reset))
				} else {
					b.WriteString(fmt.Sprintf("  ~ %s: %q → %q\n", c.Key, c.OldValue, c.NewValue))
				}
			}
		}
		b.WriteString("\n")
	}

	b.WriteString(fmt.Sprintf("%d material changes, %d counter increments\n", r.Material, r.Counters))
	return b.String()
}

// diffCPU compares two CPUStats snapshots. All fields are counters.
func diffCPU(old, new *collector.CPUStats, r *Result) {
	if old == nil {
		old = &collector.CPUStats{}
	}
	if new == nil {
		new = &collector.CPUStats{}
	}
	diffCounter := func(key string, o, n uint64) {
		if o != n {
			delta := int64(n) - int64(o)
			r.Changes = append(r.Changes, Change{"cpu", "modified", key,
				fmt.Sprintf("%d", o), fmt.Sprintf("%d (delta: %+d)", n, delta), true})
		}
	}
	diffCounter("user", old.User, new.User)
	diffCounter("nice", old.Nice, new.Nice)
	diffCounter("system", old.System, new.System)
	diffCounter("idle", old.Idle, new.Idle)
	diffCounter("iowait", old.IOWait, new.IOWait)
	diffCounter("irq", old.IRQ, new.IRQ)
	diffCounter("softirq", old.SoftIRQ, new.SoftIRQ)
	diffCounter("steal", old.Steal, new.Steal)
	diffCounter("guest", old.Guest, new.Guest)
	diffCounter("guest_nice", old.GuestNice, new.GuestNice)
}

// diffKernelCounters compares IP, TCP, UDP protocol counters. All values are counters.
func diffKernelCounters(old, new *collector.KernelCounters, r *Result) {
	if old == nil {
		old = &collector.KernelCounters{
			IP: map[string]uint64{}, TCP: map[string]uint64{}, UDP: map[string]uint64{},
		}
	}
	if new == nil {
		new = &collector.KernelCounters{
			IP: map[string]uint64{}, TCP: map[string]uint64{}, UDP: map[string]uint64{},
		}
	}
	diffCounterMap := func(section string, o, n map[string]uint64) {
		// Collect all keys
		keys := make(map[string]struct{})
		for k := range o {
			keys[k] = struct{}{}
		}
		for k := range n {
			keys[k] = struct{}{}
		}
		for k := range keys {
			ov, nv := o[k], n[k]
			if ov != nv {
				delta := int64(nv) - int64(ov)
				r.Changes = append(r.Changes, Change{section, "modified", k,
					fmt.Sprintf("%d", ov), fmt.Sprintf("%d (delta: %+d)", nv, delta), true})
			}
		}
	}
	diffCounterMap("kernel_counters.ip", old.IP, new.IP)
	diffCounterMap("kernel_counters.tcp", old.TCP, new.TCP)
	diffCounterMap("kernel_counters.udp", old.UDP, new.UDP)
}

// diffProcesses compares process inventories. RSS changes are counters; appearing/disappearing
// processes are material changes.
func diffProcesses(old, new *collector.ProcessInventory, r *Result) {
	if old == nil {
		old = &collector.ProcessInventory{}
	}
	if new == nil {
		new = &collector.ProcessInventory{}
	}

	// Track total count change as material
	if old.TotalCount != new.TotalCount {
		r.Changes = append(r.Changes, Change{"processes", "modified", "total_count",
			fmt.Sprintf("%d", old.TotalCount), fmt.Sprintf("%d", new.TotalCount), false})
	}

	// Index by PID
	oldByPID := make(map[int]collector.Process)
	for _, p := range old.TopByRSS {
		oldByPID[p.PID] = p
	}
	newByPID := make(map[int]collector.Process)
	for _, p := range new.TopByRSS {
		newByPID[p.PID] = p
	}

	// Processes in old top-N but not new: may have dropped off or exited
	for pid, op := range oldByPID {
		np, exists := newByPID[pid]
		if !exists {
			r.Changes = append(r.Changes, Change{"processes", "removed",
				fmt.Sprintf("%d (%s)", pid, op.Comm),
				fmt.Sprintf("rss=%dkB", op.RSSKB), "", false})
			continue
		}
		// RSS delta is a counter change
		if op.RSSKB != np.RSSKB {
			delta := int64(np.RSSKB) - int64(op.RSSKB)
			r.Changes = append(r.Changes, Change{"processes", "modified",
				fmt.Sprintf("%d (%s).rss_kb", pid, op.Comm),
				fmt.Sprintf("%d", op.RSSKB),
				fmt.Sprintf("%d (delta: %+d)", np.RSSKB, delta), true})
		}
	}
	// New processes that appeared in top-N
	for pid, np := range newByPID {
		if _, exists := oldByPID[pid]; !exists {
			r.Changes = append(r.Changes, Change{"processes", "added",
				fmt.Sprintf("%d (%s)", pid, np.Comm),
				"", fmt.Sprintf("rss=%dkB", np.RSSKB), false})
		}
	}
}

// diffSockets compares socket inventories.
func diffSockets(old, new *collector.SocketInventory, r *Result) {
	if old == nil {
		old = &collector.SocketInventory{}
	}
	if new == nil {
		new = &collector.SocketInventory{}
	}

	// Totals are counters
	diffStat := func(key string, ov, nv int) {
		if ov != nv {
			delta := nv - ov
			r.Changes = append(r.Changes, Change{"sockets", "modified", key,
				fmt.Sprintf("%d", ov), fmt.Sprintf("%d (delta: %+d)", nv, delta), true})
		}
	}
	diffStat("total_tcp", old.TotalTCP, new.TotalTCP)
	diffStat("total_udp", old.TotalUDP, new.TotalUDP)
	diffStat("total_listen", old.TotalListen, new.TotalListen)

	// Per-process top: material change when a process appears/disappears
	oldByPID := make(map[int]collector.SocketProcess)
	for _, sp := range old.TopByCount {
		oldByPID[sp.PID] = sp
	}
	for _, np := range new.TopByCount {
		if _, exists := oldByPID[np.PID]; !exists {
			r.Changes = append(r.Changes, Change{"sockets", "added",
				fmt.Sprintf("%d (%s)", np.PID, np.Comm),
				"", fmt.Sprintf("tcp=%d udp=%d", np.TCPCount, np.UDPCount), false})
		}
	}
	newByPID := make(map[int]collector.SocketProcess)
	for _, sp := range new.TopByCount {
		newByPID[sp.PID] = sp
	}
	for _, op := range old.TopByCount {
		if _, exists := newByPID[op.PID]; !exists {
			r.Changes = append(r.Changes, Change{"sockets", "removed",
				fmt.Sprintf("%d (%s)", op.PID, op.Comm),
				fmt.Sprintf("tcp=%d udp=%d", op.TCPCount, op.UDPCount), "", false})
		}
	}
}

// diffConnections compares established TCP connections.
// Key: protocol/process/remote_addr:remote_port — local ephemeral port is intentionally
// excluded from the key to avoid noise from port recycling between snapshots.
func diffConnections(old, new []collector.Connection, r *Result) {
	connKey := func(c collector.Connection) string {
		return fmt.Sprintf("%s/%s/%s:%d", c.Protocol, c.Process, c.RemoteAddr, c.RemotePort)
	}
	connLabel := func(c collector.Connection) string {
		proc := c.Process
		if proc == "" {
			proc = "?"
		}
		return fmt.Sprintf("%s [%s] %s:%d→%s:%d", c.State, proc, c.LocalAddr, c.LocalPort, c.RemoteAddr, c.RemotePort)
	}

	oldSet := make(map[string]collector.Connection)
	for _, c := range old {
		oldSet[connKey(c)] = c
	}
	newSet := make(map[string]collector.Connection)
	for _, c := range new {
		newSet[connKey(c)] = c
	}

	for key, oc := range oldSet {
		if _, exists := newSet[key]; !exists {
			r.Changes = append(r.Changes, Change{"connections", "removed", key, connLabel(oc), "", false})
		}
	}
	for key, nc := range newSet {
		if _, exists := oldSet[key]; !exists {
			r.Changes = append(r.Changes, Change{"connections", "added", key, "", connLabel(nc), false})
		}
	}
}

// diffNICDrivers compares NIC driver and firmware versions.
func diffNICDrivers(old, new map[string]collector.NICDriver, r *Result) {
	if old == nil {
		old = map[string]collector.NICDriver{}
	}
	if new == nil {
		new = map[string]collector.NICDriver{}
	}
	for iface, od := range old {
		nd, exists := new[iface]
		if !exists {
			r.Changes = append(r.Changes, Change{"nic_drivers", "removed", iface,
				fmt.Sprintf("driver=%s fw=%s", od.Driver, od.FirmwareVersion), "", false})
			continue
		}
		if od.Driver != nd.Driver {
			r.Changes = append(r.Changes, Change{"nic_drivers", "modified", iface + ".driver",
				od.Driver, nd.Driver, false})
		}
		if od.FirmwareVersion != nd.FirmwareVersion {
			r.Changes = append(r.Changes, Change{"nic_drivers", "modified", iface + ".fw_version",
				od.FirmwareVersion, nd.FirmwareVersion, false})
		}
	}
	for iface, nd := range new {
		if _, exists := old[iface]; !exists {
			r.Changes = append(r.Changes, Change{"nic_drivers", "added", iface,
				"", fmt.Sprintf("driver=%s fw=%s", nd.Driver, nd.FirmwareVersion), false})
		}
	}
}
