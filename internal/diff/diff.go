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

	// v0.3 Phase A security signals.
	diffUsers(old.Users, new.Users, r)
	diffGroups(old.Groups, new.Groups, r)
	diffSudoers(old.Sudoers, new.Sudoers, r)

	// v0.3 Phase E.
	diffMounts(old.Mounts, new.Mounts, r)

	// v0.3 Phase B.
	diffModules(old.Modules, new.Modules, r)

	// v0.3 Phase D.
	diffCron(old.CronJobs, new.CronJobs, r)
	diffTimers(old.Timers, new.Timers, r)

	// v0.3 Phase C.
	diffSSHKeys(old.SSHKeys, new.SSHKeys, r)

	// Optional collectors — only diffed when at least one snapshot has the data.
	if old.CPU != nil || new.CPU != nil {
		diffCPU(old.CPU, new.CPU, r)
	}
	if old.KernelCounters != nil || new.KernelCounters != nil {
		diffKernelCounters(old.KernelCounters, new.KernelCounters, r)
	}
	if old.Processes != nil || new.Processes != nil {
		wallSec := new.Timestamp.Sub(old.Timestamp).Seconds()
		diffProcesses(old.Processes, new.Processes, wallSec, r)
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

// diffProcesses compares process inventories. RSS changes are counters;
// appearing/disappearing processes are material changes. v0.4 adds:
//   - PID reuse detection via StartTicks: same PID with different StartTicks
//     is reported as removed+added rather than modified.
//   - CPU% computed from the delta of (utime+stime) ticks divided by
//     wallSec * clockTicksPerSec. Emitted as a counter change.
//   - PPID change emits "<pid>.ppid" (R26 reparented).
//   - Transition into zombie state (Z) emits "<pid>.zombie" (R27).
//   - Thread-count growth past a threshold emits "<pid>.thread_explosion"
//     (R28). Tuned to catch growth, not absolute count.
//
// wallSec is the wall-clock seconds between the two snapshots. Pass 0 to
// suppress CPU% emission (e.g., in tests where the timestamps are equal).
func diffProcesses(old, new *collector.ProcessInventory, wallSec float64, r *Result) {
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
		// PID reuse: same PID, different start_ticks (when both are populated).
		// Treat as removed+added so we don't generate spurious R26/R27 from a
		// fresh process that happens to occupy a recycled PID.
		if op.StartTicks != 0 && np.StartTicks != 0 && op.StartTicks != np.StartTicks {
			r.Changes = append(r.Changes, Change{"processes", "removed",
				fmt.Sprintf("%d (%s)", pid, op.Comm),
				fmt.Sprintf("rss=%dkB", op.RSSKB), "", false})
			r.Changes = append(r.Changes, Change{"processes", "added",
				fmt.Sprintf("%d (%s)", pid, np.Comm),
				"", fmt.Sprintf("rss=%dkB (pid reused)", np.RSSKB), false})
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

		// PPID change → R26 reparented. Material.
		if op.PPID != np.PPID {
			r.Changes = append(r.Changes, Change{"processes", "modified",
				fmt.Sprintf("%d (%s).ppid", pid, op.Comm),
				fmt.Sprintf("%d", op.PPID),
				fmt.Sprintf("%d", np.PPID), false})
		}

		// Zombie transition → R27. Only emit on the transition INTO Z; a
		// process already in Z that stays in Z is not a new event.
		if op.State != "Z" && np.State == "Z" {
			r.Changes = append(r.Changes, Change{"processes", "modified",
				fmt.Sprintf("%d (%s).zombie", pid, op.Comm),
				op.State, np.State, false})
		}

		// Thread explosion → R28. Catch growth, not absolute count: require
		// both an absolute delta of >= 100 AND new > 2 * old + 1 (so a JVM
		// going 200 → 220 doesn't fire, but a thread bomb 1 → 500 does).
		if np.Threads-op.Threads >= 100 && np.Threads > 2*op.Threads+1 {
			r.Changes = append(r.Changes, Change{"processes", "modified",
				fmt.Sprintf("%d (%s).thread_explosion", pid, op.Comm),
				fmt.Sprintf("%d", op.Threads),
				fmt.Sprintf("%d (delta: %+d)", np.Threads, np.Threads-op.Threads), false})
		}

		// CPU% from cumulative tick delta and wall-clock delta. Emitted as a
		// counter (ops-noise, not material). Skipped when we don't have ticks
		// from both snapshots, when wallSec is non-positive, or when start_ticks
		// indicates the process started after the old snapshot was taken.
		if wallSec > 0 && op.StartTicks != 0 && np.StartTicks != 0 {
			// clockTicksPerSec is _SC_CLK_TCK from sysconf. Hardcoded to 100,
			// the kernel default on x86_64/arm64 Linux for ~two decades. If
			// you ship statedrift on a tickless or HZ=250/HZ=1000 kernel,
			// CPU% will be off by a constant factor. Documented in
			// docs/V04_PLAN.md.
			const clockTicksPerSec = 100.0
			oldTicks := op.UTimeTicks + op.STimeTicks
			newTicks := np.UTimeTicks + np.STimeTicks
			if newTicks >= oldTicks {
				deltaSec := float64(newTicks-oldTicks) / clockTicksPerSec
				cpuPct := deltaSec / wallSec * 100
				if cpuPct > 0.05 { // suppress floating-point noise
					r.Changes = append(r.Changes, Change{"processes", "modified",
						fmt.Sprintf("%d (%s).cpu_pct", pid, op.Comm),
						"", fmt.Sprintf("%.1f", cpuPct), true})
				}
			}
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

// diffUsers compares /etc/passwd entries keyed by name. Modifications are
// emitted per field (alice.uid, alice.shell, etc.) so rules can target a
// specific kind of change via key-pattern.
func diffUsers(old, new []collector.User, r *Result) {
	oldMap := make(map[string]collector.User)
	for _, u := range old {
		oldMap[u.Name] = u
	}
	newMap := make(map[string]collector.User)
	for _, u := range new {
		newMap[u.Name] = u
	}

	for name, ou := range oldMap {
		nu, exists := newMap[name]
		if !exists {
			r.Changes = append(r.Changes, Change{"users", "removed", name,
				fmt.Sprintf("uid=%d gid=%d shell=%s", ou.UID, ou.GID, ou.Shell), "", false})
			continue
		}
		if ou.UID != nu.UID {
			r.Changes = append(r.Changes, Change{"users", "modified", name + ".uid",
				fmt.Sprintf("%d", ou.UID), fmt.Sprintf("%d", nu.UID), false})
		}
		if ou.GID != nu.GID {
			r.Changes = append(r.Changes, Change{"users", "modified", name + ".gid",
				fmt.Sprintf("%d", ou.GID), fmt.Sprintf("%d", nu.GID), false})
		}
		if ou.GECOS != nu.GECOS {
			r.Changes = append(r.Changes, Change{"users", "modified", name + ".gecos",
				ou.GECOS, nu.GECOS, false})
		}
		if ou.Home != nu.Home {
			r.Changes = append(r.Changes, Change{"users", "modified", name + ".home",
				ou.Home, nu.Home, false})
		}
		if ou.Shell != nu.Shell {
			r.Changes = append(r.Changes, Change{"users", "modified", name + ".shell",
				ou.Shell, nu.Shell, false})
		}
	}
	for name, nu := range newMap {
		if _, exists := oldMap[name]; !exists {
			r.Changes = append(r.Changes, Change{"users", "added", name,
				"", fmt.Sprintf("uid=%d gid=%d shell=%s", nu.UID, nu.GID, nu.Shell), false})
		}
	}
}

// diffGroups compares /etc/group entries keyed by name. Member-set changes are
// emitted as a single modification with comma-joined old/new lists; GID changes
// are emitted separately.
func diffGroups(old, new []collector.Group, r *Result) {
	oldMap := make(map[string]collector.Group)
	for _, g := range old {
		oldMap[g.Name] = g
	}
	newMap := make(map[string]collector.Group)
	for _, g := range new {
		newMap[g.Name] = g
	}

	for name, og := range oldMap {
		ng, exists := newMap[name]
		if !exists {
			r.Changes = append(r.Changes, Change{"groups", "removed", name,
				fmt.Sprintf("gid=%d members=[%s]", og.GID, strings.Join(og.Members, ",")), "", false})
			continue
		}
		if og.GID != ng.GID {
			r.Changes = append(r.Changes, Change{"groups", "modified", name + ".gid",
				fmt.Sprintf("%d", og.GID), fmt.Sprintf("%d", ng.GID), false})
		}
		oldMembers := strings.Join(og.Members, ",")
		newMembers := strings.Join(ng.Members, ",")
		if oldMembers != newMembers {
			r.Changes = append(r.Changes, Change{"groups", "modified", name + ".members",
				oldMembers, newMembers, false})
		}
	}
	for name, ng := range newMap {
		if _, exists := oldMap[name]; !exists {
			r.Changes = append(r.Changes, Change{"groups", "added", name,
				"", fmt.Sprintf("gid=%d members=[%s]", ng.GID, strings.Join(ng.Members, ",")), false})
		}
	}
}

// diffSudoers compares sudoers entries keyed by source+line. The line text is
// part of the key, so any change to a line shows up as a removed+added pair —
// callers see exactly which rules were added or taken away.
func diffSudoers(old, new []collector.SudoEntry, r *Result) {
	oldSet := make(map[string]collector.SudoEntry)
	for _, e := range old {
		oldSet[e.Source+"\t"+e.Line] = e
	}
	newSet := make(map[string]collector.SudoEntry)
	for _, e := range new {
		newSet[e.Source+"\t"+e.Line] = e
	}
	for key, e := range oldSet {
		if _, exists := newSet[key]; !exists {
			r.Changes = append(r.Changes, Change{"sudoers", "removed", key,
				fmt.Sprintf("%s: %s", e.Source, e.Line), "", false})
		}
	}
	for key, e := range newSet {
		if _, exists := oldSet[key]; !exists {
			r.Changes = append(r.Changes, Change{"sudoers", "added", key,
				"", fmt.Sprintf("%s: %s", e.Source, e.Line), false})
		}
	}
}

// diffMounts compares /proc/self/mountinfo entries keyed by mount point.
// Bind mounts targeting the same point with different sources are
// disambiguated by source as a secondary key. Per-field modifications are
// emitted so rules can target a specific kind of change via key-pattern.
func diffMounts(old, new []collector.Mount, r *Result) {
	mountKey := func(m collector.Mount) string {
		return m.MountPoint + "\t" + m.Source
	}
	oldMap := make(map[string]collector.Mount)
	for _, m := range old {
		oldMap[mountKey(m)] = m
	}
	newMap := make(map[string]collector.Mount)
	for _, m := range new {
		newMap[mountKey(m)] = m
	}

	for key, om := range oldMap {
		nm, exists := newMap[key]
		if !exists {
			r.Changes = append(r.Changes, Change{"mounts", "removed", om.MountPoint,
				fmt.Sprintf("source=%s fs=%s opts=%s", om.Source, om.FSType, om.MountOptions), "", false})
			continue
		}
		if om.Source != nm.Source {
			r.Changes = append(r.Changes, Change{"mounts", "modified", om.MountPoint + ".source",
				om.Source, nm.Source, false})
		}
		if om.FSType != nm.FSType {
			r.Changes = append(r.Changes, Change{"mounts", "modified", om.MountPoint + ".fs_type",
				om.FSType, nm.FSType, false})
		}
		if om.MountOptions != nm.MountOptions {
			r.Changes = append(r.Changes, Change{"mounts", "modified", om.MountPoint + ".mount_options",
				om.MountOptions, nm.MountOptions, false})
		}
		if om.SuperOptions != nm.SuperOptions {
			r.Changes = append(r.Changes, Change{"mounts", "modified", om.MountPoint + ".super_options",
				om.SuperOptions, nm.SuperOptions, false})
		}
	}
	for key, nm := range newMap {
		if _, exists := oldMap[key]; !exists {
			r.Changes = append(r.Changes, Change{"mounts", "added", nm.MountPoint,
				"", fmt.Sprintf("source=%s fs=%s opts=%s", nm.Source, nm.FSType, nm.MountOptions), false})
		}
	}
}

// diffModules compares loaded kernel modules keyed by name.
// A name reappearing with a different size indicates the underlying .ko file
// was replaced (potential rootkit signal). Dependency-list changes emit a
// modified change so a future rule can target supply-chain shifts.
func diffModules(old, new []collector.Module, r *Result) {
	oldMap := make(map[string]collector.Module, len(old))
	for _, m := range old {
		oldMap[m.Name] = m
	}
	newMap := make(map[string]collector.Module, len(new))
	for _, m := range new {
		newMap[m.Name] = m
	}

	for name, om := range oldMap {
		nm, exists := newMap[name]
		if !exists {
			r.Changes = append(r.Changes, Change{"modules", "removed", name,
				fmt.Sprintf("size=%d deps=%s", om.Size, strings.Join(om.Dependencies, ",")), "", false})
			continue
		}
		if om.Size != nm.Size {
			r.Changes = append(r.Changes, Change{"modules", "modified", name + ".size",
				fmt.Sprintf("%d", om.Size), fmt.Sprintf("%d", nm.Size), false})
		}
		// Dependencies are pre-sorted at collect time, so a string comparison
		// of the joined form is sufficient and avoids a slice-equality helper.
		oldDeps := strings.Join(om.Dependencies, ",")
		newDeps := strings.Join(nm.Dependencies, ",")
		if oldDeps != newDeps {
			r.Changes = append(r.Changes, Change{"modules", "modified", name + ".dependencies",
				oldDeps, newDeps, false})
		}
	}
	for name, nm := range newMap {
		if _, exists := oldMap[name]; !exists {
			r.Changes = append(r.Changes, Change{"modules", "added", name,
				"", fmt.Sprintf("size=%d deps=%s", nm.Size, strings.Join(nm.Dependencies, ",")), false})
		}
	}
}

// diffCron compares cron jobs as a set keyed by (Source, User, Schedule,
// Command). The full tuple is the natural identity — multiple jobs in one
// file legitimately share a schedule, and the same command appearing under
// a different schedule or user is a meaningfully different job. Jobs are
// emitted as added/removed; no per-field "modified" because changing any
// field produces a new identity tuple, which is what an auditor wants to
// see (the old job replaced by a new one rather than mutated in place).
func diffCron(old, new []collector.CronJob, r *Result) {
	cronKey := func(j collector.CronJob) string {
		return j.Source + "\x00" + j.User + "\x00" + j.Schedule + "\x00" + j.Command
	}
	oldSet := make(map[string]collector.CronJob, len(old))
	for _, j := range old {
		oldSet[cronKey(j)] = j
	}
	newSet := make(map[string]collector.CronJob, len(new))
	for _, j := range new {
		newSet[cronKey(j)] = j
	}
	for k, oj := range oldSet {
		if _, exists := newSet[k]; !exists {
			r.Changes = append(r.Changes, Change{"cron", "removed", oj.Source,
				fmt.Sprintf("user=%s schedule=%q cmd=%q", oj.User, oj.Schedule, oj.Command), "", false})
		}
	}
	for k, nj := range newSet {
		if _, exists := oldSet[k]; !exists {
			r.Changes = append(r.Changes, Change{"cron", "added", nj.Source,
				"", fmt.Sprintf("user=%s schedule=%q cmd=%q", nj.User, nj.Schedule, nj.Command), false})
		}
	}
}

// diffTimers compares systemd timers keyed by unit-file path. Per-field
// modified events are emitted so future rules can target a specific kind of
// change (e.g. OnCalendar shift) via key-pattern.
func diffTimers(old, new []collector.SystemdTimer, r *Result) {
	oldMap := make(map[string]collector.SystemdTimer, len(old))
	for _, t := range old {
		oldMap[t.UnitFile] = t
	}
	newMap := make(map[string]collector.SystemdTimer, len(new))
	for _, t := range new {
		newMap[t.UnitFile] = t
	}
	for path, ot := range oldMap {
		nt, exists := newMap[path]
		if !exists {
			r.Changes = append(r.Changes, Change{"timers", "removed", path,
				fmt.Sprintf("unit=%s on_calendar=%q", ot.Unit, ot.OnCalendar), "", false})
			continue
		}
		emitTimerFieldChange(r, path, "description", ot.Description, nt.Description)
		emitTimerFieldChange(r, path, "on_calendar", ot.OnCalendar, nt.OnCalendar)
		emitTimerFieldChange(r, path, "on_boot_sec", ot.OnBootSec, nt.OnBootSec)
		emitTimerFieldChange(r, path, "on_unit_active_sec", ot.OnUnitActiveSec, nt.OnUnitActiveSec)
		emitTimerFieldChange(r, path, "on_unit_inactive_sec", ot.OnUnitInactiveSec, nt.OnUnitInactiveSec)
		emitTimerFieldChange(r, path, "unit", ot.Unit, nt.Unit)
		emitTimerFieldChange(r, path, "randomized_delay_sec", ot.RandomizedDelaySec, nt.RandomizedDelaySec)
	}
	for path, nt := range newMap {
		if _, exists := oldMap[path]; !exists {
			r.Changes = append(r.Changes, Change{"timers", "added", path,
				"", fmt.Sprintf("unit=%s on_calendar=%q", nt.Unit, nt.OnCalendar), false})
		}
	}
}

func emitTimerFieldChange(r *Result, path, field, oldVal, newVal string) {
	if oldVal == newVal {
		return
	}
	r.Changes = append(r.Changes, Change{"timers", "modified", path + "." + field, oldVal, newVal, false})
}

// diffSSHKeys compares authorized_keys entries keyed by (User, Type,
// Fingerprint). The fingerprint is the cryptographic identity of the key
// material, so a fingerprint change *is* a key change — these appear as
// remove + add (which is what an auditor wants: the old key is gone, a
// new key is in). Comment and options changes on the same fingerprint
// emit modified events for diff visibility, but do not cross the identity
// boundary.
func diffSSHKeys(old, new []collector.SSHKey, r *Result) {
	keyID := func(k collector.SSHKey) string {
		return k.User + "\x00" + k.Type + "\x00" + k.Fingerprint
	}
	oldMap := make(map[string]collector.SSHKey, len(old))
	for _, k := range old {
		oldMap[keyID(k)] = k
	}
	newMap := make(map[string]collector.SSHKey, len(new))
	for _, k := range new {
		newMap[keyID(k)] = k
	}
	for id, ok := range oldMap {
		nk, exists := newMap[id]
		if !exists {
			r.Changes = append(r.Changes, Change{"ssh_keys", "removed", ok.User + " " + ok.Fingerprint,
				fmt.Sprintf("type=%s comment=%q source=%s", ok.Type, ok.Comment, ok.Source), "", false})
			continue
		}
		// Same identity tuple — surface secondary-field changes as modified.
		if ok.Comment != nk.Comment {
			r.Changes = append(r.Changes, Change{"ssh_keys", "modified",
				ok.User + " " + ok.Fingerprint + ".comment", ok.Comment, nk.Comment, false})
		}
		if ok.Options != nk.Options {
			r.Changes = append(r.Changes, Change{"ssh_keys", "modified",
				ok.User + " " + ok.Fingerprint + ".options", ok.Options, nk.Options, false})
		}
		if ok.Source != nk.Source {
			r.Changes = append(r.Changes, Change{"ssh_keys", "modified",
				ok.User + " " + ok.Fingerprint + ".source", ok.Source, nk.Source, false})
		}
	}
	for id, nk := range newMap {
		if _, exists := oldMap[id]; !exists {
			r.Changes = append(r.Changes, Change{"ssh_keys", "added", nk.User + " " + nk.Fingerprint,
				"", fmt.Sprintf("type=%s comment=%q source=%s", nk.Type, nk.Comment, nk.Source), false})
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
