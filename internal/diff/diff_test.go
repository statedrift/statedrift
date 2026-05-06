package diff

import (
	"strings"
	"testing"
	"time"

	"github.com/statedrift/statedrift/internal/collector"
)

func baseSnapshot() *collector.Snapshot {
	return &collector.Snapshot{
		Host: collector.Host{
			Hostname: "testhost",
			Kernel:   "5.15.0",
			BootID:   "abc123",
		},
		KernelParams: map[string]string{
			"net.ipv4.ip_forward": "0",
			"net.core.somaxconn":  "128",
			"vm.swappiness":       "60",
		},
		Packages: map[string]string{
			"nginx": "1.18.0",
			"curl":  "7.74.0",
		},
		Services: map[string]string{
			"nginx.service": "active (running)",
		},
		Network: collector.Network{
			Interfaces: []collector.Interface{
				{
					Name:  "eth0",
					State: "up",
					MTU:   1500,
					Stats: collector.InterfaceStats{
						RxBytes: 1000,
						TxBytes: 500,
					},
				},
			},
		},
		ListeningPorts: []collector.ListeningPort{
			{Port: 80, Protocol: "tcp", Address: "0.0.0.0"},
			{Port: 443, Protocol: "tcp", Address: "0.0.0.0"},
		},
	}
}

func TestCompareIdentical(t *testing.T) {
	snap := baseSnapshot()
	r := Compare(snap, snap)
	if r.Material != 0 {
		t.Errorf("expected 0 material changes, got %d", r.Material)
	}
	if r.Counters != 0 {
		t.Errorf("expected 0 counter changes, got %d", r.Counters)
	}
	if len(r.Changes) != 0 {
		t.Errorf("expected 0 changes, got %d: %+v", len(r.Changes), r.Changes)
	}
}

func TestCompareKernelParamAdded(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.KernelParams["kernel.randomize_va_space"] = "2"

	r := Compare(old, new)
	if !hasChange(r, "kernel_params", "added", "kernel.randomize_va_space") {
		t.Error("expected kernel_params added change for kernel.randomize_va_space")
	}
}

func TestCompareKernelParamRemoved(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	delete(new.KernelParams, "vm.swappiness")

	r := Compare(old, new)
	if !hasChange(r, "kernel_params", "removed", "vm.swappiness") {
		t.Error("expected kernel_params removed change for vm.swappiness")
	}
}

func TestCompareKernelParamModified(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.KernelParams["net.core.somaxconn"] = "4096"

	r := Compare(old, new)
	if !hasChange(r, "kernel_params", "modified", "net.core.somaxconn") {
		t.Error("expected kernel_params modified change for net.core.somaxconn")
	}
	if r.Material < 1 {
		t.Errorf("expected at least 1 material change, got %d", r.Material)
	}
}

func TestCompareListeningPortAdded(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.ListeningPorts = append(new.ListeningPorts, collector.ListeningPort{
		Port: 8080, Protocol: "tcp", Address: "0.0.0.0",
	})

	r := Compare(old, new)
	if !hasChange(r, "listening_ports", "added", "") {
		t.Error("expected listening_ports added change")
	}
}

func TestCompareListeningPortRemoved(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.ListeningPorts = new.ListeningPorts[:1] // remove port 443

	r := Compare(old, new)
	if !hasChange(r, "listening_ports", "removed", "") {
		t.Error("expected listening_ports removed change")
	}
}

func TestCompareInterfaceStatsAreCounters(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.Network.Interfaces[0].Stats.RxBytes = 9999
	new.Network.Interfaces[0].Stats.TxBytes = 9999

	r := Compare(old, new)

	for _, c := range r.Changes {
		if c.Section == "network.interfaces" && strings.Contains(c.Key, "stats") {
			if !c.Counter {
				t.Errorf("interface stat change %q should be a counter", c.Key)
			}
		}
	}
	if r.Counters < 2 {
		t.Errorf("expected at least 2 counter changes, got %d", r.Counters)
	}
}

func TestCompareInterfaceStateChange(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.Network.Interfaces[0].State = "down"

	r := Compare(old, new)
	if !hasChange(r, "network.interfaces", "modified", "eth0.state") {
		t.Error("expected network.interfaces state change")
	}
	// State change is material, not a counter
	found := false
	for _, c := range r.Changes {
		if c.Key == "eth0.state" {
			if c.Counter {
				t.Error("interface state change should NOT be a counter")
			}
			found = true
		}
	}
	if !found {
		t.Error("eth0.state change not found")
	}
}

func TestFormatContainsSymbols(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.KernelParams["net.core.somaxconn"] = "4096"
	new.KernelParams["kernel.new_param"] = "1"
	delete(new.KernelParams, "vm.swappiness")

	r := Compare(old, new)
	out := Format(r, false, false)

	if !strings.Contains(out, "+") {
		t.Error("Format output missing '+' for added change")
	}
	if !strings.Contains(out, "-") {
		t.Error("Format output missing '-' for removed change")
	}
	if !strings.Contains(out, "~") {
		t.Error("Format output missing '~' for modified change")
	}
}

func TestFormatNoChanges(t *testing.T) {
	snap := baseSnapshot()
	r := Compare(snap, snap)
	out := Format(r, false, false)
	if !strings.Contains(out, "no changes") {
		t.Errorf("expected 'no changes' in output, got: %s", out)
	}
}

func TestFilterSectionKeepsMatchingSection(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.KernelParams["net.core.somaxconn"] = "4096"
	new.Network.Interfaces[0].State = "down"

	r := Compare(old, new)
	filtered := FilterSection(r, "kernel_params")

	for _, c := range filtered.Changes {
		if c.Section != "kernel_params" {
			t.Errorf("FilterSection returned change with section %q, want kernel_params", c.Section)
		}
	}
	if filtered.Material == 0 {
		t.Error("expected at least one material change after filtering for kernel_params")
	}
}

func TestFilterSectionEmptyResult(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.KernelParams["net.core.somaxconn"] = "4096"

	r := Compare(old, new)
	filtered := FilterSection(r, "packages")

	if len(filtered.Changes) != 0 {
		t.Errorf("expected 0 changes after filtering for packages, got %d", len(filtered.Changes))
	}
}

func TestFormatColorContainsANSI(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.KernelParams["net.core.somaxconn"] = "4096"
	new.KernelParams["kernel.new_param"] = "1"
	delete(new.KernelParams, "vm.swappiness")

	r := Compare(old, new)
	out := Format(r, false, true)

	if !strings.Contains(out, "\033[") {
		t.Error("colored Format output should contain ANSI escape sequences")
	}
}

// hasChange returns true if any change matches the given criteria.
// An empty key string means "any key".
func hasChange(r *Result, section, changeType, key string) bool {
	for _, c := range r.Changes {
		if c.Section == section && c.Type == changeType {
			if key == "" || c.Key == key {
				return true
			}
		}
	}
	return false
}

// --- Optional collector diffs ---

func TestDiffCPUCounters(t *testing.T) {
	old := &collector.Snapshot{CPU: &collector.CPUStats{User: 100, System: 50}}
	new := &collector.Snapshot{CPU: &collector.CPUStats{User: 200, System: 50}}
	r := Compare(old, new)
	found := false
	for _, c := range r.Changes {
		if c.Section == "cpu" && c.Key == "user" && c.Counter {
			found = true
		}
	}
	if !found {
		t.Error("expected cpu.user counter change")
	}
	// System didn't change — should not appear
	for _, c := range r.Changes {
		if c.Section == "cpu" && c.Key == "system" {
			t.Error("cpu.system unchanged but appeared in diff")
		}
	}
	// CPU changes are all counters, so Material should be 0 from cpu section
	cpuMaterial := 0
	for _, c := range r.Changes {
		if c.Section == "cpu" && !c.Counter {
			cpuMaterial++
		}
	}
	if cpuMaterial != 0 {
		t.Errorf("cpu section produced %d non-counter changes, want 0", cpuMaterial)
	}
}

func TestDiffCPUNilOld(t *testing.T) {
	old := &collector.Snapshot{} // no CPU
	new := &collector.Snapshot{CPU: &collector.CPUStats{User: 100}}
	r := Compare(old, new)
	found := false
	for _, c := range r.Changes {
		if c.Section == "cpu" && c.Key == "user" {
			found = true
		}
	}
	if !found {
		t.Error("expected cpu.user change when old has no CPU data")
	}
}

func TestDiffKernelCounters(t *testing.T) {
	old := &collector.Snapshot{
		KernelCounters: &collector.KernelCounters{
			IP:  map[string]uint64{"InReceives": 1000},
			TCP: map[string]uint64{},
			UDP: map[string]uint64{},
		},
	}
	new := &collector.Snapshot{
		KernelCounters: &collector.KernelCounters{
			IP:  map[string]uint64{"InReceives": 1500},
			TCP: map[string]uint64{},
			UDP: map[string]uint64{},
		},
	}
	r := Compare(old, new)
	found := false
	for _, c := range r.Changes {
		if c.Section == "kernel_counters.ip" && c.Key == "InReceives" && c.Counter {
			found = true
		}
	}
	if !found {
		t.Error("expected kernel_counters.ip.InReceives counter change")
	}
}

func TestDiffProcessesAdded(t *testing.T) {
	old := &collector.Snapshot{
		Processes: &collector.ProcessInventory{TotalCount: 1, TopByRSS: []collector.Process{
			{PID: 1, Comm: "init", RSSKB: 1000},
		}},
	}
	new := &collector.Snapshot{
		Processes: &collector.ProcessInventory{TotalCount: 2, TopByRSS: []collector.Process{
			{PID: 1, Comm: "init", RSSKB: 1000},
			{PID: 999, Comm: "malware", RSSKB: 50000},
		}},
	}
	r := Compare(old, new)
	found := false
	for _, c := range r.Changes {
		if c.Section == "processes" && c.Type == "added" && strings.Contains(c.Key, "999") {
			found = true
		}
	}
	if !found {
		t.Error("expected processes added change for PID 999")
	}
}

// --- v0.4 Phase F: R26/R27/R28, PID reuse, CPU% ---

func TestDiffProcessesPPIDChangeFiresR26(t *testing.T) {
	old := &collector.Snapshot{
		Processes: &collector.ProcessInventory{TotalCount: 1, TopByRSS: []collector.Process{
			{PID: 100, PPID: 50, Comm: "child", State: "S", StartTicks: 1000},
		}},
	}
	new := &collector.Snapshot{
		Processes: &collector.ProcessInventory{TotalCount: 1, TopByRSS: []collector.Process{
			{PID: 100, PPID: 1, Comm: "child", State: "S", StartTicks: 1000},
		}},
	}
	r := Compare(old, new)
	found := false
	for _, c := range r.Changes {
		if c.Section == "processes" && c.Type == "modified" && strings.HasSuffix(c.Key, ".ppid") {
			found = true
		}
	}
	if !found {
		t.Error("expected processes .ppid change when parent changes (R26)")
	}
}

func TestDiffProcessesZombieTransitionFiresR27(t *testing.T) {
	old := &collector.Snapshot{
		Processes: &collector.ProcessInventory{TotalCount: 1, TopByRSS: []collector.Process{
			{PID: 100, Comm: "myapp", State: "S", StartTicks: 1000},
		}},
	}
	new := &collector.Snapshot{
		Processes: &collector.ProcessInventory{TotalCount: 1, TopByRSS: []collector.Process{
			{PID: 100, Comm: "myapp", State: "Z", StartTicks: 1000},
		}},
	}
	r := Compare(old, new)
	found := false
	for _, c := range r.Changes {
		if c.Section == "processes" && c.Type == "modified" && strings.HasSuffix(c.Key, ".zombie") {
			found = true
		}
	}
	if !found {
		t.Error("expected processes .zombie change on transition into Z (R27)")
	}
}

func TestDiffProcessesAlreadyZombieDoesNotFireR27(t *testing.T) {
	// Process was already a zombie — don't re-fire just because it's still Z.
	old := &collector.Snapshot{
		Processes: &collector.ProcessInventory{TotalCount: 1, TopByRSS: []collector.Process{
			{PID: 100, Comm: "myapp", State: "Z", StartTicks: 1000},
		}},
	}
	new := &collector.Snapshot{
		Processes: &collector.ProcessInventory{TotalCount: 1, TopByRSS: []collector.Process{
			{PID: 100, Comm: "myapp", State: "Z", StartTicks: 1000},
		}},
	}
	r := Compare(old, new)
	for _, c := range r.Changes {
		if strings.HasSuffix(c.Key, ".zombie") {
			t.Errorf("did not expect .zombie change when state was already Z; got %+v", c)
		}
	}
}

func TestDiffProcessesThreadExplosionFiresR28(t *testing.T) {
	// Thread bomb 1 → 500: must fire.
	old := &collector.Snapshot{
		Processes: &collector.ProcessInventory{TotalCount: 1, TopByRSS: []collector.Process{
			{PID: 100, Comm: "bomb", State: "S", Threads: 1, StartTicks: 1000},
		}},
	}
	new := &collector.Snapshot{
		Processes: &collector.ProcessInventory{TotalCount: 1, TopByRSS: []collector.Process{
			{PID: 100, Comm: "bomb", State: "S", Threads: 500, StartTicks: 1000},
		}},
	}
	r := Compare(old, new)
	found := false
	for _, c := range r.Changes {
		if c.Section == "processes" && c.Type == "modified" && strings.HasSuffix(c.Key, ".thread_explosion") {
			found = true
		}
	}
	if !found {
		t.Error("expected .thread_explosion change for 1→500 thread growth (R28)")
	}
}

func TestDiffProcessesJVMSteadyStateDoesNotFireR28(t *testing.T) {
	// JVM at 200 → 220: small delta, must NOT fire. Tunes the threshold.
	old := &collector.Snapshot{
		Processes: &collector.ProcessInventory{TotalCount: 1, TopByRSS: []collector.Process{
			{PID: 100, Comm: "java", State: "S", Threads: 200, StartTicks: 1000},
		}},
	}
	new := &collector.Snapshot{
		Processes: &collector.ProcessInventory{TotalCount: 1, TopByRSS: []collector.Process{
			{PID: 100, Comm: "java", State: "S", Threads: 220, StartTicks: 1000},
		}},
	}
	r := Compare(old, new)
	for _, c := range r.Changes {
		if strings.HasSuffix(c.Key, ".thread_explosion") {
			t.Errorf("did not expect .thread_explosion for 200→220 JVM growth; got %+v", c)
		}
	}
}

func TestDiffProcessesPIDReuseEmitsRemovedAndAdded(t *testing.T) {
	// Same PID, different StartTicks → original exited, new process took the
	// slot. Should emit removed+added, NOT modified (no spurious R26/R27).
	old := &collector.Snapshot{
		Processes: &collector.ProcessInventory{TotalCount: 1, TopByRSS: []collector.Process{
			{PID: 100, PPID: 1, Comm: "old_proc", State: "S", StartTicks: 1000},
		}},
	}
	new := &collector.Snapshot{
		Processes: &collector.ProcessInventory{TotalCount: 1, TopByRSS: []collector.Process{
			{PID: 100, PPID: 50, Comm: "new_proc", State: "Z", StartTicks: 9999}, // different start
		}},
	}
	r := Compare(old, new)
	var removed, added bool
	for _, c := range r.Changes {
		if c.Section != "processes" {
			continue
		}
		if c.Type == "removed" && strings.Contains(c.Key, "100") {
			removed = true
		}
		if c.Type == "added" && strings.Contains(c.Key, "100") {
			added = true
		}
		// PPID change and zombie transition must NOT fire on PID reuse.
		if strings.HasSuffix(c.Key, ".ppid") || strings.HasSuffix(c.Key, ".zombie") {
			t.Errorf("PID reuse should not emit %q; got %+v", c.Key, c)
		}
	}
	if !removed || !added {
		t.Errorf("expected removed+added for PID reuse, got removed=%v added=%v", removed, added)
	}
}

func TestDiffProcessesCPUPctComputed(t *testing.T) {
	// 1000 ticks (10s of CPU at 100 Hz) over 20s wall = 50% CPU.
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	old := &collector.Snapshot{
		Timestamp: t0,
		Processes: &collector.ProcessInventory{TotalCount: 1, TopByRSS: []collector.Process{
			{PID: 100, Comm: "burner", State: "R", StartTicks: 1, UTimeTicks: 0, STimeTicks: 0},
		}},
	}
	new := &collector.Snapshot{
		Timestamp: t0.Add(20 * time.Second),
		Processes: &collector.ProcessInventory{TotalCount: 1, TopByRSS: []collector.Process{
			{PID: 100, Comm: "burner", State: "R", StartTicks: 1, UTimeTicks: 700, STimeTicks: 300},
		}},
	}
	r := Compare(old, new)
	found := false
	for _, c := range r.Changes {
		if strings.HasSuffix(c.Key, ".cpu_pct") {
			found = true
			if c.NewValue != "50.0" {
				t.Errorf("cpu_pct = %q, want 50.0", c.NewValue)
			}
			if !c.Counter {
				t.Error("cpu_pct should be a counter change, not material")
			}
		}
	}
	if !found {
		t.Error("expected .cpu_pct change when ticks and wallclock are populated")
	}
}

func TestDiffNICDriverChanged(t *testing.T) {
	old := &collector.Snapshot{
		NICDrivers: map[string]collector.NICDriver{
			"eth0": {Driver: "virtio_net", FirmwareVersion: "1.0"},
		},
	}
	new := &collector.Snapshot{
		NICDrivers: map[string]collector.NICDriver{
			"eth0": {Driver: "virtio_net", FirmwareVersion: "2.0"},
		},
	}
	r := Compare(old, new)
	found := false
	for _, c := range r.Changes {
		if c.Section == "nic_drivers" && c.Key == "eth0.fw_version" && !c.Counter {
			found = true
		}
	}
	if !found {
		t.Error("expected nic_drivers eth0.fw_version material change")
	}
}

func TestDiffSocketsCounterChanges(t *testing.T) {
	old := &collector.Snapshot{
		Sockets: &collector.SocketInventory{TotalTCP: 10, TotalUDP: 2, TotalListen: 3},
	}
	new := &collector.Snapshot{
		Sockets: &collector.SocketInventory{TotalTCP: 15, TotalUDP: 2, TotalListen: 3},
	}
	r := Compare(old, new)
	found := false
	for _, c := range r.Changes {
		if c.Section == "sockets" && c.Key == "total_tcp" && c.Counter {
			found = true
		}
	}
	if !found {
		t.Error("expected sockets.total_tcp counter change")
	}
}

func TestCompareUDPPortAdded(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.ListeningPorts = append(new.ListeningPorts, collector.ListeningPort{
		Port: 53, Protocol: "udp", Address: "0.0.0.0",
	})

	r := Compare(old, new)
	if !hasChange(r, "listening_ports", "added", "") {
		t.Error("expected listening_ports added change for UDP port")
	}
	found := false
	for _, c := range r.Changes {
		if c.Section == "listening_ports" && c.Type == "added" && strings.Contains(c.Key, "udp") {
			found = true
		}
	}
	if !found {
		t.Error("expected UDP in the change key")
	}
}

func TestDiffMulticastGroupAdded(t *testing.T) {
	old := &collector.Snapshot{}
	new := &collector.Snapshot{
		MulticastGroups: []collector.MulticastGroup{
			{Interface: "eth0", Group: "224.0.0.1"},
		},
	}
	r := Compare(old, new)
	if !hasChange(r, "multicast_groups", "added", "") {
		t.Error("expected multicast_groups added change")
	}
	if r.Material == 0 {
		t.Error("expected multicast group addition to be material")
	}
}

func TestDiffMulticastGroupRemoved(t *testing.T) {
	old := &collector.Snapshot{
		MulticastGroups: []collector.MulticastGroup{
			{Interface: "eth0", Group: "224.0.0.251"},
		},
	}
	new := &collector.Snapshot{}
	r := Compare(old, new)
	if !hasChange(r, "multicast_groups", "removed", "") {
		t.Error("expected multicast_groups removed change")
	}
}

func TestDiffMulticastGroupUnchanged(t *testing.T) {
	old := &collector.Snapshot{
		MulticastGroups: []collector.MulticastGroup{
			{Interface: "eth0", Group: "224.0.0.1"},
		},
	}
	new := &collector.Snapshot{
		MulticastGroups: []collector.MulticastGroup{
			{Interface: "eth0", Group: "224.0.0.1"},
		},
	}
	r := Compare(old, new)
	for _, c := range r.Changes {
		if c.Section == "multicast_groups" {
			t.Errorf("unexpected multicast_groups change when groups are identical: %+v", c)
		}
	}
}

func TestDiffConnectionAdded(t *testing.T) {
	old := &collector.Snapshot{}
	new := &collector.Snapshot{
		Connections: []collector.Connection{
			{Protocol: "tcp", Process: "curl", LocalAddr: "10.0.0.1", LocalPort: 54321,
				RemoteAddr: "1.2.3.4", RemotePort: 443, State: "established"},
		},
	}
	r := Compare(old, new)
	if !hasChange(r, "connections", "added", "") {
		t.Error("expected connections added change")
	}
	if r.Material == 0 {
		t.Error("expected connection addition to be material")
	}
}

func TestDiffConnectionRemoved(t *testing.T) {
	old := &collector.Snapshot{
		Connections: []collector.Connection{
			{Protocol: "tcp", Process: "nginx", LocalAddr: "10.0.0.1", LocalPort: 12345,
				RemoteAddr: "5.6.7.8", RemotePort: 80, State: "established"},
		},
	}
	new := &collector.Snapshot{}
	r := Compare(old, new)
	if !hasChange(r, "connections", "removed", "") {
		t.Error("expected connections removed change")
	}
}

func TestDiffConnectionUnchanged(t *testing.T) {
	conn := collector.Connection{Protocol: "tcp", Process: "sshd", LocalAddr: "10.0.0.1",
		LocalPort: 22, RemoteAddr: "9.9.9.9", RemotePort: 60000, State: "established"}
	old := &collector.Snapshot{Connections: []collector.Connection{conn}}
	new := &collector.Snapshot{Connections: []collector.Connection{conn}}
	r := Compare(old, new)
	for _, c := range r.Changes {
		if c.Section == "connections" {
			t.Errorf("unexpected connections change when identical: %+v", c)
		}
	}
}

func TestDiffConnectionEphemeralPortNoise(t *testing.T) {
	// Same remote endpoint, different local port — should produce no change
	// because the diff key excludes the local (ephemeral) port.
	old := &collector.Snapshot{
		Connections: []collector.Connection{
			{Protocol: "tcp", Process: "curl", LocalAddr: "10.0.0.1", LocalPort: 54321,
				RemoteAddr: "1.2.3.4", RemotePort: 443, State: "established"},
		},
	}
	new := &collector.Snapshot{
		Connections: []collector.Connection{
			{Protocol: "tcp", Process: "curl", LocalAddr: "10.0.0.1", LocalPort: 54999,
				RemoteAddr: "1.2.3.4", RemotePort: 443, State: "established"},
		},
	}
	r := Compare(old, new)
	for _, c := range r.Changes {
		if c.Section == "connections" {
			t.Errorf("ephemeral port change should not produce a connections diff: %+v", c)
		}
	}
}

func TestDiffOptionalNilBothSides(t *testing.T) {
	// When both snapshots lack optional data, no changes should appear for those sections
	old := baseSnapshot()
	new := baseSnapshot()
	r := Compare(old, new)
	for _, c := range r.Changes {
		switch c.Section {
		case "cpu", "kernel_counters.ip", "kernel_counters.tcp", "kernel_counters.udp",
			"processes", "sockets", "nic_drivers", "connections":
			t.Errorf("unexpected change in section %q when both snapshots have nil optional data", c.Section)
		}
	}
}

// --- v0.3 Phase A: users / groups / sudoers ---

func TestDiffUsersAdded(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.Users = []collector.User{{Name: "alice", UID: 1000, GID: 1000, Shell: "/bin/bash"}}
	r := Compare(old, new)
	if !hasChange(r, "users", "added", "alice") {
		t.Errorf("expected users added 'alice', got %+v", r.Changes)
	}
}

func TestDiffUsersRemoved(t *testing.T) {
	old := baseSnapshot()
	old.Users = []collector.User{{Name: "alice", UID: 1000, GID: 1000, Shell: "/bin/bash"}}
	new := baseSnapshot()
	r := Compare(old, new)
	if !hasChange(r, "users", "removed", "alice") {
		t.Errorf("expected users removed 'alice', got %+v", r.Changes)
	}
}

func TestDiffUsersModifiedPerField(t *testing.T) {
	old := baseSnapshot()
	old.Users = []collector.User{{Name: "alice", UID: 1000, GID: 1000, Shell: "/bin/bash", Home: "/home/alice"}}
	new := baseSnapshot()
	new.Users = []collector.User{{Name: "alice", UID: 0, GID: 1000, Shell: "/bin/zsh", Home: "/home/alice"}}
	r := Compare(old, new)
	if !hasChange(r, "users", "modified", "alice.uid") {
		t.Errorf("expected users modified 'alice.uid'")
	}
	if !hasChange(r, "users", "modified", "alice.shell") {
		t.Errorf("expected users modified 'alice.shell'")
	}
	if hasChange(r, "users", "modified", "alice.home") {
		t.Errorf("did not expect users modified 'alice.home' (unchanged)")
	}
}

func TestDiffGroupsMembership(t *testing.T) {
	old := baseSnapshot()
	old.Groups = []collector.Group{{Name: "wheel", GID: 10, Members: []string{"alice"}}}
	new := baseSnapshot()
	new.Groups = []collector.Group{{Name: "wheel", GID: 10, Members: []string{"alice", "bob"}}}
	r := Compare(old, new)
	if !hasChange(r, "groups", "modified", "wheel.members") {
		t.Errorf("expected groups modified 'wheel.members', got %+v", r.Changes)
	}
}

func TestDiffGroupsAddedRemoved(t *testing.T) {
	old := baseSnapshot()
	old.Groups = []collector.Group{{Name: "old-team", GID: 100}}
	new := baseSnapshot()
	new.Groups = []collector.Group{{Name: "new-team", GID: 101}}
	r := Compare(old, new)
	if !hasChange(r, "groups", "removed", "old-team") {
		t.Errorf("expected groups removed 'old-team'")
	}
	if !hasChange(r, "groups", "added", "new-team") {
		t.Errorf("expected groups added 'new-team'")
	}
}

func TestDiffSudoersAddedRemoved(t *testing.T) {
	old := baseSnapshot()
	old.Sudoers = []collector.SudoEntry{
		{Source: "/etc/sudoers", Line: "Defaults env_reset"},
		{Source: "/etc/sudoers", Line: "%wheel ALL=(ALL) ALL"},
	}
	new := baseSnapshot()
	new.Sudoers = []collector.SudoEntry{
		{Source: "/etc/sudoers", Line: "Defaults env_reset"},
		{Source: "/etc/sudoers.d/oncall", Line: "%oncall ALL=(ALL) NOPASSWD: /opt/scripts/page.sh"},
	}
	r := Compare(old, new)
	if !hasChange(r, "sudoers", "removed", "") {
		t.Errorf("expected sudoers removed change for %%wheel rule")
	}
	if !hasChange(r, "sudoers", "added", "") {
		t.Errorf("expected sudoers added change for /etc/sudoers.d/oncall rule")
	}
}

func TestDiffSudoersUnchanged(t *testing.T) {
	entries := []collector.SudoEntry{
		{Source: "/etc/sudoers", Line: "Defaults env_reset"},
		{Source: "/etc/sudoers", Line: "%wheel ALL=(ALL) ALL"},
	}
	old := baseSnapshot()
	old.Sudoers = entries
	new := baseSnapshot()
	new.Sudoers = entries
	r := Compare(old, new)
	for _, c := range r.Changes {
		if c.Section == "sudoers" {
			t.Errorf("unexpected sudoers change: %+v", c)
		}
	}
}

// --- v0.3 Phase E: mounts ---

func TestDiffMountsAdded(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.Mounts = []collector.Mount{
		{Source: "//server/share", MountPoint: "/mnt/share", FSType: "cifs", MountOptions: "relatime,rw"},
	}
	r := Compare(old, new)
	if !hasChange(r, "mounts", "added", "/mnt/share") {
		t.Errorf("expected mounts added '/mnt/share', got %+v", r.Changes)
	}
}

func TestDiffMountsRemoved(t *testing.T) {
	old := baseSnapshot()
	old.Mounts = []collector.Mount{
		{Source: "//server/share", MountPoint: "/mnt/share", FSType: "cifs"},
	}
	new := baseSnapshot()
	r := Compare(old, new)
	if !hasChange(r, "mounts", "removed", "/mnt/share") {
		t.Errorf("expected mounts removed '/mnt/share'")
	}
}

func TestDiffMountsOptionFlip(t *testing.T) {
	// ro → rw is exactly the kind of change R25 should catch.
	old := baseSnapshot()
	old.Mounts = []collector.Mount{
		{Source: "/dev/sda1", MountPoint: "/data", FSType: "ext4", MountOptions: "nosuid,ro"},
	}
	new := baseSnapshot()
	new.Mounts = []collector.Mount{
		{Source: "/dev/sda1", MountPoint: "/data", FSType: "ext4", MountOptions: "nosuid,rw"},
	}
	r := Compare(old, new)
	if !hasChange(r, "mounts", "modified", "/data.mount_options") {
		t.Errorf("expected mounts modified '/data.mount_options', got %+v", r.Changes)
	}
}

func TestDiffMountsFSTypeChange(t *testing.T) {
	old := baseSnapshot()
	old.Mounts = []collector.Mount{
		{Source: "tmpfs", MountPoint: "/run", FSType: "tmpfs"},
	}
	new := baseSnapshot()
	new.Mounts = []collector.Mount{
		{Source: "tmpfs", MountPoint: "/run", FSType: "ramfs"},
	}
	r := Compare(old, new)
	if !hasChange(r, "mounts", "modified", "/run.fs_type") {
		t.Errorf("expected mounts modified '/run.fs_type'")
	}
}

func TestDiffMountsBindMountsKeyedByPointAndSource(t *testing.T) {
	// Two bind mounts targeting the same mount point with different sources
	// must be tracked separately, not merged.
	old := baseSnapshot()
	old.Mounts = []collector.Mount{
		{Source: "/dev/sda1", MountPoint: "/data", FSType: "ext4"},
		{Source: "/dev/sdb1", MountPoint: "/data", FSType: "ext4"},
	}
	new := baseSnapshot()
	new.Mounts = []collector.Mount{
		{Source: "/dev/sda1", MountPoint: "/data", FSType: "ext4"},
	}
	r := Compare(old, new)
	// /dev/sdb1 → /data should appear as removed; /dev/sda1 → /data should be unchanged.
	removedFound := false
	for _, c := range r.Changes {
		if c.Section == "mounts" && c.Type == "removed" && strings.Contains(c.OldValue, "/dev/sdb1") {
			removedFound = true
		}
	}
	if !removedFound {
		t.Errorf("expected removed change for /dev/sdb1 bind mount, got %+v", r.Changes)
	}
}

// --- v0.3 Phase B: kernel modules ---

func TestDiffModulesAdded(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.Modules = []collector.Module{
		{Name: "xfrm_user", Size: 49152},
	}
	r := Compare(old, new)
	if !hasChange(r, "modules", "added", "xfrm_user") {
		t.Errorf("expected modules added 'xfrm_user', got %+v", r.Changes)
	}
}

func TestDiffModulesRemoved(t *testing.T) {
	old := baseSnapshot()
	old.Modules = []collector.Module{
		{Name: "xfrm_user", Size: 49152},
	}
	new := baseSnapshot()
	r := Compare(old, new)
	if !hasChange(r, "modules", "removed", "xfrm_user") {
		t.Errorf("expected modules removed 'xfrm_user'")
	}
}

func TestDiffModulesSizeChange(t *testing.T) {
	// Same module name with different size = .ko file replaced. The rootkit signal.
	old := baseSnapshot()
	old.Modules = []collector.Module{
		{Name: "nf_conntrack", Size: 196608},
	}
	new := baseSnapshot()
	new.Modules = []collector.Module{
		{Name: "nf_conntrack", Size: 200704},
	}
	r := Compare(old, new)
	if !hasChange(r, "modules", "modified", "nf_conntrack.size") {
		t.Errorf("expected modules modified 'nf_conntrack.size', got %+v", r.Changes)
	}
}

func TestDiffModulesDependenciesChange(t *testing.T) {
	old := baseSnapshot()
	old.Modules = []collector.Module{
		{Name: "llc", Size: 16384, Dependencies: []string{"bridge"}},
	}
	new := baseSnapshot()
	new.Modules = []collector.Module{
		{Name: "llc", Size: 16384, Dependencies: []string{"bridge", "stp"}},
	}
	r := Compare(old, new)
	if !hasChange(r, "modules", "modified", "llc.dependencies") {
		t.Errorf("expected modules modified 'llc.dependencies'")
	}
}

func TestDiffModulesUnchanged(t *testing.T) {
	mods := []collector.Module{
		{Name: "bridge", Size: 294912},
		{Name: "llc", Size: 16384, Dependencies: []string{"bridge", "stp"}},
	}
	old := baseSnapshot()
	old.Modules = mods
	new := baseSnapshot()
	new.Modules = mods
	r := Compare(old, new)
	for _, c := range r.Changes {
		if c.Section == "modules" {
			t.Errorf("unexpected modules change on identical input: %+v", c)
		}
	}
}

// --- v0.3 Phase D: cron + timers ---

func TestDiffCronAdded(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.CronJobs = []collector.CronJob{
		{Source: "/etc/cron.d/new", User: "root", Schedule: "@hourly", Command: "/opt/run.sh"},
	}
	r := Compare(old, new)
	if !hasChange(r, "cron", "added", "/etc/cron.d/new") {
		t.Errorf("expected cron added '/etc/cron.d/new', got %+v", r.Changes)
	}
}

func TestDiffCronRemoved(t *testing.T) {
	old := baseSnapshot()
	old.CronJobs = []collector.CronJob{
		{Source: "/etc/crontab", User: "root", Schedule: "01 * * * *", Command: "run-parts /etc/cron.hourly"},
	}
	new := baseSnapshot()
	r := Compare(old, new)
	if !hasChange(r, "cron", "removed", "/etc/crontab") {
		t.Errorf("expected cron removed '/etc/crontab'")
	}
}

func TestDiffCronScheduleEditShowsAddPlusRemove(t *testing.T) {
	// Editing a job's schedule changes the identity tuple, so it appears as
	// a remove of the old and an add of the new — which is exactly what an
	// auditor wants to see (a replacement, not a silent mutation).
	old := baseSnapshot()
	old.CronJobs = []collector.CronJob{
		{Source: "/etc/crontab", User: "root", Schedule: "0 2 * * *", Command: "/opt/backup.sh"},
	}
	new := baseSnapshot()
	new.CronJobs = []collector.CronJob{
		{Source: "/etc/crontab", User: "root", Schedule: "0 4 * * *", Command: "/opt/backup.sh"},
	}
	r := Compare(old, new)
	added, removed := false, false
	for _, c := range r.Changes {
		if c.Section != "cron" {
			continue
		}
		if c.Type == "added" {
			added = true
		}
		if c.Type == "removed" {
			removed = true
		}
	}
	if !added || !removed {
		t.Errorf("expected both added and removed for schedule edit; added=%v removed=%v", added, removed)
	}
}

func TestDiffCronUnchanged(t *testing.T) {
	jobs := []collector.CronJob{
		{Source: "/etc/crontab", User: "root", Schedule: "01 * * * *", Command: "run-parts /etc/cron.hourly"},
	}
	old := baseSnapshot()
	old.CronJobs = jobs
	new := baseSnapshot()
	new.CronJobs = jobs
	r := Compare(old, new)
	for _, c := range r.Changes {
		if c.Section == "cron" {
			t.Errorf("unexpected cron change: %+v", c)
		}
	}
}

func TestDiffTimersAdded(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.Timers = []collector.SystemdTimer{
		{UnitFile: "/etc/systemd/system/foo.timer", OnCalendar: "daily", Unit: "foo.service"},
	}
	r := Compare(old, new)
	if !hasChange(r, "timers", "added", "/etc/systemd/system/foo.timer") {
		t.Errorf("expected timers added, got %+v", r.Changes)
	}
}

func TestDiffTimersOnCalendarChange(t *testing.T) {
	old := baseSnapshot()
	old.Timers = []collector.SystemdTimer{
		{UnitFile: "/etc/systemd/system/foo.timer", OnCalendar: "weekly", Unit: "foo.service"},
	}
	new := baseSnapshot()
	new.Timers = []collector.SystemdTimer{
		{UnitFile: "/etc/systemd/system/foo.timer", OnCalendar: "daily", Unit: "foo.service"},
	}
	r := Compare(old, new)
	if !hasChange(r, "timers", "modified", "/etc/systemd/system/foo.timer.on_calendar") {
		t.Errorf("expected timers modified on_calendar, got %+v", r.Changes)
	}
}

func TestDiffTimersUnchanged(t *testing.T) {
	timers := []collector.SystemdTimer{
		{UnitFile: "/etc/systemd/system/foo.timer", OnCalendar: "daily", Unit: "foo.service"},
	}
	old := baseSnapshot()
	old.Timers = timers
	new := baseSnapshot()
	new.Timers = timers
	r := Compare(old, new)
	for _, c := range r.Changes {
		if c.Section == "timers" {
			t.Errorf("unexpected timers change: %+v", c)
		}
	}
}

// --- v0.3 Phase C: SSH authorized_keys ---

func TestDiffSSHKeysAdded(t *testing.T) {
	old := baseSnapshot()
	new := baseSnapshot()
	new.SSHKeys = []collector.SSHKey{
		{User: "root", Type: "ssh-ed25519", Fingerprint: "SHA256:abc", Comment: "alice@laptop", Source: "/root/.ssh/authorized_keys"},
	}
	r := Compare(old, new)
	if !hasChange(r, "ssh_keys", "added", "root SHA256:abc") {
		t.Errorf("expected ssh_keys added 'root SHA256:abc', got %+v", r.Changes)
	}
}

func TestDiffSSHKeysRemoved(t *testing.T) {
	old := baseSnapshot()
	old.SSHKeys = []collector.SSHKey{
		{User: "alice", Type: "ssh-ed25519", Fingerprint: "SHA256:gone"},
	}
	new := baseSnapshot()
	r := Compare(old, new)
	if !hasChange(r, "ssh_keys", "removed", "alice SHA256:gone") {
		t.Errorf("expected ssh_keys removed, got %+v", r.Changes)
	}
}

func TestDiffSSHKeysFingerprintChangeIsRekey(t *testing.T) {
	// A user replacing their key is a re-key event: fingerprint changes →
	// identity changes → appears as remove + add. This is intentional —
	// auditors want to see both halves of a key rotation.
	old := baseSnapshot()
	old.SSHKeys = []collector.SSHKey{
		{User: "alice", Type: "ssh-ed25519", Fingerprint: "SHA256:old"},
	}
	new := baseSnapshot()
	new.SSHKeys = []collector.SSHKey{
		{User: "alice", Type: "ssh-ed25519", Fingerprint: "SHA256:new"},
	}
	r := Compare(old, new)
	added, removed := false, false
	for _, c := range r.Changes {
		if c.Section != "ssh_keys" {
			continue
		}
		if c.Type == "added" {
			added = true
		}
		if c.Type == "removed" {
			removed = true
		}
	}
	if !added || !removed {
		t.Errorf("expected re-key to surface as add+remove; added=%v removed=%v", added, removed)
	}
}

func TestDiffSSHKeysOptionsChangeIsModified(t *testing.T) {
	// Adding a forced-command restriction to an existing key without changing
	// the key material is a meaningful security event — surface as modified
	// rather than triggering a re-key (the identity tuple is unchanged).
	old := baseSnapshot()
	old.SSHKeys = []collector.SSHKey{
		{User: "deploy", Type: "ssh-ed25519", Fingerprint: "SHA256:same"},
	}
	new := baseSnapshot()
	new.SSHKeys = []collector.SSHKey{
		{User: "deploy", Type: "ssh-ed25519", Fingerprint: "SHA256:same",
			Options: `from="10.0.0.0/8",no-pty`},
	}
	r := Compare(old, new)
	if !hasChange(r, "ssh_keys", "modified", "deploy SHA256:same.options") {
		t.Errorf("expected ssh_keys modified options, got %+v", r.Changes)
	}
}

func TestDiffSSHKeysUnchanged(t *testing.T) {
	keys := []collector.SSHKey{
		{User: "alice", Type: "ssh-ed25519", Fingerprint: "SHA256:xyz", Source: "/home/alice/.ssh/authorized_keys"},
	}
	old := baseSnapshot()
	old.SSHKeys = keys
	new := baseSnapshot()
	new.SSHKeys = keys
	r := Compare(old, new)
	for _, c := range r.Changes {
		if c.Section == "ssh_keys" {
			t.Errorf("unexpected ssh_keys change on identical input: %+v", c)
		}
	}
}
