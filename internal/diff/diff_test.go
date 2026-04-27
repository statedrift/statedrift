package diff

import (
	"strings"
	"testing"

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
