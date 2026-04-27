package collector

import (
	"os"
	"strings"
	"testing"

	"github.com/statedrift/statedrift/internal/config"
)

func TestParseRouteLineDefault(t *testing.T) {
	line := "default via 10.0.1.1 dev eth0 proto dhcp metric 100"
	r := parseRouteLine(line)
	if r == nil {
		t.Fatal("parseRouteLine returned nil")
	}
	if r.Destination != "0.0.0.0/0" {
		t.Errorf("Destination = %q, want %q", r.Destination, "0.0.0.0/0")
	}
	if r.Gateway != "10.0.1.1" {
		t.Errorf("Gateway = %q, want %q", r.Gateway, "10.0.1.1")
	}
	if r.Device != "eth0" {
		t.Errorf("Device = %q, want %q", r.Device, "eth0")
	}
	if r.Protocol != "dhcp" {
		t.Errorf("Protocol = %q, want %q", r.Protocol, "dhcp")
	}
	if r.Metric != 100 {
		t.Errorf("Metric = %d, want 100", r.Metric)
	}
}

func TestParseRouteLineSubnet(t *testing.T) {
	line := "10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.15"
	r := parseRouteLine(line)
	if r == nil {
		t.Fatal("parseRouteLine returned nil")
	}
	if r.Destination != "10.0.1.0/24" {
		t.Errorf("Destination = %q, want %q", r.Destination, "10.0.1.0/24")
	}
	if r.Device != "eth0" {
		t.Errorf("Device = %q, want %q", r.Device, "eth0")
	}
	if r.Gateway != "" {
		t.Errorf("Gateway = %q, want empty", r.Gateway)
	}
}

func TestParseRouteLineTooShort(t *testing.T) {
	if r := parseRouteLine(""); r != nil {
		t.Error("expected nil for empty line")
	}
	if r := parseRouteLine("x y"); r != nil {
		t.Error("expected nil for short line")
	}
}

func TestParseHexAddrPortIPv4Loopback(t *testing.T) {
	// 127.0.0.1:53 → hex 0100007F:0035
	addr, port, err := parseHexAddrPort("0100007F:0035")
	if err != nil {
		t.Fatalf("parseHexAddrPort error: %v", err)
	}
	if addr != "127.0.0.1" {
		t.Errorf("addr = %q, want %q", addr, "127.0.0.1")
	}
	if port != 53 {
		t.Errorf("port = %d, want 53", port)
	}
}

func TestParseHexAddrPortIPv4Any(t *testing.T) {
	// 0.0.0.0:80 → hex 00000000:0050
	addr, port, err := parseHexAddrPort("00000000:0050")
	if err != nil {
		t.Fatalf("parseHexAddrPort error: %v", err)
	}
	if addr != "0.0.0.0" {
		t.Errorf("addr = %q, want %q", addr, "0.0.0.0")
	}
	if port != 80 {
		t.Errorf("port = %d, want 80", port)
	}
}

func TestParseHexAddrPortIPv6Any(t *testing.T) {
	addr, port, err := parseHexAddrPort("00000000000000000000000000000000:1F90")
	if err != nil {
		t.Fatalf("parseHexAddrPort error: %v", err)
	}
	if addr != "::" {
		t.Errorf("addr = %q, want %q", addr, "::")
	}
	if port != 8080 {
		t.Errorf("port = %d, want 8080", port)
	}
}

func TestParseHexAddrPortInvalid(t *testing.T) {
	_, _, err := parseHexAddrPort("nocolon")
	if err == nil {
		t.Error("expected error for input without colon")
	}
}

func TestReadOSReleaseFrom(t *testing.T) {
	f, err := os.CreateTemp("", "os-release-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	content := `ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04 LTS"
`
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	f.Close()

	got := readOSReleaseFrom(f.Name())
	if got != "Ubuntu 22.04 LTS" {
		t.Errorf("readOSReleaseFrom = %q, want %q", got, "Ubuntu 22.04 LTS")
	}
}

func TestReadOSReleaseFromMissingFile(t *testing.T) {
	got := readOSReleaseFrom("/nonexistent/path/os-release")
	if got != "unknown" {
		t.Errorf("readOSReleaseFrom missing file = %q, want %q", got, "unknown")
	}
}

func TestReadOSReleaseFromNoPrettyName(t *testing.T) {
	f, err := os.CreateTemp("", "os-release-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString("ID=myos\nVERSION=1.0\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	f.Close()

	got := readOSReleaseFrom(f.Name())
	if got != "unknown" {
		t.Errorf("readOSReleaseFrom no PRETTY_NAME = %q, want %q", got, "unknown")
	}
}

func TestMatchesAnyExact(t *testing.T) {
	if !matchesAny("docker0", []string{"docker0"}) {
		t.Error("exact match should return true")
	}
}

func TestMatchesAnyGlob(t *testing.T) {
	if !matchesAny("veth1a2b3c", []string{"veth*"}) {
		t.Error("glob veth* should match veth1a2b3c")
	}
	if !matchesAny("br-abc123", []string{"br-*"}) {
		t.Error("glob br-* should match br-abc123")
	}
}

func TestMatchesAnyNoMatch(t *testing.T) {
	if matchesAny("eth0", []string{"veth*", "docker0", "br-*"}) {
		t.Error("eth0 should not match any of the patterns")
	}
}

func TestMatchesAnyEmptyPatterns(t *testing.T) {
	if matchesAny("eth0", []string{}) {
		t.Error("empty patterns should never match")
	}
}

func TestParseRPMOutput(t *testing.T) {
	input := "bash\t5.1.8-6.el9\nglibc\t2.34-60.el9\nkernel\t5.14.0-362.el9\n"
	pkgs := parseRPMOutput(input)

	if len(pkgs) != 3 {
		t.Errorf("expected 3 packages, got %d", len(pkgs))
	}
	if pkgs["bash"] != "5.1.8-6.el9" {
		t.Errorf("bash version = %q, want 5.1.8-6.el9", pkgs["bash"])
	}
	if pkgs["glibc"] != "2.34-60.el9" {
		t.Errorf("glibc version = %q, want 2.34-60.el9", pkgs["glibc"])
	}
	if pkgs["kernel"] != "5.14.0-362.el9" {
		t.Errorf("kernel version = %q, want 5.14.0-362.el9", pkgs["kernel"])
	}
}

func TestParseRPMOutputEmpty(t *testing.T) {
	pkgs := parseRPMOutput("")
	if len(pkgs) != 0 {
		t.Errorf("expected empty map for empty input, got %d entries", len(pkgs))
	}
}

func TestParseRPMOutputSkipsMalformed(t *testing.T) {
	input := "goodpkg\t1.0-1\nnoversion\nskip\n"
	pkgs := parseRPMOutput(input)
	if _, ok := pkgs["goodpkg"]; !ok {
		t.Error("goodpkg should be parsed")
	}
	if _, ok := pkgs["noversion"]; ok {
		t.Error("line without tab should be skipped")
	}
}

func TestSnapshotIDFormat(t *testing.T) {
	// SnapshotID format: snap-YYYYMMDD-HHMMSS-<6hexchars>
	id := "snap-20260322-120000-a1b2c3"
	parts := strings.Split(id, "-")
	if len(parts) != 4 {
		t.Fatalf("expected 4 parts in snapshot ID, got %d", len(parts))
	}
	if parts[0] != "snap" {
		t.Errorf("part[0] = %q, want snap", parts[0])
	}
	if len(parts[1]) != 8 {
		t.Errorf("date part len = %d, want 8", len(parts[1]))
	}
	if len(parts[2]) != 6 {
		t.Errorf("time part len = %d, want 6", len(parts[2]))
	}
	if len(parts[3]) != 6 {
		t.Errorf("hex suffix len = %d, want 6", len(parts[3]))
	}
}

func TestRandomHexLength(t *testing.T) {
	h := randomHex(3)
	if len(h) != 6 {
		t.Errorf("randomHex(3) = %q, want 6 chars", h)
	}
	h2 := randomHex(3)
	// With overwhelming probability two calls differ (1 in 16^6 chance of collision)
	_ = h2 // just verify it doesn't panic
}

func TestCapturesEmptyListCollectsAll(t *testing.T) {
	cfg := &config.Config{Capture: nil}
	for _, section := range []string{"host", "network", "kernel_params", "packages", "services", "listening_ports"} {
		if !captures(cfg, section) {
			t.Errorf("captures(%q) = false with empty Capture list, want true", section)
		}
	}
}

func TestParseIGMPv4Addr(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"010000E0", "224.0.0.1"},   // 224.0.0.1 — all systems
		{"FB0000E0", "224.0.0.251"}, // 224.0.0.251 — mDNS
		{"00000000", "0.0.0.0"},     // degenerate
	}
	for _, tc := range cases {
		got := parseIGMPv4Addr(tc.input)
		if got != tc.want {
			t.Errorf("parseIGMPv4Addr(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseIGMPv6Addr(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"ff020000000000000000000000000001", "ff02::1"},
		{"ff020000000000000000000000000016", "ff02::16"},
	}
	for _, tc := range cases {
		got := parseIGMPv6Addr(tc.input)
		if got != tc.want {
			t.Errorf("parseIGMPv6Addr(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestIsDecimal(t *testing.T) {
	if !isDecimal("1") || !isDecimal("42") {
		t.Error("expected isDecimal to return true for digit strings")
	}
	if isDecimal("") || isDecimal("1a") || isDecimal("0A") {
		t.Error("expected isDecimal to return false for non-digit strings")
	}
}

func TestCollectPartialCarriesForwardPackages(t *testing.T) {
	prev := &Snapshot{
		Packages: map[string]string{"nginx": "1.18.0", "curl": "7.74.0"},
		Services: map[string]string{"sshd.service": "active (running)"},
	}
	// Only network is due; packages and services should be carried forward.
	due := map[string]bool{"network": true}
	cfg := config.Default()
	cfg.Capture = []string{"network", "packages", "services"}

	snap, err := CollectPartial(prev, due, "0000", cfg)
	if err != nil {
		t.Fatalf("CollectPartial error: %v", err)
	}
	if snap.Packages["nginx"] != "1.18.0" {
		t.Errorf("packages not carried forward: got %v", snap.Packages)
	}
	if snap.Services["sshd.service"] != "active (running)" {
		t.Errorf("services not carried forward: got %v", snap.Services)
	}
}

func TestCollectPartialFreshIdentity(t *testing.T) {
	prev := &Snapshot{SnapshotID: "snap-old", PrevHash: "aaa"}
	snap, err := CollectPartial(prev, map[string]bool{}, "bbb", config.Default())
	if err != nil {
		t.Fatalf("CollectPartial error: %v", err)
	}
	if snap.SnapshotID == "snap-old" {
		t.Error("SnapshotID should be freshly generated")
	}
	if snap.PrevHash != "bbb" {
		t.Errorf("PrevHash = %q, want %q", snap.PrevHash, "bbb")
	}
	if snap.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

func TestCollectPartialNoDueNoPanic(t *testing.T) {
	// Empty due map: nothing collected, everything carried forward, no panic.
	prev := &Snapshot{KernelParams: map[string]string{"vm.swappiness": "60"}}
	snap, err := CollectPartial(prev, map[string]bool{}, "hash", config.Default())
	if err != nil {
		t.Fatalf("CollectPartial error: %v", err)
	}
	if snap.KernelParams["vm.swappiness"] != "60" {
		t.Errorf("KernelParams not carried forward")
	}
}

func TestCollectPartialCollectorErrorsClearedEachCall(t *testing.T) {
	prev := &Snapshot{CollectorErrors: []string{"stale error from previous tick"}}
	snap, err := CollectPartial(prev, map[string]bool{}, "hash", config.Default())
	if err != nil {
		t.Fatalf("CollectPartial error: %v", err)
	}
	for _, e := range snap.CollectorErrors {
		if e == "stale error from previous tick" {
			t.Error("CollectorErrors should be reset each call, not carried forward")
		}
	}
}

func TestBuildInodeProcessMapReturnsMap(t *testing.T) {
	// Smoke test: buildInodeProcessMap should return a non-nil map (even if empty
	// because /proc/net is unavailable in the test environment).
	m := buildInodeProcessMap()
	if m == nil {
		t.Error("buildInodeProcessMap should return a non-nil map")
	}
}

func TestCollectListeningPortsNilInodes(t *testing.T) {
	// Passing nil inodes should not panic; Process fields will just be empty.
	ports, err := collectListeningPorts(nil)
	if err != nil {
		t.Fatalf("collectListeningPorts(nil) error: %v", err)
	}
	for _, p := range ports {
		if p.Process != "" {
			t.Errorf("expected empty Process when inodes=nil, got %q", p.Process)
		}
	}
}

func TestCollectConnectionsNilInodes(t *testing.T) {
	// Passing nil inodes should not panic.
	conns, err := collectConnections(nil)
	if err != nil {
		t.Fatalf("collectConnections(nil) error: %v", err)
	}
	// Result may be empty if no connections exist in the test environment.
	_ = conns
}

func TestCapturesRestrictedList(t *testing.T) {
	cfg := &config.Config{Capture: []string{"host", "network"}}
	if !captures(cfg, "host") {
		t.Error("captures(host) = false, want true")
	}
	if !captures(cfg, "network") {
		t.Error("captures(network) = false, want true")
	}
	if captures(cfg, "packages") {
		t.Error("captures(packages) = true, want false (not in list)")
	}
	if captures(cfg, "services") {
		t.Error("captures(services) = true, want false (not in list)")
	}
}
