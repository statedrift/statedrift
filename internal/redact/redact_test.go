package redact

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/statedrift/statedrift/internal/collector"
)

// fixtureSnapshot returns a snapshot populated with at least one entry in
// every Cat B-bearing section, so the per-flag tests can assert on each
// field without re-declaring fixtures.
func fixtureSnapshot() *collector.Snapshot {
	return &collector.Snapshot{
		SchemaVersion: "0.4",
		Host: collector.Host{
			Hostname:  "prod-web-01",
			OS:        "Linux",
			Kernel:    "5.15.0",
			Arch:      "x86_64",
			BootID:    "boot-uuid-12345",
			MachineID: "machine-uuid-67890",
		},
		Network: collector.Network{
			Interfaces: []collector.Interface{
				{
					Name:      "eth0",
					State:     "up",
					MTU:       1500,
					MAC:       "aa:bb:cc:dd:ee:ff",
					Addresses: []string{"10.0.0.5", "fe80::1"},
				},
				{
					Name:      "lo",
					State:     "up",
					MTU:       65536,
					MAC:       "00:00:00:00:00:00",
					Addresses: []string{"127.0.0.1"},
				},
			},
			Routes: []collector.Route{
				{Destination: "default", Gateway: "10.0.0.1", Device: "eth0"},
				{Destination: "10.0.0.0/24", Gateway: "0.0.0.0", Device: "eth0"},
			},
			DNS: collector.DNS{
				Nameservers:   []string{"8.8.8.8", "1.1.1.1"},
				SearchDomains: []string{"example.com", "internal.example.com"},
			},
		},
		ListeningPorts: []collector.ListeningPort{
			{Port: 22, Protocol: "tcp", Address: "0.0.0.0", Process: "sshd"},
			{Port: 443, Protocol: "tcp", Address: "10.0.0.5", Process: "nginx"},
		},
		Connections: []collector.Connection{
			{Protocol: "tcp", LocalAddr: "10.0.0.5", LocalPort: 22, RemoteAddr: "203.0.113.7", RemotePort: 51000, State: "established", Process: "sshd"},
		},
		MulticastGroups: []collector.MulticastGroup{
			{Interface: "eth0", Group: "224.0.0.1"},
		},
		Users: []collector.User{
			{Name: "alice", UID: 1000, GID: 1000, GECOS: "Alice Smith", Home: "/home/alice", Shell: "/bin/bash"},
			{Name: "root", UID: 0, GID: 0, GECOS: "root", Home: "/root", Shell: "/bin/bash"},
		},
		Groups: []collector.Group{
			{Name: "wheel", GID: 10, Members: []string{"alice"}},
			{Name: "alice", GID: 1000, Members: nil},
		},
		Sudoers: []collector.SudoEntry{
			{Source: "/etc/sudoers", Line: "alice ALL=(ALL) NOPASSWD: /usr/bin/systemctl"},
		},
		SSHKeys: []collector.SSHKey{
			{User: "alice", Source: "/home/alice/.ssh/authorized_keys", Type: "ssh-ed25519", Fingerprint: "SHA256:abc123", Comment: "alice@laptop"},
		},
		CronJobs: []collector.CronJob{
			{Source: "/etc/cron.d/backup", User: "root", Schedule: "@daily", Command: "/usr/local/bin/backup.sh"},
		},
		Timers: []collector.SystemdTimer{
			{UnitFile: "/etc/systemd/system/foo.timer", Description: "Run foo daily", OnCalendar: "daily", Unit: "foo.service"},
		},
		Mounts: []collector.Mount{
			{Source: "/dev/sda1", MountPoint: "/", FSType: "ext4", MountOptions: "rw,relatime"},
			{Source: "tmpfs", MountPoint: "/run", FSType: "tmpfs", MountOptions: "rw,nosuid"},
			{Source: "//fileserver/share", MountPoint: "/mnt/share", FSType: "cifs", MountOptions: "rw"},
			{Source: "nfs.example.com:/export", MountPoint: "/mnt/nfs", FSType: "nfs", MountOptions: "rw"},
		},
		Firewall: &collector.Firewall{
			Backend:     "iptables",
			RulesetHash: "deadbeefcafef00d",
			Rules:       2,
			RuleList: []collector.FirewallRule{
				{Table: "ip4 filter", Chain: "INPUT", Rule: "-A INPUT -s 198.51.100.9/32 -p tcp --dport 22 -j ACCEPT"},
				{Table: "ip4 filter", Chain: "INPUT", Rule: "-A INPUT -s 198.51.100.9/32 -p tcp --dport 80 -j ACCEPT"},
			},
		},
	}
}

// snapshotJSON marshals a snapshot deterministically for byte-comparison
// tests. encoding/json sorts map keys, so the output is stable.
func snapshotJSON(t *testing.T, s *collector.Snapshot) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestApplyDeterminism(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef")

	a := fixtureSnapshot()
	b := fixtureSnapshot()

	r1 := NewRedactor(Options{Network: true, Hostnames: true}, salt)
	r2 := NewRedactor(Options{Network: true, Hostnames: true}, salt)

	Apply(a, r1)
	Apply(b, r2)

	if !bytes.Equal(snapshotJSON(t, a), snapshotJSON(t, b)) {
		t.Fatal("Apply is not deterministic: same salt + same input produced different output")
	}
}

func TestApplyPerBundleUniqueness(t *testing.T) {
	saltA := []byte("0000000000000000000000000000000A")
	saltB := []byte("0000000000000000000000000000000B")

	a := fixtureSnapshot()
	b := fixtureSnapshot()

	Apply(a, NewRedactor(Options{Network: true, Hostnames: true}, saltA))
	Apply(b, NewRedactor(Options{Network: true, Hostnames: true}, saltB))

	if a.Host.Hostname == b.Host.Hostname {
		t.Errorf("different salts produced the same hostname hash: %q", a.Host.Hostname)
	}
	if a.Network.Interfaces[0].MAC == b.Network.Interfaces[0].MAC {
		t.Errorf("different salts produced the same MAC hash: %q", a.Network.Interfaces[0].MAC)
	}
}

func TestApplyCrossReferencePreservation(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef")
	s := fixtureSnapshot()

	Apply(s, NewRedactor(Options{Hostnames: true}, salt))

	// "alice" appears as Users[0].Name, Groups[0].Members[0], and
	// SSHKeys[0].User. All three must hash identically so the auditor's
	// referential view of "this user is in this group with this key"
	// survives.
	aliceUser := s.Users[0].Name
	aliceMember := s.Groups[0].Members[0]
	aliceSSH := s.SSHKeys[0].User

	if aliceUser == "alice" {
		t.Fatal("Users[0].Name was not redacted")
	}
	if aliceUser != aliceMember {
		t.Errorf("alice as Users.Name (%q) != alice as Groups.Members (%q)", aliceUser, aliceMember)
	}
	if aliceUser != aliceSSH {
		t.Errorf("alice as Users.Name (%q) != alice as SSHKeys.User (%q)", aliceUser, aliceSSH)
	}
}

func TestApplyTagPrefixIsolation(t *testing.T) {
	// A username "alice" and a hostname "alice" should hash to *different*
	// values because the tag prefix is part of the HMAC input. Otherwise
	// an auditor could correlate "this hostname equals this username."
	salt := []byte("0123456789abcdef0123456789abcdef")
	r := NewRedactor(Options{}, salt)

	asUser := r.tag(tagUser, "alice")
	asHost := r.tag(tagHost, "alice")

	if asUser == asHost {
		t.Errorf("same value under different prefixes hashed identically: %q == %q", asUser, asHost)
	}

	// Sanity: the tag prefix is the literal "user:" / "host:" string.
	if !strings.HasPrefix(asUser, "user:") {
		t.Errorf("expected user: prefix, got %q", asUser)
	}
	if !strings.HasPrefix(asHost, "host:") {
		t.Errorf("expected host: prefix, got %q", asHost)
	}
}

func TestApplyEmptyValuesPassThrough(t *testing.T) {
	salt := []byte("salt")
	r := NewRedactor(Options{}, salt)

	if got := r.tag(tagUser, ""); got != "" {
		t.Errorf("empty value should pass through, got %q", got)
	}
}

func TestApplyNetworkOnlyLeavesUsersAlone(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef")
	s := fixtureSnapshot()

	Apply(s, NewRedactor(Options{Network: true}, salt))

	if s.Users[0].Name != "alice" {
		t.Errorf("Network-only redaction touched Users.Name: %q", s.Users[0].Name)
	}
	if s.Host.Hostname != "prod-web-01" {
		t.Errorf("Network-only redaction touched Host.Hostname: %q", s.Host.Hostname)
	}
	if s.Sudoers[0].Line != "alice ALL=(ALL) NOPASSWD: /usr/bin/systemctl" {
		t.Errorf("Network-only redaction touched Sudoers.Line: %q", s.Sudoers[0].Line)
	}

	// And Network *did* get redacted.
	if s.Network.Interfaces[0].MAC == "aa:bb:cc:dd:ee:ff" {
		t.Error("Network-only redaction did not touch Interfaces.MAC")
	}
	if s.Network.Interfaces[0].Addresses[0] == "10.0.0.5" {
		t.Error("Network-only redaction did not touch Interfaces.Addresses")
	}
}

func TestApplyHostnamesOnlyLeavesNetworkAlone(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef")
	s := fixtureSnapshot()

	Apply(s, NewRedactor(Options{Hostnames: true}, salt))

	if s.Network.Interfaces[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("Hostnames-only redaction touched MAC: %q", s.Network.Interfaces[0].MAC)
	}
	if s.Network.Interfaces[0].Addresses[0] != "10.0.0.5" {
		t.Errorf("Hostnames-only redaction touched Addresses: %q", s.Network.Interfaces[0].Addresses[0])
	}
	if s.Network.DNS.Nameservers[0] != "8.8.8.8" {
		t.Errorf("Hostnames-only redaction touched DNS.Nameservers: %q", s.Network.DNS.Nameservers[0])
	}
	// Firewall rules are network Cat B — --redact-hostnames must leave them alone.
	if strings.HasPrefix(s.Firewall.RuleList[0].Rule, "fw:") {
		t.Errorf("Hostnames-only redaction touched Firewall.RuleList: %q", s.Firewall.RuleList[0].Rule)
	}

	// And Hostnames *did* get redacted.
	if s.Host.Hostname == "prod-web-01" {
		t.Error("Hostnames-only redaction did not touch Host.Hostname")
	}
	if s.Users[0].Name == "alice" {
		t.Error("Hostnames-only redaction did not touch Users.Name")
	}
}

func TestApplyNoFlagsIsNoOp(t *testing.T) {
	salt := []byte("salt")
	want := snapshotJSON(t, fixtureSnapshot())

	got := fixtureSnapshot()
	Apply(got, NewRedactor(Options{}, salt))

	if !bytes.Equal(want, snapshotJSON(t, got)) {
		t.Error("Apply with no flags mutated the snapshot")
	}
}

func TestApplyNilSnapshotAndRedactor(t *testing.T) {
	// Both should be no-ops, not panics.
	Apply(nil, NewRedactor(Options{Network: true}, []byte("x")))
	Apply(fixtureSnapshot(), nil)
}

func TestApplyNetworkFieldsAllCovered(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef")
	s := fixtureSnapshot()

	Apply(s, NewRedactor(Options{Network: true}, salt))

	checks := []struct {
		name string
		got  string
	}{
		{"Interfaces[0].MAC", s.Network.Interfaces[0].MAC},
		{"Interfaces[0].Addresses[0]", s.Network.Interfaces[0].Addresses[0]},
		{"Interfaces[0].Addresses[1]", s.Network.Interfaces[0].Addresses[1]},
		{"Routes[0].Destination", s.Network.Routes[0].Destination},
		{"Routes[0].Gateway", s.Network.Routes[0].Gateway},
		{"Routes[1].Destination", s.Network.Routes[1].Destination},
		{"DNS.Nameservers[0]", s.Network.DNS.Nameservers[0]},
		{"ListeningPorts[0].Address", s.ListeningPorts[0].Address},
		{"ListeningPorts[1].Address", s.ListeningPorts[1].Address},
		{"Connections[0].LocalAddr", s.Connections[0].LocalAddr},
		{"Connections[0].RemoteAddr", s.Connections[0].RemoteAddr},
		{"MulticastGroups[0].Group", s.MulticastGroups[0].Group},
		{"Firewall.RuleList[0].Rule", s.Firewall.RuleList[0].Rule},
		{"Firewall.RuleList[1].Rule", s.Firewall.RuleList[1].Rule},
	}

	for _, c := range checks {
		if c.got == "" {
			t.Errorf("%s was emptied — should be a tagged hash", c.name)
			continue
		}
		if !strings.Contains(c.got, ":") {
			t.Errorf("%s = %q — expected a tagged hash like ip:abc123", c.name, c.got)
		}
	}

	// Firewall table/chain are structural and stay clear; ruleset_hash is
	// already an opaque digest and is not re-redacted.
	if s.Firewall.RuleList[0].Table != "ip4 filter" || s.Firewall.RuleList[0].Chain != "INPUT" {
		t.Errorf("firewall table/chain must not be redacted: %q/%q",
			s.Firewall.RuleList[0].Table, s.Firewall.RuleList[0].Chain)
	}
	if s.Firewall.RulesetHash != "deadbeefcafef00d" {
		t.Errorf("ruleset_hash should not be re-redacted: %q", s.Firewall.RulesetHash)
	}
}

func TestApplyHostnameFieldsAllCovered(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef")
	s := fixtureSnapshot()

	Apply(s, NewRedactor(Options{Hostnames: true}, salt))

	checks := []struct {
		name string
		got  string
	}{
		{"Host.Hostname", s.Host.Hostname},
		{"Host.MachineID", s.Host.MachineID},
		{"Host.BootID", s.Host.BootID},
		{"DNS.SearchDomains[0]", s.Network.DNS.SearchDomains[0]},
		{"Users[0].Name", s.Users[0].Name},
		{"Users[0].Home", s.Users[0].Home},
		{"Users[0].GECOS", s.Users[0].GECOS},
		{"Groups[0].Name", s.Groups[0].Name},
		{"Groups[0].Members[0]", s.Groups[0].Members[0]},
		{"Sudoers[0].Line", s.Sudoers[0].Line},
		{"SSHKeys[0].User", s.SSHKeys[0].User},
		{"SSHKeys[0].Comment", s.SSHKeys[0].Comment},
		{"SSHKeys[0].Source", s.SSHKeys[0].Source},
		{"CronJobs[0].User", s.CronJobs[0].User},
		{"Timers[0].Description", s.Timers[0].Description},
		{"Timers[0].Unit", s.Timers[0].Unit},
	}

	for _, c := range checks {
		if c.got == "" {
			t.Errorf("%s was emptied — should be a tagged hash", c.name)
			continue
		}
		if !strings.Contains(c.got, ":") {
			t.Errorf("%s = %q — expected a tagged hash", c.name, c.got)
		}
	}

	// Fields that must NOT change under --redact-hostnames.
	if s.SSHKeys[0].Fingerprint != "SHA256:abc123" {
		t.Errorf("SSHKeys.Fingerprint should not be redacted (Cat A handling already happened): %q", s.SSHKeys[0].Fingerprint)
	}
	if s.SSHKeys[0].Type != "ssh-ed25519" {
		t.Errorf("SSHKeys.Type should not be redacted: %q", s.SSHKeys[0].Type)
	}
	if s.Sudoers[0].Source != "/etc/sudoers" {
		t.Errorf("Sudoers.Source should not be redacted: %q", s.Sudoers[0].Source)
	}
	if s.Timers[0].UnitFile != "/etc/systemd/system/foo.timer" {
		t.Errorf("Timers.UnitFile should not be redacted: %q", s.Timers[0].UnitFile)
	}
	if s.CronJobs[0].Source != "/etc/cron.d/backup" {
		t.Errorf("CronJobs.Source should not be redacted: %q", s.CronJobs[0].Source)
	}
	if s.CronJobs[0].Command != "/usr/local/bin/backup.sh" {
		t.Errorf("CronJobs.Command should not be touched (Cat A redaction is collect-time): %q", s.CronJobs[0].Command)
	}
}

func TestApplyMountSourcePolicy(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef")
	s := fixtureSnapshot()

	Apply(s, NewRedactor(Options{Hostnames: true}, salt))

	// Local block device — verbatim.
	if s.Mounts[0].Source != "/dev/sda1" {
		t.Errorf("Mounts[0] /dev/sda1 should pass through, got %q", s.Mounts[0].Source)
	}
	// Pseudofs — verbatim.
	if s.Mounts[1].Source != "tmpfs" {
		t.Errorf("Mounts[1] tmpfs should pass through, got %q", s.Mounts[1].Source)
	}
	// SMB share — hashed.
	if s.Mounts[2].Source == "//fileserver/share" {
		t.Error("Mounts[2] //fileserver/share should be hashed")
	}
	if !strings.HasPrefix(s.Mounts[2].Source, "host:") {
		t.Errorf("Mounts[2] expected host: prefix, got %q", s.Mounts[2].Source)
	}
	// NFS export — hashed.
	if s.Mounts[3].Source == "nfs.example.com:/export" {
		t.Error("Mounts[3] nfs.example.com:/export should be hashed")
	}
	if !strings.HasPrefix(s.Mounts[3].Source, "host:") {
		t.Errorf("Mounts[3] expected host: prefix, got %q", s.Mounts[3].Source)
	}

	// Mount points and FSTypes are not touched — they describe local
	// filesystem layout, not host identity.
	if s.Mounts[2].MountPoint != "/mnt/share" {
		t.Errorf("Mounts[2].MountPoint should pass through, got %q", s.Mounts[2].MountPoint)
	}
}

func TestIsNetworkMountSource(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"/dev/sda1", false},
		{"/dev/mapper/vg-root", false},
		{"tmpfs", false},
		{"proc", false},
		{"sysfs", false},
		{"none", false},
		{"overlay", false},
		{"//fileserver/share", true},
		{"//192.168.1.10/backup", true},
		{"nfs.example.com:/export", true},
		{"192.168.1.10:/srv/data", true},
		{"server:/", true},
		{"", false},
	}

	for _, c := range cases {
		if got := IsNetworkMountSource(c.in); got != c.want {
			t.Errorf("IsNetworkMountSource(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestApplyNoLeakOfOriginalValues(t *testing.T) {
	// End-to-end: serialize the redacted snapshot and confirm none of the
	// fixture's literal Cat B values appear anywhere in the output.
	salt := []byte("0123456789abcdef0123456789abcdef")
	s := fixtureSnapshot()
	Apply(s, NewRedactor(Options{Network: true, Hostnames: true}, salt))

	leaks := []string{
		"prod-web-01",
		"boot-uuid-12345",
		"machine-uuid-67890",
		"aa:bb:cc:dd:ee:ff",
		"10.0.0.5",
		"10.0.0.1",
		"8.8.8.8",
		"203.0.113.7",
		"alice",
		"Alice Smith",
		"/home/alice",
		"alice@laptop",
		"//fileserver/share",
		"nfs.example.com:/export",
		"example.com",
		"Run foo daily",
		"foo.service",
		"NOPASSWD",
		"198.51.100.9", // firewall rule embedded IP
	}

	out := snapshotJSON(t, s)
	for _, leak := range leaks {
		if bytes.Contains(out, []byte(leak)) {
			t.Errorf("redacted snapshot leaks %q", leak)
		}
	}
}

func TestApplyFirewallDeterministicWithinBundle(t *testing.T) {
	// Identical rule text hashes identically within a bundle, so an auditor
	// can still diff a redacted ruleset structurally (same value → same hash).
	salt := []byte("0123456789abcdef0123456789abcdef")
	rule := "-A INPUT -s 198.51.100.9/32 -j ACCEPT"
	s := &collector.Snapshot{
		Firewall: &collector.Firewall{
			Backend: "iptables",
			RuleList: []collector.FirewallRule{
				{Table: "ip4 filter", Chain: "INPUT", Rule: rule},
				{Table: "ip4 filter", Chain: "OUTPUT", Rule: rule},
			},
		},
	}
	Apply(s, NewRedactor(Options{Network: true}, salt))

	got0, got1 := s.Firewall.RuleList[0].Rule, s.Firewall.RuleList[1].Rule
	if !strings.HasPrefix(got0, "fw:") {
		t.Fatalf("rule not hashed with fw tag: %q", got0)
	}
	if got0 != got1 {
		t.Errorf("identical rule text should hash identically: %q vs %q", got0, got1)
	}
}

func TestApplyFirewallNilSafe(t *testing.T) {
	// A snapshot with no firewall section (Firewall == nil) must not panic.
	s := &collector.Snapshot{Host: collector.Host{Hostname: "h"}}
	Apply(s, NewRedactor(Options{Network: true}, []byte("salt")))
	if s.Firewall != nil {
		t.Error("nil Firewall should stay nil")
	}
}

func TestApplyTolerantOfMissingSections(t *testing.T) {
	// A snapshot without v0.3 security signal sections (i.e. an old
	// v0.1/v0.2 snapshot replayed under a v0.4 redactor) must not panic.
	s := &collector.Snapshot{
		Host: collector.Host{Hostname: "old-host"},
		Network: collector.Network{
			Interfaces: []collector.Interface{
				{Name: "eth0", MAC: "aa:bb:cc:dd:ee:ff", Addresses: []string{"10.0.0.5"}},
			},
		},
		// All v0.3+ sections nil/empty.
	}
	Apply(s, NewRedactor(Options{Network: true, Hostnames: true}, []byte("salt")))

	if s.Host.Hostname == "old-host" {
		t.Error("Host.Hostname should have been redacted")
	}
}

func TestTagOutputFormat(t *testing.T) {
	r := NewRedactor(Options{}, []byte("0123456789abcdef0123456789abcdef"))
	got := r.tag(tagIP, "10.0.0.5")

	// Format: "<prefix>:<12 hex chars>"
	parts := strings.SplitN(got, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("expected one colon, got %q", got)
	}
	if parts[0] != tagIP {
		t.Errorf("expected prefix %q, got %q", tagIP, parts[0])
	}
	if len(parts[1]) != hashHexLen {
		t.Errorf("expected %d hex chars, got %d in %q", hashHexLen, len(parts[1]), got)
	}
	for _, c := range parts[1] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("non-hex char %q in %q", c, got)
		}
	}
}

func TestOptionsAny(t *testing.T) {
	cases := []struct {
		o    Options
		want bool
	}{
		{Options{}, false},
		{Options{Network: true}, true},
		{Options{Hostnames: true}, true},
		{Options{Network: true, Hostnames: true}, true},
	}
	for _, c := range cases {
		if got := c.o.Any(); got != c.want {
			t.Errorf("Options{Network:%v, Hostnames:%v}.Any() = %v, want %v",
				c.o.Network, c.o.Hostnames, got, c.want)
		}
	}
}
