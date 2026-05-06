package export

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/statedrift/statedrift/internal/collector"
	"github.com/statedrift/statedrift/internal/hasher"
	"github.com/statedrift/statedrift/internal/redact"
	"github.com/statedrift/statedrift/internal/store"
)

// makeRedactTestStore writes a 3-snapshot chain populated with realistic
// Cat B identifiers (hostnames, IPs, MACs, usernames, mount sources) so the
// no-leak tests have something to grep against.
func makeRedactTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	s := store.New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	h := hasher.GenesisHash

	for i := 0; i < 3; i++ {
		snap := &collector.Snapshot{
			SchemaVersion: "0.4",
			Version:       "0.4.0",
			SnapshotID:    "snap-redact-test",
			Timestamp:     base.Add(time.Duration(i) * time.Second),
			PrevHash:      h,
			Host: collector.Host{
				Hostname:  "secret-prod-host-01",
				OS:        "Linux",
				Kernel:    "5.15.0",
				Arch:      "x86_64",
				BootID:    "boot-uuid-leakable",
				MachineID: "machine-uuid-leakable",
			},
			KernelParams: map[string]string{"net.ipv4.ip_forward": "0"},
			Packages:     map[string]string{},
			Services:     map[string]string{},
			Network: collector.Network{
				Interfaces: []collector.Interface{
					{
						Name:      "eth0",
						State:     "up",
						MTU:       1500,
						MAC:       "aa:bb:cc:dd:ee:ff",
						Addresses: []string{"10.99.88.77"},
					},
				},
				Routes: []collector.Route{
					{Destination: "default", Gateway: "10.99.88.1", Device: "eth0"},
				},
				DNS: collector.DNS{
					Nameservers:   []string{"203.0.113.53"},
					SearchDomains: []string{"corp.example.com"},
				},
			},
			ListeningPorts: []collector.ListeningPort{
				{Port: 22, Protocol: "tcp", Address: "10.99.88.77", Process: "sshd"},
			},
			Users: []collector.User{
				{Name: "secretuser", UID: 1000, GID: 1000, GECOS: "Secret User", Home: "/home/secretuser", Shell: "/bin/bash"},
			},
			Groups: []collector.Group{
				{Name: "wheel", GID: 10, Members: []string{"secretuser"}},
			},
			Sudoers: []collector.SudoEntry{
				{Source: "/etc/sudoers", Line: "secretuser ALL=(ALL) NOPASSWD: /usr/bin/systemctl"},
			},
			Mounts: []collector.Mount{
				{Source: "/dev/sda1", MountPoint: "/", FSType: "ext4", MountOptions: "rw,relatime"},
				{Source: "//fileserver-secret/share", MountPoint: "/mnt/share", FSType: "cifs", MountOptions: "rw"},
			},
			SSHKeys: []collector.SSHKey{
				{User: "secretuser", Source: "/home/secretuser/.ssh/authorized_keys", Type: "ssh-ed25519", Fingerprint: "SHA256:abc", Comment: "secretuser@laptop"},
			},
		}
		var err error
		h, err = s.Save(snap)
		if err != nil {
			t.Fatalf("Save snap %d: %v", i, err)
		}
	}

	return s
}

// readBundleBytes extracts every regular file from a bundle and returns the
// concatenated bytes — used for "did this literal string leak anywhere"
// grep-style tests.
func readBundleBytes(t *testing.T, bundlePath string) []byte {
	t.Helper()
	f, err := os.Open(bundlePath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)

	var all bytes.Buffer
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Skip the verify scripts — they contain literal English-language
		// strings that may share words with our test fixtures.
		if strings.HasSuffix(hdr.Name, "/verify.sh") || strings.HasSuffix(hdr.Name, "/verify.ps1") {
			io.Copy(io.Discard, tr)
			continue
		}
		if _, err := io.Copy(&all, tr); err != nil {
			t.Fatalf("read body: %v", err)
		}
	}
	return all.Bytes()
}

func TestBundleWithRedactionLeaksNothing(t *testing.T) {
	s := makeRedactTestStore(t)
	out := t.TempDir() + "/redacted.tar.gz"

	from := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 4, 1, 23, 59, 59, 0, time.UTC)

	if err := BundleWith(s, from, to, out, BundleOptions{
		Redaction: redact.Options{Network: true, Hostnames: true},
	}); err != nil {
		t.Fatalf("BundleWith: %v", err)
	}

	body := readBundleBytes(t, out)

	leaks := []string{
		"secret-prod-host-01",
		"boot-uuid-leakable",
		"machine-uuid-leakable",
		"aa:bb:cc:dd:ee:ff",
		"10.99.88.77",
		"10.99.88.1",
		"203.0.113.53",
		"corp.example.com",
		"secretuser",
		"Secret User",
		"//fileserver-secret/share",
		"NOPASSWD",
	}
	for _, leak := range leaks {
		if bytes.Contains(body, []byte(leak)) {
			t.Errorf("redacted bundle leaks %q (bundle bytes contain it)", leak)
		}
	}
}

func TestBundleWithRedactionSelfVerifies(t *testing.T) {
	s := makeRedactTestStore(t)
	out := t.TempDir() + "/redacted.tar.gz"

	from := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 4, 1, 23, 59, 59, 0, time.UTC)

	if err := BundleWith(s, from, to, out, BundleOptions{
		Redaction: redact.Options{Network: true, Hostnames: true},
	}); err != nil {
		t.Fatalf("BundleWith: %v", err)
	}

	count, brokenAt, err := VerifyBundle(out)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
	if brokenAt != -1 {
		t.Errorf("brokenAt = %d, want -1", brokenAt)
	}
}

func TestBundleWithRedactionManifestBlock(t *testing.T) {
	s := makeRedactTestStore(t)
	out := t.TempDir() + "/redacted.tar.gz"

	from := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 4, 1, 23, 59, 59, 0, time.UTC)

	if err := BundleWith(s, from, to, out, BundleOptions{
		Redaction: redact.Options{Network: true, Hostnames: true},
	}); err != nil {
		t.Fatalf("BundleWith: %v", err)
	}

	m := extractManifest(t, out)

	if m.Redaction == nil {
		t.Fatal("manifest.redaction is nil on a redacted bundle")
	}
	if got, want := strings.Join(m.Redaction.Mode, ","), "hostnames,network"; got != want {
		t.Errorf("manifest.redaction.mode = %q, want %q (sorted)", got, want)
	}
	if len(m.Redaction.Salt) != redact.SaltSize*2 {
		t.Errorf("manifest.redaction.salt length = %d, want %d hex chars", len(m.Redaction.Salt), redact.SaltSize*2)
	}
	if _, err := hex.DecodeString(m.Redaction.Salt); err != nil {
		t.Errorf("manifest.redaction.salt is not valid hex: %v", err)
	}
	if m.Redaction.ToolVersion == "" {
		t.Error("manifest.redaction.tool_version is empty")
	}

	// Manifest hostname must also be redacted (it's a Cat B identifier
	// outside the snapshot bodies).
	if m.Hostname == "secret-prod-host-01" {
		t.Errorf("manifest.hostname leaked the original hostname: %q", m.Hostname)
	}
	if !strings.HasPrefix(m.Hostname, "host:") {
		t.Errorf("manifest.hostname not in tagged form, got %q", m.Hostname)
	}
}

func TestBundleUnredactedHasNoRedactionBlock(t *testing.T) {
	s := makeRedactTestStore(t)
	out := t.TempDir() + "/plain.tar.gz"

	from := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 4, 1, 23, 59, 59, 0, time.UTC)

	if err := Bundle(s, from, to, out); err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	m := extractManifest(t, out)
	if m.Redaction != nil {
		t.Errorf("unredacted bundle should not have manifest.redaction, got %+v", m.Redaction)
	}
	if m.Hostname != "secret-prod-host-01" {
		t.Errorf("unredacted manifest.hostname = %q, want verbatim", m.Hostname)
	}
}

func TestBundleWithNetworkOnlyDoesNotRedactUsers(t *testing.T) {
	s := makeRedactTestStore(t)
	out := t.TempDir() + "/net.tar.gz"

	from := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 4, 1, 23, 59, 59, 0, time.UTC)

	if err := BundleWith(s, from, to, out, BundleOptions{
		Redaction: redact.Options{Network: true},
	}); err != nil {
		t.Fatalf("BundleWith: %v", err)
	}

	body := readBundleBytes(t, out)
	// Users should pass through verbatim.
	if !bytes.Contains(body, []byte("secretuser")) {
		t.Error("network-only redaction also removed username — should be untouched")
	}
	// Network identifiers should be gone.
	if bytes.Contains(body, []byte("10.99.88.77")) {
		t.Error("network-only redaction did not remove IP")
	}
	if bytes.Contains(body, []byte("aa:bb:cc:dd:ee:ff")) {
		t.Error("network-only redaction did not remove MAC")
	}
}

func TestBundleWithHostnamesOnlyDoesNotRedactIPs(t *testing.T) {
	s := makeRedactTestStore(t)
	out := t.TempDir() + "/hosts.tar.gz"

	from := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 4, 1, 23, 59, 59, 0, time.UTC)

	if err := BundleWith(s, from, to, out, BundleOptions{
		Redaction: redact.Options{Hostnames: true},
	}); err != nil {
		t.Fatalf("BundleWith: %v", err)
	}

	body := readBundleBytes(t, out)
	// IPs and MACs should pass through verbatim.
	if !bytes.Contains(body, []byte("10.99.88.77")) {
		t.Error("hostnames-only redaction also removed IP — should be untouched")
	}
	if !bytes.Contains(body, []byte("aa:bb:cc:dd:ee:ff")) {
		t.Error("hostnames-only redaction also removed MAC — should be untouched")
	}
	// Usernames and hostnames should be gone.
	if bytes.Contains(body, []byte("secretuser")) {
		t.Error("hostnames-only redaction did not remove username")
	}
	if bytes.Contains(body, []byte("secret-prod-host-01")) {
		t.Error("hostnames-only redaction did not remove hostname")
	}
}

func TestBundleWithRedactionDetectsTamperedSnapshot(t *testing.T) {
	// Even with redaction, verify must still catch downstream tampering of
	// a redacted snapshot. The chain is internally consistent at write
	// time; mutating a redacted snapshot's content breaks the next
	// snapshot's prev_hash check exactly like an unredacted bundle.
	s := makeRedactTestStore(t)
	out := t.TempDir() + "/redacted.tar.gz"

	from := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 4, 1, 23, 59, 59, 0, time.UTC)

	if err := BundleWith(s, from, to, out, BundleOptions{
		Redaction: redact.Options{Network: true, Hostnames: true},
	}); err != nil {
		t.Fatalf("BundleWith: %v", err)
	}

	// Read all entries; mutate the second chain snapshot.
	type entry struct {
		hdr  *tar.Header
		data []byte
	}
	var entries []entry
	in, err := os.Open(out)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	gzr, err := gzip.NewReader(in)
	if err != nil {
		in.Close()
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gzr)
	chainSeen := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if strings.Contains(hdr.Name, "/chain/") && strings.HasSuffix(hdr.Name, ".json") {
			chainSeen++
			if chainSeen == 2 {
				var snap collector.Snapshot
				if err := json.Unmarshal(data, &snap); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				snap.KernelParams["net.ipv4.ip_forward"] = "TAMPERED"
				newData, _ := json.Marshal(&snap)
				data = newData
				hdr.Size = int64(len(data))
			}
		}
		entries = append(entries, entry{hdr: hdr, data: data})
	}
	gzr.Close()
	in.Close()

	tamperedPath := t.TempDir() + "/tampered.tar.gz"
	outF, _ := os.Create(tamperedPath)
	gzw := gzip.NewWriter(outF)
	tw := tar.NewWriter(gzw)
	for _, e := range entries {
		tw.WriteHeader(e.hdr)
		tw.Write(e.data)
	}
	tw.Close()
	gzw.Close()
	outF.Close()

	_, brokenAt, err := VerifyBundle(tamperedPath)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if brokenAt == -1 {
		t.Fatal("VerifyBundle did not detect tampered redacted snapshot")
	}
}

func TestBundleWithRedactionPreservesCrossReferences(t *testing.T) {
	// The same Cat B value (here: "secretuser") appears in Users[0].Name,
	// Groups[0].Members, and SSHKeys[0].User. After redaction with a
	// single salt, all three must hash to the same tagged value.
	s := makeRedactTestStore(t)
	out := t.TempDir() + "/redacted.tar.gz"

	from := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 4, 1, 23, 59, 59, 0, time.UTC)

	if err := BundleWith(s, from, to, out, BundleOptions{
		Redaction: redact.Options{Hostnames: true},
	}); err != nil {
		t.Fatalf("BundleWith: %v", err)
	}

	// Pull the first chain snapshot back out and inspect it.
	f, _ := os.Open(out)
	defer f.Close()
	gzr, _ := gzip.NewReader(f)
	defer gzr.Close()
	tr := tar.NewReader(gzr)

	var snap collector.Snapshot
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		if !strings.Contains(hdr.Name, "/chain/") || !strings.HasSuffix(hdr.Name, ".json") {
			continue
		}
		data, _ := io.ReadAll(tr)
		if err := json.Unmarshal(data, &snap); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		break
	}

	if len(snap.Users) == 0 || len(snap.Groups) == 0 || len(snap.SSHKeys) == 0 {
		t.Fatal("test fixture missing required cross-reference rows")
	}

	user := snap.Users[0].Name
	if !strings.HasPrefix(user, "user:") {
		t.Fatalf("Users[0].Name not redacted: %q", user)
	}
	if len(snap.Groups[0].Members) == 0 || snap.Groups[0].Members[0] != user {
		t.Errorf("cross-reference broken: Users[0].Name=%q vs Groups[0].Members[0]=%v", user, snap.Groups[0].Members)
	}
	if snap.SSHKeys[0].User != user {
		t.Errorf("cross-reference broken: Users[0].Name=%q vs SSHKeys[0].User=%q", user, snap.SSHKeys[0].User)
	}
}
