package export

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/statedrift/statedrift/internal/collector"
	"github.com/statedrift/statedrift/internal/hasher"
	"github.com/statedrift/statedrift/internal/store"
)

func makeTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	s := store.New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	base := time.Date(2026, 3, 22, 10, 0, 0, 0, time.UTC)
	h := hasher.GenesisHash

	for i := 0; i < 3; i++ {
		snap := &collector.Snapshot{
			Version:        "0.1.0",
			SnapshotID:     "snap-test",
			Timestamp:      base.Add(time.Duration(i) * time.Second),
			PrevHash:       h,
			Host:           collector.Host{Hostname: "testhost", OS: "Linux", Kernel: "5.15.0"},
			KernelParams:   map[string]string{"net.ipv4.ip_forward": "0"},
			Packages:       map[string]string{},
			Services:       map[string]string{},
			ListeningPorts: []collector.ListeningPort{},
			Network: collector.Network{
				Interfaces: []collector.Interface{},
				Routes:     []collector.Route{},
				DNS:        collector.DNS{},
			},
			// Populate kernel_counters so TestVerifyPs1ParityWithVerifySh
			// exercises mixed-case keys from /proc/net/snmp. Specifically,
			// "ForwDatagrams" / "Forwarding" sort differently under
			// PowerShell's default case-insensitive Sort-Object Name vs.
			// Go's ordinal sort.Strings — without these, the parity test
			// trivially passes even with a buggy verify.ps1.
			KernelCounters: &collector.KernelCounters{
				IP: map[string]uint64{
					"DefaultTTL":    64,
					"ForwDatagrams": 0,
					"Forwarding":    1,
					"FragCreates":   0,
					"FragFails":     0,
					"InAddrErrors":  0,
					"InDelivers":    1000,
					"OutOctets":     123456,
					"OutRequests":   500,
				},
				TCP: map[string]uint64{},
				UDP: map[string]uint64{},
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

func TestBundleCreatesFile(t *testing.T) {
	s := makeTestStore(t)
	outPath := t.TempDir() + "/bundle.tar.gz"

	from := time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 22, 23, 59, 59, 0, time.UTC)

	if err := Bundle(s, from, to, outPath); err != nil {
		t.Fatalf("Bundle error: %v", err)
	}

	fi, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("bundle file not created: %v", err)
	}
	if fi.Size() == 0 {
		t.Error("bundle file is empty")
	}
}

func TestBundleEmptyRangeReturnsError(t *testing.T) {
	s := makeTestStore(t)
	outPath := t.TempDir() + "/empty.tar.gz"

	from := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC)

	if err := Bundle(s, from, to, outPath); err == nil {
		t.Error("expected error for time range with no snapshots")
	}
}

func TestBundleEmptyStoreReturnsError(t *testing.T) {
	dir := t.TempDir()
	s := store.New(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	outPath := t.TempDir() + "/bundle.tar.gz"
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)

	if err := Bundle(s, from, to, outPath); err == nil {
		t.Error("expected error for empty store")
	}
}

func TestVerifyBundleValid(t *testing.T) {
	s := makeTestStore(t)
	outPath := t.TempDir() + "/bundle.tar.gz"

	from := time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 22, 23, 59, 59, 0, time.UTC)

	if err := Bundle(s, from, to, outPath); err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	count, brokenAt, err := VerifyBundle(outPath)
	if err != nil {
		t.Fatalf("VerifyBundle error: %v", err)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
	if brokenAt != -1 {
		t.Errorf("brokenAt = %d, want -1 (valid chain)", brokenAt)
	}
}

func TestVerifyBundleNonexistentFile(t *testing.T) {
	_, _, err := VerifyBundle("/nonexistent/path/bundle.tar.gz")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestVerifyBundleDetectsEmptyBundle(t *testing.T) {
	// Write a valid gzip containing an empty tar
	path := t.TempDir() + "/empty.tar.gz"
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Close immediately — not a valid gzip, but tests error handling
	f.Close()

	_, _, err = VerifyBundle(path)
	if err == nil {
		t.Error("expected error for invalid/empty bundle")
	}
}

func TestManifestFields(t *testing.T) {
	s := makeTestStore(t)
	outPath := t.TempDir() + "/bundle.tar.gz"

	from := time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 22, 23, 59, 59, 0, time.UTC)

	if err := Bundle(s, from, to, outPath); err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	manifest := extractManifest(t, outPath)

	if manifest.Version == "" {
		t.Error("manifest.version is empty")
	}
	if manifest.Hostname == "" {
		t.Error("manifest.hostname is empty")
	}
	if manifest.OS == "" {
		t.Error("manifest.os is empty")
	}
	if manifest.Kernel == "" {
		t.Error("manifest.kernel is empty")
	}
	if manifest.SnapshotCount != 3 {
		t.Errorf("manifest.snapshot_count = %d, want 3", manifest.SnapshotCount)
	}
	if !manifest.ChainVerified {
		t.Error("manifest.chain_verified should be true")
	}
	if manifest.ChainRootHash == "" {
		t.Error("manifest.chain_root_hash is empty")
	}
	if manifest.ChainHeadHash == "" {
		t.Error("manifest.chain_head_hash is empty")
	}
	// 3 snapshots with 1s apart → avg interval = 1s
	if manifest.SnapshotIntervalAvg == "" {
		t.Error("manifest.snapshot_interval_avg is empty for multi-snapshot bundle")
	}
}

func TestBundleFileStructure(t *testing.T) {
	s := makeTestStore(t)
	outPath := t.TempDir() + "/bundle.tar.gz"

	from := time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 22, 23, 59, 59, 0, time.UTC)

	if err := Bundle(s, from, to, outPath); err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	var names []string
	f, _ := os.Open(outPath)
	defer f.Close()
	gzr, _ := gzip.NewReader(f)
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading tar: %v", err)
		}
		names = append(names, hdr.Name)
	}

	hasManifest, hasVerifySh, hasVerifyPs1, hasReadme, chainFiles := false, false, false, false, 0
	for _, n := range names {
		switch {
		case strings.HasSuffix(n, "/manifest.json"):
			hasManifest = true
		case strings.HasSuffix(n, "/verify.sh"):
			hasVerifySh = true
		case strings.HasSuffix(n, "/verify.ps1"):
			hasVerifyPs1 = true
		case strings.HasSuffix(n, "/README.txt"):
			hasReadme = true
		case strings.Contains(n, "/chain/") && strings.HasSuffix(n, ".json"):
			chainFiles++
		}
	}

	if !hasManifest {
		t.Error("bundle missing manifest.json")
	}
	if !hasVerifySh {
		t.Error("bundle missing verify.sh")
	}
	if !hasVerifyPs1 {
		t.Error("bundle missing verify.ps1")
	}
	if !hasReadme {
		t.Error("bundle missing README.txt")
	}
	if chainFiles != 3 {
		t.Errorf("bundle has %d chain JSON files, want 3", chainFiles)
	}
}

func TestVerifyBundleMatchesLocalStore(t *testing.T) {
	s := makeTestStore(t)
	outPath := t.TempDir() + "/bundle.tar.gz"

	from := time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 22, 23, 59, 59, 0, time.UTC)

	if err := Bundle(s, from, to, outPath); err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	// Verify the bundle
	bundleCount, bundleBrokenAt, err := VerifyBundle(outPath)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}

	// Verify the local store
	entries, localBrokenAt, err := s.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	if bundleCount != len(entries) {
		t.Errorf("bundle count %d != store count %d", bundleCount, len(entries))
	}
	if bundleBrokenAt != localBrokenAt {
		t.Errorf("bundle brokenAt %d != store brokenAt %d", bundleBrokenAt, localBrokenAt)
	}
}

// TestVerifyShDetectsManifestMismatch extracts a bundle, mutates manifest's
// chain_root_hash, and runs the embedded verify.sh — catching the symmetric
// gap on the bash side. Skipped if bash, jq, sha256sum, or tar is missing.
func TestVerifyShDetectsManifestMismatch(t *testing.T) {
	for _, tool := range []string{"bash", "jq", "sha256sum", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH; verify.sh test cannot run", tool)
		}
	}

	s := makeTestStore(t)
	bundlePath := t.TempDir() + "/bundle.tar.gz"
	from := time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 22, 23, 59, 59, 0, time.UTC)
	if err := Bundle(s, from, to, bundlePath); err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	// Extract bundle to a temp dir.
	extractDir := t.TempDir()
	cmd := exec.Command("tar", "xzf", bundlePath, "-C", extractDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tar xzf: %v\n%s", err, out)
	}

	// The bundle directory inside is `bundle/` (matches output filename minus .tar.gz).
	bundleDir := filepath.Join(extractDir, "bundle")

	// Sanity: clean run passes.
	out, err := exec.Command("bash", filepath.Join(bundleDir, "verify.sh"), "--quiet").CombinedOutput()
	if err != nil {
		t.Fatalf("baseline verify.sh: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Fatalf("baseline verify.sh did not PASS:\n%s", out)
	}

	// Mutate manifest.chain_root_hash.
	manifestPath := filepath.Join(bundleDir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	m.ChainRootHash = strings.Repeat("0", 64)
	out2, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, out2, 0644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	// Run verify.sh — must fail with manifest mismatch.
	cmd = exec.Command("bash", filepath.Join(bundleDir, "verify.sh"))
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	combined, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify.sh should fail on manifest mismatch, but exited 0:\n%s", combined)
	}
	if !strings.Contains(string(combined), "INTEGRITY VIOLATION") {
		t.Errorf("verify.sh output missing INTEGRITY VIOLATION:\n%s", combined)
	}
	if !strings.Contains(string(combined), "Manifest") {
		t.Errorf("verify.sh output missing Manifest mismatch detail:\n%s", combined)
	}
}

// TestVerifyBundleDetectsManifestRootMismatch flips manifest.chain_root_hash
// inside a valid bundle and confirms VerifyBundle returns ErrManifestMismatch.
// This catches whole-bundle substitution: an attacker who replaces the entire
// bundle with a different internally-consistent chain (and a regenerated
// manifest) is detected only by the manifest cross-check, not by the chain
// walk.
func TestVerifyBundleDetectsManifestRootMismatch(t *testing.T) {
	s := makeTestStore(t)
	outPath := t.TempDir() + "/bundle.tar.gz"

	from := time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 22, 23, 59, 59, 0, time.UTC)

	if err := Bundle(s, from, to, outPath); err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	// Mutate manifest.chain_root_hash. Repackage.
	in, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	gzr, err := gzip.NewReader(in)
	if err != nil {
		in.Close()
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gzr)

	type tarEntry struct {
		hdr  *tar.Header
		data []byte
	}
	var entries []tarEntry
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if strings.HasSuffix(hdr.Name, "/manifest.json") {
			var m Manifest
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatalf("manifest unmarshal: %v", err)
			}
			m.ChainRootHash = strings.Repeat("0", 64) // bogus hash
			newData, err := json.MarshalIndent(&m, "", "  ")
			if err != nil {
				t.Fatalf("marshal manifest: %v", err)
			}
			data = newData
			hdr.Size = int64(len(data))
		}
		entries = append(entries, tarEntry{hdr: hdr, data: data})
	}
	gzr.Close()
	in.Close()

	tamperedPath := t.TempDir() + "/tampered.tar.gz"
	out, err := os.Create(tamperedPath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gzw := gzip.NewWriter(out)
	tw := tar.NewWriter(gzw)
	for _, e := range entries {
		if err := tw.WriteHeader(e.hdr); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatalf("write body: %v", err)
		}
	}
	tw.Close()
	gzw.Close()
	out.Close()

	_, brokenAt, err := VerifyBundle(tamperedPath)
	if !errors.Is(err, ErrManifestMismatch) {
		t.Errorf("expected ErrManifestMismatch, got err=%v brokenAt=%d", err, brokenAt)
	}
	// Internal chain walk should still succeed — only the manifest is wrong.
	if brokenAt != -1 {
		t.Errorf("brokenAt = %d, want -1 (chain still consistent, only manifest mismatched)", brokenAt)
	}
}

// TestVerifyBundleDetectsTamperedSnapshot mutates one chain JSON inside a
// valid bundle, repackages it, and confirms VerifyBundle catches the break.
// Symmetric to store.TestVerifyChainDetectsTamperedSnapshot.
func TestVerifyBundleDetectsTamperedSnapshot(t *testing.T) {
	s := makeTestStore(t)
	outPath := t.TempDir() + "/bundle.tar.gz"

	from := time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 22, 23, 59, 59, 0, time.UTC)

	if err := Bundle(s, from, to, outPath); err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	// Sanity: original bundle verifies cleanly.
	if _, brokenAt, err := VerifyBundle(outPath); err != nil || brokenAt != -1 {
		t.Fatalf("baseline VerifyBundle: brokenAt=%d err=%v, want brokenAt=-1 err=nil", brokenAt, err)
	}

	// Read every entry, mutating the second chain snapshot's kernel param.
	type tarEntry struct {
		hdr  *tar.Header
		data []byte
	}
	var entries []tarEntry

	in, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	gzr, err := gzip.NewReader(in)
	if err != nil {
		in.Close()
		t.Fatalf("gzip reader: %v", err)
	}
	tr := tar.NewReader(gzr)

	chainSeen := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read entry %s: %v", hdr.Name, err)
		}

		isChain := strings.Contains(hdr.Name, "/chain/") && strings.HasSuffix(hdr.Name, ".json")
		if isChain {
			chainSeen++
			if chainSeen == 2 {
				var snap collector.Snapshot
				if err := json.Unmarshal(data, &snap); err != nil {
					t.Fatalf("unmarshal chain entry: %v", err)
				}
				snap.KernelParams["net.ipv4.ip_forward"] = "TAMPERED"
				newData, err := json.MarshalIndent(&snap, "", "  ")
				if err != nil {
					t.Fatalf("re-marshal tampered: %v", err)
				}
				data = newData
				hdr.Size = int64(len(data))
			}
		}
		entries = append(entries, tarEntry{hdr: hdr, data: data})
	}
	gzr.Close()
	in.Close()

	if chainSeen < 2 {
		t.Fatalf("expected at least 2 chain entries, saw %d", chainSeen)
	}

	// Repack into a new tar.gz.
	tamperedPath := t.TempDir() + "/tampered.tar.gz"
	out, err := os.Create(tamperedPath)
	if err != nil {
		t.Fatalf("create tampered: %v", err)
	}
	gzw := gzip.NewWriter(out)
	tw := tar.NewWriter(gzw)
	for _, e := range entries {
		if err := tw.WriteHeader(e.hdr); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatalf("write tar body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	_, brokenAt, err := VerifyBundle(tamperedPath)
	if err != nil {
		t.Fatalf("VerifyBundle on tampered: %v", err)
	}
	if brokenAt == -1 {
		t.Fatal("VerifyBundle did not detect tampered snapshot in bundle")
	}
	// Tamper was the second chain snapshot (index 1). Its hash no longer
	// matches snapshot #2's prev_hash, so the break surfaces at index 2.
	if brokenAt != 2 {
		t.Errorf("brokenAt = %d, want 2", brokenAt)
	}
}

// extractManifest reads manifest.json from a bundle tar.gz.
func extractManifest(t *testing.T, bundlePath string) Manifest {
	t.Helper()
	f, err := os.Open(bundlePath)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		if strings.HasSuffix(hdr.Name, "/manifest.json") {
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatalf("read manifest: %v", err)
			}
			var m Manifest
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatalf("unmarshal manifest: %v", err)
			}
			return m
		}
	}
	t.Fatal("manifest.json not found in bundle")
	return Manifest{}
}

// TestVerifyPs1Structure confirms the embedded verify.ps1 has the expected
// shape: non-empty, mentions key markers, and contains no backticks
// (PowerShell's escape character — Go raw strings cannot contain them, so
// any backtick would mean someone broke the encoding).
func TestVerifyPs1Structure(t *testing.T) {
	s := makeTestStore(t)
	bundlePath := t.TempDir() + "/bundle.tar.gz"
	from := time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 22, 23, 59, 59, 0, time.UTC)
	if err := Bundle(s, from, to, bundlePath); err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	f, err := os.Open(bundlePath)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var ps1 []byte
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		if strings.HasSuffix(hdr.Name, "/verify.ps1") {
			ps1, _ = io.ReadAll(tr)
			break
		}
	}
	if len(ps1) == 0 {
		t.Fatal("verify.ps1 not found or empty in bundle")
	}
	if strings.Contains(string(ps1), "`") {
		t.Error("verify.ps1 contains a backtick — embedded PowerShell must avoid PS escape chars to round-trip through Go raw strings")
	}
	for _, marker := range []string{
		"ConvertTo-CanonicalJson",
		"ConvertTo-CanonicalJsonString",
		"Get-SnapshotHash",
		"chain_root_hash",
		"chain_head_hash",
		"INTEGRITY VERIFIED",
		"INTEGRITY VIOLATION",
	} {
		if !strings.Contains(string(ps1), marker) {
			t.Errorf("verify.ps1 missing expected marker %q", marker)
		}
	}
}

// TestVerifyPs1ParityWithVerifySh extracts a real bundle and runs both
// verify.sh and verify.ps1 on the same content, requiring both to PASS.
// This catches canonical-JSON divergence — the highest-risk parity issue
// between the two verifiers. Skipped if either pwsh, bash, jq, sha256sum,
// or tar is missing from PATH.
func TestVerifyPs1ParityWithVerifySh(t *testing.T) {
	pwshBin := ""
	for _, candidate := range []string{"pwsh", "powershell"} {
		if p, err := exec.LookPath(candidate); err == nil {
			pwshBin = p
			break
		}
	}
	if pwshBin == "" {
		t.Skip("pwsh/powershell not on PATH; verify.ps1 parity test cannot run")
	}
	for _, tool := range []string{"bash", "jq", "sha256sum", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH; verify.sh leg of parity test cannot run", tool)
		}
	}

	s := makeTestStore(t)
	bundlePath := t.TempDir() + "/bundle.tar.gz"
	from := time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 22, 23, 59, 59, 0, time.UTC)
	if err := Bundle(s, from, to, bundlePath); err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	extractDir := t.TempDir()
	if out, err := exec.Command("tar", "xzf", bundlePath, "-C", extractDir).CombinedOutput(); err != nil {
		t.Fatalf("tar xzf: %v\n%s", err, out)
	}
	bundleDir := filepath.Join(extractDir, "bundle")

	// Both must PASS in --quiet mode on the unmodified bundle.
	shOut, err := exec.Command("bash", filepath.Join(bundleDir, "verify.sh"), "--quiet").CombinedOutput()
	if err != nil {
		t.Fatalf("verify.sh: %v\n%s", err, shOut)
	}
	if !strings.Contains(string(shOut), "PASS") {
		t.Fatalf("verify.sh did not PASS:\n%s", shOut)
	}

	ps1Cmd := exec.Command(pwshBin, "-NoProfile", "-File", filepath.Join(bundleDir, "verify.ps1"), "-Quiet")
	ps1Cmd.Env = append(os.Environ(), "NO_COLOR=1")
	ps1Out, err := ps1Cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify.ps1: %v\n%s", err, ps1Out)
	}
	if !strings.Contains(string(ps1Out), "PASS") {
		t.Fatalf("verify.ps1 did not PASS — canonical-JSON likely diverged from verify.sh:\n%s", ps1Out)
	}

	// And both must FAIL on a tampered manifest.
	manifestPath := filepath.Join(bundleDir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	m.ChainRootHash = strings.Repeat("0", 64)
	mutated, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, mutated, 0644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	if out, err := exec.Command("bash", filepath.Join(bundleDir, "verify.sh"), "--quiet").CombinedOutput(); err == nil {
		t.Fatalf("verify.sh should fail on tampered manifest; output:\n%s", out)
	}
	ps1Tampered := exec.Command(pwshBin, "-NoProfile", "-File", filepath.Join(bundleDir, "verify.ps1"), "-Quiet")
	ps1Tampered.Env = append(os.Environ(), "NO_COLOR=1")
	if out, err := ps1Tampered.CombinedOutput(); err == nil {
		t.Fatalf("verify.ps1 should fail on tampered manifest; output:\n%s", out)
	}
}
