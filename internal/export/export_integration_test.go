//go:build integration

package export

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// extractBundle extracts a tar.gz bundle into destDir and returns the bundle's
// top-level directory name.
func extractBundle(t *testing.T, bundlePath, destDir string) string {
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
	var topDir string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}

		// Track top-level directory
		parts := strings.SplitN(hdr.Name, "/", 2)
		if topDir == "" && parts[0] != "" {
			topDir = parts[0]
		}

		outPath := filepath.Join(destDir, hdr.Name)
		if strings.HasSuffix(hdr.Name, "/") || hdr.Typeflag == tar.TypeDir {
			os.MkdirAll(outPath, 0755)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}

		outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
		if err != nil {
			t.Fatalf("create %s: %v", outPath, err)
		}
		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			t.Fatalf("copy %s: %v", outPath, err)
		}
		outFile.Close()
	}
	return topDir
}

func TestVerifyShStandalonePass(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available, skipping integration test")
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum not available, skipping integration test")
	}

	s := makeTestStore(t)
	bundlePath := t.TempDir() + "/bundle.tar.gz"

	from := time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 22, 23, 59, 59, 0, time.UTC)

	if err := Bundle(s, from, to, bundlePath); err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	extractDir := t.TempDir()
	topDir := extractBundle(t, bundlePath, extractDir)
	if topDir == "" {
		t.Fatal("could not determine bundle top-level directory")
	}

	verifyScript := filepath.Join(extractDir, topDir, "verify.sh")
	if _, err := os.Stat(verifyScript); err != nil {
		t.Fatalf("verify.sh not found: %v", err)
	}

	cmd := exec.Command("bash", verifyScript)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify.sh failed (exit %v):\n%s", err, out)
	}
	if !strings.Contains(string(out), "INTEGRITY VERIFIED") {
		t.Errorf("expected INTEGRITY VERIFIED in output, got:\n%s", out)
	}
}

func TestVerifyShDetectsTamper(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available, skipping integration test")
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum not available, skipping integration test")
	}

	s := makeTestStore(t)
	bundlePath := t.TempDir() + "/bundle.tar.gz"

	from := time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 22, 23, 59, 59, 0, time.UTC)

	if err := Bundle(s, from, to, bundlePath); err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	extractDir := t.TempDir()
	topDir := extractBundle(t, bundlePath, extractDir)

	// Tamper: modify a snapshot file
	chainDir := filepath.Join(extractDir, topDir, "chain")
	entries, err := os.ReadDir(chainDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no chain files found: %v", err)
	}

	snapPath := filepath.Join(chainDir, entries[0].Name())
	data, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}

	// Modify the JSON by altering a field value
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	raw["snapshot_id"] = "tampered"
	tampered, _ := json.Marshal(raw)
	if err := os.WriteFile(snapPath, tampered, 0644); err != nil {
		t.Fatalf("write tampered snapshot: %v", err)
	}

	verifyScript := filepath.Join(extractDir, topDir, "verify.sh")
	cmd := exec.Command("bash", verifyScript)
	out, _ := cmd.CombinedOutput()

	if cmd.ProcessState.ExitCode() != 1 {
		t.Errorf("expected exit code 1 for tampered bundle, got %d\n%s", cmd.ProcessState.ExitCode(), out)
	}
	if !strings.Contains(string(out), "INTEGRITY VIOLATION") {
		t.Errorf("expected INTEGRITY VIOLATION in output, got:\n%s", out)
	}
}

func TestVerifyShQuietFlag(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available, skipping integration test")
	}

	s := makeTestStore(t)
	bundlePath := t.TempDir() + "/bundle.tar.gz"

	from := time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 22, 23, 59, 59, 0, time.UTC)

	if err := Bundle(s, from, to, bundlePath); err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	extractDir := t.TempDir()
	topDir := extractBundle(t, bundlePath, extractDir)
	verifyScript := filepath.Join(extractDir, topDir, "verify.sh")

	cmd := exec.Command("bash", verifyScript, "--quiet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify.sh --quiet failed: %v\n%s", err, out)
	}
	// Quiet mode should only print "PASS"
	trimmed := strings.TrimSpace(string(out))
	if trimmed != "PASS" {
		t.Errorf("--quiet output = %q, want %q", trimmed, "PASS")
	}
}
