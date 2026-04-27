// CLI integration tests — verifies that documented command examples work correctly.
// Each test builds the binary once (via TestMain) and exercises real commands
// against a temporary store, so broken CLI examples fail `go test ./...`.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var testBinary string

// TestMain builds the statedrift binary once for all CLI tests.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "statedrift-cli-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: MkdirTemp: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	testBinary = filepath.Join(tmp, "statedrift")
	// Build with CGO_ENABLED=0 for a clean static binary.
	cmd := exec.Command("go", "build", "-o", testBinary, ".")
	cmd.Dir = filepath.Join(".") // cmd/statedrift
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: build failed: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// sd runs the test binary with the given arguments and a temporary store.
// It returns stdout, stderr, and the exit code.
func sd(t *testing.T, store string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(testBinary, args...)
	cmd.Env = append(os.Environ(), "STATEDRIFT_STORE="+store)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			code = -1
		}
	}
	return
}

// initStore creates a temp dir, runs init and two snaps, and returns the store path.
func initStore(t *testing.T) string {
	t.Helper()
	store := t.TempDir()
	if out, errOut, code := sd(t, store, "init"); code != 0 {
		t.Fatalf("init failed (code %d):\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	if out, errOut, code := sd(t, store, "snap"); code != 0 {
		t.Fatalf("snap 1 failed (code %d):\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	if out, errOut, code := sd(t, store, "snap"); code != 0 {
		t.Fatalf("snap 2 failed (code %d):\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	return store
}

// TestCLIShowHEAD verifies: statedrift show HEAD
func TestCLIShowHEAD(t *testing.T) {
	store := initStore(t)
	out, errOut, code := sd(t, store, "show", "HEAD")
	if code != 0 {
		t.Fatalf("show HEAD failed (code %d):\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	if !strings.Contains(out, "Snapshot") {
		t.Errorf("show HEAD: expected 'Snapshot' in output, got:\n%s", out)
	}
}

// TestCLIShowHEADMinus1 verifies: statedrift show HEAD~1
func TestCLIShowHEADMinus1(t *testing.T) {
	store := initStore(t)
	out, errOut, code := sd(t, store, "show", "HEAD~1")
	if code != 0 {
		t.Fatalf("show HEAD~1 failed (code %d):\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	if !strings.Contains(out, "Snapshot") {
		t.Errorf("show HEAD~1: expected 'Snapshot' in output, got:\n%s", out)
	}
}

// TestCLIShowHEADJSON verifies: statedrift show HEAD --json produces valid JSON.
func TestCLIShowHEADJSON(t *testing.T) {
	store := initStore(t)
	out, errOut, code := sd(t, store, "show", "HEAD", "--json")
	if code != 0 {
		t.Fatalf("show HEAD --json failed (code %d):\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	var v map[string]interface{}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("show HEAD --json: output is not valid JSON: %v\noutput:\n%s", err, out)
	}
	if _, ok := v["timestamp"]; !ok {
		t.Errorf("show HEAD --json: missing 'timestamp' field in output")
	}
}

// TestCLIDiffHEAD verifies: statedrift diff HEAD~1 HEAD
func TestCLIDiffHEAD(t *testing.T) {
	store := initStore(t)
	out, errOut, code := sd(t, store, "diff", "HEAD~1", "HEAD")
	if code != 0 {
		t.Fatalf("diff HEAD~1 HEAD failed (code %d):\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	if !strings.Contains(out, "Comparing") {
		t.Errorf("diff HEAD~1 HEAD: expected 'Comparing' in output, got:\n%s", out)
	}
}

// TestCLIDiffHEADJSON verifies: statedrift diff HEAD~1 HEAD --json produces valid JSON.
func TestCLIDiffHEADJSON(t *testing.T) {
	store := initStore(t)
	out, errOut, code := sd(t, store, "diff", "HEAD~1", "HEAD", "--json")
	if code != 0 {
		t.Fatalf("diff HEAD~1 HEAD --json failed (code %d):\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	var v map[string]interface{}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("diff HEAD~1 HEAD --json: output is not valid JSON: %v\noutput:\n%s", err, out)
	}
}

// TestCLIAnalyzeJSON verifies: statedrift analyze --json produces a JSON array (even when empty).
func TestCLIAnalyzeJSON(t *testing.T) {
	store := initStore(t)
	out, errOut, code := sd(t, store, "analyze", "--json")
	if code != 0 {
		t.Fatalf("analyze --json failed (code %d):\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	trimmed := strings.TrimSpace(out)
	// Must be a JSON array, not null.
	if !strings.HasPrefix(trimmed, "[") {
		t.Errorf("analyze --json: expected JSON array, got:\n%s", out)
	}
	var v []interface{}
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		t.Fatalf("analyze --json: output is not a valid JSON array: %v\noutput:\n%s", err, out)
	}
}

// TestCLILogJSON verifies: statedrift log --json produces a JSON array.
func TestCLILogJSON(t *testing.T) {
	store := initStore(t)
	out, errOut, code := sd(t, store, "log", "--json")
	if code != 0 {
		t.Fatalf("log --json failed (code %d):\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	var v []interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &v); err != nil {
		t.Fatalf("log --json: not valid JSON array: %v\noutput:\n%s", err, out)
	}
	// init takes a genesis snapshot, so init + 2 snaps = 3 total.
	if len(v) != 3 {
		t.Errorf("log --json: expected 3 entries (genesis + 2 snaps), got %d", len(v))
	}
}

// TestCLIVerify verifies: statedrift verify exits 0 on a valid chain.
func TestCLIVerify(t *testing.T) {
	store := initStore(t)
	out, errOut, code := sd(t, store, "verify")
	if code != 0 {
		t.Fatalf("verify failed (code %d):\nstdout: %s\nstderr: %s", code, out, errOut)
	}
}

// TestCLIVerifyDetectsCorruptFile verifies that a single unparseable .json file
// in the chain dir produces INTEGRITY VIOLATION (not a green "no snapshots"
// message). Closes the failure mode where store.List() silently skips corrupt
// files and verify falsely reports success.
func TestCLIVerifyDetectsCorruptFile(t *testing.T) {
	store := initStore(t)
	chainDir := filepath.Join(store, "chain")

	// Walk to find any date dir and drop a garbage .json into it.
	dateDirs, err := os.ReadDir(chainDir)
	if err != nil {
		t.Fatalf("read chain dir: %v", err)
	}
	var dateDir string
	for _, d := range dateDirs {
		if d.IsDir() && d.Name() != "latest" {
			dateDir = filepath.Join(chainDir, d.Name())
			break
		}
	}
	if dateDir == "" {
		t.Fatalf("no date dirs found under %s", chainDir)
	}

	corrupt := filepath.Join(dateDir, "999999.999999999.json")
	if err := os.WriteFile(corrupt, []byte("{not valid json"), 0644); err != nil {
		t.Fatalf("writing corrupt snapshot: %v", err)
	}

	out, errOut, code := sd(t, store, "verify")
	if code == 0 {
		t.Fatalf("verify on corrupt store should exit non-zero, got 0\nstdout: %s\nstderr: %s", out, errOut)
	}
	if !strings.Contains(out, "INTEGRITY VIOLATION") {
		t.Errorf("verify output should mention INTEGRITY VIOLATION, got:\n%s", out)
	}
	if !strings.Contains(out, "999999.999999999.json") {
		t.Errorf("verify output should name the corrupt file, got:\n%s", out)
	}
}
