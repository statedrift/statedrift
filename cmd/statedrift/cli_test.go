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

// --- baseline ---

// TestCLIBaselinePinShowUnpinRoundtrip exercises the three Phase J
// subcommands: pin a known-good HEAD, show it, then unpin with --force.
// Refusal-without-force is covered separately.
func TestCLIBaselinePinShowUnpinRoundtrip(t *testing.T) {
	store := initStore(t)

	out, errOut, code := sd(t, store, "baseline", "pin", "HEAD")
	if code != 0 {
		t.Fatalf("baseline pin failed (code %d):\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	if !strings.Contains(out, "Baseline pinned") {
		t.Errorf("expected confirmation, got:\n%s", out)
	}

	out, errOut, code = sd(t, store, "baseline", "show")
	if code != 0 {
		t.Fatalf("baseline show failed (code %d):\nstderr: %s", code, errOut)
	}
	for _, marker := range []string{"Hash:", "Snapshot time:", "Pinned at:", "Pinned by uid:"} {
		if !strings.Contains(out, marker) {
			t.Errorf("show output missing %q:\n%s", marker, out)
		}
	}

	if _, _, code := sd(t, store, "baseline", "unpin", "--force"); code != 0 {
		t.Errorf("baseline unpin --force should exit 0, got %d", code)
	}

	if _, _, code := sd(t, store, "baseline", "show"); code == 0 {
		t.Errorf("baseline show after unpin should exit non-zero")
	}
}

// TestCLIBaselinePinRefusesOverwriteWithoutForce locks in Decision #5 of
// V04_BASELINE_PLAN.md: a fat-finger that silently replaces the
// known-good reference is the failure mode this test prevents.
func TestCLIBaselinePinRefusesOverwriteWithoutForce(t *testing.T) {
	store := initStore(t)

	if _, _, code := sd(t, store, "baseline", "pin", "HEAD"); code != 0 {
		t.Fatalf("first pin should succeed, exit %d", code)
	}
	out, errOut, code := sd(t, store, "baseline", "pin", "HEAD")
	if code == 0 {
		t.Fatalf("second pin without --force should fail, got exit 0:\n%s", out)
	}
	if !strings.Contains(errOut, "already pinned") {
		t.Errorf("expected 'already pinned' message, got:\n%s", errOut)
	}

	if _, _, code := sd(t, store, "baseline", "pin", "HEAD", "--force"); code != 0 {
		t.Errorf("pin with --force should succeed, exit %d", code)
	}
}

// TestCLIBaselineUnpinRefusesWithoutForce mirrors the pin guard.
func TestCLIBaselineUnpinRefusesWithoutForce(t *testing.T) {
	store := initStore(t)
	if _, _, code := sd(t, store, "baseline", "pin", "HEAD"); code != 0 {
		t.Fatal("setup pin failed")
	}
	out, errOut, code := sd(t, store, "baseline", "unpin")
	if code == 0 {
		t.Fatalf("unpin without --force should fail, got exit 0:\n%s", out)
	}
	if !strings.Contains(errOut, "destructive") {
		t.Errorf("expected 'destructive' message, got:\n%s", errOut)
	}
}

// TestCLIBaselineCheckAgainstSelfExitsZero locks in the Phase K exit
// contract: pin → check (default HEAD = pinned snap) returns 0
// because there are no material changes between identical snapshots.
func TestCLIBaselineCheckAgainstSelfExitsZero(t *testing.T) {
	store := initStore(t)
	if _, _, code := sd(t, store, "baseline", "pin", "HEAD"); code != 0 {
		t.Fatal("setup pin failed")
	}

	out, errOut, code := sd(t, store, "baseline", "check")
	if code != 0 {
		t.Fatalf("check against self should exit 0, got %d:\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	if !strings.Contains(out, "No drift from baseline") {
		t.Errorf("expected 'No drift' message, got:\n%s", out)
	}
}

// TestCLIBaselineCheckDetectsDrift mutates a snapshot's kernel param,
// pins HEAD~1, and confirms `check` against HEAD exits 1 with a diff.
func TestCLIBaselineCheckDetectsDrift(t *testing.T) {
	store := initStore(t)

	// Pin the older snapshot as the baseline.
	if _, _, code := sd(t, store, "baseline", "pin", "HEAD~1"); code != 0 {
		t.Fatal("setup pin failed")
	}

	// HEAD differs from HEAD~1 only in counter values for this fixture
	// (no material kernel-param changes), so we mutate one kernel
	// param in HEAD on disk via a fresh snap with a manually-edited
	// chain entry. Simpler approach: pin HEAD, take a third snap,
	// then check against the fresh HEAD — which by initStore's design
	// also has only counter deltas. Need actual material drift.
	//
	// Easiest path: mutate the latest chain file's kernel_params in
	// place (chain hash break is fine for this test — we only call
	// `check`, which doesn't run verify).
	chainDir := filepath.Join(store, "chain")
	dateDirs, err := os.ReadDir(chainDir)
	if err != nil {
		t.Fatalf("readdir chain: %v", err)
	}
	var dateDir string
	for _, d := range dateDirs {
		if d.IsDir() && d.Name() != "latest" {
			dateDir = filepath.Join(chainDir, d.Name())
		}
	}
	if dateDir == "" {
		t.Fatal("no date dir found")
	}
	files, err := os.ReadDir(dateDir)
	if err != nil {
		t.Fatalf("readdir date: %v", err)
	}
	// Pick the lexicographically last .json file → newest snapshot.
	var latest string
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".json") && f.Name() > latest {
			latest = f.Name()
		}
	}
	if latest == "" {
		t.Fatal("no snapshot file in date dir")
	}
	latestPath := filepath.Join(dateDir, latest)
	data, err := os.ReadFile(latestPath)
	if err != nil {
		t.Fatalf("read latest: %v", err)
	}
	var snap map[string]interface{}
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Force a material change in the kernel_params section.
	kp, ok := snap["kernel_params"].(map[string]interface{})
	if !ok || kp == nil {
		kp = map[string]interface{}{}
	}
	kp["statedrift.test.flag"] = "drift-induced"
	snap["kernel_params"] = kp
	mutated, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatalf("marshal mutated: %v", err)
	}
	if err := os.WriteFile(latestPath, mutated, 0644); err != nil {
		t.Fatalf("write mutated: %v", err)
	}

	// Now: baseline = HEAD~1 (the original snap-2 entry), target =
	// HEAD (mutated snap-2 plus snap-3 if any). Re-pin against the
	// non-mutated entry. initStore took 2 snaps → HEAD~1 is the
	// genesis from `init`, HEAD is the mutated last snap.
	out, errOut, code := sd(t, store, "baseline", "check")
	if code != 1 {
		t.Errorf("check on drift should exit 1, got %d:\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	if !strings.Contains(out, "statedrift.test.flag") {
		t.Errorf("diff output should mention the new key, got:\n%s", out)
	}
}

// TestCLIBaselineCheckQuietSuppressesOutput verifies that --quiet
// produces no stdout but still sets a meaningful exit code.
func TestCLIBaselineCheckQuietSuppressesOutput(t *testing.T) {
	store := initStore(t)
	if _, _, code := sd(t, store, "baseline", "pin", "HEAD"); code != 0 {
		t.Fatal("setup pin failed")
	}

	out, _, code := sd(t, store, "baseline", "check", "--quiet")
	if code != 0 {
		t.Errorf("--quiet check against self should exit 0, got %d", code)
	}
	if out != "" {
		t.Errorf("--quiet should produce no stdout, got:\n%s", out)
	}
}

// TestCLIBaselineCheckJSONShape verifies the structured output carries
// baseline hash, target timestamp, material/counter counts, and
// changes — the contract a CI consumer scripts against.
func TestCLIBaselineCheckJSONShape(t *testing.T) {
	store := initStore(t)
	if _, _, code := sd(t, store, "baseline", "pin", "HEAD"); code != 0 {
		t.Fatal("setup pin failed")
	}

	out, errOut, code := sd(t, store, "baseline", "check", "--json")
	if code != 0 {
		t.Fatalf("--json check against self should exit 0, got %d:\nstderr: %s", code, errOut)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\nout: %s", err, out)
	}
	for _, key := range []string{"baseline_hash", "baseline_timestamp", "target_timestamp", "material", "counters", "changes"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("JSON output missing key %q", key)
		}
	}
}

// TestCLIBaselineCheckNoBaselineErrors confirms `check` on a freshly-
// initialized store (no pin) produces a clear error and a non-zero
// exit, distinct from "drift detected".
func TestCLIBaselineCheckNoBaselineErrors(t *testing.T) {
	store := initStore(t)
	out, errOut, code := sd(t, store, "baseline", "check")
	if code == 0 {
		t.Fatalf("check without a pinned baseline should fail, got exit 0:\n%s", out)
	}
	if !strings.Contains(errOut, "no baseline pinned") {
		t.Errorf("expected 'no baseline pinned' message, got:\n%s", errOut)
	}
}
