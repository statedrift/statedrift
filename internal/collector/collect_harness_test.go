package collector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/statedrift/statedrift/internal/config"
)

// writeHarnessFile writes content to dir/name for a fixture.
func writeHarnessFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

// harnessCfg builds a config whose only scanned root is dir, and points HOME at
// an empty directory so the default ~/.claude scan finds nothing.
func harnessCfg(t *testing.T, dir string) *config.Config {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	cfg := config.Default()
	cfg.Harness.Roots = []string{dir}
	return cfg
}

const (
	hookSecret = "supersecretcommandvalue"
	mcpSecret  = "ghp_verysecrettokenvalue1234567890123456"
)

func TestCollectHarnessParsesConfig(t *testing.T) {
	dir := t.TempDir()
	writeHarnessFile(t, dir, "settings.json", `{
		"model": "claude-opus-4",
		"permissions": {
			"allow": ["Read(*)", "Bash(npm run *)"],
			"deny": ["Bash(rm *)"],
			"defaultMode": "acceptEdits"
		},
		"hooks": {
			"Stop": [{"matcher": "", "hooks": [{"type": "command", "command": "echo TOKEN=`+hookSecret+` done"}]}]
		}
	}`)
	writeHarnessFile(t, dir, ".mcp.json", `{
		"mcpServers": {
			"github": {"command": "npx", "args": ["-y", "server"], "env": {"GITHUB_TOKEN": "`+mcpSecret+`"}}
		}
	}`)

	inv, err := collectHarness(harnessCfg(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if inv == nil || inv.TotalConfigs != 2 {
		t.Fatalf("expected 2 configs, got %+v", inv)
	}

	var settings, mcp *HarnessConfig
	for i := range inv.Configs {
		switch filepath.Base(inv.Configs[i].Source) {
		case "settings.json":
			settings = &inv.Configs[i]
		case ".mcp.json":
			mcp = &inv.Configs[i]
		}
	}
	if settings == nil || mcp == nil {
		t.Fatal("expected both settings.json and .mcp.json configs")
	}

	if settings.Model != "claude-opus-4" {
		t.Errorf("model = %q, want claude-opus-4", settings.Model)
	}
	if settings.Permissions.DefaultMode != "acceptEdits" {
		t.Errorf("default_mode = %q", settings.Permissions.DefaultMode)
	}
	// Allow list is sorted for stable hashing.
	if len(settings.Permissions.Allow) != 2 || settings.Permissions.Allow[0] != "Bash(npm run *)" {
		t.Errorf("allow not sorted/parsed: %v", settings.Permissions.Allow)
	}
	if len(settings.Hooks) != 1 || settings.Hooks[0].Event != "Stop" || settings.Hooks[0].Fingerprint == "" {
		t.Errorf("hook not parsed: %+v", settings.Hooks)
	}

	if len(mcp.MCPServers) != 1 {
		t.Fatalf("expected 1 MCP server, got %d", len(mcp.MCPServers))
	}
	s := mcp.MCPServers[0]
	if s.Name != "github" || s.Transport != "stdio" || s.Fingerprint == "" {
		t.Errorf("mcp server not parsed: %+v", s)
	}
	if len(s.EnvKeys) != 1 || s.EnvKeys[0] != "GITHUB_TOKEN" {
		t.Errorf("env keys should record the name only: %v", s.EnvKeys)
	}
}

// TestCollectHarnessNeverStoresSecrets is the load-bearing test: no secret value
// (an MCP env value, or a credential embedded in a hook command) may appear
// anywhere in the serialized snapshot section.
func TestCollectHarnessNeverStoresSecrets(t *testing.T) {
	dir := t.TempDir()
	writeHarnessFile(t, dir, "settings.json", `{
		"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "curl -H TOKEN=`+hookSecret+`"}]}]}
	}`)
	writeHarnessFile(t, dir, ".mcp.json", `{
		"mcpServers": {"gh": {"command": "srv", "env": {"API_KEY": "`+mcpSecret+`"}}}
	}`)

	inv, err := collectHarness(harnessCfg(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), hookSecret) {
		t.Error("hook command secret leaked into the snapshot")
	}
	if strings.Contains(string(blob), mcpSecret) {
		t.Error("MCP env secret leaked into the snapshot")
	}
}

func TestCollectHarnessNoConfigYieldsNil(t *testing.T) {
	dir := t.TempDir()
	// An unrelated JSON file with no harness-relevant content must not produce
	// an entry, and no harness files at all must yield a nil section.
	writeHarnessFile(t, dir, "settings.json", `{"unrelated": true, "theme": "dark"}`)

	inv, err := collectHarness(harnessCfg(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if inv != nil {
		t.Errorf("expected nil inventory for content-free config, got %+v", inv)
	}
}

func TestParseHarnessFileMalformedIsNil(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	writeHarnessFile(t, dir, "settings.json", `{ this is not valid json `)
	if hc := parseHarnessFile(path); hc != nil {
		t.Errorf("malformed JSON should parse to nil, got %+v", hc)
	}
	if hc := parseHarnessFile(filepath.Join(dir, "does-not-exist.json")); hc != nil {
		t.Error("missing file should parse to nil")
	}
}

func TestMCPFingerprintStableAcrossSecretRotation(t *testing.T) {
	// Rotating a secret value (same env key) must not change the fingerprint —
	// only a wiring change (command/args/url/env-key-set) should.
	a := ccMCPServer{Command: "srv", Env: map[string]string{"API_KEY": "value-one"}}
	b := ccMCPServer{Command: "srv", Env: map[string]string{"API_KEY": "value-two"}}
	if mcpFingerprint(a) != mcpFingerprint(b) {
		t.Error("fingerprint changed on secret rotation; it must depend on key names only")
	}
	c := ccMCPServer{Command: "srv", Env: map[string]string{"API_KEY": "value-one", "EXTRA": "x"}}
	if mcpFingerprint(a) == mcpFingerprint(c) {
		t.Error("fingerprint must change when an env key is added")
	}
}
