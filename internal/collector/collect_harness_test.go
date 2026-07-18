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

// writeUserConfig writes a ~/.claude.json fixture into home with the given
// noise value mixed into its high-churn keys.
func writeUserConfig(t *testing.T, home, noise string) {
	t.Helper()
	writeHarnessFile(t, home, ".claude.json", `{
		"firstStartTime": "`+noise+`",
		"cachedGrowthBookFeatures": {"flag": "`+noise+`"},
		"mcpServers": {
			"github": {"command": "npx", "args": ["-y", "server"], "env": {"GITHUB_TOKEN": "`+mcpSecret+`"}}
		},
		"projects": {
			"/home/u/proj": {
				"mcpServers": {"db": {"type": "http", "url": "https://db.example/mcp"}},
				"history": ["`+noise+`"]
			},
			"/home/u/other": {"history": ["no servers here"]}
		}
	}`)
}

func TestCollectHarnessUserScopeClaudeJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeUserConfig(t, home, "noise-a")

	inv, err := collectHarness(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if inv == nil || inv.TotalConfigs != 2 {
		t.Fatalf("expected 2 configs (user scope + one project), got %+v", inv)
	}
	userSrc := filepath.Join(home, ".claude.json")
	if inv.Configs[0].Source != userSrc {
		t.Errorf("user-scope source = %q, want %q", inv.Configs[0].Source, userSrc)
	}
	if got := inv.Configs[0].MCPServers; len(got) != 1 || got[0].Name != "github" || got[0].Transport != "stdio" {
		t.Errorf("user-scope servers = %+v, want one stdio server 'github'", got)
	}
	if want := userSrc + "#/home/u/proj"; inv.Configs[1].Source != want {
		t.Errorf("project source = %q, want %q", inv.Configs[1].Source, want)
	}
	if got := inv.Configs[1].MCPServers; len(got) != 1 || got[0].Name != "db" || got[0].Transport != "http" {
		t.Errorf("project servers = %+v, want one http server 'db'", got)
	}

	blob, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), mcpSecret) {
		t.Error("MCP env secret from ~/.claude.json leaked into the snapshot")
	}
	if strings.Contains(string(blob), "noise-a") {
		t.Error("telemetry/cache content from ~/.claude.json leaked into the snapshot")
	}
}

func TestCollectHarnessUserScopeChurnInvisible(t *testing.T) {
	// The UI/telemetry keys in ~/.claude.json change on every agent run; a
	// noise-only change must produce a byte-identical harness section, or every
	// snapshot on a developer host would carry a spurious diff.
	home := t.TempDir()
	t.Setenv("HOME", home)

	writeUserConfig(t, home, "noise-a")
	before, err := collectHarness(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	writeUserConfig(t, home, "noise-b")
	after, err := collectHarness(config.Default())
	if err != nil {
		t.Fatal(err)
	}

	b1, _ := json.Marshal(before)
	b2, _ := json.Marshal(after)
	if string(b1) != string(b2) {
		t.Errorf("noise-only change altered the harness section:\nbefore: %s\nafter:  %s", b1, b2)
	}
}

func TestParseUserConfigFileMalformedIsNil(t *testing.T) {
	dir := t.TempDir()
	writeHarnessFile(t, dir, ".claude.json", `{ not json `)
	if out := parseUserConfigFile(filepath.Join(dir, ".claude.json")); out != nil {
		t.Errorf("malformed ~/.claude.json should parse to nil, got %+v", out)
	}
	if out := parseUserConfigFile(filepath.Join(dir, "missing.json")); out != nil {
		t.Error("missing file should parse to nil")
	}
	// A file with churn keys but no MCP wiring anywhere yields no entries.
	writeHarnessFile(t, dir, ".claude.json", `{"firstStartTime": "x", "projects": {"/p": {"history": []}}}`)
	if out := parseUserConfigFile(filepath.Join(dir, ".claude.json")); out != nil {
		t.Errorf("wiring-free ~/.claude.json should yield no entries, got %+v", out)
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
