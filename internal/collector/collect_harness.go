package collector

// collect_harness.go — v0.8 AI-agent-harness configuration collector.
//
// Parses the JSON config of coding/ops agents installed on the host into
// structured, security-relevant facts — the way collect_firewall parses a
// ruleset, not the way collect_filesystem hashes bytes. v1 covers Claude Code:
// the settings.json hierarchy (user + project + local) and .mcp.json. All reads
// are of regular files with encoding/json; nothing talks to a running agent and
// no os/exec is invoked.
//
// Secrets never enter the chain. MCP server env values and any credentials
// embedded in commands/urls are dropped at collect time (Cat A policy, like ssh
// key material and cron commands): we store env *key names* and a SHA-256
// fingerprint computed over the redacted definition, so a wiring change is
// visible while the secret is not stored in any form.
//
// Gated by the "harness" optional collector; off by default. A host with no
// discoverable harness config yields a nil inventory (the section is omitted),
// not an error — mirroring collectGPU/collectDataplane.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/statedrift/statedrift/internal/config"
)

// harnessFilenames are the config files looked for in each scanned root. All
// three share a JSON superset shape, so one parser handles them uniformly.
var harnessFilenames = []string{"settings.json", "settings.local.json", ".mcp.json"}

// collectHarness discovers and parses harness config under the configured roots
// (plus the daemon user's ~/.claude by default). A root named ".claude" also
// pulls MCP wiring from the sibling ~/.claude.json — the file `claude mcp add`
// writes user-scope servers to. Returns (nil, nil) when nothing is found.
func collectHarness(cfg *config.Config) (*HarnessInventory, error) {
	var configs []HarnessConfig
	seen := make(map[string]bool)
	for _, root := range harnessRoots(cfg) {
		for _, name := range harnessFilenames {
			path := filepath.Join(root, name)
			if seen[path] {
				continue
			}
			seen[path] = true
			if hc := parseHarnessFile(path); hc != nil {
				configs = append(configs, *hc)
			}
		}
		if cleaned := filepath.Clean(root); filepath.Base(cleaned) == ".claude" {
			path := cleaned + ".json"
			if !seen[path] {
				seen[path] = true
				configs = append(configs, parseUserConfigFile(path)...)
			}
		}
	}
	if len(configs) == 0 {
		return nil, nil
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].Source < configs[j].Source })
	return &HarnessInventory{TotalConfigs: len(configs), Configs: configs}, nil
}

// harnessRoots returns the directories scanned for harness config: the daemon
// user's ~/.claude (best-effort — skipped if the home dir is unknown) followed
// by any operator-configured roots. Roots are directories; each is scanned for
// the harnessFilenames.
func harnessRoots(cfg *config.Config) []string {
	var roots []string
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		roots = append(roots, filepath.Join(home, ".claude"))
	}
	roots = append(roots, cfg.Harness.Roots...)
	return roots
}

// ccConfigFile is the parsed superset of the Claude Code config files. Fields
// absent in a given file (e.g. mcpServers in settings.json, or permissions in
// .mcp.json) simply unmarshal to their zero value.
type ccConfigFile struct {
	Model       string                     `json:"model"`
	Permissions *ccPermissions             `json:"permissions"`
	Hooks       map[string][]ccHookMatcher `json:"hooks"`
	MCPServers  map[string]ccMCPServer     `json:"mcpServers"`
}

type ccPermissions struct {
	Allow       []string `json:"allow"`
	Deny        []string `json:"deny"`
	DefaultMode string   `json:"defaultMode"`
}

type ccHookMatcher struct {
	Matcher string        `json:"matcher"`
	Hooks   []ccHookEntry `json:"hooks"`
}

type ccHookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

type ccMCPServer struct {
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	URL     string            `json:"url"`
	Env     map[string]string `json:"env"`
}

// parseHarnessFile reads and parses one config file into a HarnessConfig.
// Returns nil for a missing file, malformed JSON (defensive — a hand-edited or
// future-schema file must not fail the whole snapshot), or a file with no
// security-relevant content.
func parseHarnessFile(path string) *HarnessConfig {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var f ccConfigFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil
	}

	hc := HarnessConfig{Source: path, Tool: "claude-code", Model: f.Model}

	if f.Permissions != nil {
		hc.Permissions = HarnessPerms{
			DefaultMode: f.Permissions.DefaultMode,
			Allow:       sortedCopy(f.Permissions.Allow),
			Deny:        sortedCopy(f.Permissions.Deny),
		}
	}

	hc.MCPServers = mcpList(f.MCPServers)

	for event, groups := range f.Hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				hc.Hooks = append(hc.Hooks, HarnessHook{
					Event:       event,
					Matcher:     g.Matcher,
					Fingerprint: hookFingerprint(h.Command),
				})
			}
		}
	}
	sort.Slice(hc.Hooks, func(i, j int) bool {
		if hc.Hooks[i].Event != hc.Hooks[j].Event {
			return hc.Hooks[i].Event < hc.Hooks[j].Event
		}
		if hc.Hooks[i].Matcher != hc.Hooks[j].Matcher {
			return hc.Hooks[i].Matcher < hc.Hooks[j].Matcher
		}
		return hc.Hooks[i].Fingerprint < hc.Hooks[j].Fingerprint
	})

	if harnessConfigEmpty(hc) {
		return nil
	}
	return &hc
}

// ccUserConfigFile is the slice of ~/.claude.json that carries privilege
// signal. The file also holds UI state, caches, and telemetry that churn on
// every agent run — recording any of that would break the quiet-snapshot
// property, so only MCP wiring (user scope and per-project) is declared here
// and everything else is ignored by the decoder.
type ccUserConfigFile struct {
	MCPServers map[string]ccMCPServer   `json:"mcpServers"`
	Projects   map[string]ccUserProject `json:"projects"`
}

type ccUserProject struct {
	MCPServers map[string]ccMCPServer `json:"mcpServers"`
}

// parseUserConfigFile extracts MCP wiring from a Claude Code user-scope config
// (~/.claude.json). User-scope servers become one entry keyed by the file path;
// each project with servers becomes its own "path#project" entry so its wiring
// diffs independently. Missing or malformed files yield nil, like
// parseHarnessFile.
func parseUserConfigFile(path string) []HarnessConfig {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var f ccUserConfigFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil
	}

	var out []HarnessConfig
	if servers := mcpList(f.MCPServers); len(servers) > 0 {
		out = append(out, HarnessConfig{Source: path, Tool: "claude-code", MCPServers: servers})
	}
	for proj, p := range f.Projects {
		if servers := mcpList(p.MCPServers); len(servers) > 0 {
			out = append(out, HarnessConfig{Source: path + "#" + proj, Tool: "claude-code", MCPServers: servers})
		}
	}
	return out
}

// mcpList converts a parsed mcpServers map into the stored, name-sorted form.
func mcpList(servers map[string]ccMCPServer) []HarnessMCP {
	var out []HarnessMCP
	for name, s := range servers {
		out = append(out, HarnessMCP{
			Name:        name,
			Transport:   mcpTransport(s),
			EnvKeys:     sortedKeys(s.Env),
			Fingerprint: mcpFingerprint(s),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// harnessConfigEmpty reports whether a parsed config carries no
// security-relevant content (so an unrelated JSON file is skipped rather than
// recorded as an empty entry).
func harnessConfigEmpty(hc HarnessConfig) bool {
	return hc.Model == "" &&
		hc.Permissions.DefaultMode == "" &&
		len(hc.Permissions.Allow) == 0 &&
		len(hc.Permissions.Deny) == 0 &&
		len(hc.MCPServers) == 0 &&
		len(hc.Hooks) == 0
}

// mcpTransport returns the server's transport, using the explicit "type" when
// set and otherwise inferring from which of command/url is present.
func mcpTransport(s ccMCPServer) string {
	switch {
	case s.Type != "":
		return s.Type
	case s.Command != "":
		return "stdio"
	case s.URL != "":
		return "http"
	default:
		return ""
	}
}

// mcpFingerprint is a SHA-256 over the redacted wiring of an MCP server: its
// command, args, url, transport, and env *key names* (never values). Redacting
// before hashing means an inline credential is not committed even as a hash, and
// rotating a secret value does not change the fingerprint — only a genuine
// wiring change (new command/endpoint, added/removed env key) does.
func mcpFingerprint(s ccMCPServer) string {
	var b strings.Builder
	b.WriteString("cmd=" + redactSecrets(s.Command) + "\n")
	for _, a := range s.Args {
		b.WriteString("arg=" + redactSecrets(a) + "\n")
	}
	b.WriteString("url=" + redactSecrets(s.URL) + "\n")
	b.WriteString("transport=" + mcpTransport(s) + "\n")
	for _, k := range sortedKeys(s.Env) {
		b.WriteString("env=" + k + "\n") // key name only; value is a secret, dropped
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// hookFingerprint is a SHA-256 over the redacted hook command.
func hookFingerprint(command string) string {
	sum := sha256.Sum256([]byte(redactSecrets(command)))
	return hex.EncodeToString(sum[:])
}

// sortedCopy returns a sorted copy of s (never aliases the input).
func sortedCopy(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}

// sortedKeys returns the sorted keys of m.
func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
