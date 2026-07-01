package diff

import (
	"fmt"
	"sort"

	"github.com/statedrift/statedrift/internal/collector"
)

// diffHarness compares two AI-agent-harness configuration inventories (v0.8).
//
// Like diffGPU/diffDataplane, a nil side (collector toggled on/off, or the host
// gaining/losing all harness config) emits a single summary line rather than one
// change per element. When both sides are present it reports, keyed by config
// Source (file path), under four sub-sections so the prefix-matching rules engine
// can target each element kind by Section + ChangeType alone (no KeyPattern —
// keys carry file paths, and filepath.Match's `*` does not cross `/`):
//
//   - "harness.permissions" — a *grant gained* (an allow pattern added, or a deny
//     pattern lifted) is "added" (R49, broadening); a grant lost is "removed";
//     default_mode changes are "modified". Modelling the semantics rather than
//     the literal list op means "broadening" is always ChangeType "added".
//   - "harness.mcp" — MCP server added (R50) / removed / fingerprint or transport
//     "modified" (R52, wiring changed).
//   - "harness.hooks" — hook added (R51) / removed / fingerprint "modified" (R53).
//   - "harness.model" — selected model "modified" (R54).
//
// A config file that is entirely new (or removed) is diffed against an empty
// config, so its elements surface as added (or removed) and the element rules
// fire — a new .claude/settings.json that grants a hook should trip R51.
func diffHarness(old, new *collector.HarnessInventory, r *Result) {
	if old == nil && new == nil {
		return
	}
	if old == nil {
		r.Changes = append(r.Changes, Change{"harness", "added", "inventory",
			"", harnessSummary(new), false})
		return
	}
	if new == nil {
		r.Changes = append(r.Changes, Change{"harness", "removed", "inventory",
			harnessSummary(old), "", false})
		return
	}

	oldBySrc := indexHarness(old.Configs)
	newBySrc := indexHarness(new.Configs)
	for _, src := range sortedAddrUnion(harnessSources(oldBySrc), harnessSources(newBySrc)) {
		oc := oldBySrc[src] // zero value = empty config when the source is new
		nc := newBySrc[src] // zero value = empty config when the source is gone
		diffHarnessConfig(src, oc, nc, r)
	}
}

// diffHarnessConfig emits the element-level changes between two configs sharing
// a Source (either may be the zero value when the file was added/removed).
func diffHarnessConfig(src string, o, n collector.HarnessConfig, r *Result) {
	if o.Model != n.Model {
		r.Changes = append(r.Changes, Change{"harness.model", "modified", src + " model",
			o.Model, n.Model, false})
	}
	diffHarnessPerms(src, o.Permissions, n.Permissions, r)
	diffHarnessMCP(src, o.MCPServers, n.MCPServers, r)
	diffHarnessHooks(src, o.Hooks, n.Hooks, r)
}

// diffHarnessPerms reports permission-boundary changes. A grant gained (allow
// added OR deny lifted) is "added"; a grant lost (allow removed OR deny added)
// is "removed"; a default_mode change is "modified".
func diffHarnessPerms(src string, o, n collector.HarnessPerms, r *Result) {
	if o.DefaultMode != n.DefaultMode {
		r.Changes = append(r.Changes, Change{"harness.permissions", "modified", src + " default_mode",
			o.DefaultMode, n.DefaultMode, false})
	}
	for _, p := range stringsMinus(n.Allow, o.Allow) { // allow added → broadened
		r.Changes = append(r.Changes, Change{"harness.permissions", "added", src + " allow " + p,
			"", p, false})
	}
	for _, p := range stringsMinus(o.Deny, n.Deny) { // deny lifted → broadened
		r.Changes = append(r.Changes, Change{"harness.permissions", "added", src + " deny-lifted " + p,
			"", p, false})
	}
	for _, p := range stringsMinus(o.Allow, n.Allow) { // allow removed → narrowed
		r.Changes = append(r.Changes, Change{"harness.permissions", "removed", src + " allow " + p,
			p, "", false})
	}
	for _, p := range stringsMinus(n.Deny, o.Deny) { // deny added → narrowed
		r.Changes = append(r.Changes, Change{"harness.permissions", "removed", src + " deny-added " + p,
			"", p, false})
	}
}

// diffHarnessMCP reports MCP server changes, keyed by server name within a config.
func diffHarnessMCP(src string, o, n []collector.HarnessMCP, r *Result) {
	oByName := indexMCP(o)
	nByName := indexMCP(n)
	for _, name := range sortedAddrUnion(mcpNames(oByName), mcpNames(nByName)) {
		om, inOld := oByName[name]
		nm, inNew := nByName[name]
		switch {
		case inOld && !inNew:
			r.Changes = append(r.Changes, Change{"harness.mcp", "removed", src + " " + name,
				mcpSummary(om), "", false})
		case !inOld && inNew:
			r.Changes = append(r.Changes, Change{"harness.mcp", "added", src + " " + name,
				"", mcpSummary(nm), false})
		default:
			if om.Transport != nm.Transport {
				r.Changes = append(r.Changes, Change{"harness.mcp", "modified", src + " " + name + " transport",
					om.Transport, nm.Transport, false})
			}
			if om.Fingerprint != nm.Fingerprint {
				r.Changes = append(r.Changes, Change{"harness.mcp", "modified", src + " " + name + " fingerprint",
					om.Fingerprint, nm.Fingerprint, false})
			}
		}
	}
}

// diffHarnessHooks reports hook changes, keyed by event+matcher+fingerprint. A
// hook's identity is (event, matcher); a fingerprint change on the same identity
// is a "modified", while a change of event/matcher is a remove + add.
func diffHarnessHooks(src string, o, n []collector.HarnessHook, r *Result) {
	oByID := indexHooks(o)
	nByID := indexHooks(n)
	for _, id := range sortedAddrUnion(hookIDs(oByID), hookIDs(nByID)) {
		oh, inOld := oByID[id]
		nh, inNew := nByID[id]
		switch {
		case inOld && !inNew:
			r.Changes = append(r.Changes, Change{"harness.hooks", "removed", src + " " + id,
				oh.Fingerprint, "", false})
		case !inOld && inNew:
			r.Changes = append(r.Changes, Change{"harness.hooks", "added", src + " " + id,
				"", nh.Fingerprint, false})
		default:
			if oh.Fingerprint != nh.Fingerprint {
				r.Changes = append(r.Changes, Change{"harness.hooks", "modified", src + " " + id + " fingerprint",
					oh.Fingerprint, nh.Fingerprint, false})
			}
		}
	}
}

// harnessSummary renders a one-line roll-up for the nil-side add/remove lines.
func harnessSummary(h *collector.HarnessInventory) string {
	var mcp, hooks int
	for _, c := range h.Configs {
		mcp += len(c.MCPServers)
		hooks += len(c.Hooks)
	}
	return fmt.Sprintf("%d configs, %d MCP servers, %d hooks", len(h.Configs), mcp, hooks)
}

// mcpSummary renders a one-line "<transport>" for added/removed MCP server lines.
func mcpSummary(m collector.HarnessMCP) string {
	if m.Transport != "" {
		return m.Transport
	}
	return m.Name
}

func indexHarness(cs []collector.HarnessConfig) map[string]collector.HarnessConfig {
	m := make(map[string]collector.HarnessConfig, len(cs))
	for _, c := range cs {
		m[c.Source] = c
	}
	return m
}

func harnessSources(m map[string]collector.HarnessConfig) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func indexMCP(ms []collector.HarnessMCP) map[string]collector.HarnessMCP {
	m := make(map[string]collector.HarnessMCP, len(ms))
	for _, s := range ms {
		m[s.Name] = s
	}
	return m
}

func mcpNames(m map[string]collector.HarnessMCP) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// indexHooks keys hooks by their (event, matcher) identity. A duplicate identity
// (same event+matcher, different command) keeps the last — rare, and the
// fingerprint diff still surfaces a change.
func indexHooks(hs []collector.HarnessHook) map[string]collector.HarnessHook {
	m := make(map[string]collector.HarnessHook, len(hs))
	for _, h := range hs {
		m[hookID(h)] = h
	}
	return m
}

func hookIDs(m map[string]collector.HarnessHook) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// hookID is the event/matcher identity of a hook.
func hookID(h collector.HarnessHook) string {
	if h.Matcher == "" {
		return h.Event
	}
	return h.Event + "/" + h.Matcher
}

// stringsMinus returns the elements of a not present in b, preserving a's order.
func stringsMinus(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, s := range b {
		set[s] = true
	}
	var out []string
	for _, s := range a {
		if !set[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
