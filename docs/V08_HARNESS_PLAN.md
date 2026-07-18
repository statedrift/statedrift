# v0.8 — AI harness configuration collector (`harness`)

Status: **implemented** (see "Status" at the end for what shipped vs. this
proposal). Free, opt-in, daemon-free.
Follows the `firewall` collector's "parse into structured rules, diff
semantically" pattern — not the `filesystem` collector's "hash the bytes"
pattern. Additive `harness` snapshot section (`omitempty`; old snapshots
deserialize cleanly), so **no schema-version bump** is required for the section
itself — but see "Schema note" below, because this collector carries redacted
fields and that interacts with the export-redaction story.

## Why this exists

In an org where coding/ops agents have real access, **the agent's own
configuration is security-critical infrastructure** — and it currently drifts
unaudited. The signals map cleanly onto primitives statedrift already watches:

| Harness config element            | Equivalent host primitive already covered |
|-----------------------------------|-------------------------------------------|
| Tool permission allow/deny lists  | sudoers — privilege boundary              |
| MCP servers (added endpoint/cmd)  | mounts + connections — new egress/tool    |
| Hooks (event → shell command)     | cron / systemd timers — **persistent code execution** |
| Model / endpoint selection        | data-flow destination                     |

An added Stop-hook is persistent code execution; a new MCP server is new egress
plus new tools; a broadened allowlist is privilege escalation. These are
R17/R19/R23/R39-shaped signals applied to the agent layer.

This is a deliberate scope expansion from host state toward agent/application
configuration state. Note it as such in the release notes so the broadened
remit is explicit.

## Scope decision (v1 is deliberately narrow)

**v1 covers Claude Code's JSON config only.** Rationale, each constraint is real:

1. **Stdlib-only forbids YAML/TOML.** `encoding/json` is in the stdlib; YAML is
   not, and adding a YAML dependency violates the project's stdlib-only rule.
   Claude Code config is JSON (`settings.json`, `.mcp.json`), so it is fully
   parseable with `encoding/json`. Other harnesses (Cursor, Cline, Continue,
   aider) come **later, behind the same collector**, only as their formats are
   JSON-reachable. Do not chase multi-vendor in v1 — format churn across vendors
   is a maintenance treadmill that fights the C-style-simplicity ethos.
2. **Scope is user/project space, not `/etc`.** These files live in `~/.claude/`
   and project `.claude/` trees, not fixed host paths. So discovery is a
   **configurable-roots model like `filesystem`**, not a hardcoded path like
   `modules`. Default roots: the invoking config hierarchy (see "Sources").
3. **Secrets-heavy → collect-time redaction is mandatory (Cat A).** MCP server
   definitions carry API keys/tokens in `env` blocks and inline in `command`
   args/`url`. These are Cat A secrets: **dropped at collect time**, never at
   export — same policy as ssh-key material and cron commands. We store key
   *names* and a content *hash*, never values. See "Redaction" below.

A host with no discoverable harness config yields a **nil** section (omitted),
not an error — the common case, mirroring `gpu`/`dataplane`.

## Sources (the Claude Code config hierarchy, JSON only)

Read as regular files (no `os/exec`, no talking to any running agent):

- `~/.claude/settings.json` — user settings
- `<root>/.claude/settings.json` — project settings
- `<root>/.claude/settings.local.json` — local project overrides
- `<root>/.mcp.json` — project MCP servers
- (enterprise managed settings path — optional, later)

Each parsed file becomes one `HarnessConfig` entry tagged by `Source` (its path),
exactly as `sudoers`/`cron` tag lines by provenance. Roots are configurable;
default is the user home `~/.claude` plus any roots listed in config.

## What it collects (structured, not hashed)

Per source file, the **security-relevant** fields only — not the whole document:

1. **Permissions** — `permissions.allow[]`, `permissions.deny[]`, and the
   default mode. Each entry is a tool/command pattern (e.g. `Bash(npm run *)`).
   This is the privilege boundary; a broadened allow-list or a dropped deny is
   the escalation signal.
2. **MCP servers** — per server: `name`, `transport` (stdio/sse/http), and a
   **redacted fingerprint** of its command/url/env (see Redaction). A new server
   = new tools + new egress. We never store the env values or full command.
3. **Hooks** — per hook: `event` (PreToolUse/PostToolUse/Stop/…), `matcher`, and
   a **redacted fingerprint** of the command. A new/changed hook = code that runs
   automatically; the highest-signal element here.
4. **Model / env** — selected `model` and security-relevant top-level toggles
   (e.g. anything that disables a guardrail). Plain values, no secrets.

## Redaction (Cat A — collect time)

MCP `env`/`command`/`url` and hook `command` strings can embed credentials.
Policy mirrors ssh keys and cron:

- **Values dropped at collect time**, not export. The chain never contains the
  secret in any form.
- For each MCP server and each hook, store **key names** (`env` keys, sorted)
  plus a **SHA-256 fingerprint** of the canonicalized command/url/env, run
  through the existing `redactSecrets` (`internal/collector/redact.go`) first.
  The fingerprint changes iff the underlying definition changes — giving a
  "this MCP server's wiring was altered" diff signal **without** storing what it
  is.
- Therefore **no Category B fields and no plaintext secrets** ever enter the
  snapshot, so — unlike `firewall` — this section needs **no export-time
  redaction flag** and **no DESIGN §4.5 row**. (Confirm during implementation
  that no `permissions` pattern leaks an identifier; allow-list patterns are
  tool globs, not Cat B, so this should hold.)

## Data model (internal/collector/types.go)

```go
type HarnessInventory struct {
    TotalConfigs int             `json:"total_configs"`
    Configs      []HarnessConfig `json:"configs"` // sorted by Source for canonical output
}

type HarnessConfig struct {
    Source      string          `json:"source"`       // file path, provenance
    Tool        string          `json:"tool"`         // "claude-code" (room for others later)
    Model       string          `json:"model,omitempty"`
    Permissions HarnessPerms    `json:"permissions"`
    MCPServers  []HarnessMCP    `json:"mcp_servers,omitempty"`  // sorted by Name
    Hooks       []HarnessHook   `json:"hooks,omitempty"`        // sorted by Event+Matcher
}

type HarnessPerms struct {
    DefaultMode string   `json:"default_mode,omitempty"`
    Allow       []string `json:"allow,omitempty"` // sorted
    Deny        []string `json:"deny,omitempty"`  // sorted
}

type HarnessMCP struct {
    Name        string   `json:"name"`
    Transport   string   `json:"transport,omitempty"`  // stdio|sse|http
    EnvKeys     []string `json:"env_keys,omitempty"`   // names only, sorted; values dropped
    Fingerprint string   `json:"fingerprint"`          // sha256 of redacted command/url/env
}

type HarnessHook struct {
    Event       string `json:"event"`               // PreToolUse|PostToolUse|Stop|...
    Matcher     string `json:"matcher,omitempty"`
    Fingerprint string `json:"fingerprint"`         // sha256 of redacted command
}

// Snapshot.Harness *HarnessInventory `json:"harness,omitempty"`
```

## Diff (internal/diff/diff_harness.go)

nil/nil → nothing. One nil → single summary line (`harness` section), like gpu.
Keyed by `Source`, then by element identity within each config. Use sub-section
names so rules' Section prefix-match keeps the element kinds from colliding
(same trick as `network.interfaces` / `dataplane.pf`):

- `harness.permissions` — a *grant gained* (an allow pattern added, OR a deny
  pattern lifted) is **ChangeType "added"**; a grant lost is "removed";
  `default_mode` changes are "modified". Modelling the semantics rather than the
  literal list op means "broadening" is always "added", so one rule (R49) catches
  both the allow-added and deny-lifted cases without the allow/deny asymmetry the
  proposal worried about.
- `harness.mcp` — server added/removed; per-server `transport`/`fingerprint`
  changes are "modified".
- `harness.hooks` — hook added/removed; `fingerprint` change is "modified".
- `harness.model` — model change is "modified".

Identity choices mirror existing collectors: a permission entry is keyed by its
exact pattern; an MCP server by name; a hook by (event, matcher).

**Implementation note — no `KeyPattern`.** The proposal keyed R52 on
`*.fingerprint`. That does not work: `matchesRule` matches `KeyPattern` with
`filepath.Match`, whose `*` does **not** cross `/`, and harness change keys carry
config **file paths** (with `/`). So every harness rule matches on Section-prefix
+ ChangeType **only**, and the element kinds are separated into distinct
sub-sections instead. This also split the proposal's combined
"MCP_OR_HOOK_CHANGED" into two per-section rules.

## Rules (internal/rules/rules.go) — allocated R49–R54

| ID  | Name                          | Section               | Change    | Severity |
|-----|-------------------------------|-----------------------|-----------|----------|
| R49 | HARNESS_PERMISSION_BROADENED  | `harness.permissions` | added     | High     |
| R50 | HARNESS_MCP_SERVER_ADDED      | `harness.mcp`         | added     | High     |
| R51 | HARNESS_HOOK_ADDED            | `harness.hooks`       | added     | High     |
| R52 | HARNESS_MCP_SERVER_CHANGED    | `harness.mcp`         | modified  | Medium   |
| R53 | HARNESS_HOOK_CHANGED          | `harness.hooks`       | modified  | Medium   |
| R54 | HARNESS_MODEL_CHANGED         | `harness.model`       | modified  | Low      |

All free. After this work, next free rule ID is **R55**. (A permission
*narrowing* and `default_mode` change are visible in the diff but intentionally
have no rule yet — future candidates.)

## Config knob

```go
// Collectors struct — add:
Harness bool `json:"harness"`

// New config block, like Filesystem:
type Harness struct {
    Roots []string `json:"roots"` // extra dirs to scan; ~/.claude always scanned
}
```

(Shipped without the proposed `Tools` field — v1 is Claude-Code-only, so a
harness selector has nothing to select yet. Add it when a second harness lands.)

Gated by `collectors.harness`; off by default. Additive roots, like
`filesystem.roots`.

## Wiring (mirror `dataplane`)

- config: `Collectors.Harness` + `IsEnabled("harness")` + `Harness{Roots}` +
  add `"harness"` to `knownSectionNames`.
- collect.go: gate in `Collect` and `CollectPartial`.
- diff.go: call `diffHarness` when either side non-nil.
- main.go `allWatchSections`: add `"harness"` — cheap file reads, belongs in watch.
- redact.go: reuse `redactSecrets` for the MCP/hook fingerprint inputs.
- CLAUDE.md: document under optional collectors; bump "Next free rule ID" to R55.
- README + CONFIGURATION + DESIGN §4.2 collector table + §4.5 (exempt — no Cat B).

## Schema note

The `harness` section is additive and `omitempty`, so pre-v0.8 snapshots
deserialize unchanged. No schema-version bump for the section. Confirm the
fingerprint-only design holds (no secret, no Cat B) before finalizing — that is
the one assertion the whole "no export redaction needed" claim rests on.

## Open questions

1. **Discovery scope.** Per-user `~/.claude` is straightforward; project
   `.claude` trees across a host are not (which projects? walk where?). v1 may
   limit to explicitly-configured roots + the daemon user's home.
2. **One harness or many.** Ship Claude-Code-only first; add other harnesses
   only as their config formats become JSON-reachable under the stdlib-only
   constraint.
3. **Tier.** `harness` is a collector, and collectors are free-tier.

## Checklist

- [x] types + `Snapshot.Harness` field
- [x] collect_harness.go + test (fake config tree; secrets-never-stored test;
      fingerprint-stable-across-rotation test)
- [x] config wiring (`Collectors.Harness`, `Harness{Roots}`, knownSectionNames)
- [x] collect.go Collect + CollectPartial
- [x] diff_harness.go + diff.go call + test
- [x] rules R49–R54 + test
- [x] allWatchSections
- [x] docs (CLAUDE.md / README / CONFIGURATION / DESIGN §4.2 + §4.5)
- [x] gofmt -w . ; go vet ./... ; go test ./... — all green (full suite exit 0)

## Status: IMPLEMENTED (uncommitted, on branch `feat/v0.8-harness-collector`)

Shipped mostly as proposed. Deltas from the proposal, all recorded above:
- Rules are **R49–R54** (six), not R49–R53 (five): the combined
  "MCP_OR_HOOK_CHANGED" split into R52 (MCP changed) + R53 (hook changed) because
  **no rule can use `KeyPattern`** here — `filepath.Match`'s `*` does not cross
  the `/` in path-bearing keys. Rules match Section-prefix + ChangeType only.
- Permission broadening is modelled semantically (allow-added OR deny-lifted →
  ChangeType "added"), so a single R49 covers both.
- Config `Harness` shipped with `Roots` only; no `Tools` field (v1 is
  Claude-Code-only). Next free rule ID is now **R55**.

## v0.8.2 addendum — user-scope ~/.claude.json (2026-07-18)

Gap found in review: `claude mcp add` (user scope) writes MCP servers to
`~/.claude.json` — a file v1 never scanned, so the most common way a server
gets wired in was invisible. Fix: any scanned root whose basename is
`.claude` also parses the sibling `.claude.json` via a dedicated decoder
(`ccUserConfigFile`) that declares ONLY `mcpServers` and
`projects.*.mcpServers`; every other key (UI state, caches, telemetry —
high-churn) is ignored so noise-only edits yield byte-identical sections
(regression-tested). User-scope servers keep the file path as Source;
per-project servers get `path#project` so each project diffs independently.
R50/R52 fire unchanged (diff keys by Source; rules are section+ChangeType
only). No schema change, no new config knob.
