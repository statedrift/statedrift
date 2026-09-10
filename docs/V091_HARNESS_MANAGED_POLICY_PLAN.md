# v0.9.1 — harness: collect the enterprise managed policy (issue #46)

Status: DONE (this branch).

## Problem

Claude Code resolves permissions by merging scopes with defined precedence;
the highest-precedence scope for managed deployments is the enterprise policy
file — on Linux, `/etc/claude-code/managed-settings.json`. The harness
collector scanned only `settings.json` / `settings.local.json` / `.mcp.json`
under its roots (daemon user's `~/.claude` + `harness.roots`), so the managed
policy was invisible twice over: filename not in the scan set, directory not a
root. A change to the one file that most broadly rewrites what agents on the
host may touch produced zero diff and tripped no rule. Reported by a reviewer
on the launch blog post.

## Decisions (settled — don't relitigate)

- `managed-settings.json` joins `harnessFilenames` (scanned in **every** root:
  harmless where absent, and an operator root carrying one is honored).
- `/etc/claude-code` becomes a default root via package var `managedPolicyDir`
  — a var, not a const, so tests can point it at a fixture. Every test that
  reaches `collectHarness` isolates it (`isolateManagedPolicy` helper),
  closing the same "/etc bleeds into tests" hazard the test audit flagged for
  `/etc/statedrift`.
- No schema change (schema stays 0.5): entries are ordinary `HarnessConfig`
  rows keyed by file path; existing `harness.*` diff sub-sections and rules
  R49–R54 fire unchanged (new/removed file diffs against empty).
- Project-scope config remains opt-in via `harness.roots` — documented
  explicitly in the README collectors table instead of auto-discovered
  (walking every checkout on a host is a cost/noise decision for another day).
- Resolving the *effective merged* config per Claude Code's precedence order
  is deliberately out of scope — roadmap-tier derived section, tracked in the
  issue. Per-file recording stays the base layer: a permission staged in a
  lower-precedence file is still attack-surface change worth recording.

## Changes

- `internal/collector/collect_harness.go` — filename added; `managedPolicyDir`
  var; `harnessRoots` appends it between home root and operator roots.
- `internal/collector/collect_harness_test.go` — `isolateManagedPolicy`
  helper wired into `harnessCfg` and both user-scope tests;
  `TestCollectHarnessManagedPolicy` covers both halves (filename in an
  operator root; default managed-policy dir with no operator roots).
- README collectors table, docs/DESIGN.md sources row, CHANGELOG Unreleased.
