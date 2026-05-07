# v0.4 Baseline Plan — `statedrift baseline`

Status: Redaction shipped (PR #6 `f7153a1`). This document plans the next
v0.4 deliverable: `statedrift baseline pin / check / show / unpin` for
compliance-grade drift detection.

Scope is **strictly compliance baseline**: one pinned snapshot + diff.
Behavioral baselines (time/load/cycle conditions) are explicitly v0.5+ via
`when`/`expected` clauses on rules — see "Out of scope — behavioral
baselines" below.

The remaining v0.4 themes — SELinux / AppArmor enforcement state and
firewall rule hashing — are tracked in `ROADMAP.md` and get their own
plan docs when their phase opens.

## Goal

Let an operator pin a known-good snapshot as the compliance reference,
then ask "are we still in compliance?" at any later point: run
`statedrift baseline check`, see a structural diff against the pinned
baseline, and get a non-zero exit code if there's drift. Suitable for CI
gates, compliance dashboards, and "show me everything that changed since
the last audited state" workflows.

## Storage

A new file at `<store>/baseline.json` (sibling to `chain/` and `head`).
The pinned snapshot is **copied**, not referenced — the baseline survives
chain GC and an auditor can read it self-contained without chasing into
the chain directory.

Wrapper format:

```json
{
  "pinned_at":      "2026-05-07T01:30:00Z",
  "pinned_by_uid":  0,
  "snapshot_hash":  "sha256...",
  "tool_version":   "0.4.0",
  "snapshot":       { ... full Snapshot JSON ... }
}
```

`snapshot_hash` is the canonical-JSON hash of the embedded snapshot,
computed via `internal/hasher.Hash` — anyone can verify the wrapper is
internally consistent by re-hashing the embedded snapshot and comparing.

**Why a wrapper rather than a bare snapshot file?** The pin metadata
(when, by whom) is operationally meaningful but doesn't belong in the
snapshot itself (it'd corrupt the chain hash if ever fed back in). The
wrapper keeps pin metadata cleanly separated.

## Subcommands

| Command | Behavior |
|---|---|
| `baseline pin <ref>` | Resolve ref (`HEAD`, `HEAD~N`, hash prefix — same parser as `show`/`diff`), copy the snapshot into `baseline.json`, report the pinned hash. Refuses to overwrite an existing pin without `--force`. |
| `baseline show` | Print pin metadata (hash, original timestamp, pinned-at, pinned-by-uid). Optionally takes `--full` to also dump the embedded snapshot (matches `cmdShow` rendering). |
| `baseline check [ref]` | Diff the pinned baseline against `ref` (default `HEAD`). Output uses `diff.Format` exactly like `statedrift diff`. Exit 0 if zero **material** changes, 1 if any. |
| `baseline unpin` | Remove `baseline.json`. Refuses without `--force`. |

`check` flags:
- `--material-only` (default **true** — counter noise is irrelevant for compliance).
- `--include-counters` to opt in to counter changes.
- `--quiet` to suppress output and just set exit code (CI-friendly).
- `--json` for machine-readable diff output (matches `analyze --json`).

## Decisions

1. **Single pin, no names.** v0.4 supports one baseline at a time.
   Named baselines (`pin --name pre-deploy`, `check --against pre-deploy`)
   is a v0.5+ candidate if customers ask. Keeping it single now avoids
   designing a directory layout we may regret.
2. **Snapshot copy, not reference.** `baseline.json` carries the full
   snapshot. Survives GC, no chain-side bookkeeping needed, auditor can
   inspect with `cat baseline.json | jq`.
3. **Material-only by default.** Counter deltas (kernel ticks, packet
   counters) are operational noise. A compliance check that fires on
   normal traffic flow is useless. `--include-counters` opts in for
   forensic uses.
4. **Exit code 0/1 only.** Compliance scripts gate on "is there drift?";
   they don't need to distinguish "store not initialized" from "no
   baseline pinned" via exit code. Print a clear stderr message and exit
   1 on any error, 0 only when zero material changes.
5. **`--force` for destructive operations.** `pin` over an existing
   baseline and `unpin` both require `--force`. Compliance baselines
   represent operator-attested known-good state; a fat-finger that
   silently replaces or deletes one is a bigger problem than the friction
   of a force flag.
6. **No multi-host fleet support.** Per chain = per host = per baseline.
   Cross-host baseline export/import/compare is the v0.6 fleet feature
   and gets a different command surface.
7. **Baseline is not part of the hash chain.** Pinning does not append
   to the chain, does not bump the head hash, and does not interact with
   `verify`. The chain is the forensic record; the baseline is a
   compliance reference. Conflating them would mean every pin/unpin
   modifies the chain — wrong granularity for both.
8. **No baseline-aware export.** `statedrift export` does not
   automatically include the baseline file. If an auditor asks for the
   pin, ship `baseline.json` alongside the bundle. Promote to
   `export --include-baseline` only if a customer asks; the bundle path
   is already complex enough.

## Phases

Each phase ships a complete unit with tests. Mirrors v0.3 / redaction
discipline.

### Phase J — storage + pin/show/unpin

- New package `internal/baseline/`:
  - `Pin{PinnedAt, PinnedByUID, SnapshotHash, ToolVersion, Snapshot}` struct.
  - `Path(basePath string) string` — returns `<basePath>/baseline.json`.
  - `Read(path) (*Pin, error)`, `Write(path, *Pin) error`. Atomic write
    (write-temp + rename, like `internal/store/store.go::writeFileAtomic`).
  - `Exists(path) bool`.
  - `Remove(path) error`.
  - HMAC-style internal-consistency check on Read: re-hash the embedded
    snapshot and confirm it equals `SnapshotHash`. Mismatch → error.
- CLI handlers in `cmd/statedrift/main.go`:
  - `cmdBaseline` dispatcher (subcommand parser).
  - `cmdBaselinePin`, `cmdBaselineShow`, `cmdBaselineUnpin`.
- Tests:
  - Pin → Read round-trips.
  - Pin refuses overwrite without `--force`.
  - Read on tampered `baseline.json` (hash mismatch) errors clearly.
  - Read on missing file is a typed error so `check` can distinguish
    "no baseline pinned" from generic I/O errors.

### Phase K — `baseline check`

- `cmdBaselineCheck`:
  - Read pin; resolve target ref (default `HEAD`); call
    `diff.Compare(pin.Snapshot, target)`.
  - Apply `--material-only` filter (default true) before format/output.
  - `--quiet` suppresses output; `--json` emits a structured diff (reuse
    the analyze JSON format if it fits, otherwise design a minimal one).
  - Exit code: 0 if zero material changes (counters always ignored for
    exit code regardless of `--include-counters`), 1 otherwise.
- Tests:
  - Pin a snapshot, check against itself → exit 0.
  - Pin, then mutate one kernel param, check → exit 1, diff lists it.
  - `--quiet` produces no stdout but sets exit 1 on drift.
  - Counter-only changes do not flip exit code regardless of flags.

### Phase L — docs

- `docs/DESIGN.md`: short new section under §6 (CLI surface) or as a
  new top-level §7 documenting the baseline as a compliance-only
  reference, its non-participation in the hash chain, and its bounded
  scope vs the v0.5+ behavioral story.
- `README.md`: new subsection in the command reference; example workflow
  ("pin after CI passes; check on every deploy").
- `CHANGELOG.md`: entry under `[0.4.0] — Unreleased`.

## Out of scope — behavioral baselines

(Full rationale in `feedback`-class memory `project_baseline_compliance_vs_behavioral.md`.)

`statedrift baseline` does **not** express expectations conditional on
time of day, day of week, system load, or business cycle. A compliance
baseline asks "different from approved state?"; a behavioral baseline
asks "normal for this time/condition?". They have different storage
models (one ref vs aggregated history), different query models (diff vs
time-series aggregation), and different buyers (compliance lead vs SRE).

The agreed v0.5+ shape is to extend the rules engine schema with optional
`when` (time predicate) and `expected` (range/distribution) clauses.
Example sketch:

```json
{
  "id":       "R30_STOCKPROC_OFF_HOURS",
  "rule":     "process('stockproc').cpu_pct < 5",
  "when":     "weekdays 16:00-09:30 America/New_York",
  "expected": "stockproc idle outside US market hours"
}
```

This requires three v0.5+ prerequisites: (1) a clock source +
timezone-of-record convention, (2) a `when`-expression parser, and (3) a
"values for field X across the last N snapshots" query layer. None are
in v0.4 scope.

Do not extend `baseline` with `--at`, `--during`, `--load-below`, or
similar — that's the exact sideways-pull the scope decision rejected.
Behavioral lives in rules, compliance lives in baseline.

## Out of scope (other v0.4 themes)

- **SELinux / AppArmor enforcement state** — separate phase, separate
  plan doc when it opens.
- **Firewall rule hashing** — same.
- **Fleet baseline** — v0.6 with a different command surface.

## Cross-references

- `project_baseline_compliance_vs_behavioral.md` (auto-memory) — the
  scope-boundary decision this plan implements.
- `project_v04_progress.md` (auto-memory) — v0.4 phase status board.
- `docs/V04_PLAN.md` — the redaction-flags plan; same shape and
  discipline applied here.
- `ROADMAP.md` — v0.4 "security completeness" theme.
