# v0.4 Plan — Security Completeness

Status: Draft. v0.3.0 shipped 2026-05-04. v0.4 development starts week
of 2026-05-11.

## Goal

Two-part release:

1. **Free-tier completeness.** Close the remaining v0.3 deferred items
   (process forensics, export redaction) and add three new security
   signals (SELinux/AppArmor enforcement, firewall rule hashing,
   limited filesystem hash diff) plus a `statedrift baseline` CLI for
   ad-hoc compliance checks.
2. **Pro: `statedrift report`.** Auditor-grade signed report (PDF /
   HTML) summarizing a baseline-vs-current diff with embedded chain
   verification. Gates on `FeatureReport` (already defined in
   `internal/license/license.go`).

## Scope — seven phases

| Phase | Theme | Sources / Surfaces | Tier | Rules |
|-------|-------|--------------------|------|-------|
| F | Process forensics (deferred from v0.3) | `/proc/[pid]/status`, `/proc/[pid]/stat` | Free | R26, R27, R28 |
| G | Export redaction flags | `statedrift export --redact-*` | Free | — |
| H | SELinux / AppArmor enforcement state | `/sys/fs/selinux/enforce`, `/sys/kernel/security/apparmor/profiles` | Free | R29, R30 |
| I | Firewall rule hashing | `iptables-save`, `nft list ruleset` | Free | R31 |
| J | Limited filesystem hash diff | named files only (sshd_config, sudoers, kernel cmdline, …) | Free | R32 |
| K | `statedrift baseline pin` / `baseline check` | new CLI subcommands; pins a snapshot ref as the compliance baseline | Free | — |
| L | `statedrift report` | new CLI subcommand; PDF + HTML; embeds chain verify | **Pro** (`FeatureReport`) | — |

Rule numbering is illustrative; finalize per phase. Total target: 7
new rules (R26–R32), all free, bringing the free-tier rule count to
R01–R10 + R14–R25 + R26–R32 = 25 rules. Pro rules remain R11–R13.

Each phase ships a complete unit: collector / handler + `types.go`
fields + `diff` function (where applicable) + rules + tests + CHANGELOG
line. Don't merge a phase half-done.

## Decisions

1. **`FeatureReport` already exists** in `internal/license/license.go`
   as a feature constant. No license schema changes needed. Phase L
   wires existing `license.HasFeature(lic, license.FeatureReport)`
   into the new `cmd/statedrift/main.go report` handler.

2. **Process forensics carried forward from v0.3.** Per the
   v0.3/v0.4 scope-split decision (2026-04-26), Phase F implements
   the previously-designed extension verbatim: extend `Process` with
   `Threads`, `UTimeTicks`, `STimeTicks`, `StartTicks` (PPID already
   exists). Compute CPU% at diff time, not collect time — snapshots
   store cumulative ticks; diff has both timestamps to derive
   Δticks/Δwallclock. Use `start_ticks` to detect PID reuse → treat
   as removed+added, not modified. New rules: R26_PROCESS_REPARENTED,
   R27_PROCESS_ZOMBIE, R28_PROCESS_THREAD_EXPLOSION.

3. **Baseline is a snapshot ref, not a separate file.** `statedrift
   baseline pin <ref>` writes the chosen snapshot's hash to
   `/var/lib/statedrift/baseline.json` (a one-line pointer:
   `{"hash": "...", "pinned_at": "..."}`). `baseline check` reads it,
   resolves the snapshot from the chain, runs the existing diff
   machinery, prints the result. No new storage format, no new diff
   semantics. The pinned snapshot is just another link in the chain
   — chain integrity guarantees it can't be silently rewritten.

   **Boundary: compliance baseline only, not behavioral.** Baseline
   answers "what's different from the certified state?" — boolean
   drift against one pinned snapshot. It does NOT express expectations
   that vary with time, load, or business cycle (e.g., "CPU% should
   be 60–90% on weekdays 09:30 ET when markets open"). Those are
   behavioral baselines — different storage model (aggregated
   history, not a single ref), different query (distribution +
   deviation, not diff), different audience (SRE/ops, not compliance).
   See "Out of scope — behavioral baselines" below for the rationale
   and the planned shape of that work.

4. **Report is single-host in v0.4.** Cross-host / fleet reports are
   v0.6 territory. Format: PDF + HTML, both generated from the same
   intermediate template. PDF generation: stdlib `image/png` for the
   chain-verification badge, plain text PDF (no external deps —
   write a minimal PDF writer if needed, or generate HTML and accept
   that "PDF" means "Print to PDF from the HTML version" in the v0.4
   docs if writing a PDF emitter blows scope). Decide before starting
   Phase L; do not let this become an open-ended yak-shave.

5. **`schema_version` bumps to `"0.4"`** in Phase F (first phase that
   adds fields). Same precedent as v0.3.

6. **Sudoers redaction note from v0.3 plan applies.** When Phase G
   ships `--redact-*`, sudoers `Line` content must be redacted too —
   sudoers lines contain usernames and hostnames covered by the Cat B
   redaction policy. Already noted as a TODO in `V03_PLAN.md:564`.

7. **Release mechanics for the Pro feature** — license signing key
   handling and Pro-release smoke tests — are tracked in an internal
   release runbook, not in this public plan.

## Free vs Pro in v0.4

**Free (no license needed):**

- All collectors: process forensics, SELinux/AppArmor, firewall hashes,
  named-file hashes
- All anomaly rules: R26–R32 (Phase F + H + I + J rules)
- `statedrift baseline pin` and `statedrift baseline check`
- `statedrift export --redact-network --redact-hostnames` and any
  other Cat B redaction flags
- Chain integrity, `verify`, all v0.1–v0.3 commands

**Pro (`FeatureReport` license required):**

- `statedrift report` — generates the auditor-facing artifact
  - Inputs: `--baseline <ref>` (defaults to pinned baseline),
    `--current <ref>` (defaults to HEAD), `--format pdf|html`,
    `--output <path>`
  - Contents: chain-verification badge (signed by a separate signing
    key from the license-verification key — distinction documented
    in DESIGN.md), baseline-vs-current diff summary, anomaly findings
    table, identifier inventory per the v0.3 redaction policy
  - Failure mode without license: `cmd/statedrift/main.go` prints
    "statedrift: report requires a Pro license. See …" and exits 1.
    Does NOT degrade silently.

## Phase F — known limitations

Process snapshots are sampled at collect time, so:

- Short-lived processes (< collect interval) are invisible. This is
  inherent to interval-based collection; documented limitation.
- CPU% derived at diff time means a process that started *between*
  T1 and T2 has no T1 baseline. Diff treats it as "added" and
  reports CPU% as N/A rather than computing against zero.
- `start_ticks` is monotonic against boot; reboot resets the
  reference. Diff across a reboot must use existing R10 boot-detection
  to invalidate stale process state.

## Phase F — manual tests

### Smoke
- ☐ Spawn process, snap, diff. Process appears with non-zero CPU%
  in the second snapshot.
- ☐ Reboot, snap. R10 fires. Process state cleared. No spurious
  R26/R27/R28 findings.

### Rule firing on realistic scenarios
- ☐ R26: kill PID 1 child, watch child get reparented to PID 1
  via `prctl(PR_SET_CHILD_SUBREAPER)` or systemd reparenting. Diff
  must flag `R26_PROCESS_REPARENTED`.
- ☐ R27: spawn process, parent exits without `wait()`. Diff after
  collection must flag `R27_PROCESS_ZOMBIE`.
- ☐ R28: spawn JVM or any process that legitimately has > 200
  threads. Diff must NOT flag — threshold tuned to catch *growth*,
  not absolute count. Spawn a thread-bomb (1 → 500 threads in one
  interval) and verify R28 fires.

### Edge cases
- ☐ PID reuse: kill PID N, spawn replacement that gets PID N.
  `start_ticks` differs. Diff treats as removed+added, NOT modified.
  Verify no false R26/R27 from the swap.
- ☐ Permission errors reading `/proc/[pid]/status` for processes
  not owned by the collector user — collector continues, logs to
  stderr, does not crash.

## Phase G — manual tests

### Smoke
- ☐ `statedrift export <ref> --redact-network --redact-hostnames
  --output bundle.tgz`. Untar, inspect: no raw IPs, no raw MACs,
  no raw hostnames. Sudoers `Line` entries with hostnames also
  redacted (per v0.3 TODO at V03_PLAN.md:564).
- ☐ Same source ref, two `--redact-*` exports → bundle hashes
  differ across hosts (per-host salt) but redacted-id mapping is
  internally consistent (same IP → same hash within one bundle).
- ☐ verify.sh inside redacted bundle still passes.

### Edge cases
- ☐ `--redact-network` without `--redact-hostnames` (and vice
  versa) — partial redaction works correctly, neither flag implies
  the other.
- ☐ Empty fields and IPv6 addresses redact without panic.

## Phase H — manual tests

### Smoke
- ☐ SELinux enforcing host: snap, find SELinux state in JSON.
  Toggle to permissive (`setenforce 0`). Snap, diff fires R29.
- ☐ AppArmor host (Ubuntu): same flow with `aa-complain` /
  `aa-enforce` on a profile, R30 fires.
- ☐ Host without LSM: collector emits empty/absent SELinux and
  AppArmor sections without erroring.

## Phase I — manual tests

### Smoke
- ☐ `iptables -A INPUT -p tcp --dport 12345 -j ACCEPT`. Snap,
  diff fires R31_FIREWALL_RULES_CHANGED. Hash is over the canonical
  rule text, not the line numbers.
- ☐ `nftables` host: equivalent test via `nft add rule ...`.
- ☐ Host with neither: collector emits empty section, no error.

## Phase J — manual tests

### Smoke
- ☐ Modify `/etc/ssh/sshd_config`, snap, diff fires
  R32_NAMED_FILE_CHANGED with the file path. Hash matches
  `sha256sum` output.
- ☐ Touch a file in the watch list without changing content
  (mtime change only) — no rule fires (we hash content, not
  metadata).
- ☐ Watch-list file is missing — collector records absence
  rather than erroring.

## Phase K — manual tests

### Smoke
- ☐ `statedrift baseline pin HEAD`. File written to
  `/var/lib/statedrift/baseline.json`. Re-pinning overwrites with
  no warning.
- ☐ `statedrift baseline check` with no changes since pin →
  exit 0, "no drift from baseline".
- ☐ `statedrift baseline check` after intentional change →
  non-zero exit, prints diff. Output stable (deterministic order).
- ☐ `baseline check` with deleted/corrupt baseline.json →
  helpful error pointing to `baseline pin`.
- ☐ `baseline check` after the pinned snapshot has been GC'd —
  detect, error clearly. Document the interaction with retention
  policy (pinned baselines should not be GC'd; add a
  `baseline.json` → "do not GC" hook in `internal/store`).

## Phase L — manual tests

### Smoke
- ☐ With valid `FeatureReport` license:
  `statedrift report --baseline HEAD~7 --current HEAD --format pdf
  --output audit.pdf`. PDF opens. Contains: chain badge, diff
  summary, anomaly findings, identifier inventory.
- ☐ Same with `--format html` produces a self-contained HTML
  file (CSS inline, no external assets).
- ☐ Without license file → exits 1 with clear message.
- ☐ With expired license → exits 1, message references expiry
  date.

(Additional Pro-release smoke tests live in the internal release
runbook.)

### Cross-phase integration
- ☐ Pipeline: `baseline pin` → make changes → `report --baseline
  pinned`. Report uses pinned ref correctly.
- ☐ Report with redacted bundle: `--redacted` flag (or report
  generated from a previously-redacted export) preserves
  identifier-redaction in the rendered output.

## Recommended sequencing

1. **Phase F first** — process forensics. Already designed in detail
   from the v0.3 scope-split work; lowest spec risk; reuses existing
   diff machinery. Use it to lock in `schema_version: "0.4"`
   placement.
2. **Add CHANGELOG stub** — `## [0.4.0] — Unreleased` heading once
   Phase F merges. Without it the `make release` extractor produces
   an empty release body.
3. **Phase G (export redaction)** — small, unblocks external bundle
   sharing, exercises the Cat B redaction policy that DESIGN.md
   already documents. Sudoers redaction TODO closes here.
4. **Phase K (baseline pin/check)** — small, foundational for L.
   Ships before H/I/J because L depends on K and the rest are
   independent collectors.
5. **Phases H, I, J in parallel-ish** — independent collectors, can
   land in any order. H is easiest (parsing /sys), I has the most
   parsing surface (iptables vs nft), J is scope-sensitive (which
   files to watch).
6. **Phase L last** — Pro report. Needs K. Should not start until
   H/I/J have landed because the report aggregates their findings.
7. **Cut v0.4.0** once all seven phases land. Bump `Makefile:5`
   VERSION to `0.4.0` *as part of the release commit*. Follow the
   internal release runbook for the Pro-release steps.

## v0.4-adjacent housekeeping

- **Update `ROADMAP.md`** — line 17 still says "In progress —
  v0.3.0". Move v0.3 into Released, replace with v0.4 in-progress
  block. (Should land before Phase F starts, not bundled with the
  release.)
- **Update `DESIGN.md`** — add `Process` struct extension fields,
  baseline pointer file format, report signing key vs license
  verification key distinction, R29–R32 to the rule inventory.

## Out of scope (v0.5 or later)

- **Recursive filesystem hash trees** with structural diff (v0.5
  per `ROADMAP.md`). v0.4 ships only the named-file hash watchlist;
  the recursive-tree version is meaningfully different (Merkle
  tree, mount-aware, ignore patterns).
- **Customizable policy rules** (v0.5).
- **Fleet baseline export / import / compare** (v0.6).
- **`statedrift hub`** — multi-host aggregation server (v0.6).
- **`kthreads` collector** — kernel-thread inventory (v0.5+).
- **SIEM event export (`FeatureSIEM`)** — license constant exists
  but no v0.4 implementation. Slated for v0.5 or v0.6 once the
  fleet/hub model stabilizes.
- **Real-time monitoring**, **cloud control plane state**,
  **modifying system state** — out of scope at the project level
  per `ROADMAP.md:46`.

### Out of scope — behavioral baselines

`baseline pin` / `baseline check` are deliberately limited to
**compliance baselines** (one snapshot ref, boolean drift). They do
not express expectations that vary with time, load, or business
cycle. Concrete example: "this stock-processing app should hit
60–90% CPU on weekdays 09:30–09:45 America/New_York at market open,
and again at 15:45–16:00 at close." A single pinned snapshot cannot
encode that — the *expected* state is different at different times.

**Why split them:**

| | Compliance baseline (v0.4) | Behavioral baseline (deferred) |
|---|---|---|
| Question | "Different from approved state?" | "Normal for this time/condition?" |
| Storage | One pinned snapshot ref | Aggregated history across many snapshots |
| Output | Boolean drift + diff | Distribution + deviation score |
| Audience | Compliance / audit | SRE / security ops |
| Query model | Diff (already exists) | Time-series aggregation (new) |

Conflating them in one command serves neither: auditors get false
positives from expected daily swings; SREs get false negatives
because compliance-grade pins don't capture behavioral norms.

**Deeper structural reason this isn't a v0.4 flag:** behavioral
baselines need time-series aggregation across many past snapshots
("what's the typical 09:30 ET CPU% on Mondays?"). The chain stores
discrete snapshots — it's a ledger, not a TSDB. Computing
distributions from it is doable but it's a new query layer, not a
flag on `baseline check`.

**Planned shape (v0.5+):** extend the rules engine with optional
time predicates and expected-value clauses, e.g.:

```json
{
  "id": "R40_MARKET_OPEN_CPU_BAND",
  "when": "Mon-Fri 09:30-09:45 America/New_York",
  "subject": "process",
  "match": { "name": "stockproc" },
  "expected": { "cpu_pct": { "min": 60, "max": 90 } },
  "severity": "warn"
}
```

This shape keeps behavioral checks inside the existing rules
machinery (free tier R-rules already evaluate diffs), avoids a new
top-level `policy` command, and reuses the rules.json schema with
two additions (`when`, `expected`). An alternative (separate
`statedrift policy` command with its own DSL) was considered and
rejected as more product surface to maintain for the same outcome.

Tracking the prerequisites: the rules engine needs (1) a clock
source (`time.Now()` is fine; document the timezone-of-record
convention), (2) a parser for `when` expressions (cron-ish or
RFC 5545 RRULE-lite), (3) a way to query "values for field X across
the last N snapshots" — that last one is the new query layer and is
the actual scope cost. None of this fits v0.4.
