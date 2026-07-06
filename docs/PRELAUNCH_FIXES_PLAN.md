# Pre-launch CLI hardening — plan & progress

Five usability fixes identified by a full-repo review ahead of wider
promotion. First impressions are the theme: each item is something a
first-time user hits within minutes of installing.

## Items

| # | Item | Status |
|---|------|--------|
| 1 | Test suite clobbers the developer's real `~/.config/statedrift/config.json`; `SaveUserStorePath` persists zero-values that override defaults | DONE |
| 2 | Stale in-binary help: `help analyze` claimed free tier is "R01–R10"; `help diff` listed 6 of ~22 sections | DONE |
| 3 | Unknown flags silently ignored (`snap --json` "succeeded"); `show` printed a blank hash header; no `--version`/`-h` conventions | DONE |
| 4 | "no daemon" phrasing → "no daemon required" (the binary ships an optional `daemon` command) | DONE (README already said "required"; docs kept consistent) |
| 5 | `install.sh` silently installed a relative `--prefix` into its own temp dir (deleted by the EXIT trap) | DONE |

## What changed

### 1. Config safety
- `cmd/statedrift/cli_test.go`: `sd()` now isolates every child process —
  `HOME` and `XDG_CONFIG_HOME` point inside the per-test temp dir, and
  `STATEDRIFT_CONFIG` points at a nonexistent file so a host
  `/etc/statedrift/config.json` cannot leak into test behavior.
- `internal/config.SaveUserStorePath` now merges `store_path` into the
  existing file at the raw-JSON level instead of marshaling the whole
  `Config` struct. Previously it wrote `"retention_days": 0`,
  `"interval": ""` etc., which override the built-in defaults at load
  time (`gc` then reported "older than 0 days").
- `init` now prints `✓ Store path saved to <path>` so repointing the
  user config is visible, never silent.
- New regression test: `TestCLIInitWritesMinimalUserConfig`.

### 2. Help accuracy
- `help analyze`: free tier is R01–R54 except the [PRO] rules R11–R13.
- `help diff`: full section list, and documents that `--section` is a
  prefix match.
- `help gc` + README: document `--days N` and the "0 = keep forever"
  semantics.

### 3. Arg-parsing hardening
- New `checkArgs` helper: every command validates its arguments before
  acting. Unknown flags, flags missing a required value, and surplus
  positional args all exit 1 with a pointer to `statedrift help <cmd>`.
  A typo can no longer silently produce a false "clean" result.
- `statedrift <cmd> --help` / `-h` now prints that command's help
  (previously `diff --help` parsed `--help` as a snapshot ref).
- `--version` / `-v` aliases for `version`.
- `show` header bug fixed: `resolveRef` now returns the entry's hash;
  the old pointer comparison against a second `store.List()` never
  matched, so the header printed `Snapshot ` with no hash.
- `diff --no-color` (documented but ignored) is now honored, and both
  `diff` and `baseline check` respect the `NO_COLOR` env var.
- `gc --days` rejects non-numeric/negative values instead of silently
  ignoring them; `--days 0` explains "keep forever" instead of
  "Removing snapshots older than 0 days... Nothing to remove."
- New regression tests: `TestCLIUnknownFlagRejected`,
  `TestCLIFlagMissingValueRejected`, `TestCLIVersionFlag`,
  `TestCLISubcommandHelp`, `TestCLIShowPrintsHash`.

### 5. install.sh
- `PREFIX` is resolved to an absolute path before the script `cd`s into
  its download temp dir, so `--prefix ./bin` installs where the caller
  expects instead of into the temp dir the EXIT trap deletes.

## Verification
- `go vet ./...` and `go test ./...` pass (including the new CLI tests).
- Manual smoke test of every new behavior against a scratch store.
- `install.sh --prefix ./rel-test` verified end-to-end against the live
  v0.8.0 GitHub release.
- Confirmed a full test run no longer creates/modifies
  `~/.config/statedrift/config.json`.

---

# Round 2 — papercut fixes (follow-up PR)

Second batch, same theme: no silent lies, honest exit codes, and test
coverage for the alerting path.

| # | Item | Status |
|---|------|--------|
| 6 | `diff --section <typo>` silently printed "(no changes)" | DONE |
| 7 | `analyze` always exited 0, even on critical findings | DONE |
| 8 | `watch`/webhook path had zero test coverage | DONE |
| 9 | README had no `analyze` reference; unknown command dumped the full help screen | DONE |

## What changed

### 6. `--section` validation
- `internal/diff` gains `KnownSections` (every section `Compare` can emit)
  and `ValidSectionFilter` (a filter is valid iff it is a prefix of a known
  section — `FilterSection` matches the filter as a prefix of a Change's
  Section, so anything else can only produce an empty result).
- `diff --section kernelparams` now exits 1 with the unknown-section error.
- Tests: `TestValidSectionFilter`, `TestKnownSectionsCoverEmittedSections`,
  CLI `TestCLIDiffSectionTypoRejected`.

### 7. `analyze --fail-on <severity>`
- New flag: exit 1 if any finding is at or above the threshold
  (low/medium/high/critical). The default exit stays 0 so existing
  scripts are unaffected; CI/cron gates opt in, mirroring
  `baseline check`'s exit contract. Works in both human and `--json` mode.
- Invalid threshold values are rejected.
- Tests: `TestSeverityRank`, `TestFailOnMet` (unit), `TestCLIAnalyzeFailOn`.

### 8. `watch --once` + webhook coverage
- New `--once` flag: run a single snap/diff/alert cycle and exit — the
  testability seam, and genuinely useful for cron users who don't want a
  resident process. The tick body is unchanged, just extracted into a
  closure shared by the ticker loop and the `--once` path.
- `postWebhook` now has direct unit tests via `httptest`: payload shape
  (host, UTC RFC3339 timestamp, material/counters, changes), content type,
  and survival of 5xx responses and dead endpoints.
- CLI test `TestCLIWatchOnce`: one tick appends exactly one snapshot and
  the chain still verifies.

### 9. Output polish
- README gains a `### statedrift analyze` reference section (rule output
  example uses the real R14/R08 rule names) and documents `watch --once`.
- Unknown commands print a two-line hint instead of dumping the ~50-line
  usage screen that scrolled the error out of view
  (`TestCLIUnknownCommandShortHint`).

## Verification (round 2)
- `go vet ./...`, `gofmt` clean, full `go test ./...` pass.
- Manual smoke test: section typo rejected / valid section accepted,
  `--fail-on` validation + clean-diff exit 0, `watch --once` single cycle,
  short unknown-command hint.
