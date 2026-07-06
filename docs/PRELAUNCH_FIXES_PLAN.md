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
