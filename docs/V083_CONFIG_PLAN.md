# v0.8.3 — `statedrift config` command

## Problem

After `install.sh` there is no config file anywhere, and nothing tells the
user one is needed. Enabling an optional collector (the first thing a new
user tries — usually `harness`) meant discovering the JSON schema in the
README and hand-writing `~/.config/statedrift/config.json` or
`/etc/statedrift/config.json`. `init` writes only `store_path`.

## Decision

Fix it in the binary, not the install script. The script can't know the
right config location (root vs user), can't write `/etc` without sudo, and
any config it drops would drift from the binary's real schema. The binary
owns the schema, so it prints and edits it.

## Shape

```
statedrift config                  # effective merged config + sources
statedrift config example          # complete sample, every value = default
statedrift config enable <name>    # flip one collector switch on
statedrift config disable <name>   # ... off
```

Design points (settled, don't relitigate):

- `enable`/`disable` write the **user** config via the same raw-JSON
  key-level merge as `SaveUserStorePath` — never marshal the whole struct
  (zero values like `retention_days: 0` would override built-in defaults).
  The merge is deep for the `collectors` object so enabling one collector
  never clobbers another.
- A malformed existing user config is an **error**, not a clobber.
- After writing, reload the layered config and report the **effective**
  state: warn when the system config overrides the flip, or when
  `"all": true` keeps a collector enabled after a `disable`.
- `config example` prints defaults spelled out (e.g. filesystem caps as
  their real values, not the 0 that means "default") so saving the file
  unchanged never alters behavior. Verified by test.
- No generic `set key value` — that's config-management surface we don't
  want yet. Collector switches only.
- Not gated on `requireInit`; works before `init`.

## Progress

- [x] `internal/config`: `KnownCollectors`, `SystemConfigPath()`,
      `ExampleJSON()`, `SetCollector()`
- [x] `cmd/statedrift`: `config` dispatch + show/example/enable/disable,
      usage line, `help config`, post-`init` hint line
- [x] Tests: 6 new in `internal/config`, 4 new CLI tests (no live
      collects — cheap)
- [x] Docs: README (quick start, collectors intro, harness box, command
      reference, configuration section), docs/CONFIGURATION.md (layering,
      command section, full collectors table in schema sample), CHANGELOG
      Unreleased
- [ ] Release: cut v0.8.3 (Mon 2026-07-27) so the install one-liner serves
      a binary that has the command before the Show HN post (Tue 2026-07-28)
