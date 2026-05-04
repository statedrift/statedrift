# Changelog

All notable changes to statedrift are documented in this file.

Format: [Semantic Versioning](https://semver.org/). Types of changes:
`Added`, `Changed`, `Fixed`, `Removed`, `Security`.

---

## [0.3.0] — 2026-05-04

Free-tier value bump: five new always-on security-signal collectors, 12 new
free anomaly rules (R14–R25), and a reusable secret-pattern redactor.

### Added

**Always-on security-signal collectors** — enabled by default in
`capture` (no config change needed). All five collectors are world-readable
where possible, fall back to best-effort on per-source permission errors,
and use stdlib only (no new external commands).

- `users`, `groups`, `sudoers` (Phase A) — `/etc/passwd`, `/etc/group`, and
  `/etc/sudoers` + `/etc/sudoers.d/*` with whitespace-normalized,
  comment-folded lines.
- `modules` (Phase B) — loaded kernel modules from `/proc/modules`. Captures
  Name, Size, and sorted Dependencies; drops RefCount (varies constantly),
  State, and load address (zeros under kASLR for non-root). A name
  reappearing with a changed Size signals a `.ko` file replacement.
- `ssh_keys` (Phase C) — authorized_keys for every user listed in
  `/etc/passwd`, including service accounts in `/var/lib/*`. The base64
  public-key body is **never** stored in the chain — we hash it (SHA256,
  OpenSSH `SHA256:base64nopad` form) at collect time and discard the
  body. Captures `(user, type, fingerprint, comment, options)` only;
  forced-command options pass through the secret redactor. Recognizes
  the closed set of OpenSSH keytypes including signed user certificates.
- `cron`, `timers` (Phase D) — cron jobs from `/etc/crontab`, `/etc/cron.d/*`,
  and `/var/spool/cron/*` (RHEL + Debian layouts), and systemd `.timer`
  units from `/etc/systemd/system` and `/usr/lib/systemd/system` with
  documented unit-file precedence (etc overrides lib). Read directly from
  unit files rather than via `systemctl list-timers` to avoid the noisy
  last-/next-run timestamps that would dominate the diff. Cron command
  bodies pass through the secret redactor.
- `mounts` (Phase E) — `/proc/self/mountinfo` with `password=` /
  `credentials=` / `cred=` option keys stripped at collect time per the
  Cat A redaction policy. Mount options sorted alphabetically for stable
  hashing across kernel versions; bind mounts to the same point with
  different sources are diff-tracked separately.

**Twelve new free-tier anomaly rules** (R01–R10 unchanged from v0.2):
- `R14_USER_ADDED` (high), `R15_USER_MODIFIED` (medium), `R16_SUDOERS_MODIFIED` (critical, fires on any change)
- `R17_MODULE_LOADED` (high), `R18_MODULE_REMOVED` (medium)
- `R19_SSH_KEY_ADDED` (critical), `R20_SSH_KEY_REMOVED` (medium)
- `R21_CRON_MODIFIED` (high, fires on any change), `R22_TIMER_MODIFIED` (high, fires on any change)
- `R23_MOUNT_ADDED` (high), `R24_MOUNT_REMOVED` (medium), `R25_MOUNT_OPTIONS_CHANGED` (high — catches `ro`→`rw` flips, dropped `nosuid`/`nodev`/`noexec`)

**Reusable secret-pattern redactor** (`internal/collector/redact.go`)
- Drops inline credentials matching common KEY=value patterns (PASSWORD,
  PASSWD, SECRET, TOKEN, AUTH, CREDENTIAL, PRIVATE_KEY) — case-insensitive
  on the key, supporting prefixed names like `MYSQL_PASSWORD` and
  `AWS_SECRET_ACCESS_KEY`.
- Drops known token formats: AWS access keys (`AKIA[0-9A-Z]{16}`), GitHub
  PATs (`ghp_`/`ghs_`/`gho_`/`ghu_`/`ghr_`), and `Authorization: Bearer`
  tokens.
- Applied to cron command bodies, SSH `command=` forced-command options,
  and any future free-text capture (kernel cmdline planned for v0.4).

**Schema metadata**
- New `schema_version: "0.3"` field on snapshots produced by v0.3+ binaries.
  Cheap (~10 lines), doesn't affect the chain or hash, and lets future
  schema changes be detected without guessing from field presence. Old
  v0.1/v0.2 snapshots without the field still verify and diff cleanly.

### Changed

- `capture` allowlist now includes `users`, `groups`, `sudoers`, `mounts`,
  `modules`, `cron`, `timers`, `ssh_keys` by default. Existing user
  configs that override `capture` will continue to work; sections not
  listed in the override remain unset (omitempty), preserving the v0.2
  shape.
- Per-source permission errors during multi-source reads (notably
  `/var/spool/cron` mode 0700 root-only and per-user `~/.ssh/authorized_keys`
  mode 0600) are silently skipped rather than aborting the entire
  section. Production runs as root see everything; non-root snaps now
  capture the world-readable subset instead of returning empty.

### Security

- Cron command bodies and SSH forced-command options are redacted at
  collect time. `MYSQL_PASSWORD=hunter2 backup.sh` in `/etc/cron.d/`
  becomes `MYSQL_PASSWORD=<redacted> backup.sh` in the snapshot — the
  secret never enters the chain. Best-effort: novel secret formats not
  in the pattern list will not be caught; document and expand the
  pattern list in `internal/collector/redact.go` rather than handling
  redaction at multiple sites.
- SSH public-key bodies (the base64 blob after the keytype) are hashed
  to a SHA256 fingerprint at collect time and discarded. The body
  itself is never recorded. `TestParseAuthorizedKeysLineNeverContainsBody`
  enforces this invariant and rejects substrings of length ≥ 30 chars
  from the body in any output field.

---

## [0.2.0] — 2026-04-26

### Added

**Optional collectors** — opt in via `collectors` section in `/etc/statedrift/config.json`; set `"all": true` to enable everything.
- `cpu` — CPU mode ticks from `/proc/stat` (counters)
- `kernel_counters` — IP/TCP/UDP protocol counters from `/proc/net/snmp` (counters)
- `processes` — top-N processes by RSS from `/proc/[pid]/status`
- `sockets` — socket inventory per PID from `/proc/net/tcp`+`udp`
- `nic_drivers` — NIC driver and firmware via `ethtool -i`

**New CLI commands**
- `analyze` — runs the anomaly rules engine against the latest snapshot or a referenced one. R01-R10 free, R11-R13 Pro. `--rules <file>` to load custom rules; `--json` for machine output.
- `watch` — continuous snap loop with diff-on-tick and optional webhook alerting. `--interval`, `--webhook`, `--material-only`, `--json`. Supports per-section intervals via `section_intervals` in config.

**Pro license framework** — license file at `/etc/statedrift/license.json` gates Pro features (`analyze`, `report`, `siem`, `hub`, `all`). Free tier covers R01-R10 anomaly rules, all collectors, and all core commands.

**Audit bundles**
- Windows-native `verify.ps1` shipped alongside `verify.sh`. Compatible with Windows PowerShell 5.1 or PowerShell 7.5+; no external dependencies. (PowerShell 7.0–7.4 auto-parses JSON date strings in a way that breaks canonical-JSON parity with `verify.sh`; the script exits with a clear version-bump message on those versions.)
- Both verifiers use ordinal byte-comparison sort for canonical-JSON keys (matches `jq -cS` and Go's `sort.Strings`).

**Integrity hardening**
- `chain_root_hash` and `chain_head_hash` recorded in `manifest.json`; both verifiers cross-check against recomputed values.
- Snapshot count claim in manifest is verified against actual file count.

### Changed
- `daemon` — sub-minute intervals are accepted (for demos and tests). `watch` keeps the 1-minute floor for production safety.
- `verify.sh` — uses ordinal sort throughout to guarantee parity with the Go writer's canonical JSON.

### Fixed
- Diff suppresses counter-only changes by default in the `--material-only` view.

---

## [0.1.0] — 2026-03-28

Initial public release.

### Added

**Core engine**
- SHA-256 hash chain with canonical JSON serialization (keys sorted at every nesting level)
- Append-only flat file store with date-based directory layout (`chain/YYYY-MM-DD/HHMMSS.json`)
- `head` file tracking the hash of the latest snapshot
- Tamper detection: any modification to a stored snapshot breaks the chain

**Snapshot collector** (reads from `/proc`, `/sys`, `dpkg`/`rpm`, `systemctl`)
- `host` — hostname, OS, kernel version, uptime
- `network.interfaces` — IPs, link state, MTU, packet/byte counters
- `network.routes` — routing table (destination, gateway, device, metric)
- `network.dns` — nameservers and search domains from `/etc/resolv.conf`
- `kernel_params` — configurable sysctl values
- `packages` — installed package names and versions (dpkg and rpm)
- `services` — systemd unit names and active states
- `listening_ports` — TCP sockets in LISTEN state from `/proc/net/tcp`
- `collector_errors` field records non-fatal collection failures
- Interface ignore patterns (glob-based, e.g. `veth*`, `docker0`)
- Snapshot ID includes a random 6-character hex suffix for uniqueness

**CLI commands**
- `init` — initialize store, take genesis snapshot
- `snap` — on-demand snapshot with inline diff from previous
- `log` — history with `--since`/`--until` date filtering and `--json` output
- `show` — full snapshot display; supports `HEAD`, `HEAD~N`, hash prefix; `--json` flag
- `diff` — compare two snapshots; `--section`, `--material-only`, `--json`, `--no-color` flags
- `verify` — validate local chain or an export bundle (pass path as argument)
- `export` — create `.tar.gz` audit bundle with `--from`/`--to` date range
- `daemon` — continuous collection with `--interval` flag; `--install` generates systemd unit
- `gc` — remove snapshots older than `retention_days`, re-link chain
- `version` — print binary version
- `help <command>` — per-command usage with examples

**Export bundles**
- Contains snapshot JSON files, `manifest.json`, `verify.sh`, and `README.txt`
- `verify.sh` requires only `sha256sum` + `jq` — no Go toolchain needed
- Chain verified before and after bundle creation
- `statedrift verify bundle.tar.gz` verifies a bundle without manual extraction

**Configuration** (`/etc/statedrift/config.json`)
- `store_path`, `interval`, `retention_days`
- `kernel_params` — custom list of sysctl paths to capture
- `capture` — which sections to collect
- `ignore.interfaces` and `ignore.packages` — glob patterns to exclude
- `STATEDRIFT_CONFIG` env var overrides config path
- `STATEDRIFT_STORE` env var overrides store path

**Daemon & systemd**
- `daemon --install` generates `/etc/systemd/system/statedrift.service`
- Graceful shutdown on `SIGTERM`/`SIGINT`
- One log line per snapshot: timestamp + hash prefix

**Display**
- ANSI color output: green `+`, red `-`, yellow `~`, dim counters
- Color auto-disabled when stdout is not a terminal, `NO_COLOR` is set, or `TERM=dumb`
- `--no-color` flag on all commands as fallback

**Release tooling**
- `make release` — cross-compiles `linux/amd64` and `linux/arm64`, packages archives, generates `sha256sums.txt`
- `install.sh` — downloads and installs from GitHub Releases

**Tests**
- Unit tests for hasher, store, diff, config, collector (parse functions), daemon, export
- Integration tests for export bundle round-trip and `verify.sh` (build tag `integration`)
- Test coverage: hasher determinism, canonical JSON, tamper detection, chain verification

[0.2.0]: https://github.com/statedrift/statedrift/releases/tag/v0.2.0
[0.1.0]: https://github.com/statedrift/statedrift/releases/tag/v0.1.0
