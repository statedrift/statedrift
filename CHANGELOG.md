# Changelog

All notable changes to statedrift are documented in this file.

Format: [Semantic Versioning](https://semver.org/). Types of changes:
`Added`, `Changed`, `Fixed`, `Removed`, `Security`.

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
