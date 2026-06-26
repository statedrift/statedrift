# Changelog

All notable changes to statedrift are documented in this file.

Format: [Semantic Versioning](https://semver.org/). Types of changes:
`Added`, `Changed`, `Fixed`, `Removed`, `Security`.

---

## [Unreleased]

### Fixed

- **`gc` no longer breaks the hash chain when more than one snapshot survives
  pruning.** GC re-roots the oldest survivor to the genesis hash, which changes
  that snapshot's hash; previously the later survivors still referenced the
  pre-rewrite hash, so `verify` reported a broken link at the second survivor,
  and the unrefreshed `head` pointer meant the next `snap` chained from a hash
  that no longer existed. GC now re-links the entire surviving tail and updates
  `head`. Single-survivor pruning was unaffected. Surfaced by the new
  store error-path tests below.

### Changed

- **Test hardening (no runtime behavior change).** CI and `make test-race` now
  run the suite under the data-race detector, covering the concurrent `daemon`
  and `watch` paths. Added fuzz targets for canonical-JSON/hash (idempotency +
  determinism — the property the tamper-evidence guarantee rests on) and for
  the eight `/proc` and command-output line parsers (no panic on hostile
  input). `internal/store` statement coverage rose 56% → 84%.

---

## [0.5.0] — 2026-06-26

v0.5 deepens the diff: firewall moves from "did it change?" to "which rule
changed?", a new filesystem collector hashes watched roots into a per-file
tree for content / permission / ownership drift, and the anomaly engine gains
both smart filesystem/firewall rules and a customizable value-condition matcher
for user-authored policy.

### Added

- **Phase O — per-rule firewall diff.** `Firewall` gains `rule_list`, the
  parsed, ordered ruleset (`{table, chain, rule}` per entry). The diff now
  reports per-chain `added` / `removed` rules and detects per-chain
  `reordered` changes (firewalls are first-match-wins, so moving a DROP above
  an ACCEPT is a behavioural change). A rule edited in place surfaces as
  removed + added (rules are atomic). Parsers cover both `iptables-save`
  (v4/v6 kept distinct via `ip4`/`ip6` table tags) and `nft list ruleset`.
- **Phase P — recursive filesystem hash tree.** New opt-in collector
  (`collectors.filesystem`, default off) that walks a configured set of roots
  — defaulting to `/etc` — and records, per path, the mode / ownership / size
  and a streamed SHA-256 for regular files, plus a single Merkle `root_hash`.
  The diff reports per-file `added` / `removed` / `modified` changes (the
  latter keyed by attribute: `.mode` / `.uid` / `.gid` / `.size` / `.sha256` /
  `.target`), catching config drift, tampered binaries, and permission
  changes. Symlinks are recorded but never followed. Size caps
  (`max_file_size` 50 MiB, `max_files` 50000) bound snapshot growth with
  deterministic truncation. The collector and its diff are free; paths and
  hashes are not Category B, so the section is not redacted (see
  `docs/DESIGN.md` §4.5).
- **Phase Q — anomaly rules R34–R36 (free).** Three security rules over the
  Phase O/P data. The diff emits bare, path-free synthetic signal keys (like
  `ruleset_changed`); the rules are thin matchers:
  - **R34_FS_SETUID_ADDED** (high) — a watched file gained the setuid/setgid
    bit, or a new setuid/setgid file appeared under a watched root.
  - **R35_FS_WORLD_WRITABLE** (high) — a watched path became world-writable
    (others-write) without the sticky bit. Symlinks and sticky dirs are exempt.
  - **R36_FW_WORLD_OPEN_SENSITIVE** (high) — a new firewall INPUT rule accepts
    a sensitive port (SSH/RDP/DB/container API/…) from any source.
- **Customizable policy rules (free).** Rules in `rules.json` gain an optional
  `match` field: a list of value conditions (all ANDed) that inspect the
  change's value, not just its section/key. Operators: `eq` / `ne` /
  `contains` / `prefix` / `suffix` / `regex`, numeric `gt` / `lt` / `gte` /
  `lte`, and `changed`; `field` selects `new` (default) / `old` / `key`. This
  lets operators author precise policies like "fire when `net.ipv4.ip_forward`
  becomes `1`" or "fire when a numeric value exceeds a threshold". Fully
  backward-compatible — a rule with no `match` (and every built-in rule)
  behaves exactly as before. Unknown operators, bad regexes, and non-numeric
  operands fail closed (no match), so a typo cannot silently fire a rule.

### Changed

- **`schema_version` bumped `0.4` → `0.5`.** `rule_list` is additive and
  `omitempty`; pre-0.5 snapshots simply lack it and diff via the Phase N
  hash-only path. R32 (`ruleset_changed`) and R33 (`flushed`) fire exactly
  as before from the retained `ruleset_hash` / `rules` signals.
- **Firewall is now redactable.** This reverses Phase N's hash-only stance:
  storing the rules means firewall now carries Category B identifiers
  (IPs/CIDRs/ports), so `--redact-network` hashes each rule's text whole
  (`fw:<hash>`, sudoers-style); table and chain names stay clear. See
  `docs/DESIGN.md` §4.5.

---

## [0.4.0] — 2026-06-12

Security completeness: process forensics, export-time redaction, a
compliance-grade `baseline` command, SELinux/AppArmor enforcement tracking,
and firewall ruleset hashing — plus 8 new free anomaly rules (R26–R33).

### Added

- **Phase F — process forensics.** `Process` struct gains `Threads`,
  `UTimeTicks`, `STimeTicks`, `StartTicks` fields. Tick fields are read from
  `/proc/[pid]/stat`; `Threads` from `/proc/[pid]/status`. CPU% is derived
  at diff time from cumulative-tick delta over wall-clock delta (assumes
  `CLK_TCK = 100`, the Linux default on x86_64/arm64). PID reuse is
  detected via `StartTicks`: same PID with different start time is reported
  as removed+added rather than modified, suppressing spurious R26/R27.
- **R26_PROCESS_REPARENTED** — fires when a process's PPID changes between
  snapshots. Medium severity.
- **R27_PROCESS_ZOMBIE** — fires when a process transitions into the
  zombie (Z) state. Low severity. Does not re-fire while the process
  remains a zombie.
- **R28_PROCESS_THREAD_EXPLOSION** — fires when thread count grows by ≥ 100
  AND new ≥ 2× old + 1. Tuned to catch sudden growth (fork bombs, leaks)
  without flagging steady-state JVM workloads. Medium severity.
- Snapshots gain `schema_version: "0.4"`. v0.3 readers ignore the field.
- **Phases G+H — export-time redaction.** `statedrift export` accepts
  `--redact-network` and `--redact-hostnames`. Each Category B identifier
  (per `docs/DESIGN.md` §4.5) is replaced by a deterministic
  HMAC-SHA256-derived tagged hash (e.g. `ip:e3fe802e89e8`,
  `host:c80530af83aa`, `user:1e0f9b3c4a2d`). The HMAC key is a 32-byte
  per-bundle salt stored in `manifest.json`; the redacted bundle is itself
  a re-chained, internally consistent hash chain, so `verify.sh` and
  `verify.ps1` work without modification. Same value within a bundle
  hashes identically (cross-references like `users[].name` →
  `groups[].members` survive); same value across bundles hashes
  differently (no cross-bundle fingerprint). The local chain is never
  redacted — it remains forensic ground truth.
- `manifest.json` gains an optional `redaction` block with `mode`, `salt`
  (hex), and `tool_version` when redaction is applied. Manifest's
  `hostname` field is also redacted under `--redact-hostnames`. See
  `docs/DESIGN.md` §4.6 for the full trust model and deliberate
  non-coverage list (PIDs, process binary names).
- **Phases J+K+L — `statedrift baseline`.** New top-level command for
  compliance-grade drift detection: pin a known-good snapshot, then
  `check` later snapshots against it and gate CI on the exit code.
  Subcommands: `baseline pin <ref> [--force]`, `baseline show
  [--full]`, `baseline unpin --force`, `baseline check [ref]
  [--include-counters] [--quiet] [--json] [--no-color]`. The pinned
  snapshot is copied verbatim to `<store>/baseline.json` (a small
  wrapper carries pin metadata) — survives chain GC, no chain-side
  bookkeeping. **Baseline is not part of the hash chain**: pinning does
  not append, does not bump `head`, does not interact with `verify`.
  `check` exits 0 if zero **material** changes, 1 otherwise; counter
  deltas never affect the exit code. Scope is strictly compliance:
  no time/load/cycle conditions (those are deferred to v0.5+ via
  `when`/`expected` clauses on rules). See `docs/V04_BASELINE_PLAN.md`
  for the full plan and `docs/DESIGN.md` §6.1 for the architecture
  rationale.
- **Phase M — MAC enforcement state (SELinux/AppArmor).** New always-on
  `mac` capture section records the host's Mandatory Access Control state.
  SELinux: runtime mode (`/sys/fs/selinux/enforce`), persisted config mode
  and policy type (`/etc/selinux/config`), and policy version. AppArmor:
  enforce/complain profile counts (`/sys/kernel/security/apparmor/profiles`)
  with a rolled-up mode. Detection precedence is SELinux → AppArmor → none;
  all reads are from `/sys` and `/etc` with no external commands. The
  section carries no Category B identifiers, so it is exempt from
  export-time redaction. See `docs/V04_MAC_PLAN.md`.
- **R29_MAC_ENFORCEMENT_DISABLED** — fires when MAC goes from actively
  enforcing/permissive to disabled or absent. High severity.
- **R30_MAC_MODE_DEGRADED** — fires when enforcement weakens without a full
  disable: SELinux enforcing→permissive, or AppArmor enforce-profile count
  drops. High severity.
- **R31_MAC_CONFIG_DRIFT** — fires when the SELinux runtime mode no longer
  matches the persisted `/etc/selinux/config` value (e.g. a live
  `setenforce` not written to config). Fires only on transition into the
  mismatched state. Medium severity.
- **Phase N — firewall rule hashing.** New always-on `firewall` capture
  section records the *identity* of the host's packet-filter ruleset: the
  backend (`nftables`/`iptables`/`none`), a SHA-256 of the canonicalized
  ruleset, and a rule count. Canonicalization strips volatile content
  (packet/byte counters, the `iptables-save` timestamp header) so a stable
  ruleset hashes stably. The collector shells out to `nft` / `iptables-save`
  (backend precedence nftables → iptables → none, by tool presence), the same
  approach as the packages/services/nic_drivers collectors; reading requires
  root. Only the hash is stored — never the rules, which embed IPs/CIDRs/ports
  — so the section carries no Category B identifiers and is exempt from
  export-time redaction. Per-rule structural diff remains a v0.5 concern.
  See `docs/V04_FIREWALL_PLAN.md`.
- **R32_FIREWALL_RULESET_CHANGED** — fires when the canonical ruleset hash
  changes between snapshots. Medium severity.
- **R33_FIREWALL_FLUSHED** — fires when a populated ruleset (≥ 5 rules) drops
  to zero while the packet-filter engine is still present — the signature of
  `iptables -F` / `nft flush ruleset`. Dominant over R32. High severity.

### Fixed

- **`watch` now monitors security signals.** The per-section scheduler
  (`allWatchSections`) previously omitted every v0.3 security signal
  (`users`, `groups`, `sudoers`, `mounts`, `modules`, `cron`, `timers`,
  `ssh_keys`), so `statedrift watch` collected them only on the first tick
  and then carried them forward verbatim — drift in those sections (a new
  sudoers entry, a new user, a kernel module load) went undetected until a
  full `snap`/`daemon` collect. All of them, plus the new `mac` section, are
  now scheduled and re-collected at their configured interval. `daemon` was
  unaffected (it always does a full collect).

### Changed

- `diffProcesses` now takes a `wallSec` parameter computed from the two
  snapshots' `Timestamp` fields. Internal API; no impact on the snapshot
  schema or CLI.
- `internal/export.Bundle` gains a sibling `BundleWith(s, from, to, out,
  opts)` that accepts `BundleOptions{Redaction: redact.Options}`. The
  existing `Bundle` is preserved as a thin shim — no breaking change.

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
