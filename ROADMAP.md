# Roadmap

The goal: a tamper-evident record of every host change, free for individual
operators, with an optional Pro tier for fleet baselining and reporting.

## Released

- **v0.1.0** — Initial release. SHA-256 hash-chained snapshots of host
  state, append-only store, structural diff, audit bundles with offline
  `verify.sh`.
- **v0.2.0** — Optional collectors (CPU, kernel counters, processes,
  sockets, NIC drivers). `analyze` command with rules R01-R10 (free) and
  R11-R13 (Pro). `watch` command with webhook alerts. Pro license
  framework. Audit bundles add a Windows-native `verify.ps1` alongside
  `verify.sh`.
- **v0.3.0** — Free-tier security signal expansion: users, groups, and
  sudoers; loaded kernel modules; SSH authorized keys; cron jobs and
  systemd timers; mounts. Rules R14-R25.
- **v0.4.0** — Security completeness: SELinux / AppArmor enforcement
  state (R29-R31), firewall ruleset hashing (R32-R33), process-forensics
  rules (R26-R28), `statedrift baseline` pin / check / unpin for ad-hoc
  compliance gates, and export-time redaction (`--redact-network`,
  `--redact-hostnames`).
- **v0.5.x** — Rule-by-rule firewall diff (per-chain added / removed /
  reordered rules). Opt-in `filesystem` collector: recursive hash trees
  over configured roots with per-file structural diff. Anomaly rules
  R34-R36 (setuid added, world-writable path, sensitive port opened).
  Customizable policy rules: `rules.json` gains a `match`
  value-condition matcher (eq / ne / contains / prefix / suffix / regex,
  numeric comparisons, and `changed`).
- **v0.6.0** — Opt-in `containers` collector: running-container
  inventory from `/proc` cgroup membership, runtime-agnostic and
  daemon-free (R37-R39, including privileged-container detection).
  Opt-in `gpu` collector: NVIDIA inventory from `/proc/driver/nvidia`
  for driver / VBIOS / model drift (R40-R43).
- **v0.7.0** — Opt-in `dataplane` collector: SR-IOV physical functions
  and DPDK-bound NICs from `/sys` (R44-R47), plus R48 for in-place
  kernel-module replacement.
- **v0.8.0** — Opt-in `harness` collector: AI coding-agent configuration
  (Claude Code's `settings.json` / `.mcp.json`) — permissions, MCP
  servers, hooks, and model — with secrets dropped at collect time
  (R49-R54).
- **v0.8.1** — CLI polish: `analyze --fail-on`, `watch --once`,
  `diff --section` validation, strict flag parsing, `--help` /
  `--version` everywhere.

## Planned

- **Harness depth.** Cover more of the agent-config surface (additional
  config locations and agent harnesses beyond Claude Code) so MCP and
  permission drift is visible wherever it is defined.
- **Agent transcript anchoring.** Anchor the agent's session logs
  (e.g. Claude Code's per-session transcripts) into the chain so
  truncated, rewritten, or deleted agent history is detectable — an
  agent (or attacker) covering its tracks becomes visible drift.
  Content is never stored or interpreted: only sizes and incremental
  segment hashes, computed append-only-aware so each snapshot reads
  just the bytes added since the last one, however large the logs
  grow.
- **Fleet (Pro).** Baseline export / import / compare across many
  hosts — the same tamper-evident chain, aggregated.
- **Reporting (Pro).** Time-range summaries and audit-ready narratives
  built from the chain.
- **External timestamping.** Optional posting of head hashes to a
  transparency log so even the operator cannot backdate history.

Versions ship roughly every 4-6 weeks. The free tier always includes
the core hash chain, all collectors, the free anomaly rules
(R01-R54, excluding the Pro rules R11-R13), and customizable policy
rules. Pro adds depth, fleet, and reporting.

## Out of scope

- Real-time monitoring — statedrift records at intervals, not
  continuously.
- Cloud control plane state — host-level only.
- Modifying system state — statedrift is read-only by design.

## Influence priorities

Open an issue or discussion at
[github.com/statedrift/statedrift](https://github.com/statedrift/statedrift)
to shape the order. Released collectors are firm; the planned items are
softer. If you have a concrete use case that should jump the queue,
please say so.
