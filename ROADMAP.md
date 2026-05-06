# Roadmap

The goal: a tamper-evident record of every host change, free for individual
operators, with an optional Pro tier for fleet baselining and policy.

## Released

- **v0.1.0** — Initial release. SHA-256 hash-chained snapshots of host
  state, append-only store, structural diff, audit bundles with offline
  `verify.sh`.
- **v0.2.0** — Optional collectors (CPU, kernel counters, processes,
  sockets, NIC drivers). `analyze` command with rules R01-R10 (free) and
  R11-R13 (Pro). `watch` command with webhook alerts. Pro license
  framework. Audit bundles add a Windows-native `verify.ps1` alongside
  `verify.sh`.
- **v0.3.0** — Free-tier security signals: users/groups/sudoers,
  loaded kernel modules with signatures, SSH authorized keys, cron
  jobs and systemd timers, mount points. Adds rules R14-R25 to the
  free anomaly engine. Snapshots gain a `schema_version` field.

## In progress — v0.4.0

Security completeness. Process forensics (carried from v0.3),
`statedrift export --redact-*` flags, SELinux / AppArmor enforcement
state, firewall rule hashing, limited filesystem hash diff for
named files, and `statedrift baseline` (`pin` / `check`) for ad-hoc
compliance checks against a pinned snapshot. Adds rules R26-R32 to
the free anomaly engine.

Pro: `statedrift report` — auditor-grade signed PDF / HTML report
summarizing a baseline-vs-current diff with embedded chain
verification.

See `docs/V04_PLAN.md` for the full phase breakdown.

## Planned

- **v0.5.0 — Pro depth.** Recursive filesystem hash trees with
  structural diff. Rule-by-rule firewall diff. Customizable policy rules.
- **v0.6.0 — Fleet (Pro).** Baseline export / import / compare across
  many hosts. Container runtime state. AI / GPU runtime configuration.
  DPDK, SR-IOV, and other kernel-bypass networking detection.

Versions ship roughly every 4-6 weeks. The free tier always includes
the core hash chain, all collectors, and rules R01-R25. Pro adds depth,
fleet, and custom policy.

## Out of scope

- Real-time monitoring — statedrift records at intervals, not
  continuously.
- Cloud control plane state — host-level only.
- Modifying system state — statedrift is read-only by design.

## Influence priorities

Open an issue or discussion at
[github.com/statedrift/statedrift](https://github.com/statedrift/statedrift)
to shape the order. Items in v0.4 are firmer; v0.5 and v0.6 are
softer. If you have a concrete use case that should jump the queue,
please say so.
