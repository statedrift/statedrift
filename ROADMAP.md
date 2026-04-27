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

## In progress — v0.3.0

Free-tier security signal expansion:

- User and group changes (`/etc/passwd`, `/etc/group`, sudoers)
- Loaded kernel modules and their signatures
- SSH authorized keys across all home directories
- Cron jobs and systemd timers
- Mount points and filesystem types

Adds rules R14-R25 to the free anomaly engine.

## Planned

- **v0.4.0 — Security completeness.** SELinux / AppArmor enforcement
  state. Limited filesystem hash diff. Firewall rule hashing.
  `statedrift baseline` for ad-hoc compliance checks against a saved
  known-good state.
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
to shape the order. Items in v0.3 and v0.4 are firmer; v0.5 and v0.6
are softer. If you have a concrete use case that should jump the queue,
please say so.
