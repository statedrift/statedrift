# statedrift Configuration Reference

## Config file location

Statedrift reads `/etc/statedrift/config.json` on startup.

Override with the `STATEDRIFT_CONFIG` environment variable:

```bash
STATEDRIFT_CONFIG=/home/user/statedrift.json statedrift snap
```

If the file does not exist, all defaults apply — no error is reported.

## Full config schema

```json
{
  "store_path": "/var/lib/statedrift",
  "interval": "1h",
  "retention_days": 365,
  "kernel_params": [
    "net.ipv4.ip_forward",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv4.tcp_syncookies",
    "net.core.somaxconn",
    "net.core.rmem_default",
    "net.core.rmem_max",
    "net.core.wmem_default",
    "net.core.wmem_max",
    "net.ipv4.tcp_fin_timeout",
    "net.ipv4.tcp_keepalive_time",
    "net.ipv4.tcp_tw_reuse",
    "net.ipv6.conf.all.forwarding",
    "kernel.pid_max",
    "kernel.shmmax",
    "kernel.shmall"
  ],
  "capture": [
    "host",
    "network",
    "kernel_params",
    "packages",
    "services",
    "listening_ports",
    "multicast"
  ],
  "collectors": {
    "all": false,
    "cpu": false,
    "kernel_counters": false,
    "processes": false,
    "sockets": false,
    "nic_drivers": false,
    "connections": false
  },
  "ignore": {
    "interfaces": [],
    "packages": []
  }
}
```

## Field reference

### `store_path`

**Type:** string
**Default:** `/var/lib/statedrift`
**Env override:** `STATEDRIFT_STORE`

Path to the snapshot store directory. Must be writable by the user running `statedrift init` and `statedrift snap`.

```json
{ "store_path": "/data/statedrift" }
```

---

### `interval`

**Type:** string (Go duration)
**Default:** `"1h"`
**CLI override:** `--interval` flag on `statedrift daemon`

Snapshot interval for daemon mode. Accepts Go duration strings: `30s`, `15m`, `1h`, `4h`, `24h`. Minimum value is `1m`.

```json
{ "interval": "15m" }
```

---

### `retention_days`

**Type:** integer
**Default:** `365`

Number of days to retain snapshots. Snapshots older than this are removed by `statedrift gc`. Setting to `0` disables retention (keep forever). Re-runs of `statedrift gc` are safe — the chain is re-linked after deletion.

```json
{ "retention_days": 90 }
```

---

### `kernel_params`

**Type:** array of strings
**Default:** see above (17 common sysctl paths)

List of sysctl parameter paths to capture in each snapshot. Each entry maps to a file under `/proc/sys/` (dots become slashes). If a path doesn't exist on the host, it is silently skipped and recorded in `collector_errors`.

```json
{
  "kernel_params": [
    "net.ipv4.ip_forward",
    "net.core.somaxconn",
    "vm.swappiness"
  ]
}
```

To capture all sysctl values, use `sysctl -a` to find the paths available on your system.

---

### `capture`

**Type:** array of strings
**Default:** `["host", "network", "kernel_params", "packages", "services", "listening_ports"]` (all sections)

Which sections to collect in each snapshot. Sections not listed are skipped entirely — their fields are absent from the snapshot JSON and excluded from diffs. Omitting sections reduces snapshot size and collection time.

An empty array or omitting the field collects everything (same as listing all sections).

| Value | What it captures |
|-------|-----------------|
| `host` | Hostname, OS, kernel version, boot ID |
| `network` | Interfaces, routes, DNS |
| `kernel_params` | Sysctl values |
| `packages` | Installed packages (dpkg/rpm) |
| `services` | Systemd unit states |
| `listening_ports` | TCP/UDP listening sockets with process names |
| `multicast` | IGMP/MLD group memberships (IPv4 + IPv6) |

```json
{ "capture": ["host", "network", "kernel_params"] }
```

Note: optional collectors (`cpu`, `kernel_counters`, `processes`, `sockets`, `nic_drivers`, `connections`) are controlled separately via the `collectors` section, not `capture`.

---

### `section_intervals`

**Type:** object (section name → Go duration string)
**Default:** `{}` (all sections use `interval`)

Per-section collection interval overrides. Lets you run expensive or slow-changing sections less often than fast-changing ones, without sacrificing granularity where it matters.

Keys are the same names used in `capture` and `collectors`. Sections not listed inherit `interval`. The watch ticker fires at the minimum interval across all configured sections.

```json
{
  "interval": "1h",
  "section_intervals": {
    "connections":     "1m",
    "listening_ports": "1m",
    "processes":       "5m",
    "packages":        "6h",
    "services":        "6h",
    "nic_drivers":     "6h"
  }
}
```

With this config the ticker fires every minute. On each tick only `connections` and `listening_ports` are re-read. `processes` is refreshed every 5th minute. `packages`, `services`, and `nic_drivers` are refreshed once every 6 hours. All other sections use the base `1h`. Every snapshot is still a complete JSON document — non-due sections carry forward their last-known values.

Valid section names: `host`, `network`, `kernel_params`, `packages`, `services`, `listening_ports`, `multicast`, `cpu`, `kernel_counters`, `processes`, `sockets`, `nic_drivers`, `connections`.

Note: `section_intervals` only applies to `watch`. The `daemon` and `snap` commands always do a full collect.

---

### `collectors`

**Type:** object
**Default:** all fields `false`

Gates the optional collectors added in v0.2. All are off by default (opt-in). Each reads from `/proc` or calls system tools and adds data to the snapshot that is not captured by the core sections.

| Field | Source | Notes |
|-------|--------|-------|
| `all` | — | Set `true` to enable every optional collector; individual fields are ignored when this is set |
| `cpu` | `/proc/stat` | Cumulative CPU mode ticks (counters) |
| `kernel_counters` | `/proc/net/snmp` | IP/TCP/UDP protocol counters |
| `processes` | `/proc/[pid]/status` | Top-20 processes by RSS |
| `sockets` | `/proc/net/tcp`, `/proc/net/udp` | Socket counts per process |
| `nic_drivers` | `ethtool -i` | NIC driver and firmware versions |
| `connections` | `/proc/net/tcp` | Established + SYN_SENT TCP connections with process names |

Enable everything:

```json
{ "collectors": { "all": true } }
```

Enable selectively (process and connection tracking without high-churn counters):

```json
{
  "collectors": {
    "processes": true,
    "connections": true,
    "nic_drivers": true
  }
}
```

`cpu` and `kernel_counters` produce counter-only diffs (they never trigger material change alerts). They are useful for trend analysis but add noise to `statedrift diff` output. Enable them when you want the full picture; leave them off for alert-focused deployments.

---

### `ignore.interfaces`

**Type:** array of strings (glob patterns)
**Default:** `[]` (nothing ignored)

Interface names matching any of these glob patterns are excluded from snapshots. Uses `filepath.Match` syntax.

| Pattern | Matches |
|---------|---------|
| `"docker0"` | exact name |
| `"veth*"` | veth0, veth1abc, etc. |
| `"br-*"` | Docker bridge networks |
| `"lo"` | loopback (already excluded by default) |

```json
{
  "ignore": {
    "interfaces": ["docker0", "veth*", "br-*", "flannel*"]
  }
}
```

---

### `ignore.packages`

**Type:** array of strings (glob patterns)
**Default:** `[]` (nothing ignored)

Package names matching any of these glob patterns are excluded from snapshots. Useful for excluding high-churn or irrelevant packages.

```json
{
  "ignore": {
    "packages": ["linux-headers-*", "linux-image-*"]
  }
}
```

---

### `display_tz`

**Type:** string (IANA zone name, `"UTC"`, or `"Local"`)
**Default:** `"UTC"`
**Env override:** `STATEDRIFT_TZ`

Controls how times are rendered in CLI output and how operator-typed dates
(`--since`, `--until`, `--from`, `--to`) are interpreted. Snapshot storage
is **always UTC** regardless of this setting — the timestamp is part of the
canonical JSON the hash chain is built over, so changing it on disk would
break every chain.

JSON output paths (`statedrift log --json`, webhook payloads from
`statedrift watch`) also stay UTC, so machine consumers see a stable wire
format. This setting affects only human-readable CLI output and the
parsing of operator-supplied date flags.

Special values:
- `""` or `"UTC"` — UTC
- `"Local"` — host's local zone (from `/etc/timezone` or `TZ` env)
- IANA name — e.g. `"America/Los_Angeles"`, `"Europe/Berlin"`

```json
{ "display_tz": "America/Los_Angeles" }
```

```bash
STATEDRIFT_TZ=Europe/Berlin statedrift log
```

---

## Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `STATEDRIFT_STORE` | Override store path | `/var/lib/statedrift` |
| `STATEDRIFT_CONFIG` | Override config file path | `/etc/statedrift/config.json` |
| `STATEDRIFT_TZ` | Override `display_tz` for CLI output and `--since`/`--from` parsing | `UTC` |
| `NO_COLOR` | Set to any value to disable ANSI colors | (unset) |

Environment variables take precedence over config file values.

---

## Example configs

### Minimal (no config file needed)

Just use defaults. Run `sudo statedrift init` and you're done.

---

### Container-optimized

No systemd, no packages (assume immutable image), short retention.

```json
{
  "store_path": "/var/lib/statedrift",
  "interval": "5m",
  "retention_days": 7,
  "capture": ["host", "network", "kernel_params", "listening_ports", "multicast"],
  "ignore": {
    "interfaces": ["docker0", "veth*", "br-*"]
  }
}
```

---

### Comprehensive audit (high-value host)

All core sections, all optional collectors, keep for 2 years.

```json
{
  "store_path": "/var/lib/statedrift",
  "interval": "1h",
  "retention_days": 730,
  "kernel_params": [
    "net.ipv4.ip_forward",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv4.tcp_syncookies",
    "net.core.somaxconn",
    "net.core.rmem_max",
    "net.core.wmem_max",
    "net.ipv4.tcp_fin_timeout",
    "net.ipv4.tcp_keepalive_time",
    "net.ipv4.tcp_tw_reuse",
    "net.ipv6.conf.all.forwarding",
    "kernel.pid_max",
    "kernel.shmmax",
    "kernel.shmall",
    "vm.swappiness",
    "vm.dirty_ratio"
  ],
  "capture": [
    "host", "network", "kernel_params",
    "packages", "services", "listening_ports", "multicast"
  ],
  "collectors": {
    "all": true
  }
}
```

---

### Alert-focused with per-section intervals

Fast connection and process tracking; expensive sections run hourly.

```json
{
  "store_path": "/var/lib/statedrift",
  "interval": "1h",
  "retention_days": 365,
  "capture": [
    "host", "network", "kernel_params",
    "packages", "services", "listening_ports", "multicast"
  ],
  "collectors": {
    "processes": true,
    "connections": true,
    "nic_drivers": true
  },
  "section_intervals": {
    "connections":     "1m",
    "listening_ports": "1m",
    "processes":       "5m",
    "packages":        "6h",
    "services":        "6h",
    "nic_drivers":     "6h"
  }
}
```

---

### CI / ephemeral hosts

Short interval, no retention needed (ship exports immediately).

```json
{
  "store_path": "/tmp/statedrift",
  "interval": "1m",
  "retention_days": 1,
  "capture": ["host", "network", "listening_ports"]
}
```
