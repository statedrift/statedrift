# statedrift Design

This document is the technical companion to `README.md`. It explains **why**
statedrift is shaped the way it is — the design tenets, the data model, the
hash chain mechanics, and the tradeoffs that fall out of them. Read this if
you're contributing, evaluating the tool for your own use, or auditing a
bundle and want to understand exactly what you're looking at.

For user-facing CLI reference, see `README.md`. For threat-model depth, see
`docs/SECURITY.md`. For the per-version release procedure, see
`docs/RELEASE.md`.

---

## 1. Purpose

statedrift is a single-binary agent that continuously records tamper-evident
snapshots of host operational state, letting an operator `diff` any two
points in time and `export` a cryptographically verifiable evidence bundle
to a third party. The "third party" is typically an auditor, an incident
responder reconstructing events, or an internal compliance team.

The product solves two adjacent problems that existing tools handle poorly:

1. **Configuration drift is invisible.** Hosts change between deployments,
   between reboots, and between human operators. By the time someone notices
   that `net.ipv4.ip_forward` is `1` on a host that should have it at `0`,
   no log records when it changed or who did it.
2. **Audit evidence is expensive and untrusted.** Producing "what did
   production look like on 2026-01-15?" for an SOC 2 auditor typically
   means screenshots, ad-hoc scripts, and spreadsheets. An auditor who
   doesn't trust the source has no way to verify them.

statedrift records what each host *actually is*, with a hash chain that
makes retroactive edits detectable. The output is a compact JSON record
plus a script that anyone with `sha256sum` and `jq` can verify. No
ongoing trust in the operator is required.

What statedrift is **not**:

- **Not a monitoring tool.** It does not alert on metrics, graph time
  series, or aggregate across hosts in real time. It records.
- **Not a configuration management tool.** It does not enforce desired
  state, push changes, or remediate. Read-only by design.
- **Not a file-integrity tool.** It does not hash file contents. AIDE,
  Tripwire, and Samhain occupy that space and do it better.
- **Not a fleet aggregator** (yet). Single-host scope through v0.3.
  Fleet baseline export/import is on the roadmap.

---

## 2. Design tenets

These are the rules the project tries not to violate.

**Single static binary.** No runtime, no interpreter, no package manager
needed at deployment. `scp` the binary onto a host and it works. CGO is
disabled in release builds; the resulting executable links nothing
external. This makes statedrift trivially deployable on stripped or
embedded systems and removes "did the dependency drift?" as a class of
bug.

**Stdlib only.** The Go module declares zero external dependencies. The
collector reads `/proc`, `/sys`, and a small set of `/etc` files. It
shells out only to package managers (`dpkg-query`, `rpm`) and a few
read-only tools (`ip`, `systemctl`, `ethtool`) — never to any tool that
mutates state. Adding a third-party Go module requires a deliberate
case; the bar is high because every dep multiplies the supply-chain
surface for a compliance product.

**Read-only by design.** The agent observes; it never mutates. There
is no command that writes to `/etc`, `/proc`, `/sys`, or anywhere the
host's own state lives. The single sink is the snapshot store under
`/var/lib/statedrift`. This bounds the blast radius if statedrift is
ever exploited and rules out a class of audit objections.

**Plain JSON, plain files.** Each snapshot is one JSON document in one
file. The store is a directory tree of those files. No database, no
binary container format, no custom serialization. An auditor with `cat`,
`ls`, and `jq` can inspect everything statedrift produces. Failure
modes are correspondingly simple: a corrupted file is one bad snapshot,
not a wedged database.

**Determinism.** The same host state, sampled twice, produces byte-for-byte
identical JSON (modulo timestamps and snapshot IDs). Every collector
sorts its output. Map keys serialize alphabetically. This is what makes
the hash chain meaningful — non-deterministic output would generate
spurious diffs that bury real ones.

**Free tier carries the value.** The hash chain, all collectors, the
diff engine, audit bundles, and rules R01–R25 are free. Paid Pro
features are an additive layer for fleet baselining and customizable
policy. A single-host operator running statedrift on their personal
infrastructure should never feel cornered into a paid tier to use it
for its stated purpose.

---

## 3. Architecture

### 3.1 Pipeline

```
   /proc, /sys, dpkg, systemctl, ip, ethtool
                      │
                      ▼
            ┌──────────────────┐
            │ Snapshot Collector│
            └────────┬──────────┘
                     │ (Snapshot struct)
                     ▼
            ┌──────────────────┐
            │  Canonical JSON   │
            │     + SHA-256     │
            └────────┬──────────┘
                     │ (SHA-256 = next prev_hash)
                     ▼
            ┌──────────────────┐
            │ Append-Only Store │  /var/lib/statedrift/chain/YYYY-MM-DD/HHMMSS.json
            └────────┬──────────┘
                     │
        ┌────┬───────┼───────┬────────┐
        ▼    ▼       ▼       ▼        ▼
       log  show   diff    verify   export
                                       │
                                       ▼
                              audit bundle (.tar.gz)
                              + verify.sh + verify.ps1
```

Five subsystems, each in `internal/`:

| Package | Role |
|---|---|
| `internal/collector` | Reads host state, produces a `Snapshot` struct |
| `internal/hasher` | Canonical-JSON serialization + SHA-256 hash |
| `internal/store` | Append-only flat-file persistence with date-based directories |
| `internal/diff` | Structural comparison between two `Snapshot` values |
| `internal/export` | Builds tarballs with self-contained `verify.sh` and `verify.ps1` |
| `internal/rules` | Anomaly rules engine evaluated against diff output |
| `internal/license` | HMAC-SHA256 license verification gating Pro rules/features |

`cmd/statedrift/main.go` is the CLI entry point — argument parsing, command
dispatch, and human-readable output formatting. It depends on every
`internal/*` package but no `internal/*` package depends on it.

### 3.2 Tech choices

| Choice | Why |
|---|---|
| **Go** | Single static binary, fast cross-compile, infrastructure operators trust Go binaries because every CNCF project they already run is Go. Faster than Python for collection workloads, simpler deployment than Rust. |
| **Plain JSON** | Human-readable, structurally diffable, universally parseable. Every Linux host already has `jq`. |
| **Flat files** | One snapshot per file. Auditable with `ls`. No database to corrupt, no schema migration, no special tooling required for forensics. |
| **SHA-256** | Universally available (`sha256sum` on every distro). Fast, well-understood, sufficient for integrity (statedrift makes no confidentiality claims). 256 bits of pre-image resistance leaves substantial headroom for a multi-decade chain. |
| **tar.gz** | Bundle format. Universal — any auditor can extract one without statedrift installed. Good compression on repetitive JSON. |
| **HMAC-SHA256 for license signing** | Trivially implementable in `verify.sh` if needed for Pro-license parity later. Symmetric (signer and verifier share the secret). Verification is a single hash compare. |

**Why not Rust?** The performance difference at this workload is
irrelevant — collection latency is dominated by `/proc` reads, not by
Go's allocator. Go gets to a working static-Linux binary faster, has a
lower contributor barrier, and ships with a stdlib JSON encoder we can
canonicalize without pulling external crates. If a future workload
shifts toward filesystem hashing (recursive trees, large-file streaming),
revisit.

**Why not SQLite?** A flat-file store is auditable by anyone with `ls`
and `cat`, with no special tooling. That matters when the entire point
is transparency and verifiability. A database adds one more thing the
auditor has to trust — and one more thing that can go subtly wrong.

**Why not Protobuf/CBOR/MessagePack?** Smaller wire format, but every
auditor with a JSON parser can read snapshots; binary formats require a
schema and a reader. Compactness is the wrong optimization for an
artifact whose primary consumer is a human.

---

## 4. Data model

### 4.1 Snapshot schema

A snapshot is a single JSON document with a fixed top-level shape. Each
section is either a struct, a map, or an array of structs. The fields are
documented in `internal/collector/types.go`; what follows is the conceptual
model.

```jsonc
{
  "schema_version": "0.3",                  // present on v0.3+ snapshots
  "version": "0.3.0",                       // statedrift binary version
  "snapshot_id": "snap-20260322-140000-a3f8c1",
  "timestamp": "2026-03-22T14:00:00.000Z",  // UTC
  "prev_hash": "<64-hex SHA-256 of preceding snapshot, or 64 zeros>",

  "host": { /* hostname, OS, kernel, arch, boot_id, machine_id */ },

  "network": {
    "interfaces": [ /* per-NIC: name, state, MTU, MAC, addresses, stats */ ],
    "routes":     [ /* per-route: destination, gateway, device, metric, protocol */ ],
    "dns":        { /* nameservers, search domains */ }
  },

  "kernel_params":   { /* sysctl key → value (selected subset) */ },
  "packages":        { /* package name → version */ },
  "services":        { /* unit name → "active (running)" etc. */ },
  "listening_ports": [ /* per-listener: port, protocol, address, process */ ],

  // v0.3 always-on security signals
  "users":   [ /* /etc/passwd entries */ ],
  "groups":  [ /* /etc/group entries with sorted members */ ],
  "sudoers": [ /* /etc/sudoers + /etc/sudoers.d/* normalized lines */ ],
  "modules": [ /* /proc/modules: name, size, sorted dependencies */ ],
  "ssh_keys":      [ /* SHA-256 fingerprint only — body never stored */ ],
  "cron_jobs":     [ /* per-source: user, schedule, redacted command */ ],
  "systemd_timers":[ /* per-unit-file: OnCalendar, OnBootSec, etc. */ ],
  "mounts":        [ /* /proc/self/mountinfo with credentials stripped */ ],

  // v0.2 optional collectors — present only when enabled
  "cpu":            { /* CPU mode ticks */ },
  "kernel_counters":{ /* IP/TCP/UDP from /proc/net/snmp */ },
  "processes":      { /* top-N by RSS */ },
  "sockets":        { /* socket count per process */ },
  "nic_drivers":    { /* per-interface driver+firmware via ethtool -i */ },
  "connections":    [ /* established TCP connections */ ],
  "multicast_groups":[ /* IGMP/MLD memberships */ ],

  "collector_errors": [ /* non-fatal errors from this collection */ ]
}
```

Each top-level section is independently optional. A snapshot from a
v0.1.0 binary lacks the v0.2 and v0.3 sections; the diff engine and
verify path treat absent sections as "no data" rather than errors,
which keeps cross-version chains valid for the lifetime of the project.

### 4.2 What is captured

| Section | Sources | Why it matters |
|---|---|---|
| **host** | `/etc/hostname`, `/etc/os-release`, `uname`, `/etc/machine-id`, `/proc/sys/kernel/random/boot_id` | Identifies the machine and detects reboots (`boot_id` rotates) |
| **network.interfaces** | `/sys/class/net/*` | IP, MTU, link state changes are common drift causes |
| **network.routes** | `/proc/net/route` and `ip route` | Routing changes silently redirect traffic |
| **network.dns** | `/etc/resolv.conf` | DNS rewrites can break or hijack services without other symptoms |
| **kernel_params** | `/proc/sys/` (allowlisted keys) | Sysctl flips are security-relevant (`ip_forward`, `rp_filter`) |
| **packages** | `dpkg-query` / `rpm -qa` | Package changes = attack surface changes |
| **services** | `systemctl list-units` | Proves what was running |
| **listening_ports** | `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp` | New listeners are new exposure |
| **users / groups / sudoers** (v0.3) | `/etc/passwd`, `/etc/group`, `/etc/sudoers` + `/etc/sudoers.d/*` | Privilege drift; new accounts; sudoers edits |
| **modules** (v0.3) | `/proc/modules` | Kernel module loads can install rootkits or hook syscalls |
| **ssh_keys** (v0.3) | `~/.ssh/authorized_keys{,2}` per `/etc/passwd` user | New SSH keys grant remote login; persistence vector |
| **cron_jobs** (v0.3) | `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*` | Cron runs arbitrary commands as root |
| **systemd_timers** (v0.3) | `/etc/systemd/system/*.timer`, `/usr/lib/systemd/system/*.timer` | Same as cron, different mechanism |
| **mounts** (v0.3) | `/proc/self/mountinfo` | Mount adds, `ro→rw` flips, dropped `nosuid`/`nodev`/`noexec` |

### 4.3 What is deliberately not captured

These are decisions, not omissions.

- **Packet payloads or traffic content** — privacy and legal risk; out
  of scope.
- **File contents** — size, noise, and a different tool's job.
- **Environment variables, credentials, secrets** — the entire redaction
  policy (section 4.5) exists to keep these out of the chain.
- **Full process tree** — too noisy for hourly snapshots; available as
  the optional `processes` collector (top-N by RSS) when explicitly
  enabled.
- **Application-level state** (database contents, application configs
  beyond systemd) — out of scope for a host-level tool.
- **Dynamic SSH keys via `AuthorizedKeysCommand`** — only filesystem
  authorized_keys are read in v0.3.

### 4.4 Counter fields and "material" diffs

Some captured fields are inherently counters: `interface.stats.rx_bytes`,
`/proc/stat` CPU ticks, `/proc/net/snmp` IP/TCP/UDP counters. These
change every snapshot regardless of whether anything material happened.

The diff engine tags these `Counter: true` and the analyze engine
silently ignores them — counter changes never trigger anomaly rules.
The CLI's `--material-only` flag suppresses them from human output, and
`watch --material-only` skips counter-only diffs when deciding whether
to emit a webhook.

This split — **material** vs **counter** — is load-bearing. Without it,
a routine snapshot would generate dozens of "changes" that mean nothing
to an auditor and dilute the real signal.

### 4.5 Identifiers in snapshots

This section exists because an audit bundle is a transferable artifact:
once you `export` and send a `.tar.gz` to a third party, every value in
every snapshot is in their hands. Operators should know exactly what
they are sharing.

The project classifies captured values into two categories with
different handling rules. The full policy lives in
`feedback_pii_redaction.md`; what follows is the inventory.

**Category A — secrets and key material. Dropped at collection time;
never enter the chain.**

| Where it would have appeared | Treatment |
|---|---|
| `/etc/shadow`, `/etc/gshadow` | Never read |
| Raw SSH public-key body (the base64 blob) | Hashed to a SHA-256 fingerprint; body discarded |
| Mount option `password=`, `credentials=`, `cred=` | Stripped from the option string before storage |
| Cron command `MYSQL_PASSWORD=…`, `AWS_SECRET_ACCESS_KEY=…`, etc. | Pattern-redacted to `KEY=<redacted>` |
| AWS access key IDs (`AKIA[0-9A-Z]{16}`) | Replaced with `<redacted>` wherever they appear in cron / SSH options / future free-text fields |
| GitHub PATs (`ghp_…`, `ghs_…`, etc.) | Replaced with `<redacted>` |
| `Authorization: Bearer …` tokens | Token replaced with `<redacted>`, scheme keyword preserved |

The redactor is `internal/collector/redact.go`. Tests in
`internal/collector/redact_test.go` enforce that each pattern is dropped
end-to-end. The set is best-effort: novel secret formats not in the
list will not be caught — expand the pattern list there rather than
handling redaction at multiple sites.

**Category B — operational identifiers. Kept verbatim in the local
chain. Redactable at export time when shipping to external recipients.**

These are personally or operationally identifying values that statedrift
*needs* in the chain to be useful (an internal incident responder
diffing snapshots needs the actual IPs and usernames; hashing them at
collect time would destroy the tool's value). They become a concern
only when an audit bundle leaves the operator's premises.

| Section | Field | Identifier type |
|---|---|---|
| `host` | `hostname` | Host identity |
| `host` | `machine_id` | Stable per-OS-install identifier |
| `host` | `boot_id` | Per-boot identifier |
| `network.interfaces` | `mac` | MAC address (Cat B for fleet) |
| `network.interfaces` | `addresses` | IPv4/IPv6 addresses |
| `network.routes` | `gateway`, `destination` | IP / CIDR |
| `network.dns` | `nameservers`, `search_domains` | IP and DNS name |
| `listening_ports` | `address`, `process` | IP + process name |
| `connections` (optional) | `local_addr`, `remote_addr`, `process` | Endpoint pairs and process names |
| `users` | `name`, `home`, `gecos`, `shell` | Login name + display name + path |
| `groups` | `name`, `members` | Group and membership composition |
| `sudoers[].line` | full normalized line | Includes usernames, hostnames, command paths |
| `cron_jobs` | `user`, `command` (post-redaction) | Runtime identity + command string |
| `systemd_timers` | `description`, `unit` | Free-text labels |
| `ssh_keys` | `user`, `comment`, `fingerprint` | Login name + free-text label + key fingerprint |
| `mounts` | `source`, `mount_point` | Includes remote-mount sources like `//server/share` |
| `processes` (optional) | `comm` | Process command name |
| `services` | unit names | Unit names can leak deployment topology |

Operators preparing to send an audit bundle externally should treat the
above as the surface to review. v0.4 will ship `statedrift export
--redact-network --redact-hostnames` flags that hash Cat B identifiers
deterministically inside the bundle (so structural relationships
survive — same IP gets the same hash within the bundle — without leaking
the real values). Until those flags ship, manual review is the
recommendation.

What the bundle does **not** contain (verified by tests in
`internal/collector/`):

- Cleartext SSH public-key bodies
- Cleartext shadow-file content
- Cleartext mount credentials
- Pattern-matched secrets in cron commands or SSH `command=` options

If a pattern is missed and a secret leaks, the right fix is updating
the redactor pattern list, not re-handling at the site of leakage.

---

## 5. Hash chain mechanics

### 5.1 Canonical JSON

For the chain to verify, two parties (the collector and an auditor's
`verify.sh`) must produce byte-identical JSON from the same `Snapshot`
value. Go's default `encoding/json` does not guarantee this — map
iteration order is randomized, and floating-point formatting has edge
cases.

statedrift defines its own canonical form:

- Object keys sorted alphabetically at every level (recursive, including
  nested objects inside arrays).
- No whitespace. Compact encoding.
- UTF-8 only.
- Strings escaped per RFC 8259 (no extensions).
- Numbers formatted as integers when integer-valued; finite floats
  rendered with the shortest unambiguous form. statedrift does not emit
  `NaN`, `Infinity`, or `-Infinity` — these would not survive JSON
  round-trip.

The implementation is in `internal/hasher/`. The bundle's `verify.sh`
and `verify.ps1` independently re-implement the same rules using only
`jq` (POSIX) or PowerShell built-ins, so a verifier never has to trust
the statedrift binary.

### 5.2 Linkage

```
Snapshot 0 (genesis)
  prev_hash: 0000000000000000000000000000000000000000000000000000000000000000
  hash:      SHA-256(canonical_json(snapshot_0)) = "a1b2…"

Snapshot 1
  prev_hash: "a1b2…"     ← genesis's hash
  hash:      SHA-256(canonical_json(snapshot_1)) = "d4e5…"

Snapshot 2
  prev_hash: "d4e5…"
  hash:      SHA-256(canonical_json(snapshot_2)) = "g7h8…"
```

The hash is computed over the canonical JSON *including* `prev_hash`,
so any change anywhere in the document — including the link itself —
shifts the hash. There is no separate signature; the chain is the
integrity primitive.

### 5.3 Genesis

A fresh store starts with one snapshot whose `prev_hash` is sixty-four
zeros. This anchors the chain to a fixed value and makes the first
snapshot's hash a function only of its captured content.

`statedrift init` writes the genesis. `statedrift init --force`
discards an existing chain and writes a new genesis — the only command
in the tool that destructively modifies the store, intentionally
quarantined behind an explicit flag.

### 5.4 Verification semantics

`statedrift verify` walks the chain from genesis to head. For each
snapshot `i` at hash `h_i`:

1. Recompute `canonical_json(snapshot_i)` and its SHA-256 — must equal
   the hash recorded in the store's filename and `head` file.
2. Read `prev_hash` from `snapshot_i`. For `i > 0`, must equal `h_{i-1}`.
3. For genesis, `prev_hash` must be sixty-four zeros.

The first failure aborts walk and reports which snapshot broke and how.
All snapshots prior to the break are confirmed intact; everything from
the break onward is suspect. This is intentional: tampering with one
snapshot can only invalidate it and its successors; the operator can
still trust history before the break.

`statedrift verify <bundle.tar.gz>` does the same against an exported
bundle. The bundle contains its own `manifest.json` recording the
chain root hash and head hash at export time; `verify` cross-checks
both against the recomputed values, catching cases where someone
modified the bundle's manifest *and* its snapshots in lockstep.

### 5.5 The tail-anchor problem

A hash chain protects only its *interior*. The last snapshot has no
successor; modifying it is undetectable from the chain alone.

statedrift partially mitigates this with the `head` file — a separate
record of the latest snapshot's hash, written atomically on every
`snap`. `verify` cross-checks the recomputed last hash against `head`,
so modifying the last snapshot without also forging `head` is caught.

An attacker with write access to both files can still evade detection.
The reliable fix is **external anchoring**: getting the head hash out
of the operator's filesystem before an incident. Roads to this:

- Send export bundles to write-once external storage on a schedule
- Post the head hash to a transparency log (OpenTimestamps, Sigstore
  Rekor)
- Push the head to a remote chain server (planned for fleet mode)

These are not in v0.3. The threat model documents the limitation
explicitly in `docs/SECURITY.md`.

---

## 6. Store layout

```
/var/lib/statedrift/                # default; configurable
├── head                            # 64-hex SHA-256 of latest snapshot
├── chain/
│   ├── 2026-03-22/                 # one directory per UTC date
│   │   ├── 140000.json             # snapshot taken at 14:00:00 UTC
│   │   ├── 150000.json
│   │   └── 160000.json
│   ├── 2026-03-23/
│   │   └── 090000.json
│   └── …
└── exports/                        # generated audit bundles
    └── statedrift-export-2026-03-01-2026-03-22.tar.gz
```

**Date-based directories** because they're easy to browse, easy to
archive (tar an old directory), and easy to scope an export to a time
range without scanning every file.

**One file per snapshot** because corruption is bounded to one snapshot
rather than the entire chain. Loss recovery is `rm` and `verify`.

**The `head` file** because walking the entire chain to find the latest
snapshot would be O(n); maintaining a one-line pointer makes `snap`
constant-time and lets `verify` cheaply confirm the last hash matches
expectations.

**Atomic writes.** Every snapshot file and the `head` pointer are
written to a temp file in the same directory and `rename(2)`d into
place. On a single Linux filesystem, `rename` is atomic — a crash
mid-write leaves either the previous file or the new file, never a
partial write at the destination path. This prevents a daemon killed
during a snapshot from producing a corrupt chain entry.

**Append-only enforcement.** Linux supports a per-file append-only
attribute via `chattr +a`. statedrift documents (but does not enforce)
setting `chattr +a /var/lib/statedrift/chain/` so even root cannot
modify or delete existing snapshots without first removing the
attribute (which is logged by the kernel audit subsystem if enabled).
This is the canonical "the agent itself cannot rewrite history"
posture; the agent's user does not need write-modify access, only
write-append.

Per-snapshot JSON is typically 50–200 KB depending on host density. At
one snapshot per hour, a single host produces ~1.5 MB/day, ~550 MB/year.
`statedrift gc` removes snapshots older than `retention_days` (default
365) and re-links the chain so `verify` still passes on the survivors.

---

## 7. Diff semantics

### 7.1 Structural, not textual

The diff engine compares two `Snapshot` structs section by section, not
via text diff. This matters because:

- Section ordering in JSON is irrelevant; a textual diff would treat
  reordered fields as changes. Canonical JSON makes ordering stable,
  but the diff engine doesn't depend on that to be correct.
- Each section has a *natural identity* for its members: routes are
  keyed by `(destination, gateway, device)`; SSH keys by `(user, type,
  fingerprint)`; cron jobs by `(source, user, schedule, command)`. A
  textual diff would key by line number and misattribute changes when
  a single insertion shifts subsequent lines.
- The diff output is consumed by both humans (CLI) and the rules engine
  (which matches by `(section, change_type, key_pattern)`). A
  structured diff with stable keys is what makes rule patterns work.

### 7.2 Output shape

Every diff change is a `Change{ Section, Type, Key, OldValue, NewValue,
Counter }`:

| Field | Values |
|---|---|
| `Section` | `"network.interfaces"`, `"packages"`, `"users"`, etc. — matches the snapshot section it came from |
| `Type` | `"added"`, `"removed"`, `"modified"` |
| `Key` | The natural identity of the changed member, e.g. `"eth0.mtu"`, `"alice"`, `"/dev/sda1"` |
| `OldValue` / `NewValue` | Display strings; absent for added/removed |
| `Counter` | `true` if this is a counter increment (rules ignore these) |

The CLI renders these as `+`, `-`, `~` prefixed lines with optional
ANSI color. JSON output (`--json`) emits the array of `Change` objects
verbatim for piping into other tools.

### 7.3 Anomaly rules

The `internal/rules` package evaluates a static rule set against a diff
result. A rule is `{ ID, Section, ChangeType, KeyPattern, Severity, Pro }`
and matches when:

- `Change.Counter` is false (rules ignore counter increments by design)
- `Change.Section` has `Rule.Section` as a prefix (so `Rule.Section:
  "scheduled_tasks"` matches `Change.Section: "scheduled_tasks.cron"`)
- `Change.Type` matches `Rule.ChangeType` (or `Rule.ChangeType` is `"any"`)
- `Change.Key` matches `Rule.KeyPattern` (filepath glob; empty matches
  everything)

Rules R01–R10 (v0.2) cover host-level operational changes: new listening
port, package added/removed/upgraded, service state change, kernel param
change, network interface change, host reboot.

Rules R14–R25 (v0.3) cover security signals: user account add / modify,
sudoers change, kernel module load / unload, SSH key add / remove, cron
job change, systemd timer change, mount add / remove, mount option
change.

Rules R11–R13 are the Pro examples: NIC firmware change, large process
RSS growth, new high-socket-count process.

User-supplied rules in `/etc/statedrift/rules.json` (or a path passed to
`analyze --rules`) are merged with the defaults; matching IDs override.
This keeps the default set conservative and lets operators opt into
stricter posture without forking the binary.

---

## 8. Audit bundles

The bundle is the artifact that distinguishes statedrift from a logging
tool. It is the thing you hand to an auditor.

```
audit-q1/
├── manifest.json    # host, time range, snapshot count, chain root + head hashes
├── chain/
│   ├── 20260301-000000.json
│   ├── 20260301-010000.json
│   └── …
├── verify.sh        # POSIX bash + sha256sum + jq
├── verify.ps1       # PowerShell 5.1 or 7.5+ (no external deps)
└── README.txt       # human-readable explanation of what this bundle is
```

The bundle's verifiers re-implement canonical JSON and SHA-256 chain
walking. They use only tools the auditor's machine already has:

- **`verify.sh`** — POSIX bash, `sha256sum`, `jq`. Available on any
  modern Linux or macOS.
- **`verify.ps1`** — PowerShell 5.1 (Windows ships it) or PowerShell
  7.5+ (auditors who installed pwsh on macOS / Linux). Versions 7.0–7.4
  are explicitly unsupported because of a JSON date-parsing
  incompatibility documented in CHANGELOG.

The auditor never installs statedrift. They never trust statedrift's
own `verify` command. They run the script that came in the bundle, and
it independently confirms the chain is intact. This is the "zero
ongoing trust" property the project optimizes for.

The bundle also records `chain_root_hash` and `chain_head_hash` in
`manifest.json`. Both verifiers cross-check against recomputed values
— so an attacker who modifies the manifest *and* the snapshots in
lockstep still gets caught (the recomputed root won't match the recorded
root if any snapshot was changed).

---

## 9. Free / Pro boundary

statedrift is open-core. Source is open under MIT; anyone can clone,
build, and modify. A small set of features is gated by license check.

The free tier includes:

- The full hash chain, every collector (always-on and optional),
  `init`, `snap`, `daemon`, `watch`, `log`, `show`, `diff`, `verify`,
  `export`, `gc`, `analyze` itself
- Anomaly rules R01–R10 and R14–R25 (twenty-three rules covering host
  state and security signals)
- Audit bundles with `verify.sh` and `verify.ps1`

A single-host operator running statedrift to record their own
infrastructure never hits a Pro gate.

The Pro tier is an additive layer for fleet baselining and customizable
policy. Pro rules R11–R13 are examples included in the binary; they
require a valid license to evaluate (otherwise silently skipped).
Future Pro features sit in this same layer and use the same gating
mechanism.

### 9.1 License verification mechanism

Pro features are gated by an HMAC-SHA256-signed license file. The
verifier (`internal/license/`) checks the signature using a key
(`LICENSE_SECRET`) baked into the binary at build time via Go's
`-ldflags -X`.

```
license.json            ─┐
   {                     │
     "feature": "...",   │
     "expires": "...",   ├──► HMAC-SHA256(canonical) ─► compare ─► allow/deny
     "signature": "..."  │            │
   }                     │            │
                         │      LICENSE_SECRET (compile-time)
                         │            │
                         └────────────┘
```

The Makefile defaults to a development placeholder when `LICENSE_SECRET`
is unset. Source-built binaries verify against whatever secret was
present at build time — so a contributor running `make build` can
self-mint test licenses against their own placeholder build, and a
production binary verifies licenses signed with the production secret.

Two binary populations are separated by their compiled-in secret:

- **Self-built binaries** (operator clones repo, runs `make build`) —
  default placeholder; the operator can mint licenses against their
  own build for any reason, but those licenses do not validate against
  any other binary.
- **Official release binaries** (downloaded from the GitHub releases
  page) — built with the production secret; only licenses signed with
  the production secret validate.

The rotation policy for `LICENSE_SECRET` is operational and lives in
`project_license_secret_rotation.md`.

---

## 10. Open design tensions

These are real tradeoffs the project makes that someone reading the
code may want to push back on. They are listed not because they're
wrong but because they're decisions worth understanding.

**Snapshot frequency vs. drift granularity.** One hour is the daemon
default. It catches drift well enough for change-window auditing but
misses sub-hour incidents (an attacker who installs and removes a
package within fifteen minutes leaves no trace). `watch` allows
five-minute or finer intervals at the cost of more disk and more diff
noise. The right answer depends on the threat model; statedrift makes
the choice configurable rather than picking for the operator.

**Counter inclusion.** Per-interface byte counters and CPU mode ticks
are noisy on every snapshot. They're included anyway because they
*are* a signal — a sudden traffic anomaly between two snapshots is
real information — and the material/counter split keeps them from
drowning the diff. Excluding them entirely would lose value; including
them without the split would lose usability.

**Container ephemerality.** Docker creates and destroys network
interfaces (`vethXXXX`, `br-XXXX`) at every container boundary. Without
filtering, container hosts produce gigantic diffs of pure noise. The
`ignore.interfaces` glob list handles this for v0.3. A "container-aware"
mode that snapshots the runtime (running containers, image SHAs,
volumes) is on the roadmap; deciding *which* runtime API to bind
against (Docker, containerd, CRI-O) without pulling external deps is
the open question.

**`AuthorizedKeysFile` overrides.** The SSH collector reads
`~/.ssh/authorized_keys{,2}` for every `/etc/passwd` user. OpenSSH's
sshd_config can redirect via `AuthorizedKeysFile` (e.g.
`/etc/ssh/authorized_keys.d/%u`); v0.3 does not honor that override.
Hosts with custom locations appear key-less in snapshots. Documented
limitation; planned fix is a v0.4 sshd_config-aware resolver.

**LDAP / NSS users.** v0.3 reads `/etc/passwd` directly. Users
provisioned via NSS modules (LDAP, AD, FreeIPA) do not appear in the
`users` section. Same constraint applies to the SSH collector (it
iterates the local `passwd` users to find home directories). This is
the largest gap in the current security-signal coverage; mitigation is
left to a fleet-mode integration in v0.5+.

**Append-only attribute is documentation, not enforcement.** The
project tells operators to set `chattr +a` on the chain directory.
The agent does not set it for them, because doing so would require the
agent to escalate privileges beyond what's needed for collection.
Operators who skip this step still get hash-chain detection; they lose
the "agent itself cannot rewrite history" property.

**No artifact signing for releases.** Trust in the binary download is
the SHA-256 file in the GitHub release plus GitHub's TLS. There is no
GPG or cosign signature. This is consistent with the project's posture
of avoiding crypto infrastructure that operators don't already have;
adding signed release artifacts is a future consideration if Pro
customers ask.

---

## 11. Further reading

- `README.md` — user-facing CLI reference and quick start
- `docs/CONFIGURATION.md` — full config schema with field-by-field
  explanations
- `docs/SECURITY.md` — threat model, attack matrix, atomic-write and
  tail-anchor details
- `docs/RELEASE.md` — release procedure, history table, rotation
  considerations
- `ROADMAP.md` — versions and what each one targets
- `CHANGELOG.md` — per-release changes
- `internal/collector/types.go` — authoritative Snapshot schema
- `internal/hasher/` — canonical-JSON implementation
- `internal/rules/rules.go` — `DefaultRules()` is the canonical free + Pro rule set
