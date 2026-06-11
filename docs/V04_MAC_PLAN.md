# v0.4 Phase M — SELinux / AppArmor enforcement state

Status: in progress. Branch `feat/v04-phase-m-mac`.

One of the two remaining v0.4 "Security completeness" themes (the other is
firewall rule hashing). Adds a Mandatory Access Control (MAC) enforcement
signal so that downgrading or disabling SELinux/AppArmor between snapshots is
caught as drift.

## Decisions (locked — do not relitigate)

1. **Always-on, capture-gated** — section `"mac"` lives in the capture
   allowlist alongside the v0.3 security signals (`users`, `modules`,
   `mounts`). It is NOT a default-off optional collector. MAC enforcement is
   a cheap sysfs read and a core security property; opting in would undercut a
   security-completeness theme.
2. **AppArmor: counts only** — `enforce_count` / `complain_count`. No
   per-profile inventory in v0.4 (deferred to v0.5). A drop in `enforce_count`
   is the high-signal event; per-profile churn would be noisy.
3. **No external commands** — all reads from `/sys` and `/etc`, mirroring
   `collect_security.go`. No `getenforce`/`aa-status` subprocess. Every parse
   path has a `…From(path)` variant for tests.
4. **No `schema_version` bump** — `MAC` is an additive, omitempty pointer
   field. Pre-0.4 snapshots simply lack it. `schema_version` stays `"0.4"`.
5. **SELinux precedence over AppArmor** — a host runs one MAC system. Detection
   order: SELinux (if `/sys/fs/selinux` mounted) → AppArmor (if module enabled)
   → `system:"none"`. The two are never reported together.
6. **No Cat B identifiers** — MAC fields (mode strings, policy type name,
   counts) carry no IPs/hostnames/user names/paths, so the section needs no
   export-time redaction. DESIGN.md §4.5 gets a row noting "none".

## Data model — `internal/collector/types.go`

```go
type MAC struct {
    System        string `json:"system"`          // "selinux" | "apparmor" | "none"
    Mode          string `json:"mode,omitempty"`  // selinux runtime: enforcing|permissive|disabled
    ConfigMode    string `json:"config_mode,omitempty"`    // selinux /etc/selinux/config SELINUX=
    PolicyType    string `json:"policy_type,omitempty"`    // selinux SELINUXTYPE=
    PolicyVersion string `json:"policy_version,omitempty"` // selinux /sys/fs/selinux/policyvers
    EnforceCount  int    `json:"enforce_count,omitempty"`  // apparmor profiles in enforce mode
    ComplainCount int    `json:"complain_count,omitempty"` // apparmor profiles in complain mode
}
```

`Snapshot` gains `MAC *MAC \`json:"mac,omitempty"\``.

## Collector — `internal/collector/collect_mac.go`

`collectMAC()` dispatches on detection precedence:

- **SELinux** when `/sys/fs/selinux/enforce` is readable:
  - `Mode` from `/sys/fs/selinux/enforce` (`1`→enforcing, `0`→permissive).
    If selinuxfs is absent but `/etc/selinux/config` says `disabled`, report
    `system:"selinux", mode:"disabled"`.
  - `PolicyVersion` from `/sys/fs/selinux/policyvers`.
  - `ConfigMode` (`SELINUX=`) and `PolicyType` (`SELINUXTYPE=`) from
    `/etc/selinux/config`.
- **AppArmor** when `/sys/module/apparmor/parameters/enabled` is `Y`:
  - Parse `/sys/kernel/security/apparmor/profiles`; each line is
    `<name> (<mode>)`. Tally `enforce` and `complain`. `Mode` is set to
    `enforcing` (at least one enforce profile) else `permissive`.
- **none** otherwise.

Helpers: `readSELinuxFrom(selinuxDir, configPath)`, `readAppArmorFrom(enabledPath, profilesPath)`,
`parseSELinuxConfig(r)`, `parseAppArmorProfiles(r)`.

## Diff — `internal/diff/diff.go`

`diffMAC(old, new *MAC, r *Result)`. Emits Section `"mac"` field-level changes
(system, mode, config_mode, policy_type, policy_version, enforce_count,
complain_count) AND three synthetic keys that drive the declarative rules
(same mechanism as `*.zombie` / `*.thread_explosion` in `diffProcesses`):

- `enforcement_disabled` — was active (enforcing/permissive), now disabled or
  `system:"none"`.
- `mode_degraded` — selinux enforcing→permissive, OR apparmor `enforce_count`
  decreased.
- `config_drift` — selinux runtime `Mode` ≠ `ConfigMode` (live `setenforce`
  vs persisted boot config).

Nil-handling: both nil → no change; old nil & new present → treat as new
section (additions), no synthetic alarms; old present & new nil → emit
`enforcement_disabled` (section vanished).

## Rules — `internal/rules/rules.go` (free tier)

| ID | Severity | Section | KeyPattern |
|----|----------|---------|------------|
| R29_MAC_ENFORCEMENT_DISABLED | High | mac | `enforcement_disabled` |
| R30_MAC_MODE_DEGRADED | High | mac | `mode_degraded` |
| R31_MAC_CONFIG_DRIFT | Medium | mac | `config_drift` |

## Wiring

- `collect.go::Collect` — `if captures(cfg, "mac")` branch.
- `collect.go::CollectPartial` — `if due["mac"] && captures(cfg, "mac")` branch.
- `config.go` — add `"mac"` to `Default().Capture`, `knownCaptureSections`,
  `knownSectionNames`.
- `diff.go::Compare` — call `diffMAC(old.MAC, new.MAC, r)`.

## Tests

- `collect_mac_test.go` — selinux enforcing/permissive/disabled, config parse,
  apparmor enforce/complain counts, precedence, none.
- `diff_mac_test.go` — each synthetic signal fires exactly when intended;
  field changes; nil transitions.
- Rule evaluation — extend the rules test to assert R29/R30/R31 fire on the
  synthetic keys.

## Docs

- `CHANGELOG.md` `[0.4.0] — Unreleased` — Phase M entry.
- `README.md` + `CLAUDE.md` — collector/section list.
- `docs/DESIGN.md` — identifier-inventory row (Cat B: none) and MAC fields.

## Definition of done

`go vet ./...`, `go test ./...` green; `gofmt -w .` clean. PR off
`feat/v04-phase-m-mac` into `main`. After this lands, only firewall rule
hashing remains before a v0.4.0 release cut.
