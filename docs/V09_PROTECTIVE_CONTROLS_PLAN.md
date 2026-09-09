# v0.9 — Protective-control-removed rule class (R55–R60)

**Status: IMPLEMENTED on `main` (uncommitted).** `gofmt` clean, `go vet ./...` and
`go test ./...` green.

Implements `docs/design/protective-controls.md` §8 steps 1 and 2: the persistent
service-enablement prerequisite, then the Tier-A core rules R55–R60. All free tier.
No new collector switch, no new config knob, no Pro gating, no schema-version bump.

---

## 1. Prerequisite — persistent service enablement (`service_enablement`)

### The problem it solves

`snap.Services` comes from `systemctl list-units --type=service`, i.e. **runtime**
state (`active (running)`). "auditd was disabled" is therefore only visible as a
transient `active → inactive`, indistinguishable from a reboot, a deploy, or a
maintenance restart. Every service-based guardrail rule built on that signal would
be noisy. The orthogonal fact — *is the unit wired to start at all* — is the one
somebody changes deliberately, and it survives a reboot.

### Source: the filesystem, not `systemctl list-unit-files`

The design doc (§5.1, §9) assumed a second `systemctl` call and flagged only the
"one more subprocess" cost. Measured on a RHEL 8 host, that assumption was wrong in
a way that mattered:

| | calls | entries | time |
|---|---|---|---|
| `list-units --type=service` (existing) | 1 | 70 | ~0.005 s |
| `list-unit-files --type=service` (design-doc plan) | 1 | 307 | **~0.95–1.5 s** |
| `/etc` + `/run` symlink scan (**shipped**) | 0 | 54 | **< 0.01 s** |

A full `snap` on that host is 2.37 s, so the `list-unit-files` route would have added
**~40 % to every snapshot** — systemd stats every unit file across the search path —
and put 307 entries per snapshot into the chain, 169 of them `static` units that
carry no enablement decision at all.

Every enablement *decision* is already a symlink:

- `<root>/<target>.wants/<unit>` and `<root>/<target>.requires/<unit>` — `systemctl enable`
- `<root>/<unit>` → `/dev/null` — `systemctl mask`
- `<root>/<unit>` → `<other unit>` — an `[Install] Alias=`

with `<root>` = `/etc/systemd/system` (persistent) or `/run/systemd/system` (`--runtime`).
Reading them is a handful of readdirs, needs no `os/exec` at all, and matches the
daemon-free rule the `gpu` / `dataplane` / `harness` collectors already hold.

Measured after the change: snapshot time unchanged (2.38–2.51 s, within noise),
snapshot size 114 419 → 117 762 bytes (+2.9 %), 54 enablement entries.

**Trade-off accepted, recorded:** units enabled by a vendor preset under `/usr/lib`
are not visible, and a plain disable is observed as the unit *leaving* the map (a
`removed` change) rather than an explicit `"disabled"` value. Both are fine — the
rules key on "a unit that was enabled no longer is", which covers disable and
uninstall alike. On the measurement host the scan found 47 of the 57 units
`systemctl` calls `enabled`; the 10 missing are alias symlinks (`dbus-org.*`,
`display-manager.service`) and templates (`getty@.service`) — every real unit in the
control catalogs (`auditd`, `firewalld`, `rsyslog`, …) is present.

### Data model — a new top-level section, not a change to `services`

```go
// internal/collector/types.go
ServiceEnablement map[string]string `json:"service_enablement,omitempty"`
```

Values: `enabled[-runtime]:<sorted,comma-joined targets>`, `masked[-runtime]`,
`alias[-runtime]:<unit>`. Stored verbatim in systemd's own vocabulary — observe,
never interpret.

Two rejected alternatives:

- **Fold it into the existing `services` value** (`"active (running) [enabled]"`) —
  mutates an existing schema field (breaks every fixture and `services` test) and
  re-merges runtime with persistent state, which is the noise being removed.
- **Sub-section `services.enablement`** — `Rule.Section` matches by **prefix**, so
  R06 (service state changed, MED) and R07 (new service unit, HIGH) would silently
  start firing on every enablement change and every newly-installed unit.
  A sibling top-level section keeps the two independently rule-able; `--section service`
  still matches both, `--section services` only runtime.

Schema stays **0.5** — additive `omitempty` field, exactly like the v0.6/v0.7/v0.8
collectors.

### Precedence rules (all covered by tests)

1. Persistent beats runtime for the same unit (the durable fact wins).
2. A mask beats a stale `.wants` link in the same root (systemd will not start it).
3. `.wants` and `.requires` of the same target record that target **once**, sorted,
   so the value never depends on directory read order.

### Failure handling — the one that matters

A missing root (`/etc/systemd/system` absent: a container, a non-systemd image) is
"nothing decided", not an error. **Any other read failure returns an error and a nil
map**, and `Compare` diffs the section only when *both* snapshots carry it. An empty
map on a failed scan would otherwise diff as "every protective service on this host
was disabled at once" and fire R55/R57/R60 across the board. The same guard covers
the upgrade path (a pre-v0.9 snapshot has no section).

### Wiring

Collected inside the **existing** `captures(cfg, "services")` block in `Collect` and
the `due["services"] && captures(cfg, "services")` block in `CollectPartial`. No new
capture-section name, no `knownCaptureSections` / `knownSectionNames` /
`allWatchSections` entry, no config change — it is part of "services" as far as an
operator is concerned, and it inherits the watch-scheduler slot `services` already has.
`"service_enablement"` added to `diff.KnownSections` so `--section` validation is honest.

---

## 2. Tier-A core rules R55–R60

All `Pro: false`. No synthetic diff keys: per design doc §2 the direction here is
unambiguously expressible with declarative `Match` conditions, and keeping it
declarative keeps every control catalog overridable per-ID in
`/etc/statedrift/rules.json` without a rebuild.

Shared constants above `DefaultRules()` (`rules.go`):
`unitWasEnabled` = `^enabled` · `unitNowOff` = `^(masked.*)?$` · `monitoringStems`
· `monitoringPackageRe` · `monitoringUnitRe` · `firewallUnitRe` · `auditUnitRe` ·
`securitySysctlRe` · `protectiveCronRe`.

| ID | Name | Sev | Section | Type | Match |
|----|------|-----|---------|------|-------|
| R55_AUDIT_DAEMON_DISABLED | Audit daemon disabled | high | `service_enablement` | any | `auditUnitRe` + armed→off |
| R56_MONITORING_PACKAGE_REMOVED | Monitoring or telemetry package removed | high | `packages` | removed | `monitoringPackageRe` |
| R57_MONITORING_SERVICE_DISABLED | Monitoring or telemetry service disabled | high | `service_enablement` | any | `monitoringUnitRe` + armed→off |
| R58_PROTECTIVE_CRON_REMOVED | Protective scheduled job removed | medium | `cron` | removed | `protectiveCronRe` on **old** |
| R59_SECURITY_SYSCTL_LOOSENED | Security sysctl loosened | high | `kernel_params` | modified | `securitySysctlRe` + `new eq "0"` |
| R60_FIREWALL_SERVICE_DISABLED | Firewall service disabled | high | `service_enablement` | any | `firewallUnitRe` + armed→off |

Design points behind that table:

- **Deviation from the design-doc §4 draft, deliberate.** R55/R57/R60 fire on the
  *persistent* enablement loss, not runtime `active → inactive`. That is the entire
  point of the §5.1 prerequisite: a stop is a reboot, a disable/mask is a decision.
  Runtime stops remain covered by R06 at medium. Rule names say "disabled", not "stopped".
- **`ChangeType: "any"`** because a disable arrives as a `removed` change and a mask as
  a `modified` one; the `old`/`new` conditions are what actually pin the direction.
  Requiring `old` to match `^enabled` means `masked → disabled` (already off) is silent.
- **R58 matches on `OldValue`**, not `Key`: `diffCron` puts `user=… schedule=… cmd=…`
  in the value and only the source file path in the key, and the telling name is
  almost always in the command.
- **R59 covers only the sysctls where 0 is the loosened value.** `ip_forward`,
  `accept_redirects` and `accept_source_route` loosen toward 1; one rule cannot express
  both directions and R08 already covers kernel-param changes broadly. Only four of
  R59's catalog are in `defaultKernelParams` — the rest need the operator to list them
  in `config.kernel_params`, which the rule description says.
- **auditd is in R55 and R56, deliberately not in R57**, so one event yields one
  finding. Caught by the end-to-end run below (it fired R55 *and* R57 before the split);
  `TestAuditDaemonDoesNotDoubleFire` locks it in. There is no package-level R55, so
  R56's catalog does include the `auditd` / `audispd-plugins` packages.

---

## 3. Tests

`internal/rules/rules_controls_test.go` — follows the `internal/rules/*_test.go`
convention (stdlib only, synthetic `[]Change{}` literals, the shared `fired` helper):

- positive per rule, including `enabled-runtime:` loss and both disable *and* mask forms;
- negatives: a runtime `services` stop must not fire any of them; a control being
  *restored* must not fire; `masked → disabled` must not fire; a non-catalog unit
  (`nginx.service`) must not fire; a non-hardening sysctl, a hardening-direction
  change, and `ip_forward → 1` must not fire R59; an ordinary cron job and an
  ordinary package removal must not fire R58/R56;
- `TestProtectiveControlRulesAreFreeTier` — `Pro == false`, and all six are present;
- `TestDefaultRuleRegexesCompile` — every `regex` condition in **every** built-in rule
  compiles. `matchCondition` fails closed on a bad pattern, so a typo would make a rule
  silently dead in production while every positive test still passed.

`internal/collector/collect_units_test.go` — a fixture tree exercising both roots,
two targets on one unit, `.wants`+`.requires` de-duplication, mask, alias, ignored
noise (drop-in dirs, `.timer` links, plain files), mask-beats-stale-link,
persistent-beats-runtime, missing roots ⇒ no error, and **unreadable root ⇒ error +
nil map** (skipped when running as root).

`internal/diff/diff_test.go` — `service_enablement` emits the exact
added/removed/modified shapes the rules consume; a nil side on either snapshot emits
nothing; an *empty but non-nil* map still diffs normally.

### Cross-layer binding (`internal/diff/diff_test.go`)

Each layer otherwise pins its own string literals — the collector test asserts
`"enabled:multi-user.target"`, the diff test asserts `Section: "service_enablement"`,
the rules test builds its own `Change` literal — but nothing asserted they are the
*same* strings. A coordinated rename of the section name, or a change to which
`ChangeType` a transition produces, could leave a rule matching a shape nothing emits
with the whole suite green.

`evaluateRules()` runs a `Compare` result through the same conversion
`cmd/statedrift/main.go` does and returns the rule IDs that fired. Three tests use it:
a disable (`removed` shape) must fire R55, a mask (`modified` shape) must fire R60,
and a runtime `services` stop must fire none of the three service rules — the
false positive this whole section exists to prevent, asserted end-to-end rather than
on a literal.

**Cost, accepted deliberately:** this makes `internal/diff`'s tests import `rules`.
No import cycle (`rules` imports nothing from `diff`), but it is a new pattern — the
diff tests previously imported only `collector`. Future rule classes should extend
`evaluateRules` rather than re-inventing the conversion.

**Mutation-verified.** Renaming the section in `diff.go` *and* updating every existing
diff test in lockstep (leaving `rules.go` untouched) leaves exactly these two tests
failing, with the "have diverged" message. Renaming in `diff.go` alone fails four tests.

The same pipeline was also run once by hand across all six rules during development;
that run is what surfaced the auditd double-fire between R55 and R57.

---

## 4. Docs updated in this change

- `docs/DESIGN.md` §4.5 — Cat B inventory row for `service_enablement` next to the
  existing `services` row (unit names, same class, "not covered"; no paths, IPs,
  users or file contents).
- `CHANGELOG.md` `[Unreleased]` → Added: the section and R55–R60, with the cost
  rationale. Next free rule ID: **R61**.
- `CLAUDE.md` (local, gitignored): new v0.9 section; `R01–R60 free`, next ID R61.
- `README.md`: `service_enablement` row in the "What gets captured" table; rule-count
  mentions `54 → 60`; free-tier line `R01–R54 → R01–R60`.

---

## 5. Explicitly out of scope

- **R61 thermal/throttle** (design doc §8 step 3) — needs regex tuning against real hosts.
- **R62–R64 swap / CPU governor / resource limits** — Tier B, each a full
  collector+diff+rule change; design doc §5.2 rates their security value as debatable.
- **The §6 "control catalog" Go abstraction** — three catalogs do not justify it yet.
- **README prose/marketing for the new class** — the table row and counts are updated
  for accuracy; a feature callout (like the `harness` box) was not part of this task.

---

## 6. Answers to the design doc's §9 open questions

1. **Second `systemctl` call** — avoided entirely; measured at ~1 s and replaced with
   a < 10 ms filesystem scan. See §1.
2. **Rule-class label** — "protective control" throughout code comments, rule
   descriptions and docs (not "guardrail" / "control regression").
3. **Catalog contents** — shipped deliberately conservative; every catalog is a regex
   on the rule row, so operators extend or replace it per-ID in `rules.json`.

---

## 7. Checklist

- [x] `types.go` — `ServiceEnablement` field
- [x] `collect_units.go` — filesystem enablement scan + precedence + failure semantics
- [x] `collect.go` — wiring at both `Collect` and `CollectPartial` sites
- [x] `diff.go` — nil-guarded `diffMap("service_enablement", …)` + `KnownSections`
- [x] `rules.go` — R55–R60 + shared catalogs; next free ID → R61
- [x] `rules_controls_test.go` — positive / negative / free-tier / regex-compiles
- [x] `collect_units_test.go` — fixture tree, precedence, failure modes
- [x] `diff_test.go` — transition shapes + nil-side guard + cross-layer binding (R55/R60 fire, runtime stop does not), mutation-verified
- [x] `gofmt -w .`, `go vet ./...`, `go test ./...` (all green; CLI suite 173 s)
- [x] Live check on a real host: 54 entries, snapshot time unchanged
- [x] DESIGN §4.5 row, CHANGELOG, CLAUDE.md, README
- [ ] Commit + PR (not done — no commit was requested)
