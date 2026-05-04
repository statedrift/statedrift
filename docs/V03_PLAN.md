# v0.3 Plan — Free Security Signals

Status: Phases A and E landed 2026-05-04. v0.2.0 shipped 2026-04-29.

## Goal

Expand the free anomaly engine from 10 rules (R01–R10) to 25 (R01–R25)
by adding five host-level security-signal collectors. Pro tier gains
nothing in v0.3 — this is a free-tier value bump.

Explicitly **out of scope** for v0.3: process/CPU/thread expansion
(deferred to v0.4 per the scope-split decision on 2026-04-26).

## Scope — five phases

| Phase | Section | Sources | Rules (proposed) |
|-------|---------|---------|------------------|
| A | Users, groups, sudoers | `/etc/passwd`, `/etc/group`, `/etc/sudoers`, `/etc/sudoers.d/*` | R14, R15, R16 |
| B | Loaded kernel modules | `/proc/modules`; `modinfo` for signatures | R17, R18 |
| C | SSH authorized keys | `/home/*/.ssh/authorized_keys`, `/root/.ssh/authorized_keys` | R19, R20 |
| D | Cron + systemd timers | `/etc/cron*`, `/var/spool/cron/*`, `systemctl list-timers --all` | R21, R22 |
| E | Mounts | `/proc/self/mountinfo` | R23, R24, R25 |

Rule numbering is illustrative; finalize per phase. Total target: 12 new
free rules, landing across the five phases.

Each phase ships a complete unit: collector + `types.go` fields +
`diff` function + rules + tests + CHANGELOG line. Don't merge a phase
half-done.

## Decisions (resolved 2026-05-03)

1. **Always-on collectors** for A–E. The launch narrative is "free
   security signals out of the box." SSH keys handled specially per the
   redaction policy below.

2. **Diff refactor deferred.** No concrete spec was captured; current
   diff.go is fine for five more sections. Revisit only when there's a
   concrete second use case beyond host state (e.g. tracking arbitrary
   external state with the same diff machinery) — at that point the
   refactor has two examples to design against, not one.

3. **PII / secrets redaction policy** — applies project-wide, not just
   v0.3.

   Two distinct categories with different handling:

   **A. Secrets and key material — redact at collection time** (never
   write to the chain in the first place):
   - **Never collect** `/etc/shadow`, `/etc/gshadow`, or raw key
     material.
   - **Structurally parse** files that may contain secrets and drop
     the secret-bearing fields. Examples:
     - SSH authorized keys → `(type, fingerprint, comment)` only;
       hash the body if material-change detection is needed.
     - fstab / mountinfo → strip `password=` and `credentials=` from
       options strings.
   - **Pattern-redact** known secret formats in free-form text (cron
     command bodies, kernel cmdline, similar): AWS access keys,
     GitHub PATs, generic high-entropy tokens.
   - **Cron specifically** is tricky — operators do put inline
     secrets like `MYSQL_PASSWORD=foo backup.sh` in cron commands.
     Pattern-redact at collect time and note the limitation in docs.
     When in doubt, drop the field rather than ship a "redacted"
     placeholder that still leaks structure.

   **B. Operational identifiers (IP, MAC, hostname, username) — keep
   verbatim in the chain; redact at export time** when needed:
   - These are PII under GDPR / CCPA / HIPAA when linkable to
     individuals, but they're also the load-bearing data for the
     tool: hashing `10.0.0.5 → <hash1>` at collect time destroys
     debugging value, anomaly detection, and route/gateway
     relationships.
   - Local chain stores actual values. Internal incident responders
     get full fidelity.
   - **`statedrift export --redact-network --redact-hostnames`** (v0.4)
     produces a redacted bundle for external recipients (auditors,
     support tickets, public bug reports). Hash deterministically
     within the bundle so structural relationships survive (same IP
     → same hash, so "route → gateway" still parses).

   **Document** the full policy in DESIGN.md, including an
   "Identifiers in snapshots" inventory so users know what's in a
   bundle before they ship it.

4. **Add `schema_version: "0.3"` to snapshots.** Cheap (~10 lines)
   metadata field, doesn't affect the chain or semantics, but only
   addable cheaply *once* — before any installed base exists. v0.3 is
   the right window. Cross-version diff/verify across the v0.1 → v0.3
   transition is not a concern (no installed users); the field is
   purely defensive for future schema changes.

## Phase E — known limitations

- **No mount-noise filtering.** Snapshots include all mounts as the
  kernel reports them. On hosts with churn (Kubernetes nodes rotating
  pod overlay mounts, Ubuntu boxes with snap refresh) this can
  generate volume in diff/analyze output. `cmdShow` filters virtual
  filesystems (`source == fstype`) for display, but the chain stores
  them all. If noise becomes a real problem, add `cfg.Ignore.Mounts`
  glob list (mirroring `cfg.Ignore.Interfaces`).
- **No automount-content awareness.** `autofs` mountpoints appear as
  the autofs daemon (`systemd-1`) until traffic triggers an actual
  mount, at which point the underlying mount appears separately.
  Documented kernel behavior; not a bug.
- **`source == fstype` heuristic in show.** This is a pragmatic
  filter to avoid a 200-line wall on container hosts, but it
  occasionally hides interesting mounts (e.g. `tracefs` whose source
  is `none`, not `tracefs`). All mounts remain in the JSON output
  and the diff; only the human-readable `show` block applies the
  filter.
- **R25 fires on any mount-options change.** A nominally cosmetic
  edit (e.g. kernel reordering option strings between minor
  versions) could fire R25. The collector pre-sorts options to
  mitigate this, but kernel-introduced new options (e.g. new
  `seclabel` semantics) will still register. Promote to per-flag
  rules (R25a `MOUNT_BECAME_RW`, R25b `LOST_NOSUID`, etc.) if the
  catch-all proves too coarse.

## Phase E — manual tests

Status legend: ✅ verified on 2026-05-04 · ☐ recommended, not yet run.

### Smoke

1. ✅ **Genesis includes mounts.** `statedrift init` (no sudo
   needed; /proc/self/mountinfo is world-readable). Inspect
   `.mounts` count and a few entries in JSON. Verified: 38 entries
   on RHEL test host, escaped paths (`/run/media/ibu/My Passport`)
   correctly unescaped, options sorted alphabetically.
2. ✅ **`source == fstype` filter in show.** RHEL test host renders
   8 entries in the human-readable Mounts block (the audit-relevant
   subset) out of 38 total stored. Filter verified to drop tmpfs /
   proc / sysfs / overlay / cgroup but keep ext4/xfs / fuse / autofs.

### Rule firing on realistic scenarios

3. ☐ **R23 fires on new mount.** `sudo mount -t tmpfs none /mnt/x`
   then `sudo statedrift snap` and `analyze`. Expect
   `R23_MOUNT_ADDED` (high). Clean up with `sudo umount /mnt/x`.
4. ☐ **R24 fires on unmount.** Snapshot a host with `/mnt/x`
   mounted, unmount, snapshot again, analyze. Expect
   `R24_MOUNT_REMOVED` (medium).
5. ☐ **R25 fires on `ro → rw` flip.** `sudo mount -o
   remount,rw /some/ro/mount`, snap, analyze. Expect
   `R25_MOUNT_OPTIONS_CHANGED` (high). The audit-critical scenario.

### Edge cases

6. ☐ **Credentials stripped end-to-end.** Mount a CIFS share with
   `credentials=/etc/cifs.creds` (or a fake `password=foo` option
   for a real fs). Snap, then check the JSON: the Mount entry must
   not contain `credentials=` or `password=` substrings anywhere
   under `mounts[].super_options` or `mounts[].mount_options`.
7. ☐ **Bind mounts diff correctly.** Bind-mount the same target to
   two different sources, snap, remove one, snap, diff. Expect
   the removed bind to appear as a single mounts removed change.
   Already covered by unit test
   `TestDiffMountsBindMountsKeyedByPointAndSource`.
8. ☐ **Escaped whitespace in mountpoints.** Already covered by
   `TestParseMountinfoLineEscapedMountpoint` and observed live with
   `/run/media/ibu/My Passport`.

### Verified during Phase E development

- ✅ Credential-stripping (`credentials=`, `password=`, `cred=`,
  case-insensitive) covered by `TestRedactAndSortOptions` and
  `TestParseMountinfoLineCredentialsStripped`. `username=` retained
  per redaction policy (Cat B identifier, redactable at export).
- ✅ Mount options pre-sorted alphabetically for stable hashing
  across kernel versions.
- ✅ Variable-length optional-fields block in mountinfo parsed
  correctly (covered by both basic and no-optional-fields fixtures).

## Phase A — manual tests

Unit tests cover parsing, diffing, and rule firing in isolation. These
are the manual scenarios that exercise the live host and the rendered
output. Run before declaring a phase complete; re-run before any
release that touches these collectors.

Status legend: ✅ verified on 2026-05-04 · ☐ recommended, not yet run.

### Smoke

1. ✅ **Genesis as root surfaces all three sections.**
   `sudo statedrift init` then inspect `.users / .groups / .sudoers /
   .schema_version` in the resulting JSON. Verified: 47 users, 75
   groups, 13 sudoers entries, schema_version="0.3", no
   collector_errors.
2. ☐ **Hash chain verifies after multiple snapshots.** Take 2–3
   snapshots back-to-back, run `statedrift verify`. Should report
   INTEGRITY VERIFIED — catches non-determinism in the new
   collectors (e.g. unsorted Members would break this).

### Rule firing on realistic scenarios

3. ☐ **R14 fires on new user.** `sudo useradd -m sdtest_user` →
   `sudo statedrift snap` → `statedrift analyze` should list
   `R14_USER_ADDED` (high). Clean up with `sudo userdel -r sdtest_user`.
4. ☐ **R15 fires on privilege escalation.** `sudo usermod -u 0
   sdtest_user` then snap + analyze. Should fire `R15_USER_MODIFIED`
   (medium). The auditor scenario; if R15 misses it, the rule's too
   narrow.
5. ☐ **R16 fires on sudoers change.** Drop a new file in
   `/etc/sudoers.d/`, snap, analyze. Should fire
   `R16_SUDOERS_MODIFIED` (critical).

### Edge cases

6. ☐ **`#includedir /etc/sudoers.d` is treated as a comment.** On a
   Debian/Ubuntu host this line typically appears in `/etc/sudoers`.
   It must be skipped by the collector (we treat all `#`-prefixed
   lines as comments) while the dirGlob still picks up the
   sudoers.d files separately.
7. ☐ **Whitespace-only edits don't drift.** Edit `/etc/sudoers` and
   add extra spaces/tabs to an existing rule without changing the
   meaning. Snap, diff. Expected: zero sudoers changes (the
   normalization should absorb cosmetic whitespace).
8. ☐ **Group membership change shows in diff.** `sudo gpasswd -a
   sdtest_user wheel` → snap → diff. Expected:
   `groups modified wheel.members`. R15 will not fire (it's a
   `users` rule, not `groups`); confirm the diff is human-readable.

### Cross-section / integration

9. ☐ **Audit bundle export contains the new sections.**
   `statedrift export bundle.tar.gz` → `tar tf` → grep for
   hostname/username/GECOS. Expected: present verbatim (Cat B
   identifiers stay until v0.4 `--redact-*` flags ship). Eyeball
   "would I be comfortable sending this externally?" — validates
   the v0.4 redaction work matters.
10. ☐ **Watch loop picks up the new sections.** `sudo statedrift
    watch --interval 30s`, then drop a file in `/etc/sudoers.d/`.
    Confirm it appears in the watch output and R16 fires via webhook
    if wired. Tests `CollectPartial` dispatch for the new sections.

### Verified-by-eyeball during Phase A

- ✅ `cmdShow` renders Users (count), Groups (members-only subset),
  and Sudoers (full) when run as root.
- ✅ Permission-denied on `/etc/sudoers` (non-root run) surfaces in
  the new "Collector errors" footer instead of being silently
  swallowed; `Sudoers:` block prints an explicit "(none collected
  — requires root, see collector_errors)" line.
- ✅ Whitespace-collapsing inside Defaults env_keep `+= "..."` strings
  preserved verbatim (the normalizer collapses unquoted whitespace
  runs only).

## Phase A — known limitations

Documenting deliberate non-coverage for users/groups/sudoers (the
Phase A scope). When v0.3 ships, distill these into release notes
(what's not covered) and `docs/DESIGN.md` (why); retire from this
plan doc once promoted.

- **Privilege-escalation-specific rules deferred.** R15 fires on any
  user `modified` at medium severity. UID changing to 0, addition to
  `wheel` / `sudo` / `admin` groups, and similar privilege-relevant
  signals are not separately rule-tagged in Phase A. Promote to a
  dedicated rule (e.g., `R15a_USER_BECAME_ROOT`) if the medium-severity
  catch-all proves too coarse in practice.
- **Secret-pattern redaction on sudoers lines.** Sudoers commands are
  typically binary paths (`/usr/bin/systemctl restart nginx`), not
  credential-bearing shell commands; the cron-style risk of inline
  secrets is low. We do not pattern-redact sudoers `Line` content in
  Phase A. Revisit as defense-in-depth when the cron pattern-redactor
  lands in Phase D.
- **PAM config not collected.** `/etc/pam.d/*` and `/etc/pam.conf`
  define the actual authentication posture (password complexity, 2FA,
  lockout). Real security signal, but parsing the auth/account/
  password/session stacks correctly is its own collector. Park as a
  v0.4 candidate or a Phase A.5 follow-up.
- **NSS users (LDAP, etc.) not collected.** Phase A reads
  `/etc/passwd` and `/etc/group` only. Users provisioned via NSS
  modules will not appear in snapshots. Documented limitation;
  fleet-scale orgs likely to want this in v0.5+ when fleet baseline
  features land.

## Note for v0.4 export-redaction

When `statedrift export --redact-*` flags ship (v0.4), the redaction
must extend to `Sudoers[].Line` content as well — sudoers lines
contain usernames and hostnames that are also covered by the Cat B
redaction policy. This is a known TODO; do not ship `--redact-*`
without sudoers coverage.

## Recommended sequencing

1. **Phase A first** — users/groups/sudoers. Highest auditor value,
   simplest collector, smallest risk surface. Use it to lock in
   conventions (always-on wiring, diff func placement, rule format,
   `schema_version` field placement) for B–E.
2. **Add CHANGELOG stub** — `## [0.3.0] — Unreleased` heading once
   Phase A merges. Without it the `make release` extractor produces
   an empty release body (see `docs/RELEASE.md`).
3. **Phase E (mounts) next** — easiest, exercises the
   `password=`/`credentials=` strip path from the redaction policy.
4. **Phase B (kernel modules), then D (cron + timers)** — D is where
   the cron-redaction pattern matcher first lands; design it as a
   reusable helper since it'll also apply to kernel cmdline later.
5. **Phase C (SSH keys) last** — most sensitive, benefits from the
   redaction conventions established in D. Implementation:
   `(type, fingerprint, comment, sha256(body))` per key.
6. **Cut v0.3.0** once all five phases land. Bump `Makefile:5`
   VERSION to `0.3.0` *as part of the release commit*, not in
   advance (see `project_github_release.md` versioning convention).

## Other v0.3-adjacent housekeeping

These are not v0.3 features but should land in the same window:

- **Branch protection on `main`** — Settings → Branches → require PRs
  + passing CI before merge.
- **`docs/DESIGN.md`** — pending writeup; raw material in the
  private repo's `veridyn-mvp-spec.md`. Must include an
  "Identifiers in snapshots" inventory (IPs, MACs, hostnames,
  usernames, GECOS field) so users understand what's in an audit
  bundle before they ship it externally.
- **Real `LICENSE_SECRET` rotation** — only if v0.3 ships any new
  Pro features. v0.3 as currently scoped is free-tier-only, so
  rotation can stay deferred.

## Out of scope (v0.4 or later)

- Process struct extension: `Threads`, `UTimeTicks`, `STimeTicks`,
  `StartTicks`. CPU% computed at diff time. PID-reuse detection via
  `start_ticks`. Rules R26–R28.
- **Export-time redaction flags** (`statedrift export --redact-network
  --redact-hostnames`). Operational identifiers stay verbatim in the
  local chain; redaction happens only when producing a bundle for
  external recipients. Determines the export-flow data model — a
  bigger change than a v0.3 collector.
- SELinux / AppArmor enforcement state, firewall rule hashing,
  `statedrift baseline` (v0.4 per `ROADMAP.md`).
- Recursive filesystem hash trees, customizable policy rules (v0.5).
- Fleet baseline export / import / compare (v0.6).
- `kthreads` collector (v0.5+).
