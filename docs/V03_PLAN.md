# v0.3 Plan — Free Security Signals

Status: All five phases (A, B, C, D, E) landed 2026-05-04. v0.2.0 shipped 2026-04-29. Ready to cut v0.3.0 once a CHANGELOG stub lands and the manual test passes have been run on a release-candidate build.

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

## Phase C — known limitations

- **AuthorizedKeysFile sshd_config override not honored.** OpenSSH
  lets admins redirect authorized keys to e.g.
  `/etc/ssh/authorized_keys.d/%u` via the `AuthorizedKeysFile`
  directive. v0.3 only checks the standard `<home>/.ssh/authorized_keys`
  and `authorized_keys2` paths. Hosts with custom locations will
  appear key-less in the snapshot. Promote to an sshd_config-aware
  resolver in v0.4 if real deployments rely on the override.
- **AuthorizedKeysCommand not invoked.** `AuthorizedKeysCommand` runs
  an arbitrary helper to emit keys (commonly used for LDAP / IDP
  integration). statedrift will not see those keys. Documented gap;
  fleet-scale orgs that lean on this should treat it as an external
  observability gap until v0.5+ when fleet-baseline features land.
- **Host CA trust (TrustedUserCAKeys, RevokedKeys) not collected.**
  Certificate-authority configuration is a separate signal class —
  parse them in a follow-up Phase F if customers ask. R19/R20 do not
  cover CA-signed user certificates as a category.
- **Hashed `known_hosts`-style entries in authorized_keys not
  decoded.** The HashKnownHosts directive applies to known_hosts, not
  authorized_keys, so this is mostly a non-issue, but worth noting
  the parser does not unhash anything.
- **Body-leakage is the load-bearing invariant.** The collector
  computes the SHA256 fingerprint at parse time and discards the
  base64 body. `TestParseAuthorizedKeysLineNeverContainsBody` checks
  this directly. If that test ever needs to be relaxed, the redaction
  policy says: drop the field rather than ship a partial leak — do
  not ship a "body[:32]+'...'" placeholder.
- **Per-user permission errors are silently skipped.** Mirrors Phase
  D's /var/spool/cron handling: when statedrift runs as a non-root
  non-alice user, alice's mode-0600 authorized_keys is unreadable
  but does not abort collection. Production runs should be root.

## Phase C — manual tests

Status legend: ✅ verified on 2026-05-04 · ☐ recommended, not yet run.

### Smoke

1. ☐ **Genesis as root surfaces ssh_keys.** `sudo statedrift init`
   then inspect `.ssh_keys` in the resulting JSON. Hosts with at
   least one logged-in user typically show 1–10 keys; pure-server
   hosts may show only `/root/.ssh/authorized_keys`.
2. ☐ **Hash chain verifies after multiple snapshots.** Two
   back-to-back snaps as root, then `statedrift verify`. Catches
   non-determinism in user iteration order or fingerprint encoding.
3. ☐ **No key body in JSON.** `grep -E 'AAAA[A-Za-z0-9+/]{60,}'`
   the snapshot file (or `jq -r '.ssh_keys[]' | grep AAAA`). Must
   return nothing — base64 key bodies are 60+ char strings starting
   with the canonical AAAA prefix; if any leak, this catches them.

### Rule firing on realistic scenarios

4. ☐ **R19 fires on new SSH key.** `sudo bash -c 'echo "ssh-ed25519
   AAAA<…> attacker@laptop" >> /root/.ssh/authorized_keys'` →
   `sudo statedrift snap` → `analyze`. Expect `R19_SSH_KEY_ADDED`
   (critical). The auditor's nightmare scenario; if R19 misses this
   the rule is broken.
5. ☐ **R20 fires on key removal.** Snapshot a host with a known
   authorized_keys entry, remove it, snapshot again, analyze.
   Expect `R20_SSH_KEY_REMOVED` (medium).
6. ☐ **Re-key surfaces as add+remove.** Replace an existing key with
   a new one (different fingerprint, same user). Expect both R19 and
   R20 to fire on the same diff.

### Edge cases

7. ☐ **Forced-command options redacted.** Add a key with
   `command="bash -c 'AWS_SECRET_ACCESS_KEY=hunter2 deploy.sh'"`
   prefix. Snap, then grep `hunter2` the JSON — must return nothing.
8. ☐ **Service account in /var/lib found.** Some deploy users have
   home dir `/var/lib/jenkins` or similar. Add a key, snap; the
   user should appear in ssh_keys despite not being in /home.
9. ☐ **authorized_keys2 also picked up.** Drop a key in
   `~/.ssh/authorized_keys2` (legacy but still honored by sshd if
   AuthorizedKeysFile points there). Confirm it appears in JSON
   with `Source` ending in `authorized_keys2`.

### Verified during Phase C development

- ✅ Body never appears in any field of the parsed SSHKey, including
  partial substrings of length ≥ 30 (covered by
  `TestParseAuthorizedKeysLineNeverContainsBody`).
- ✅ Forced-command options pass through `redactSecrets` (covered
  by `TestParseAuthorizedKeysLineRedactsCommandSecrets`).
- ✅ Permission-denied per-user authorized_keys does not abort
  collection (covered by `TestReadSSHKeysFromUnreadableHomeIsBestEffort`).
- ✅ OpenSSH user certificates (ssh-ed25519-cert-v01@openssh.com
  etc.) recognized as valid keytypes (covered by
  `TestParseAuthorizedKeysLineCertType`).

## Phase D — known limitations

- **`/etc/cron.{daily,hourly,weekly,monthly}/` not collected.** These
  are script directories run by anacron / `run-parts`; the schedule is
  implicit by the directory name and the script contents are tracked
  by the package manager via the `packages` collector. Adding a
  rogue script to e.g. `/etc/cron.daily/` would *not* fire R21.
  Auditors who care about this should verify the relevant directories
  via filesystem integrity tooling outside statedrift's scope. Promote
  to a directory-listing collector in v0.4 if real-world incidents
  show this gap is being exploited.
- **No anacron `/etc/anacrontab`.** Same operational class as the
  daily-script directories above; deferred for the same reason.
- **Cron env-var assignments (`MAILTO=`, `SHELL=`, `PATH=`) skipped.**
  These are not jobs and `MAILTO` in particular is sometimes edited
  for benign reasons (e.g. on-call rotation). Documented limitation;
  if a customer asks for it later, capture them as a separate
  `cron_env` field rather than mixing into `CronJobs`.
- **`statedrift` does not see user-installed `crontab -u`-only
  entries on systems with restrictive crontab permissions.** When
  /var/spool/cron is mode 0700 and statedrift runs as a non-root
  user, the per-user crontabs are unreadable. Surfaces in
  `collector_errors` when this happens; production deployments should
  run snapshots as root.
- **Systemd timers read directly from unit files, not via
  `systemctl`.** Means we miss dynamic / generator-produced units
  (rare but possible — e.g. `systemd-cron-generator`). We also miss
  user-scope (`systemctl --user`) timers. Trade-off accepted: avoiding
  the systemctl spawn keeps the always-on collector cheap and stays
  consistent with the project's stdlib-only convention. Document for
  v0.5+ when fleet/agent-mode features land.
- **Last-run / next-run timestamps deliberately dropped.**
  `systemctl list-timers` exposes `LAST` and `NEXT` columns but those
  change on every snapshot for any timer that recently fired, which
  would dominate the diff with operationally-meaningless churn. The
  static schedule (OnCalendar etc.) is what carries the drift signal;
  if a customer needs run history, that's a separate "timer activity"
  feature.
- **Secret-pattern redaction is best-effort.** `redactSecrets` covers
  the common credential-name patterns (PASSWORD, SECRET, TOKEN, etc.)
  plus AWS / GitHub / Bearer token formats. Novel secret formats will
  not be caught. The reusable helper lives in
  `internal/collector/redact.go` so kernel-cmdline collection (planned
  v0.4) can apply the same redactor; expand the pattern list there
  rather than duplicating logic.

## Phase D — manual tests

Status legend: ✅ verified on 2026-05-04 · ☐ recommended, not yet run.

### Smoke

1. ☐ **Genesis as root surfaces both sections.** `sudo statedrift
   init` then inspect `.cron_jobs / .systemd_timers` in the resulting
   JSON. RHEL hosts typically show 1–3 cron jobs (the
   `/etc/cron.d/0hourly` driver) and 5–10 systemd timers (dnf, fstrim,
   logrotate, etc.). schema_version stays "0.3".
2. ☐ **Hash chain verifies after multiple snapshots.** Two
   back-to-back snaps as root, then `statedrift verify`. Catches
   non-determinism in cron sort order or timer-file enumeration.

### Rule firing on realistic scenarios

3. ☐ **R21 fires on new cron job.** `echo "@hourly root /opt/test.sh"
   | sudo tee /etc/cron.d/test` → `sudo statedrift snap` → `analyze`.
   Expect `R21_CRON_MODIFIED` (high). Clean up with
   `sudo rm /etc/cron.d/test`.
4. ☐ **R22 fires on timer change.** `sudo systemctl edit
   --full dnf-makecache.timer` (change OnUnitInactiveSec=1h → 30min),
   then snap + analyze. Expect `R22_TIMER_MODIFIED` (high). The
   audit-critical scenario: a timer's frequency or target unit
   changing under the operator's nose.
5. ☐ **Per-user crontab change fires R21.** `sudo crontab -u alice -e`
   to add a job, snap, analyze. Confirm the job appears with
   `Source: /var/spool/cron/alice` and `User: alice` in JSON, and
   R21 fires.

### Edge cases

6. ☐ **Inline secret in cron command is redacted.** `echo "0 2 * * *
   root MYSQL_PASSWORD=hunter2 /opt/backup.sh" | sudo tee
   /etc/cron.d/redaction-test`, snap, then `grep hunter2` the JSON
   snapshot file — must return nothing. The audit-trail leak case;
   if this fails, the redactor is broken and we have a chain
   contamination problem.
7. ☐ **Editor backup files in cron.d ignored.** Save a vim `.swp`
   or `~`-suffixed file in `/etc/cron.d/`; snap should not list it
   in JSON. Already covered by unit test
   `TestReadCronFromAllSources`.
8. ☐ **Same-named timer in /etc and /usr/lib — etc wins.** Already
   covered by `TestReadTimersFromOverrideOrder`. If a customer ever
   reports a "wrong timer schedule in snapshot," verify they don't
   have a stale unit in /etc shadowing the package version.

### Verified during Phase D development

- ✅ Cron env-var assignments (SHELL=, MAILTO=, PATH=) skipped at
  parse time (covered by `TestIsCronEnvAssignment` and
  `TestReadCrontabFileSkipsCommentsAndEnv`).
- ✅ Cron command bodies pass through `redactSecrets` for inline
  PASSWORD=, AWS keys, GitHub tokens, Bearer tokens (covered by the
  TestRedactSecrets* family).
- ✅ Per-user crontabs read user from filename, not from line
  (covered by `TestParseCronLineStandardNoUserField` and
  `TestReadCronFromAllSources`).
- ✅ Timer unit files with no `[Timer]` section return nil (defensive
  against stray `*.timer` matches; covered by
  `TestReadTimerUnitFileNoTimerSection`).

## Phase B — known limitations

- **No module signature collection.** `modinfo -F signature` would tell us
  whether a `.ko` file is signed and by which key, but spawning one
  modinfo process per loaded module (typically 100+) on every snapshot
  is too expensive for an always-on collector. R17/R18 cover the
  high-signal events (load/unload). Revisit in v0.4 with a sysfs- or
  direct-file-read approach if signature drift becomes a real-world ask.
- **No taint detection.** `/proc/sys/kernel/tainted` and per-module
  `/sys/module/<name>/taint` would surface out-of-tree modules and
  proprietary modules. Park as a v0.4 candidate; not load-bearing for
  the v0.3 free-tier signal set.
- **RefCount, State, and load address dropped.** RefCount changes
  constantly (kernel activity) and would dominate diffs. State is
  almost always "Live"; transitional Loading/Unloading states are too
  short-lived to snapshot reliably. The load address is zeros for
  non-root readers under kASLR. Excluding these keeps the chain quiet
  and the diff focused on real drift.
- **Module-replaced-with-different-version detection is partial.** R17
  fires when a name appears that wasn't there before, and the diff
  emits a `modules modified <name>.size` change when an existing
  module's size shifts (potential .ko replacement). There is no
  separate rule for the size-shift case — fold into a follow-up rule if
  in-place replacement proves to be a common attack pattern in the
  wild.

## Phase B — manual tests

Status legend: ✅ verified on 2026-05-04 · ☐ recommended, not yet run.

### Smoke

1. ☐ **Genesis includes modules.** `statedrift init` (no sudo needed;
   /proc/modules is world-readable). Inspect `.modules` count and a
   few entries in JSON. Expect 50–200+ entries on a typical Linux
   host; deps sorted alphabetically per entry.
2. ☐ **Hash chain verifies after multiple snapshots.** Two back-to-back
   snapshots followed by `statedrift verify` must report INTEGRITY
   VERIFIED — catches non-determinism in the dependency-sort path.

### Rule firing on realistic scenarios

3. ☐ **R17 fires on module load.** `sudo modprobe dummy` →
   `sudo statedrift snap` → `analyze`. Expect `R17_MODULE_LOADED`
   (high). Clean up with `sudo modprobe -r dummy`.
4. ☐ **R18 fires on module unload.** Snapshot a host with `dummy`
   loaded, unload, snapshot again, analyze. Expect
   `R18_MODULE_REMOVED` (medium).
5. ☐ **Size-change diff visible (no rule).** Replace a module's `.ko`
   in `/lib/modules/$(uname -r)/...` with a recompiled version of
   different size, `rmmod && modprobe` to take it live, snap, diff.
   Expect `modules modified <name>.size`. R17/R18 will not fire
   (the name was continuous); confirm the diff still reads cleanly.

### Edge cases

6. ☐ **No-deps module ('-').** Load any module with no dependencies
   (e.g. `dummy`). The JSON entry must have `"dependencies": null` or
   omitted, never `["-"]`.
7. ☐ **Multi-dep module dependency change shows in diff.** Force a
   dependency change (e.g. by loading `nft_fib_ipv6` after the rest
   of the nft_fib chain). Expect
   `modules modified <name>.dependencies`.

### Verified during Phase B development

- ✅ Trailing-comma deps (`nf_nat_tftp,`) parsed correctly
  (covered by `TestParseModulesLineSingleDep`).
- ✅ Out-of-load-order deps sorted alphabetically in output (covered
  by `TestParseModulesLineMultipleDepsSorted`).
- ✅ Malformed lines and unparseable sizes return nil rather than
  crash (covered by `TestParseModulesLineMalformed`).

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
   on RHEL test host, escaped paths (`/run/media/&lt;user&gt;/External Drive`)
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
   `/run/media/&lt;user&gt;/External Drive`.

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
