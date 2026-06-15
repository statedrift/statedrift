# v0.5 Phase Q — anomaly rules R34–R36 (filesystem + firewall)

Status: in progress. Branch `feat/v05-phase-q-anomaly-rules`. Third v0.5 theme
(after Phase O firewall diff, Phase P filesystem tree). Turns the new Phase O/P
data into security signals.

Three new **free** rules over the data the last two phases added:

- **R34_FS_SETUID_ADDED** (high) — a setuid/setgid bit appeared on a watched
  file (new privileged binary, or an existing file gaining the bit).
- **R35_FS_WORLD_WRITABLE** (high) — a watched file/dir became world-writable
  (others-write) without the sticky bit — anyone can overwrite it.
- **R36_FW_WORLD_OPEN_SENSITIVE** (high) — a new firewall INPUT rule accepts a
  sensitive port (22/3389/3306/…) from any source.

## Decisions (locked)

1. **Detection lives in the diff layer, rules are thin matchers.** The rules
   engine matches only Section / ChangeType / KeyPattern — it cannot inspect
   values, and `KeyPattern` uses `filepath.Match`, which does not cross `/`.
   So, exactly like R32/R33 (`ruleset_changed`/`flushed`) and R29–R31, the diff
   computes the semantic signal and emits a **bare, path-free synthetic key**;
   the rule is a one-line declarative matcher. The affected path/rule travels
   in the change's value, not its key.
2. **All free.** Continues the free engine (R01–R33 already free). No Pro flag,
   no `LICENSE_SECRET` impact. [[feedback_public_need_to_know]] —
   nothing new is uploaded beyond the usual public repo docs.
3. **Conservative, documented heuristics.** Better to under-fire than to cry
   wolf. setuid/world-writable parse the `os.FileMode` string precisely;
   firewall world-open is heuristic (string scan) and scoped to INPUT chains.
4. **No schema change, no new collector.** Pure diff + rules. `schema_version`
   stays `0.5`.

## Synthetic signals — diff layer

`os.FileMode.String()` renders the setuid/setgid/sticky bits as leading
`u`/`g`/`t` (Lstat populates `os.ModeSetuid/Setgid/Sticky` for on-disk files).
The trailing 9 chars are always the rwx perm block. Detection helpers:

- `isSetuidMode(mode)` — `mode[:len-9]` contains `u` or `g`.
- `isWorldWritableMode(mode)` — perm block others-write is `w`, AND not sticky
  (no `t` in prefix), AND not a symlink (no `L`).

### `internal/diff/diff_filesystem.go`

Emit per affected entry (in both the **added** branch and the **modified**
branch, the latter only when the bit is newly *gained*):

- setuid/setgid → `Change{"filesystem", "modified", "setuid_added", "", path}`
- world-writable → `Change{"filesystem", "modified", "world_writable", "", path}`

Keys are bare (path in the value) so a `filepath.Match` rule can hit them and
so multiple files aggregate into one finding with a match count. The existing
per-file `.mode`/`.sha256`/… changes stay for human diff readability (same
detail+signal duplication as firewall's per-rule + `ruleset_changed`).

### `internal/diff/diff_firewall.go`

In `diffFirewallRules`, for each **added** rule, if `firewallRuleWorldOpen`
returns true emit `Change{"firewall", "modified", "world_open", "", rule}`.

`firewallRuleWorldOpen(chain, rule)`:
- chain is `INPUT`/`input` (inbound exposure only).
- rule accepts: contains `-j ACCEPT` (iptables) or ` accept` (nft).
- destination port (`--dport`/`dport`) is in `sensitiveFirewallPorts`
  (22, 23, 445, 1433, 3306, 3389, 5432, 6379, 9200, 11211, 27017, 2375, 2376).
- source is any: no restricting `-s`/`saddr`, or an explicit `0.0.0.0/0` / `::/0`.

Only newly-added rules fire (a pre-existing exposure is not a new event).

## Rules — `internal/rules/rules.go`

Append after R33 (free block, before the Pro block):

```go
{ID: "R34_FS_SETUID_ADDED",        Severity: High,   Section: "filesystem", ChangeType: "modified", KeyPattern: "setuid_added"},
{ID: "R35_FS_WORLD_WRITABLE",      Severity: High,   Section: "filesystem", ChangeType: "modified", KeyPattern: "world_writable"},
{ID: "R36_FW_WORLD_OPEN_SENSITIVE",Severity: High,   Section: "firewall",   ChangeType: "modified", KeyPattern: "world_open"},
```

(full Name/Description as in the other rules).

## Tests

- `diff_filesystem_test.go` — setuid file added → `setuid_added`; mode change
  gaining setgid → `setuid_added`; a file gaining others-write → `world_writable`;
  sticky world-writable dir and symlinks do **not** fire; plain perm change
  with no security transition emits no synthetic key.
- `diff_firewall_test.go` — added `--dport 22 -j ACCEPT` with no source →
  `world_open`; same rule but `-s 10.0.0.0/8` → none; non-sensitive port → none;
  FORWARD/OUTPUT chain → none; a world-open rule already present in old (only
  reordered) → none. nft `tcp dport 3389 accept` → fires.
- `rules_test.go` (or new `rules_anomaly_test.go`) — R34/R35/R36 fire on their
  keys; are free-tier; a plain `.mode`/`.sha256` change does not fire R34/R35.

## Docs

- `CHANGELOG.md` `[0.5.0]` — Phase Q rules R34–R36.
- `README.md` / any rules listing — bump free rules to R01–R36.
- `ROADMAP.md` — note smart filesystem/firewall anomaly rules delivered.
- `CLAUDE.md` (local-only, gitignored) — bump free rule range.
- `docs/DESIGN.md` if it enumerates rules.

## Definition of done

`go vet ./...`, `go test ./...` green; `gofmt -w .` clean. PR off
`feat/v05-phase-q-anomaly-rules` into `main`. VERSION stays `0.4.0`.

## Progress

- [x] Filesystem synthetic signals + helpers (diff_filesystem.go) — setuid_added
      / world_writable on added + gained-bit modify; sticky/symlink exempt. 5 tests.
- [x] Firewall world-open signal + helpers (in diff.go diffFirewallRules) —
      INPUT-only, sensitive dport, any-source heuristic; only on added. 6 tests.
- [x] Rules R34–R36 (rules.go, free) + 5 tests (rules_anomaly_test.go).
- [x] Docs — CHANGELOG [0.5.0]; ROADMAP delivered + free-tier range R01–R36;
      DESIGN free-tier range; CLAUDE.md (local) next ID R37. README needs no
      rule-list edit (no per-rule list there).
- [ ] Commit + PR
