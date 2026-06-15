# v0.5 Phase P — Recursive filesystem hash tree

Status: in progress. Branch `feat/v05-phase-p-filesystem-hash-tree`. Second
v0.5 theme (after Phase O per-rule firewall diff).

A new opt-in collector that hashes a configured set of filesystem roots into a
per-file tree (`{path, mode, uid, gid, size, sha256}`) plus a single Merkle
root hash, so the diff can show per-file added / removed / modified changes —
catching config drift, tampered files, and permission/ownership changes.

## Decisions (locked — confirmed with user 2026-06-14)

1. **Free, opt-in collector.** Consistent with CLAUDE.md ("all collectors
   free") and the defined freemium boundary (Pro = rules/baseline/report/SIEM/
   hub). NOT license-gated — there is no license-gated collector in the
   codebase and this phase does not introduce one. The structural diff is free
   too (mirrors Phase O's free-diff decision). "Pro depth" for filesystem is
   deferred to later themes: filesystem anomaly rules (R34+), baseline pin,
   and report integration. **LICENSE_SECRET is untouched this phase.**
2. **Opt-in via `collectors.filesystem`** (default false), like the other
   optional collectors. `collectors.all: true` enables it too.
3. **Default root `/etc`.** When enabled with no explicit `filesystem.roots`,
   the collector hashes `/etc` only — the highest-value, modest-size target
   (config / credential / unit drift). Operators widen via `filesystem.roots`.
   Keeps the append-only chain small by default.
4. **Size caps, deterministic truncation.** `max_file_size` (default 50 MiB):
   regular files larger than this are recorded (path/mode/size) but not hashed
   (`sha256` empty). `max_files` (default 50000): walking stops once the cap is
   hit and `truncated: true` is set. The walk is lexical (filepath.WalkDir
   order), so truncation is stable across runs.
5. **No symlink following; record the target.** Symlinks are recorded with
   their `target` and not dereferenced (avoids cycles and root escapes).
   Directories and special files are recorded for mode/ownership but carry no
   `sha256` and `size: 0` (directory size is noisy).
6. **Paths are not Category B.** Default roots are system config paths; like
   `mounts.mount_point` (DESIGN §4.5, "Local filesystem layout — not Cat B"),
   paths, modes, uid/gid, and content hashes are not operational identifiers.
   No redaction this phase. Caveat documented: operators who watch
   identifier-bearing paths (e.g. `/home/<user>`) should review before export.
7. **No `schema_version` bump.** Already `0.5` (Phase O). `filesystem` is
   additive / `omitempty`; pre-Phase-P 0.5 snapshots simply lack it.

## Data model — `internal/collector/types.go`

```go
type FileEntry struct {
    Path   string `json:"path"`             // absolute path
    Mode   string `json:"mode"`             // os.FileMode string, e.g. "-rw-r--r--", "drwxr-xr-x", "Lrwxrwxrwx"
    UID    uint32 `json:"uid"`
    GID    uint32 `json:"gid"`
    Size   int64  `json:"size"`             // 0 for dirs/symlinks/special
    SHA256 string `json:"sha256,omitempty"` // regular files only, within size cap
    Target string `json:"target,omitempty"` // symlink target
}

type FilesystemTree struct {
    Roots     []string    `json:"roots"`               // roots actually scanned
    RootHash  string      `json:"root_hash"`           // Merkle root over all entries
    Files     int         `json:"files"`               // entry count
    Truncated bool        `json:"truncated,omitempty"` // hit max_files
    Entries   []FileEntry `json:"entries,omitempty"`   // lexical order
}
```

`Snapshot.Filesystem *FilesystemTree` (`json:"filesystem,omitempty"`), nil when
the collector is disabled or on pre-Phase-P snapshots.

## Config — `internal/config/config.go`

- `Collectors.Filesystem bool` + `IsEnabled("filesystem")`.
- New `Filesystem` sub-struct on `Config`:
  ```go
  type Filesystem struct {
      Roots       []string `json:"roots"`
      Excludes    []string `json:"excludes"`       // glob patterns on full path
      MaxFileSize int64    `json:"max_file_size"`  // bytes; 0 → 50 MiB
      MaxFiles    int      `json:"max_files"`      // 0 → 50000
  }
  ```
- `"filesystem"` added to `knownSectionNames` (section_intervals support; the
  collector is expensive, so per-section intervals are useful).
- Defaults applied in the collector: empty `Roots` → `["/etc"]`.

## Collector — `internal/collector/collect_filesystem.go`

`collectFilesystem(cfg *config.Config) (*FilesystemTree, error)`:
- For each root, `filepath.WalkDir` in lexical order. Skip excluded paths
  (glob match on full path; on a dir match, `SkipDir`).
- Per entry: `Lstat` for mode/uid/gid/size (uid/gid via `info.Sys().(*syscall.Stat_t)`).
  Regular files ≤ `max_file_size` are SHA-256 hashed (streamed). Symlinks
  record `Target`. Dirs/special: no hash, size 0.
- Unreadable files/dirs are skipped gracefully (recorded via the snapshot's
  `collector_errors`, not fatal).
- Stop at `max_files`; set `Truncated`.
- `RootHash` = SHA-256 over the canonical per-entry serialization in walk order.

Wire into `collect.go` `Collect` and `CollectPartial` behind
`cfg.Collectors.IsEnabled("filesystem")`, alongside the other optional
collectors.

## Diff — `internal/diff/diff_filesystem.go`

`diffFilesystem(old, new *FilesystemTree, r *Result)` — group entries by path
and emit (paths iterate sorted for determinism):
- `added` — path in new, not old (`filesystem`/`<path>`).
- `removed` — path in old, not new.
- `modified` — path in both with a changed attribute; one change per differing
  attribute, keyed `<path>.<attr>` (`.mode`, `.uid`, `.gid`, `.size`,
  `.sha256`, `.target`) — mirrors `diffNICDrivers`.

Wire into `Compare`: `if old.Filesystem != nil || new.Filesystem != nil`. No
rule signals this phase (filesystem anomaly rules R34+ are a future Pro theme).

## Tests

- `collect_filesystem_test.go` — build a temp tree (files, subdir, symlink,
  oversized file), assert entries/modes/hashes, exclude globs, `max_files`
  truncation + stable order, `max_file_size` skips the hash, deterministic
  `RootHash` (same tree → same hash; one byte changed → different hash).
- `diff_filesystem_test.go` — added / removed / per-attribute modified
  (content, mode, ownership, size, symlink target); identical tree → no
  changes; nil transitions.
- `config_test.go` — `IsEnabled("filesystem")`, `all:true` covers it,
  section_intervals accepts `"filesystem"`.

## Docs

- `CHANGELOG.md` — add to `[0.5.0] — Unreleased`: Phase P filesystem collector.
- `README.md` — collector table row; note opt-in + default `/etc`.
- `docs/DESIGN.md` — §4.2 collector inventory row; §4.5 a `filesystem` row
  (paths/hashes — not Cat B, like `mounts.mount_point`, with the `/home`
  caveat).
- `ROADMAP.md` — mark "Recursive filesystem hash trees with structural diff"
  delivered.
- `CLAUDE.md` — add `filesystem` to the v0.2 optional collectors list.

## Definition of done

`go vet ./...`, `go test ./...` green; `gofmt -w .` clean. PR off
`feat/v05-phase-p-filesystem-hash-tree` into `main`. VERSION stays `0.4.0`
(latest released tag — do not pre-bump).

## Progress

- [x] Data model (types.go) — `FilesystemTree`, `FileEntry`, `Snapshot.Filesystem`.
- [x] Config — `Collectors.Filesystem` + `IsEnabled`; `Filesystem` struct;
      `FSDefault*` consts/`FSDefaultRoots`; `filesystem` known section.
- [x] Collector (collect_filesystem.go) + 7 tests — walk, lstat, stream hash,
      symlink target, excludes, max_files truncation, max_file_size, Merkle root.
- [x] Wire into Collect / CollectPartial (opt-in gate).
- [x] Diff (diff_filesystem.go) + wired into Compare + 5 tests — added/removed,
      per-attr modified, symlink target, unchanged-root short-circuit, nil summary.
- [x] Config tests — IsEnabled(filesystem), all:true, section_intervals.
- [x] Docs (CHANGELOG/README/DESIGN §4.2+§4.5/ROADMAP/CLAUDE.md).
- [ ] Commit + PR.
