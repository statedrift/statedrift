# v0.6 — Container runtime collector (free)

Status: in progress. Branch `feat/v06-container-collector`.

## What and why

A new opt-in collector that records the **running container inventory** so the
diff/rules engine can flag a container appearing or disappearing — a new
container outside a change window is a classic foothold for cryptominers,
backdoors, and lateral movement. Mirrors the v0.5 Phase P filesystem collector
in shape: opt-in collector → snapshot section → per-item diff → anomaly rules.

**Decision (user, 2026-06-26): ships FREE.** This reshapes the first v0.6
deliverable as free value and keeps the `LICENSE_SECRET` rotation cliff
deferred (no Pro feature yet). The Pro "fleet" work remains future.

## Design (locked)

1. **Data source: cgroups, not a runtime daemon.** Containers are detected by
   parsing `/proc/[pid]/cgroup` and grouping PIDs by the container ID embedded
   in the cgroup path. This is runtime-agnostic (Docker, containerd/CRI-O,
   podman all leave identifiable paths), needs no `docker.sock` / daemon
   socket, requires no extra privilege beyond reading `/proc`, and degrades
   gracefully — fully consistent with every other collector. No `os/exec`.
2. **Runtime-CLI augmentation is deferred.** Image name, labels, and creation
   time would need `docker`/`crictl`/`podman` (daemon-dependent, runtime
   specific). Out of scope for v1; the cgroup inventory is the security signal.
3. **Privileged-container detection deferred.** Reading the init process's
   `CapEff` from `/proc/[pid]/status` to flag privileged containers is a strong
   follow-up signal but adds scope; v1 is appearance/disappearance only.
4. **Additive, no schema bump.** New `containers` snapshot field is
   `omitempty`; `schema_version` stays `0.5`. Pre-existing snapshots simply
   lack it. Default off (opt-in), like every collector since v0.2.

## cgroup → container ID/runtime mapping

`/proc/[pid]/cgroup` lines look like `hierarchy:controllers:path`. The path
carries the container ID for containerized processes (examples seen in the
wild, cgroup v1 and v2):

- Docker:        `…/docker/<64-hex>`  or  `…/docker-<64-hex>.scope`
- containerd/CRI:`…/cri-containerd-<64-hex>.scope`  or  `…/kubepods/…/<64-hex>`
- CRI-O:         `…/crio-<64-hex>.scope`
- podman:        `…/libpod-<64-hex>`  or  `…/machine.slice/libpod-<64-hex>`

`parseCgroupForContainer(content string) (id, runtime string, ok bool)` (pure,
unit-tested) scans the lines, finds the first segment matching a known runtime
prefix wrapping a 64-hex (or ≥12-hex) ID, and returns the **short** 12-char ID
plus the inferred runtime (`docker` / `containerd` / `cri-o` / `podman` /
`unknown`). Host/non-container processes (paths like `/user.slice/...`,
`/system.slice/<name>.service`) return `ok=false`.

## Data model — `internal/collector/types.go`

```go
type ContainerInventory struct {
    TotalCount int         `json:"total_count"`
    Containers []Container `json:"containers"`
}

type Container struct {
    ID        string `json:"id"`               // short (12-char) container id
    Runtime   string `json:"runtime"`          // docker|containerd|cri-o|podman|unknown
    Command   string `json:"command,omitempty"`// comm of the lowest-PID process (representative)
    Processes int    `json:"processes"`        // process count (volatile → counter in diff)
}
```

Snapshot gains `Containers *ContainerInventory \`json:"containers,omitempty"\``.
Containers sorted by ID for deterministic, canonical output.

## Collector — `internal/collector/collect_containers.go`

- `collectContainers() (*ContainerInventory, error)` — walk `/proc/[pid]`, read
  `cgroup`, map via `parseCgroupForContainer`, group PIDs by container ID,
  record runtime + representative command (lowest PID's `comm` from
  `/proc/[pid]/status`) + process count. Skip PIDs that exit mid-walk.
- `parseCgroupForContainer` is the pure, fixture-tested core.

Wire into the snapshot assembly behind `cfg.Collectors.IsEnabled("containers")`,
exactly like `filesystem`.

## Config — `internal/config/config.go`

- Add `Containers bool \`json:"containers"\`` to `Collectors`; add the
  `"containers"` case to `IsEnabled` and the known-collectors set.

## Diff — `internal/diff/diff_containers.go`

- Key by container ID. `added` → new container (the signal); `removed` →
  container gone. `modified`: `<id>.runtime` / `<id>.command` (rare) as real
  changes; `<id>.processes` marked `Counter:true` (volatile, rules ignore).
- Dispatch from `diff.go` when either side has `Containers` (mirror filesystem).

## Rules — `internal/rules/rules.go` (free, next IDs R37/R38)

- **R37_CONTAINER_STARTED** (medium) — section `containers`, change_type
  `added`. New container appeared.
- **R38_CONTAINER_STOPPED** (low) — change_type `removed`. Container gone.

Next free rule ID becomes **R39**.

## Tests

- `collect_containers_test.go` — `parseCgroupForContainer` table: docker v1/v2,
  containerd, cri-o, podman, kubepods, host slices (user/system → not a
  container), empty, malformed. Plus an inventory grouping test over a fake
  `/proc` tree if practical.
- `diff_containers_test.go` — added/removed/modified; process-count change is a
  counter (no rule fire); runtime change is a real modify.
- `rules_test.go` — R37 fires on `containers/added`, R38 on `removed`, both free;
  a process-count counter change fires neither.
- Fuzz: extend `internal/collector/fuzz_test.go` with
  `FuzzParseCgroupForContainer` (no panic on hostile cgroup content).

## Docs

- `CHANGELOG.md` `[Unreleased]` — container collector + R37/R38.
- `ROADMAP.md` — note container runtime state delivered (free); v0.6 Pro fleet
  still pending.
- `README.md` / `docs/DESIGN.md` — collector table row; DESIGN §4.5 redaction
  inventory: container IDs/commands are not Cat B secrets (IDs are random,
  commands are process names) → not redacted. Note that explicitly.
- `CLAUDE.md` (local) — add `containers` collector; next rule ID R39.

## Definition of done

`go vet ./...`, `go test -race ./...` green; `gofmt -w .` clean; fuzz seeds
pass. PR off `feat/v06-container-collector` into `main`. VERSION stays `0.5.1`.

## Follow-up — privileged-container detection (R39, delivered)

The deferred privileged-container signal, built as the next free increment:
- `Container.CapEff` records the representative process's effective-capability
  hex bitmask (`/proc/[pid]/status` `CapEff:`) — a stored fact.
- Diff derives a bare-key `privileged_container` signal (mirrors filesystem
  setuid) when `isPrivilegedCaps(capEff)` is newly true: CAP_SYS_ADMIN (bit 21)
  set. Docker's default cap set drops it, so its presence = `--privileged` /
  `--cap-add=SYS_ADMIN`. Fires on a privileged container appearing OR an
  existing one gaining it; the readable `<id>.cap_eff` change is also emitted.
- **R39_PRIVILEGED_CONTAINER** (high), free. **Next free rule ID now R40.**
- Tests: collector captures CapEff; diff signal on add/gain, none for default
  caps or already-privileged; R39 fires on the signal, not on a plain add.

## Progress

- [x] types: ContainerInventory/Container + Snapshot field (omitempty, schema 0.5)
- [x] config: Containers gate + IsEnabled + knownSectionNames
- [x] collector: parseCgroupForContainer + collectContainersFrom + wiring (both
      full Collect and CollectPartial dispatch sites); added to allWatchSections
      (watch scheduler) since cgroup reads are cheap — filesystem stays excluded.
- [x] collector parser: 32–64-hex floor excludes k8s pod-UUID fragments so the
      64-hex container segment is the only match; runtime via path tokens.
- [x] diff: diff_containers.go + dispatch (added/removed signal; runtime/command
      real; processes counter).
- [x] rules: R37_CONTAINER_STARTED (medium) / R38_CONTAINER_STOPPED (low), free.
      Next free rule ID now R39.
- [x] tests: collect_containers_test (parser table incl. docker v1/v2,
      containerd, cri-o, podman, kubepods, host slices, malformed; inventory
      grouping over a fake /proc); diff_containers_test; rules R37/R38 + counter;
      FuzzParseCgroupForContainer (no panic).
- [x] docs: CHANGELOG [Unreleased], ROADMAP (delivered/free), README, DESIGN
      (rule range R01–R38 + free-tier list), CLAUDE.md (local, next ID R39).
- [x] gofmt + vet + go test -race ./internal/... green.
- [ ] commit + PR (cmd -race in flight)
