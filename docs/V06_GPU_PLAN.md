# v0.6 — GPU / accelerator inventory collector (free)

## Goal
A free, opt-in `gpu` collector that records the host's GPU/accelerator
inventory and flags driver / firmware / hardware drift — the AI-infra
analogue of the `nic_drivers` collector. Daemon-free, stdlib-only, no extra
privilege: reads the NVIDIA kernel driver's procfs tree (`/proc/driver/nvidia`).
No `nvidia-smi`, no `os/exec`, no device-management library.

## Scope (v0.6)
- **Vendor:** NVIDIA only. It dominates AI/ML infrastructure and exposes a
  stable, parse-friendly procfs interface with no tooling. AMD/ROCm and other
  accelerators are a deliberate deferral; the data model (`GPU.Model` carries
  the vendor/marketing name) extends to them later.
- **Captured (host-global):** `driver_version` from
  `/proc/driver/nvidia/version` (the `NVRM version:` line).
- **Captured (per GPU)** from `/proc/driver/nvidia/gpus/<pci-bus>/information`:
  - `bus_location` — PCI address (e.g. `0000:01:00.0`); the stable identity key.
  - `model` — marketing name (e.g. `NVIDIA A100-SXM4-40GB`).
  - `vbios_version` — video-BIOS (firmware) string.
- **Deliberately NOT captured:** GPU UUID (a stable per-device hardware
  identifier — would pull in Category-B redaction wiring; deferred like the
  container collector deferred image/labels), utilization/temperature/MIG
  layout (volatile or `nvidia-smi`-only — daemon/exec dependency we are avoiding).

## Data model (schema stays 0.5 — additive, omitempty)
`collector.GPUInventory{ DriverVersion, TotalCount, GPUs []GPU }`,
`collector.GPU{ BusLocation, Model, VBIOSVersion }`,
`Snapshot.GPU *GPUInventory json:"gpu,omitempty"`.

Hosts with no NVIDIA driver (`/proc/driver/nvidia` absent) yield a **nil**
inventory and **no error** — the section is simply omitted. This is the common
case and must not produce collector errors.

## Diff (`internal/diff/diff_gpu.go`)
Mirrors `diffContainers`:
- nil/nil → nothing; one-sided nil → single `inventory` summary line
  (collector toggled, or driver loaded/unloaded).
- host `driver_version` change → bare key `driver_version`.
- per-GPU keyed by `bus_location`: `added` / `removed`; `<bus>.model` and
  `<bus>.vbios_version` modifications. `model` change is informational
  (uncovered by rules, like container `.command`).

## Rules (free) — next free ID after this block is **R44**
| ID | Trigger | Severity | Rationale |
|----|---------|----------|-----------|
| R40_GPU_ADDED | `gpu` added | Low | GPUs don't hot-add on a stable host; appearance = hardware/passthrough change. |
| R41_GPU_REMOVED | `gpu` removed | Medium | A vanished GPU (Xid/fell-off-bus, removal, lost passthrough) silently degrades AI workloads — higher-signal direction than added. |
| R42_GPU_DRIVER_CHANGED | `gpu` modified `driver_version` | Medium | Up/downgrade; a rollback can reintroduce vulnerable driver code. |
| R43_GPU_VBIOS_CHANGED | `gpu` modified `*.vbios_version` | High | VBIOS reflash = firmware-level tampering/persistence (cf. NIC firmware R11). |

## Redaction
No Category-B identifiers: bus address (structural, like a filesystem path),
hardware model name, and version strings — analogous to `mac`/`filesystem`
fields. Section is **exempt** from export redaction. New DESIGN §4.5 row records
this.

## Wiring checklist (parity with the `containers` collector)
- [x] `internal/collector/types.go` — `GPUInventory`/`GPU` + `Snapshot.GPU`.
- [x] `internal/collector/collect_gpu.go` — `collectGPU`/`collectGPUFrom` + parsers.
- [x] `internal/collector/collect_gpu_test.go`.
- [x] `internal/config/config.go` — `Collectors.GPU`, `IsEnabled("gpu")`, `knownSectionNames`.
- [x] `internal/collector/collect.go` — dispatch in `Collect` + `CollectPartial`.
- [x] `internal/diff/diff_gpu.go` + `diff_gpu_test.go`; dispatch in `diff.go`.
- [x] `internal/rules/rules.go` — R40–R43 (+ rule test).
- [x] `cmd/statedrift/main.go` — add `"gpu"` to `allWatchSections` (cheap /proc
      read; a GPU dropping off the bus is exactly near-real-time drift).
- [x] `CHANGELOG.md` `[Unreleased]`, `docs/DESIGN.md` capture table + §4.5 row.

## Invariants
- `go vet ./...` and `go test ./...` pass after every change.
- stdlib only. Schema unchanged (0.5). `gofmt -w .` before commit.
