# v0.7 — Network dataplane collector (SR-IOV / DPDK)

Status: scaffolding. Free, opt-in, daemon-free. Follows the v0.6 `gpu` collector
pattern exactly. No schema change required beyond the additive `dataplane` section
(old snapshots deserialize cleanly; field is `omitempty`).

## What it collects (from `/sys`, regular files only — no symlink resolution)

Two facts about how host NICs are wired into the fast path:

1. **SR-IOV physical functions** — a NIC PF that exposes Virtual Functions.
   - Source: `/sys/class/net/<iface>/device/sriov_totalvfs` (presence ⇒ SR-IOV
     capable) + `sriov_numvfs`.
   - Identity + driver from `/sys/class/net/<iface>/device/uevent`
     (`PCI_SLOT_NAME=`, `DRIVER=`). uevent is a regular file, so the collector
     and its tests need no symlink plumbing.

2. **DPDK-bound devices** — a network-class PCI device handed to a userspace
   poll-mode driver, so the kernel netdev (and its firewall) no longer sees it.
   - Source: walk `/sys/bus/pci/devices/<addr>/`; `class` starts `0x02`
     (network controller) AND `uevent` `DRIVER=` ∈ {`vfio-pci`,
     `uio_pci_generic`, `igb_uio`}.

No NVIDIA-style daemon, no `os/exec`. A host with neither SR-IOV PFs nor
DPDK-bound devices yields a **nil** section (omitted), not an error — the common
case, mirroring `gpu`.

## Cat B / redaction
None. PCI addresses, driver names, kernel netdev names, and VF counts are not
Category B identifiers (same call as `gpu`: PCI address + version strings are not
Cat B). Section is **not** subject to export-time redaction; no DESIGN §4.5 row.

## Data model (internal/collector/types.go)
- `NetDataplane{ PFs []SRIOVPF; DPDKDevices []DPDKDevice }` (both sorted by pci_address)
- `SRIOVPF{ PCIAddress, Interface, Driver string; NumVFs, TotalVFs int }`
- `DPDKDevice{ PCIAddress, Driver string }`
- `Snapshot.Dataplane *NetDataplane json:"dataplane,omitempty"`

## v0.7 iteration — VF↔PF linkage + NUMA locality
- `DPDKDevice.PhysFn` — parent PF PCI address when the device is an SR-IOV VF
  (read from the `physfn` symlink via `os.Readlink`+basename; the ONE place this
  collector reads a link target — everything else is regular files). Surfaced in
  the diff summary as `vfio-pci vf-of 0000:01:00.0`.
- `SRIOVPF.NumaNode` + `DPDKDevice.NumaNode` — placement locality from
  `numa_node` (regular file); `-1` sentinel on non-NUMA hosts. Diffed as
  `<addr>.numa_node`.
- Deliberately did NOT add PF mtu/link-state: already captured by the always-on
  `network` capture section (Interface.State/MTU) keyed by name — duplicating it
  here would double diff noise on a link flap.

## Diff (internal/diff/diff_dataplane.go)
nil/nil → nothing. One nil → single summary line (`dataplane` section), like gpu.
Both present, keyed by PCI address:
- `dataplane.pf` added/removed; modified `<pci>.num_vfs` / `.total_vfs` /
  `.driver` / `.interface` (none counters — VF count change is a real reconfig).
- `dataplane.dpdk` added/removed; modified `<pci>.driver`.

Sub-section names (`dataplane.pf`, `dataplane.dpdk`) exploit the rules engine's
prefix-match on Section so the two "added" rule kinds don't collide (same trick
as `network.interfaces`).

## Rules (internal/rules/rules.go) — next free ID was R44
- R44_SRIOV_PF_ADDED      — `dataplane.pf`  added     — Low
- R45_SRIOV_PF_REMOVED    — `dataplane.pf`  removed   — Medium
- R46_SRIOV_VF_COUNT_CHANGED — `dataplane.pf` modified, key `*.num_vfs` — Medium
- R47_DPDK_DEVICE_BOUND   — `dataplane.dpdk` added    — Medium
Next free rule ID after this work: **R48**.

## Config knob (v0.7 iteration)
`Collectors.Dataplane` gates the collector; `Dataplane.DPDKDrivers []string`
(`dataplane.dpdk_drivers`) adds extra userspace driver names **on top of** the
built-in `vfio-pci`/`uio_pci_generic`/`igb_uio` set. Additive only — a
misconfiguration can never disable detection of the defaults (`dpdkDriverSet`
seeds the defaults first, then merges extras, skipping empty strings).

## Wiring
- config: `Collectors.Dataplane` + `IsEnabled("dataplane")` + `Dataplane{DPDKDrivers}` + knownSectionNames.
- collect.go: gate in `Collect` and `CollectPartial` (mirror gpu).
- diff.go: call `diffDataplane` when either side non-nil.
- main.go `allWatchSections`: add `"dataplane"` (cheap /sys reads → belongs in watch).
- CLAUDE.md: document under v0.6/v0.7 optional collectors; bump "Next free rule ID".

## Tests
- collect_dataplane_test.go — fake `/sys` tree (regular files): PF with VFs,
  DPDK-bound device, non-network PCI ignored, empty host → nil.
- diff_dataplane_test.go — added/removed/nil-summary/num_vfs change/dpdk bind.
- rules: R44–R47 fire on the corresponding changes.

## Checklist
- [x] types + Snapshot field
- [x] collect_dataplane.go + test
- [x] config wiring
- [x] collect.go Collect + CollectPartial
- [x] diff_dataplane.go + diff.go call + test
- [x] rules R44–R47 + test
- [x] allWatchSections
- [x] docs (CLAUDE.md)
- [x] gofmt -w . ; go vet ./... ; go test ./... — all green (full suite exit 0)

## Status: SCAFFOLD COMPLETE (uncommitted, on `main`)
Not yet committed/branched. No release cut. Next free rule ID now R48.
