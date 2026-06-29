package collector

// collect_dataplane.go — v0.7 network-dataplane inventory collector.
//
// Records how the host's NICs are wired into the fast path, read from /sys: a
// handful of regular files plus, for VF→PF linkage, the single `physfn` symlink
// per Virtual Function (read with os.Readlink — its target string, never its
// contents). No nvidia-smi-style helper, no os/exec. Two facts:
//
//   - SR-IOV physical functions: a NIC that exposes Virtual Functions. Detected
//     by the presence of /sys/class/net/<iface>/device/sriov_totalvfs; identity
//     and driver come from the sibling uevent file (PCI_SLOT_NAME=, DRIVER=).
//   - DPDK-bound devices: a network-class PCI device handed to a userspace
//     poll-mode driver (vfio-pci/uio_pci_generic/igb_uio). Detected by walking
//     /sys/bus/pci/devices and matching the device class + bound driver.
//
// Gated by the "dataplane" optional collector; off by default. A host with no
// SR-IOV PFs and no DPDK-bound NICs yields a nil inventory (the section is
// omitted), not an error — the common case, mirroring collectGPU.

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// defaultDPDKDrivers is the built-in set of userspace poll-mode drivers that
// take a NIC away from the kernel networking stack. A device bound to one of
// these is "DPDK managed". Operators can extend (never shrink) this set via
// config.Dataplane.DPDKDrivers for vendor-specific or out-of-tree UIO drivers.
var defaultDPDKDrivers = []string{"vfio-pci", "uio_pci_generic", "igb_uio"}

// collectDataplane reads the host /sys tree. extraDrivers are additional
// userspace driver names (from config) to treat as DPDK on top of the built-in
// defaults.
func collectDataplane(extraDrivers []string) (*NetDataplane, error) {
	return collectDataplaneFrom("/sys", extraDrivers)
}

// collectDataplaneFrom is the testable variant pointed at a /sys-like root. It
// returns (nil, nil) when the host has neither SR-IOV physical functions nor
// DPDK-bound NICs — the normal case. Missing trees (/sys/class/net or
// /sys/bus/pci absent, as in some containers) are treated as "nothing found",
// not an error.
func collectDataplaneFrom(sysRoot string, extraDrivers []string) (*NetDataplane, error) {
	pfs, err := collectSRIOVPFs(sysRoot)
	if err != nil {
		return nil, err
	}
	dpdk, err := collectDPDKDevices(sysRoot, dpdkDriverSet(extraDrivers))
	if err != nil {
		return nil, err
	}
	if len(pfs) == 0 && len(dpdk) == 0 {
		return nil, nil
	}
	return &NetDataplane{PFs: pfs, DPDKDevices: dpdk}, nil
}

// dpdkDriverSet returns the effective DPDK driver set: the built-in defaults
// plus any operator-supplied extras. Extras are additive so a misconfiguration
// can never disable detection of the standard vfio-pci/uio drivers.
func dpdkDriverSet(extra []string) map[string]bool {
	set := make(map[string]bool, len(defaultDPDKDrivers)+len(extra))
	for _, d := range defaultDPDKDrivers {
		set[d] = true
	}
	for _, d := range extra {
		if d != "" {
			set[d] = true
		}
	}
	return set
}

// collectSRIOVPFs walks /sys/class/net and returns one SRIOVPF per interface
// that advertises sriov_totalvfs (i.e. is an SR-IOV physical function).
func collectSRIOVPFs(sysRoot string) ([]SRIOVPF, error) {
	netDir := filepath.Join(sysRoot, "class", "net")
	entries, err := os.ReadDir(netDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var pfs []SRIOVPF
	for _, e := range entries {
		iface := e.Name()
		devDir := filepath.Join(netDir, iface, "device")

		total, ok := readIntFile(filepath.Join(devDir, "sriov_totalvfs"))
		if !ok {
			continue // not an SR-IOV physical function
		}
		num, _ := readIntFile(filepath.Join(devDir, "sriov_numvfs"))

		pf := SRIOVPF{Interface: iface, NumVFs: num, TotalVFs: total}
		uevent := parseUevent(filepath.Join(devDir, "uevent"))
		pf.PCIAddress = uevent["PCI_SLOT_NAME"]
		pf.Driver = uevent["DRIVER"]
		pf.NumaNode = readNumaNode(filepath.Join(devDir, "numa_node"))
		pfs = append(pfs, pf)
	}

	sort.Slice(pfs, func(i, j int) bool { return pfs[i].PCIAddress < pfs[j].PCIAddress })
	return pfs, nil
}

// collectDPDKDevices walks /sys/bus/pci/devices and returns one DPDKDevice per
// network-class device bound to one of the userspace poll-mode drivers in the
// supplied set.
func collectDPDKDevices(sysRoot string, dpdkDrivers map[string]bool) ([]DPDKDevice, error) {
	pciDir := filepath.Join(sysRoot, "bus", "pci", "devices")
	entries, err := os.ReadDir(pciDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var devs []DPDKDevice
	for _, e := range entries {
		addr := e.Name()
		base := filepath.Join(pciDir, addr)

		class, ok := readTrimmedFile(filepath.Join(base, "class"))
		if !ok || !strings.HasPrefix(class, "0x02") {
			continue // not a network controller
		}
		driver := parseUevent(filepath.Join(base, "uevent"))["DRIVER"]
		if !dpdkDrivers[driver] {
			continue // bound to its kernel driver (or unbound) — not DPDK
		}
		devs = append(devs, DPDKDevice{
			PCIAddress: addr,
			Driver:     driver,
			PhysFn:     readPhysFn(filepath.Join(base, "physfn")),
			NumaNode:   readNumaNode(filepath.Join(base, "numa_node")),
		})
	}

	sort.Slice(devs, func(i, j int) bool { return devs[i].PCIAddress < devs[j].PCIAddress })
	return devs, nil
}

// parseUevent reads a sysfs uevent file ("KEY=value" lines) into a map. A
// missing or unreadable file yields an empty (non-nil) map.
func parseUevent(path string) map[string]string {
	m := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		key, val, ok := strings.Cut(scanner.Text(), "=")
		if ok {
			m[key] = strings.TrimSpace(val)
		}
	}
	return m
}

// readTrimmedFile reads a single-line sysfs file, returning its trimmed contents
// and whether the read succeeded.
func readTrimmedFile(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}

// readNumaNode reads a sysfs numa_node file. A missing or unparseable file
// yields -1, matching the kernel's own sentinel for "no NUMA affinity".
func readNumaNode(path string) int {
	n, ok := readIntFile(path)
	if !ok {
		return -1
	}
	return n
}

// readPhysFn resolves the SR-IOV `physfn` symlink and returns the parent PF's
// PCI address (the link's final path element, e.g. "0000:01:00.0"). Returns ""
// when the link is absent — i.e. the device is not a Virtual Function.
func readPhysFn(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

// readIntFile reads a sysfs file expected to hold a single integer.
func readIntFile(path string) (int, bool) {
	s, ok := readTrimmedFile(path)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}
