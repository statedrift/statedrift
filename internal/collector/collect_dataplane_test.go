package collector

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// writeFile writes content to path, creating parent directories.
func writeDataplaneFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writePF adds an SR-IOV physical function under /sys/class/net/<iface>.
func writePF(t *testing.T, root, iface, pci, driver string, numvfs, totalvfs int) {
	t.Helper()
	dev := filepath.Join(root, "class", "net", iface, "device")
	writeDataplaneFile(t, filepath.Join(dev, "sriov_totalvfs"), strconv.Itoa(totalvfs)+"\n")
	writeDataplaneFile(t, filepath.Join(dev, "sriov_numvfs"), strconv.Itoa(numvfs)+"\n")
	writeDataplaneFile(t, filepath.Join(dev, "uevent"),
		"DRIVER="+driver+"\nPCI_SLOT_NAME="+pci+"\nPCI_ID=8086:1572\n")
	writeDataplaneFile(t, filepath.Join(dev, "numa_node"), "1\n")
}

// writePCIDevice adds a PCI device under /sys/bus/pci/devices/<addr>.
func writePCIDevice(t *testing.T, root, addr, class, driver string) {
	t.Helper()
	base := filepath.Join(root, "bus", "pci", "devices", addr)
	writeDataplaneFile(t, filepath.Join(base, "class"), class+"\n")
	writeDataplaneFile(t, filepath.Join(base, "uevent"),
		"DRIVER="+driver+"\nPCI_SLOT_NAME="+addr+"\n")
	writeDataplaneFile(t, filepath.Join(base, "numa_node"), "0\n")
}

// linkVF adds an SR-IOV `physfn` symlink under the VF's PCI device dir pointing
// at its parent PF, mirroring how the kernel exposes the relationship.
func linkVF(t *testing.T, root, vfAddr, pfAddr string) {
	t.Helper()
	base := filepath.Join(root, "bus", "pci", "devices", vfAddr)
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../"+pfAddr, filepath.Join(base, "physfn")); err != nil {
		t.Fatal(err)
	}
}

func TestCollectDataplaneEmpty(t *testing.T) {
	// No /sys/class/net and no /sys/bus/pci → nil inventory, no error.
	root := t.TempDir()
	inv, err := collectDataplaneFrom(root, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inv != nil {
		t.Errorf("expected nil inventory on bare host, got %+v", inv)
	}
}

func TestCollectDataplaneNoSRIOVNoDPDK(t *testing.T) {
	// A plain NIC bound to its kernel driver: no sriov_totalvfs, not a DPDK
	// driver → nothing collected.
	root := t.TempDir()
	writeDataplaneFile(t, filepath.Join(root, "class", "net", "eth0", "device", "uevent"),
		"DRIVER=e1000e\nPCI_SLOT_NAME=0000:00:1f.6\n")
	writePCIDevice(t, root, "0000:00:1f.6", "0x020000", "e1000e")

	inv, err := collectDataplaneFrom(root, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inv != nil {
		t.Errorf("expected nil inventory, got %+v", inv)
	}
}

func TestCollectDataplanePFAndDPDK(t *testing.T) {
	root := t.TempDir()
	// Two SR-IOV PFs (out of order so we can check sorting).
	writePF(t, root, "ens2f1", "0000:81:00.1", "mlx5_core", 0, 16)
	writePF(t, root, "ens1f0", "0000:01:00.0", "i40e", 4, 8)
	// One DPDK-bound NIC and one network NIC on its kernel driver.
	writePCIDevice(t, root, "0000:02:00.0", "0x020000", "vfio-pci")
	writePCIDevice(t, root, "0000:01:00.0", "0x020000", "i40e")
	// A storage controller bound to vfio-pci must be ignored (not network class).
	writePCIDevice(t, root, "0000:03:00.0", "0x010802", "vfio-pci")

	inv, err := collectDataplaneFrom(root, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inv == nil {
		t.Fatal("expected non-nil inventory")
	}

	if len(inv.PFs) != 2 {
		t.Fatalf("expected 2 PFs, got %d (%+v)", len(inv.PFs), inv.PFs)
	}
	// Sorted by PCI address → 0000:01:00.0 first.
	pf := inv.PFs[0]
	if pf.PCIAddress != "0000:01:00.0" {
		t.Errorf("PFs not sorted: first = %q", pf.PCIAddress)
	}
	if pf.Interface != "ens1f0" || pf.Driver != "i40e" || pf.NumVFs != 4 || pf.TotalVFs != 8 {
		t.Errorf("unexpected PF fields: %+v", pf)
	}
	if pf.NumaNode != 1 {
		t.Errorf("PF numa_node = %d, want 1", pf.NumaNode)
	}

	if len(inv.DPDKDevices) != 1 {
		t.Fatalf("expected 1 DPDK device, got %d (%+v)", len(inv.DPDKDevices), inv.DPDKDevices)
	}
	d := inv.DPDKDevices[0]
	if d.PCIAddress != "0000:02:00.0" || d.Driver != "vfio-pci" {
		t.Errorf("unexpected DPDK device: %+v", d)
	}
	if d.PhysFn != "" {
		t.Errorf("bare DPDK device should have no phys_fn, got %q", d.PhysFn)
	}
	if d.NumaNode != 0 {
		t.Errorf("DPDK device numa_node = %d, want 0", d.NumaNode)
	}
}

func TestCollectDataplaneVFLinkage(t *testing.T) {
	root := t.TempDir()
	// A VF (carved from PF 0000:01:00.0) handed to vfio-pci for a guest/DPDK app.
	writePCIDevice(t, root, "0000:01:10.0", "0x020000", "vfio-pci")
	linkVF(t, root, "0000:01:10.0", "0000:01:00.0")

	inv, err := collectDataplaneFrom(root, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inv == nil || len(inv.DPDKDevices) != 1 {
		t.Fatalf("expected the VF to be collected, got %+v", inv)
	}
	d := inv.DPDKDevices[0]
	if d.PhysFn != "0000:01:00.0" {
		t.Errorf("phys_fn = %q, want parent PF 0000:01:00.0", d.PhysFn)
	}
}

func TestReadNumaNodeMissing(t *testing.T) {
	// Absent numa_node → -1 (the kernel's "no NUMA" sentinel), not 0.
	if got := readNumaNode(filepath.Join(t.TempDir(), "numa_node")); got != -1 {
		t.Errorf("readNumaNode(missing) = %d, want -1", got)
	}
}

func TestCollectDataplaneCustomDPDKDriver(t *testing.T) {
	root := t.TempDir()
	// A network NIC bound to a vendor UIO driver not in the built-in set.
	writePCIDevice(t, root, "0000:04:00.0", "0x020000", "mlx_uio")

	// Without config, the custom driver is not recognized → nothing collected.
	inv, err := collectDataplaneFrom(root, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inv != nil {
		t.Errorf("custom driver must not match the built-in set, got %+v", inv)
	}

	// With it added to the config set, it is detected.
	inv, err = collectDataplaneFrom(root, []string{"mlx_uio"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inv == nil || len(inv.DPDKDevices) != 1 || inv.DPDKDevices[0].Driver != "mlx_uio" {
		t.Fatalf("expected the custom-driver device to be detected, got %+v", inv)
	}
}

func TestDPDKDriverSetIsAdditive(t *testing.T) {
	set := dpdkDriverSet([]string{"mlx_uio", ""})
	for _, d := range defaultDPDKDrivers {
		if !set[d] {
			t.Errorf("built-in driver %q must remain in the set even with extras", d)
		}
	}
	if !set["mlx_uio"] {
		t.Error("custom driver mlx_uio missing from set")
	}
	if set[""] {
		t.Error("empty driver name must be ignored")
	}
}

func TestParseUevent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "uevent")
	writeDataplaneFile(t, path, "DRIVER=vfio-pci\nPCI_SLOT_NAME=0000:02:00.0\nMODALIAS=pci:vXYZ\n")
	m := parseUevent(path)
	if m["DRIVER"] != "vfio-pci" || m["PCI_SLOT_NAME"] != "0000:02:00.0" {
		t.Errorf("unexpected uevent parse: %+v", m)
	}
	// Missing file → empty, non-nil map.
	if got := parseUevent(filepath.Join(root, "nope")); got == nil || len(got) != 0 {
		t.Errorf("expected empty map for missing file, got %+v", got)
	}
}
