package collector

import (
	"os"
	"path/filepath"
	"testing"
)

// writeGPUTree builds a fake /proc/driver/nvidia tree under root with the given
// driver-version file content and one information file per bus.
func writeGPUTree(t *testing.T, root, versionContent string, gpus map[string]string) {
	t.Helper()
	base := filepath.Join(root, "driver", "nvidia")
	if err := os.MkdirAll(filepath.Join(base, "gpus"), 0o755); err != nil {
		t.Fatal(err)
	}
	if versionContent != "" {
		if err := os.WriteFile(filepath.Join(base, "version"), []byte(versionContent), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for bus, info := range gpus {
		dir := filepath.Join(base, "gpus", bus)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "information"), []byte(info), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

const sampleNvidiaVersion = "NVRM version: NVIDIA UNIX x86_64 Kernel Module  535.129.03  Tue Oct 31 19:57:38 UTC 2023\n" +
	"GCC version:  gcc version 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04)\n"

func sampleGPUInfo(model, vbios, bus string) string {
	return "Model: \t\t " + model + "\n" +
		"IRQ:   \t\t 45\n" +
		"GPU UUID: \t GPU-deadbeef-0000-1111-2222-333344445555\n" +
		"Video BIOS: \t " + vbios + "\n" +
		"Bus Location: \t " + bus + "\n" +
		"Device Minor: \t 0\n"
}

func TestCollectGPUNoDriver(t *testing.T) {
	// /proc/driver/nvidia absent → nil inventory, no error (the common case).
	root := t.TempDir()
	inv, err := collectGPUFrom(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inv != nil {
		t.Errorf("expected nil inventory when no NVIDIA driver present, got %+v", inv)
	}
}

func TestCollectGPUParsesDriverAndGPUs(t *testing.T) {
	root := t.TempDir()
	writeGPUTree(t, root, sampleNvidiaVersion, map[string]string{
		"0000:81:00.0": sampleGPUInfo("NVIDIA A100-SXM4-40GB", "92.00.45.00.07", "0000:81:00.0"),
		"0000:01:00.0": sampleGPUInfo("NVIDIA A100-SXM4-40GB", "92.00.45.00.07", "0000:01:00.0"),
	})

	inv, err := collectGPUFrom(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inv == nil {
		t.Fatal("expected non-nil inventory")
	}
	if inv.DriverVersion != "535.129.03" {
		t.Errorf("driver version = %q, want 535.129.03", inv.DriverVersion)
	}
	if inv.TotalCount != 2 || len(inv.GPUs) != 2 {
		t.Fatalf("expected 2 GPUs, got TotalCount=%d len=%d", inv.TotalCount, len(inv.GPUs))
	}
	// Sorted by bus location → 0000:01:00.0 first.
	if inv.GPUs[0].BusLocation != "0000:01:00.0" {
		t.Errorf("GPUs not sorted by bus location: first = %q", inv.GPUs[0].BusLocation)
	}
	g := inv.GPUs[0]
	if g.Model != "NVIDIA A100-SXM4-40GB" || g.VBIOSVersion != "92.00.45.00.07" {
		t.Errorf("unexpected GPU fields: %+v", g)
	}
}

func TestCollectGPUDriverLoadedNoGPUs(t *testing.T) {
	// Driver present (tree exists) but no GPU subdirs → empty, non-nil inventory.
	root := t.TempDir()
	writeGPUTree(t, root, sampleNvidiaVersion, nil)
	inv, err := collectGPUFrom(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inv == nil {
		t.Fatal("expected non-nil inventory when driver tree exists")
	}
	if inv.TotalCount != 0 || len(inv.GPUs) != 0 {
		t.Errorf("expected zero GPUs, got %d", inv.TotalCount)
	}
	if inv.DriverVersion != "535.129.03" {
		t.Errorf("driver version = %q, want 535.129.03", inv.DriverVersion)
	}
}

func TestCollectGPUFallsBackToDirName(t *testing.T) {
	// information file missing the "Bus Location" line → bus id comes from dir.
	root := t.TempDir()
	info := "Model: \t\t NVIDIA L4\nVideo BIOS: \t 95.04.2c.00.01\n"
	writeGPUTree(t, root, sampleNvidiaVersion, map[string]string{"0000:c1:00.0": info})
	inv, err := collectGPUFrom(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(inv.GPUs) != 1 || inv.GPUs[0].BusLocation != "0000:c1:00.0" {
		t.Fatalf("expected bus location from dir name, got %+v", inv.GPUs)
	}
}

func TestParseNvidiaDriverVersion(t *testing.T) {
	cases := map[string]string{
		sampleNvidiaVersion: "535.129.03",
		"NVRM version: NVIDIA UNIX Open Kernel Module  550.54.14  ...\n": "550.54.14",
		"GCC version: gcc 11\n": "", // no NVRM line
		"":                      "",
	}
	for in, want := range cases {
		if got := parseNvidiaDriverVersion(in); got != want {
			t.Errorf("parseNvidiaDriverVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseGPUInformation(t *testing.T) {
	g := parseGPUInformation(sampleGPUInfo("NVIDIA H100 80GB HBM3", "96.00.61.00.04", "0000:1b:00.0"))
	if g.Model != "NVIDIA H100 80GB HBM3" {
		t.Errorf("model = %q", g.Model)
	}
	if g.VBIOSVersion != "96.00.61.00.04" {
		t.Errorf("vbios = %q", g.VBIOSVersion)
	}
	if g.BusLocation != "0000:1b:00.0" {
		t.Errorf("bus = %q", g.BusLocation)
	}
}
