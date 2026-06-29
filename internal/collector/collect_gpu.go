package collector

// collect_gpu.go — v0.6 GPU / accelerator inventory collector.
//
// GPUs are read from the NVIDIA kernel driver's procfs interface
// (/proc/driver/nvidia): the host driver version from .../version and, per GPU,
// its PCI bus location, model, and video-BIOS version from
// .../gpus/<bus>/information. This needs no nvidia-smi, no daemon, and no extra
// privilege beyond reading /proc. Gated by the "gpu" optional collector; off by
// default. A host with no NVIDIA driver loaded yields a nil inventory (the
// section is omitted), not an error — that is the common case.

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// collectGPU reads the NVIDIA driver procfs tree under /proc.
func collectGPU() (*GPUInventory, error) {
	return collectGPUFrom("/proc")
}

// collectGPUFrom is the testable variant pointed at a /proc-like root. It
// returns (nil, nil) when /proc/driver/nvidia is absent — the normal case on a
// host with no NVIDIA GPU or driver loaded. When the tree exists it returns an
// inventory (possibly with zero GPUs, which is itself the fact that the driver
// is loaded but exposes none).
func collectGPUFrom(procRoot string) (*GPUInventory, error) {
	base := filepath.Join(procRoot, "driver", "nvidia")
	if _, err := os.Stat(base); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	inv := &GPUInventory{}
	if v, err := os.ReadFile(filepath.Join(base, "version")); err == nil {
		inv.DriverVersion = parseNvidiaDriverVersion(string(v))
	}

	gpusDir := filepath.Join(base, "gpus")
	entries, err := os.ReadDir(gpusDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(gpusDir, e.Name(), "information"))
		if err != nil {
			continue // GPU went away mid-walk or unreadable; skip
		}
		g := parseGPUInformation(string(data))
		if g.BusLocation == "" {
			g.BusLocation = e.Name() // the directory name is the PCI bus id
		}
		inv.GPUs = append(inv.GPUs, g)
	}

	sort.Slice(inv.GPUs, func(i, j int) bool {
		return inv.GPUs[i].BusLocation < inv.GPUs[j].BusLocation
	})
	inv.TotalCount = len(inv.GPUs)
	return inv, nil
}

// parseNvidiaDriverVersion extracts the driver version from the content of
// /proc/driver/nvidia/version. The relevant line is the "NVRM version:" line,
// e.g. "NVRM version: NVIDIA UNIX x86_64 Kernel Module  535.129.03  Tue ...";
// we return the first dotted-numeric token on it ("535.129.03"). Returns "" if
// no such line/token is found.
func parseNvidiaDriverVersion(content string) string {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "NVRM") {
			continue
		}
		for _, tok := range strings.Fields(line) {
			if isDottedVersion(tok) {
				return tok
			}
		}
	}
	return ""
}

// isDottedVersion reports whether s is a run of digits and dots containing at
// least one dot (e.g. "535.129.03"), so it is not confused with the bare
// integers ("x86_64" is excluded by the non-digit rune check).
func isDottedVersion(s string) bool {
	if !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

// parseGPUInformation parses a /proc/driver/nvidia/gpus/<bus>/information file.
// Lines are "Key:<whitespace>value"; we keep Model, Video BIOS, and Bus
// Location and ignore the rest (IRQ, GPU UUID, Device Minor).
func parseGPUInformation(content string) GPU {
	var g GPU
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		key, val, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.TrimSpace(key) {
		case "Model":
			g.Model = val
		case "Video BIOS":
			g.VBIOSVersion = val
		case "Bus Location":
			g.BusLocation = val
		}
	}
	return g
}
