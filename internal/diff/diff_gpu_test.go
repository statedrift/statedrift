package diff

import (
	"testing"

	"github.com/statedrift/statedrift/internal/collector"
)

func gi(driver string, gpus ...collector.GPU) *collector.GPUInventory {
	return &collector.GPUInventory{DriverVersion: driver, TotalCount: len(gpus), GPUs: gpus}
}

func TestDiffGPUAddedRemoved(t *testing.T) {
	old := gi("535.129.03", collector.GPU{BusLocation: "0000:01:00.0", Model: "A100"})
	new := gi("535.129.03", collector.GPU{BusLocation: "0000:81:00.0", Model: "A100"})

	r := &Result{}
	diffGPU(old, new, r)

	if findChange(r, "gpu", "added", "0000:81:00.0") == nil {
		t.Error("expected added change for new GPU")
	}
	if findChange(r, "gpu", "removed", "0000:01:00.0") == nil {
		t.Error("expected removed change for missing GPU")
	}
}

func TestDiffGPUDriverVersionChange(t *testing.T) {
	old := gi("535.129.03", collector.GPU{BusLocation: "0000:01:00.0", Model: "A100"})
	new := gi("550.54.14", collector.GPU{BusLocation: "0000:01:00.0", Model: "A100"})

	r := &Result{}
	diffGPU(old, new, r)

	c := findChange(r, "gpu", "modified", "driver_version")
	if c == nil {
		t.Fatal("expected driver_version change")
	}
	if c.Counter {
		t.Error("driver_version change must not be a counter")
	}
}

func TestDiffGPUVBIOSChange(t *testing.T) {
	old := gi("535.129.03", collector.GPU{BusLocation: "0000:01:00.0", Model: "A100", VBIOSVersion: "92.00.45.00.07"})
	new := gi("535.129.03", collector.GPU{BusLocation: "0000:01:00.0", Model: "A100", VBIOSVersion: "92.00.45.00.09"})

	r := &Result{}
	diffGPU(old, new, r)

	if findChange(r, "gpu", "modified", "0000:01:00.0.vbios_version") == nil {
		t.Error("expected per-GPU vbios_version change")
	}
	// VBIOS-only change must not also emit a model change.
	if findChange(r, "gpu", "modified", "0000:01:00.0.model") != nil {
		t.Error("unexpected model change")
	}
}

func TestDiffGPUModelChange(t *testing.T) {
	old := gi("535.129.03", collector.GPU{BusLocation: "0000:01:00.0", Model: "A100"})
	new := gi("535.129.03", collector.GPU{BusLocation: "0000:01:00.0", Model: "H100"})

	r := &Result{}
	diffGPU(old, new, r)

	if findChange(r, "gpu", "modified", "0000:01:00.0.model") == nil {
		t.Error("expected per-GPU model change")
	}
}

func TestDiffGPUCollectorToggle(t *testing.T) {
	r := &Result{}
	diffGPU(nil, gi("535.129.03", collector.GPU{BusLocation: "0000:01:00.0"}), r)
	if findChange(r, "gpu", "added", "inventory") == nil {
		t.Error("expected single inventory-added summary when collector enabled")
	}

	r = &Result{}
	diffGPU(gi("535.129.03", collector.GPU{BusLocation: "0000:01:00.0"}), nil, r)
	if findChange(r, "gpu", "removed", "inventory") == nil {
		t.Error("expected single inventory-removed summary when collector disabled")
	}
}

func TestDiffGPUBothNilNoChange(t *testing.T) {
	r := &Result{}
	diffGPU(nil, nil, r)
	if len(r.Changes) != 0 {
		t.Errorf("both-nil should emit no changes, got %d", len(r.Changes))
	}
}

func TestDiffGPUNoChange(t *testing.T) {
	g := collector.GPU{BusLocation: "0000:01:00.0", Model: "A100", VBIOSVersion: "92.00.45.00.07"}
	r := &Result{}
	diffGPU(gi("535.129.03", g), gi("535.129.03", g), r)
	if len(r.Changes) != 0 {
		t.Errorf("identical inventories should emit no changes, got %d", len(r.Changes))
	}
}
