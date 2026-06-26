package collector

import (
	"os"
	"path/filepath"
	"testing"
)

const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestParseCgroupForContainer(t *testing.T) {
	cases := []struct {
		name        string
		content     string
		wantOK      bool
		wantID      string
		wantRuntime string
	}{
		{
			name:        "docker cgroup v1",
			content:     "12:hugetlb:/docker/" + hex64 + "\n1:name=systemd:/docker/" + hex64,
			wantOK:      true,
			wantID:      hex64[:12],
			wantRuntime: "docker",
		},
		{
			name:        "docker cgroup v2 scope",
			content:     "0::/system.slice/docker-" + hex64 + ".scope",
			wantOK:      true,
			wantID:      hex64[:12],
			wantRuntime: "docker",
		},
		{
			name:        "cri-containerd scope",
			content:     "0::/system.slice/cri-containerd-" + hex64 + ".scope",
			wantOK:      true,
			wantID:      hex64[:12],
			wantRuntime: "containerd",
		},
		{
			name:        "crio scope",
			content:     "0::/system.slice/crio-" + hex64 + ".scope",
			wantOK:      true,
			wantID:      hex64[:12],
			wantRuntime: "cri-o",
		},
		{
			name:        "podman libpod scope",
			content:     "0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-" + hex64 + ".scope",
			wantOK:      true,
			wantID:      hex64[:12],
			wantRuntime: "podman",
		},
		{
			name:        "kubepods plain id (pod uuid not matched)",
			content:     "0::/kubepods/besteffort/pod1234abcd-5678-90ab-cdef-1234567890ab/" + hex64,
			wantOK:      true,
			wantID:      hex64[:12],
			wantRuntime: "containerd",
		},
		{
			name:    "host user slice — not a container",
			content: "0::/user.slice/user-1000.slice/session-3.scope",
			wantOK:  false,
		},
		{
			name:    "host system service — not a container",
			content: "12:devices:/system.slice/sshd.service\n0::/system.slice/sshd.service",
			wantOK:  false,
		},
		{
			name:    "init scope — not a container",
			content: "0::/init.scope",
			wantOK:  false,
		},
		{
			name:    "empty",
			content: "",
			wantOK:  false,
		},
		{
			name:    "malformed lines",
			content: "garbage\n::\n:::\nnotanumber:x",
			wantOK:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, runtime, ok := parseCgroupForContainer(tc.content)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (id=%q runtime=%q)", ok, tc.wantOK, id, runtime)
			}
			if !ok {
				return
			}
			if id != tc.wantID {
				t.Errorf("id = %q, want %q", id, tc.wantID)
			}
			if runtime != tc.wantRuntime {
				t.Errorf("runtime = %q, want %q", runtime, tc.wantRuntime)
			}
		})
	}
}

// writeProc lays down a fake /proc/<pid>/{cgroup,status} pair.
func writeProc(t *testing.T, root, pid, cgroup, comm string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup), 0644); err != nil {
		t.Fatalf("write cgroup: %v", err)
	}
	if comm != "" {
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte("Name:\t"+comm+"\nState:\tR\n"), 0644); err != nil {
			t.Fatalf("write status: %v", err)
		}
	}
}

func TestCollectContainersFromGroupsByID(t *testing.T) {
	root := t.TempDir()
	idA := hex64
	idB := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	// Two PIDs in container A (lower PID 100 is the representative), one in B,
	// plus a host process that must be ignored.
	writeProc(t, root, "100", "0::/system.slice/docker-"+idA+".scope", "nginx")
	writeProc(t, root, "150", "0::/system.slice/docker-"+idA+".scope", "nginx-worker")
	writeProc(t, root, "200", "0::/system.slice/cri-containerd-"+idB+".scope", "redis-server")
	writeProc(t, root, "1", "0::/init.scope", "systemd")
	// A non-PID directory and a stray file must be skipped.
	if err := os.MkdirAll(filepath.Join(root, "acpi"), 0755); err != nil {
		t.Fatal(err)
	}

	inv, err := collectContainersFrom(root)
	if err != nil {
		t.Fatalf("collectContainersFrom: %v", err)
	}
	if inv.TotalCount != 2 {
		t.Fatalf("TotalCount = %d, want 2", inv.TotalCount)
	}
	// Sorted by ID: idA (0123…) before idB (fedc…).
	if inv.Containers[0].ID != idA[:12] {
		t.Errorf("container[0].ID = %q, want %q", inv.Containers[0].ID, idA[:12])
	}
	if inv.Containers[0].Runtime != "docker" {
		t.Errorf("container[0].Runtime = %q, want docker", inv.Containers[0].Runtime)
	}
	if inv.Containers[0].Processes != 2 {
		t.Errorf("container[0].Processes = %d, want 2", inv.Containers[0].Processes)
	}
	if inv.Containers[0].Command != "nginx" {
		t.Errorf("container[0].Command = %q, want nginx (lowest PID representative)", inv.Containers[0].Command)
	}
	if inv.Containers[1].ID != idB[:12] || inv.Containers[1].Runtime != "containerd" {
		t.Errorf("container[1] = %+v, want id %q runtime containerd", inv.Containers[1], idB[:12])
	}
}

func TestCollectContainersFromEmpty(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, "1", "0::/init.scope", "systemd")
	inv, err := collectContainersFrom(root)
	if err != nil {
		t.Fatalf("collectContainersFrom: %v", err)
	}
	if inv.TotalCount != 0 {
		t.Errorf("TotalCount = %d, want 0 (no containers)", inv.TotalCount)
	}
}

func TestCollectContainersFromMissingProc(t *testing.T) {
	if _, err := collectContainersFrom(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("collectContainersFrom on a missing root should error")
	}
}
