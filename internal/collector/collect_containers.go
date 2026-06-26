package collector

// collect_containers.go — v0.6 container inventory collector.
//
// Containers are detected purely from /proc cgroup membership: a containerized
// process has its container ID embedded in the path of /proc/[pid]/cgroup. This
// is runtime-agnostic (Docker, containerd/CRI, CRI-O, podman) and needs no
// daemon socket or extra privilege beyond reading /proc. Gated by the
// "containers" optional collector; off by default.

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// hexID matches a run of hex of container-ID length. Runtimes embed the full
// 64-char container ID in the cgroup path. The 32-char floor is deliberate: it
// admits every real container ID while excluding the ≤12-char hex fragments
// that appear in Kubernetes pod UUIDs (e.g. ".../pod<uuid>/<64hex>"), so the
// 64-hex container segment is the only thing that matches.
var hexID = regexp.MustCompile(`[0-9a-f]{32,64}`)

// parseCgroupForContainer inspects the content of a /proc/[pid]/cgroup file and
// returns the short (12-char) container ID and inferred runtime if the process
// belongs to a container. Host and plain-systemd processes (user.slice,
// system.slice/<unit>.service, init scope) return ok=false.
func parseCgroupForContainer(content string) (id, runtime string, ok bool) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		// Format: hierarchy:controllers:path  (path may itself contain ':').
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if cid, rt, found := matchContainerPath(parts[2]); found {
			return cid, rt, true
		}
	}
	return "", "", false
}

// matchContainerPath extracts a container ID + runtime from a single cgroup
// path. The container ID is the path segment that is (a "<prefix>-"-tagged or
// bare) 32–64-char hex run; the runtime is inferred from tokens in the path.
func matchContainerPath(path string) (id, runtime string, ok bool) {
	for _, seg := range strings.Split(path, "/") {
		s := strings.TrimSuffix(seg, ".scope")
		m := hexID.FindString(s)
		if m == "" {
			continue
		}
		// The hex run must be the whole segment or its "<prefix>-<hex>" tail,
		// not a fragment embedded in a longer name.
		if s != m && !strings.HasSuffix(s, "-"+m) {
			continue
		}
		return shortID(m), detectRuntime(path), true
	}
	return "", "", false
}

// detectRuntime infers the container runtime from tokens anywhere in the cgroup
// path. Order matters: cri-containerd and crio must be checked before the bare
// "docker"/"containerd" substrings.
func detectRuntime(path string) string {
	switch {
	case strings.Contains(path, "cri-containerd"):
		return "containerd"
	case strings.Contains(path, "crio-"):
		return "cri-o"
	case strings.Contains(path, "libpod"):
		return "podman"
	case strings.Contains(path, "docker"):
		return "docker"
	case strings.Contains(path, "kubepods"), strings.Contains(path, "containerd"):
		return "containerd"
	}
	return "unknown"
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// collectContainers walks /proc and groups containerized processes by their
// container ID. Processes that exit mid-walk are skipped. Returns an inventory
// sorted by container ID.
func collectContainers() (*ContainerInventory, error) {
	return collectContainersFrom("/proc")
}

// collectContainersFrom is the testable variant pointed at a /proc-like root.
func collectContainersFrom(procRoot string) (*ContainerInventory, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}

	type agg struct {
		runtime string
		minPID  int
		command string
		count   int
	}
	byID := make(map[string]*agg)

	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID directory
		}
		data, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "cgroup"))
		if err != nil {
			continue // process exited or unreadable
		}
		id, runtime, ok := parseCgroupForContainer(string(data))
		if !ok {
			continue
		}
		a := byID[id]
		if a == nil {
			a = &agg{runtime: runtime, minPID: pid}
			byID[id] = a
		}
		a.count++
		if pid <= a.minPID || a.command == "" {
			a.minPID = pid
			if comm := readComm(filepath.Join(procRoot, e.Name(), "status")); comm != "" {
				a.command = comm
			}
		}
	}

	inv := &ContainerInventory{TotalCount: len(byID)}
	for id, a := range byID {
		inv.Containers = append(inv.Containers, Container{
			ID:        id,
			Runtime:   a.runtime,
			Command:   a.command,
			Processes: a.count,
		})
	}
	sort.Slice(inv.Containers, func(i, j int) bool {
		return inv.Containers[i].ID < inv.Containers[j].ID
	})
	return inv, nil
}

// readComm returns the Name field from a /proc/[pid]/status file, or "".
func readComm(statusPath string) string {
	f, err := os.Open(statusPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Name:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		}
	}
	return ""
}
