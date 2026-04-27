package collector

import (
	"os"
	"strings"
	"testing"
)

func TestCollectCPUParsesStatFile(t *testing.T) {
	// Write a synthetic /proc/stat-style file and test the parser directly.
	// We use a temp file but the function reads /proc/stat directly, so we
	// test via parseCPUStat instead.
	line := "cpu  12345 678 9012 345678 90 1 23 4 5 6"
	stats, err := parseCPUStat(line)
	if err != nil {
		t.Fatalf("parseCPUStat error: %v", err)
	}
	if stats.User != 12345 {
		t.Errorf("User = %d, want 12345", stats.User)
	}
	if stats.Nice != 678 {
		t.Errorf("Nice = %d, want 678", stats.Nice)
	}
	if stats.System != 9012 {
		t.Errorf("System = %d, want 9012", stats.System)
	}
	if stats.Idle != 345678 {
		t.Errorf("Idle = %d, want 345678", stats.Idle)
	}
	if stats.IOWait != 90 {
		t.Errorf("IOWait = %d, want 90", stats.IOWait)
	}
	if stats.Guest != 5 {
		t.Errorf("Guest = %d, want 5", stats.Guest)
	}
	if stats.GuestNice != 6 {
		t.Errorf("GuestNice = %d, want 6", stats.GuestNice)
	}
}

func TestCollectCPULineTooShort(t *testing.T) {
	_, err := parseCPUStat("cpu 1 2")
	if err == nil {
		t.Error("expected error for short cpu line")
	}
}

func TestParseKernelCounters(t *testing.T) {
	input := `Ip: Forwarding DefaultTTL InReceives
Ip: 1 64 1000
Udp: InDatagrams NoPorts
Udp: 500 3
`
	kc, err := parseKernelCounterLines(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseKernelCounterLines error: %v", err)
	}
	if kc.IP["InReceives"] != 1000 {
		t.Errorf("IP.InReceives = %d, want 1000", kc.IP["InReceives"])
	}
	if kc.IP["Forwarding"] != 1 {
		t.Errorf("IP.Forwarding = %d, want 1", kc.IP["Forwarding"])
	}
	if kc.UDP["InDatagrams"] != 500 {
		t.Errorf("UDP.InDatagrams = %d, want 500", kc.UDP["InDatagrams"])
	}
	if kc.UDP["NoPorts"] != 3 {
		t.Errorf("UDP.NoPorts = %d, want 3", kc.UDP["NoPorts"])
	}
}

func TestReadProcStatus(t *testing.T) {
	f, err := os.CreateTemp("", "proc-status-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	content := `Name:	nginx
State:	S (sleeping)
PPid:	1
VmRSS:	20480 kB
VmSize:	102400 kB
`
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	f.Close()

	p, err := readProcStatusFrom(f.Name(), 1234)
	if err != nil {
		t.Fatalf("readProcStatusFrom error: %v", err)
	}
	if p.Comm != "nginx" {
		t.Errorf("Comm = %q, want nginx", p.Comm)
	}
	if p.State != "S" {
		t.Errorf("State = %q, want S", p.State)
	}
	if p.PPID != 1 {
		t.Errorf("PPID = %d, want 1", p.PPID)
	}
	if p.RSSKB != 20480 {
		t.Errorf("RSSKB = %d, want 20480", p.RSSKB)
	}
	if p.VMSKB != 102400 {
		t.Errorf("VMSKB = %d, want 102400", p.VMSKB)
	}
	if p.PID != 1234 {
		t.Errorf("PID = %d, want 1234", p.PID)
	}
}

func TestReadProcStatusMissingName(t *testing.T) {
	f, err := os.CreateTemp("", "proc-status-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())
	f.WriteString("State:\tR (running)\n")
	f.Close()

	_, err = readProcStatusFrom(f.Name(), 999)
	if err == nil {
		t.Error("expected error for missing Name field")
	}
}
