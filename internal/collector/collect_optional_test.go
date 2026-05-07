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
Threads:	4
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
	if p.Threads != 4 {
		t.Errorf("Threads = %d, want 4", p.Threads)
	}
}

func TestReadProcStat(t *testing.T) {
	// Synthetic /proc/<pid>/stat. Format from proc(5):
	// pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt
	// majflt cmajflt utime stime cutime cstime priority nice num_threads
	// itrealvalue starttime vsize ...
	// Field positions (1-indexed): utime=14, stime=15, starttime=22.
	f, err := os.CreateTemp("", "proc-stat-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	content := `1234 (ng inx) S 1 1234 1234 0 -1 4194304 100 0 0 0 ` +
		`777 333 0 0 20 0 4 0 ` +
		`9999 ` +
		`123456 256 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0
`
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	f.Close()

	utime, stime, starttime, err := readProcStatFrom(f.Name())
	if err != nil {
		t.Fatalf("readProcStatFrom error: %v", err)
	}
	if utime != 777 {
		t.Errorf("utime = %d, want 777", utime)
	}
	if stime != 333 {
		t.Errorf("stime = %d, want 333", stime)
	}
	if starttime != 9999 {
		t.Errorf("starttime = %d, want 9999", starttime)
	}
}

func TestReadProcStatCommWithSpacesAndParens(t *testing.T) {
	// Real-world example: comm can contain spaces and parens. The kernel
	// guarantees the *last* ')' is the end of comm. Verify our parser handles
	// "(weird ) comm)" correctly.
	f, err := os.CreateTemp("", "proc-stat-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	content := `42 (weird ) comm) S 1 42 42 0 -1 0 0 0 0 0 ` +
		`100 50 0 0 20 0 1 0 ` +
		`5000 ` +
		`0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
`
	f.WriteString(content)
	f.Close()

	utime, stime, starttime, err := readProcStatFrom(f.Name())
	if err != nil {
		t.Fatalf("readProcStatFrom error: %v", err)
	}
	if utime != 100 || stime != 50 || starttime != 5000 {
		t.Errorf("got utime=%d stime=%d starttime=%d, want 100/50/5000", utime, stime, starttime)
	}
}

func TestReadProcStatMalformed(t *testing.T) {
	f, err := os.CreateTemp("", "proc-stat-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())
	f.WriteString("1234 (no_close_paren S 1 1\n")
	f.Close()

	if _, _, _, err := readProcStatFrom(f.Name()); err == nil {
		t.Error("expected error for stat file with no closing paren")
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
