package collector

import (
	"os"
	"reflect"
	"testing"
)

func TestParseModulesLineNoDeps(t *testing.T) {
	line := `uinput 20480 0 - Live 0x0000000000000000`
	m := parseModulesLine(line)
	if m == nil {
		t.Fatalf("parseModulesLine returned nil for valid line")
	}
	if m.Name != "uinput" {
		t.Errorf("Name = %q, want uinput", m.Name)
	}
	if m.Size != 20480 {
		t.Errorf("Size = %d, want 20480", m.Size)
	}
	if m.Dependencies != nil {
		t.Errorf("Dependencies = %v, want nil for '-'", m.Dependencies)
	}
}

func TestParseModulesLineSingleDep(t *testing.T) {
	// /proc/modules emits dep lists with a trailing comma.
	line := `nf_conntrack_tftp 16384 3 nf_nat_tftp, Live 0x0000000000000000`
	m := parseModulesLine(line)
	if m == nil {
		t.Fatalf("nil")
	}
	want := []string{"nf_nat_tftp"}
	if !reflect.DeepEqual(m.Dependencies, want) {
		t.Errorf("Dependencies = %v, want %v", m.Dependencies, want)
	}
}

func TestParseModulesLineMultipleDepsSorted(t *testing.T) {
	// Kernel emits deps in load order, not alphabetical. Output must be sorted.
	line := `nft_fib 16384 3 nft_fib_inet,nft_fib_ipv4,nft_fib_ipv6, Live 0x0000000000000000`
	m := parseModulesLine(line)
	if m == nil {
		t.Fatalf("nil")
	}
	want := []string{"nft_fib_inet", "nft_fib_ipv4", "nft_fib_ipv6"}
	if !reflect.DeepEqual(m.Dependencies, want) {
		t.Errorf("Dependencies = %v, want %v", m.Dependencies, want)
	}
}

func TestParseModulesLineMalformed(t *testing.T) {
	cases := []string{
		"",
		"too few",
		"name notanumber 0 - Live 0x0", // size not parseable
	}
	for _, line := range cases {
		if m := parseModulesLine(line); m != nil {
			t.Errorf("expected nil for malformed line %q, got %+v", line, m)
		}
	}
}

func TestParseModuleDeps(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"-", nil},
		{"", nil},
		{"foo,", []string{"foo"}},
		{"b,a,", []string{"a", "b"}},
		{"a,b,c,", []string{"a", "b", "c"}},
	}
	for _, c := range cases {
		got := parseModuleDeps(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseModuleDeps(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestReadModulesFromFixture(t *testing.T) {
	f, err := os.CreateTemp("", "modules-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	// Intentionally out of alphabetical order — readModulesFrom must sort.
	content := `uinput 20480 0 - Live 0x0000000000000000
bridge 294912 0 - Live 0x0000000000000000
stp 16384 1 bridge, Live 0x0000000000000000
llc 16384 2 bridge,stp, Live 0x0000000000000000
`
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	f.Close()

	modules, err := readModulesFrom(f.Name())
	if err != nil {
		t.Fatalf("readModulesFrom: %v", err)
	}
	if len(modules) != 4 {
		t.Fatalf("got %d modules, want 4", len(modules))
	}

	wantNames := []string{"bridge", "llc", "stp", "uinput"}
	gotNames := []string{modules[0].Name, modules[1].Name, modules[2].Name, modules[3].Name}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Errorf("names = %v, want %v (sorted)", gotNames, wantNames)
	}

	// llc depends on bridge and stp, in that load order — output must be sorted.
	var llc Module
	for _, m := range modules {
		if m.Name == "llc" {
			llc = m
			break
		}
	}
	wantDeps := []string{"bridge", "stp"}
	if !reflect.DeepEqual(llc.Dependencies, wantDeps) {
		t.Errorf("llc.Dependencies = %v, want %v", llc.Dependencies, wantDeps)
	}
}

func TestReadModulesFromMissing(t *testing.T) {
	if _, err := readModulesFrom("/nonexistent/path/modules"); err == nil {
		t.Error("expected error for missing file")
	}
}
