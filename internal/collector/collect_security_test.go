package collector

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReadPasswdFrom(t *testing.T) {
	f, err := os.CreateTemp("", "passwd-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	content := `# comment line
root:x:0:0:root:/root:/bin/bash

bin:x:1:1:bin:/bin:/usr/sbin/nologin
alice:x:1000:1000:Alice Smith,,,:/home/alice:/bin/zsh
bogus-line-without-enough-fields
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
`
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	f.Close()

	users, err := readPasswdFrom(f.Name())
	if err != nil {
		t.Fatalf("readPasswdFrom: %v", err)
	}

	want := []User{
		{Name: "alice", UID: 1000, GID: 1000, GECOS: "Alice Smith,,,", Home: "/home/alice", Shell: "/bin/zsh"},
		{Name: "bin", UID: 1, GID: 1, GECOS: "bin", Home: "/bin", Shell: "/usr/sbin/nologin"},
		{Name: "nobody", UID: 65534, GID: 65534, GECOS: "nobody", Home: "/nonexistent", Shell: "/usr/sbin/nologin"},
		{Name: "root", UID: 0, GID: 0, GECOS: "root", Home: "/root", Shell: "/bin/bash"},
	}
	if !reflect.DeepEqual(users, want) {
		t.Errorf("users mismatch\n got: %+v\nwant: %+v", users, want)
	}
}

func TestReadPasswdFromMissing(t *testing.T) {
	if _, err := readPasswdFrom("/nonexistent/path/passwd"); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestReadGroupFrom(t *testing.T) {
	f, err := os.CreateTemp("", "group-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	content := `# group file
root:x:0:
wheel:x:10:alice,bob
empty:x:42:
sudo:x:27:bob, alice
malformed
`
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	f.Close()

	groups, err := readGroupFrom(f.Name())
	if err != nil {
		t.Fatalf("readGroupFrom: %v", err)
	}

	want := []Group{
		{Name: "empty", GID: 42, Members: nil},
		{Name: "root", GID: 0, Members: nil},
		{Name: "sudo", GID: 27, Members: []string{"alice", "bob"}},
		{Name: "wheel", GID: 10, Members: []string{"alice", "bob"}},
	}
	if !reflect.DeepEqual(groups, want) {
		t.Errorf("groups mismatch\n got: %+v\nwant: %+v", groups, want)
	}
}

func TestNormalizeSudoersLine(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"  alice  ALL=(ALL)\tNOPASSWD:\t/usr/bin/systemctl   ", "alice ALL=(ALL) NOPASSWD: /usr/bin/systemctl"},
		{"", ""},
		{"   ", ""},
		{"\t# leading-tab comment\t", "# leading-tab comment"},
		{"Defaults\t\tenv_reset", "Defaults env_reset"},
	}
	for _, c := range cases {
		got := normalizeSudoersLine(c.in)
		if got != c.want {
			t.Errorf("normalizeSudoersLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestShouldSkipSudoersInclude(t *testing.T) {
	cases := []struct {
		name string
		skip bool
	}{
		{"", true},
		{".hidden", true},
		{"backup~", true},
		{"old.bak", true},  // contains '.'
		{"file.swp", true}, // contains '.'
		{"my.rules", true}, // contains '.'
		{"oncall_admins", false},
		{"team-rules", false},
		{"99_local", false},
	}
	for _, c := range cases {
		got := shouldSkipSudoersInclude(c.name)
		if got != c.skip {
			t.Errorf("shouldSkipSudoersInclude(%q) = %v, want %v", c.name, got, c.skip)
		}
	}
}

func TestReadSudoersFromMainOnly(t *testing.T) {
	dir, err := os.MkdirTemp("", "sudoers-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	mainPath := filepath.Join(dir, "sudoers")
	content := `# main sudoers
Defaults env_reset
Defaults secure_path="/usr/local/sbin:/usr/local/bin"

root ALL=(ALL:ALL) ALL
%wheel  ALL=(ALL)  ALL

# A continuation line:
alice ALL=NOPASSWD: \
    /usr/bin/systemctl restart nginx, \
    /usr/bin/systemctl reload nginx
`
	if err := os.WriteFile(mainPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	entries, err := readSudoersFrom(mainPath, "")
	if err != nil {
		t.Fatalf("readSudoersFrom: %v", err)
	}

	wantLines := []string{
		"%wheel ALL=(ALL) ALL",
		"Defaults env_reset",
		`Defaults secure_path="/usr/local/sbin:/usr/local/bin"`,
		"alice ALL=NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/systemctl reload nginx",
		"root ALL=(ALL:ALL) ALL",
	}
	if len(entries) != len(wantLines) {
		t.Fatalf("got %d entries, want %d: %+v", len(entries), len(wantLines), entries)
	}
	for i, e := range entries {
		if e.Source != mainPath {
			t.Errorf("entries[%d].Source = %q, want %q", i, e.Source, mainPath)
		}
		if e.Line != wantLines[i] {
			t.Errorf("entries[%d].Line = %q, want %q", i, e.Line, wantLines[i])
		}
	}
}

func TestReadSudoersFromIncludeDir(t *testing.T) {
	dir, err := os.MkdirTemp("", "sudoers-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	mainPath := filepath.Join(dir, "sudoers")
	if err := os.WriteFile(mainPath, []byte("Defaults env_reset\n"), 0o644); err != nil {
		t.Fatalf("WriteFile main: %v", err)
	}

	includeDir := filepath.Join(dir, "sudoers.d")
	if err := os.MkdirAll(includeDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	files := map[string]string{
		"oncall":     "%oncall ALL=(ALL) NOPASSWD: /opt/scripts/page.sh\n",
		"admins":     "%admins ALL=(ALL) ALL\n",
		"backup~":    "should-be-skipped\n", // editor backup
		"old.bak":    "should-be-skipped\n", // contains '.'
		".hidden":    "should-be-skipped\n", // dotfile
		"deploy.swp": "should-be-skipped\n", // contains '.'
	}
	for name, content := range files {
		path := filepath.Join(includeDir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
	}

	dirGlob := filepath.Join(includeDir, "*")
	entries, err := readSudoersFrom(mainPath, dirGlob)
	if err != nil {
		t.Fatalf("readSudoersFrom: %v", err)
	}

	// Expect three entries total: 1 from main + 2 from non-skipped includes.
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(entries), entries)
	}

	// Confirm the editor-backup / hidden / dotted-name files were skipped.
	for _, e := range entries {
		if filepath.Base(e.Source) == "backup~" ||
			filepath.Base(e.Source) == "old.bak" ||
			filepath.Base(e.Source) == ".hidden" ||
			filepath.Base(e.Source) == "deploy.swp" {
			t.Errorf("entry from skipped file leaked through: %+v", e)
		}
	}
}

func TestReadSudoersFromMissingMain(t *testing.T) {
	// Some hosts put everything in /etc/sudoers.d and have no /etc/sudoers.
	// readSudoersFrom must not fail; it should return only include-dir entries.
	dir, err := os.MkdirTemp("", "sudoers-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	includeDir := filepath.Join(dir, "sudoers.d")
	if err := os.MkdirAll(includeDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(includeDir, "team"), []byte("%team ALL=(ALL) ALL\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	entries, err := readSudoersFrom(filepath.Join(dir, "does-not-exist"), filepath.Join(includeDir, "*"))
	if err != nil {
		t.Fatalf("readSudoersFrom: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(entries), entries)
	}
	if entries[0].Line != "%team ALL=(ALL) ALL" {
		t.Errorf("entry.Line = %q", entries[0].Line)
	}
}
