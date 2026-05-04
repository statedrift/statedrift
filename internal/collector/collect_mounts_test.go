package collector

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseMountinfoLineBasic(t *testing.T) {
	// Typical ext4 root mount with no optional fields.
	line := `26 1 254:0 / / rw,relatime shared:1 - ext4 /dev/mapper/rhel-root rw,seclabel`
	m := parseMountinfoLine(line)
	if m == nil {
		t.Fatalf("parseMountinfoLine returned nil for valid line")
	}
	if m.MountPoint != "/" {
		t.Errorf("MountPoint = %q, want /", m.MountPoint)
	}
	if m.Source != "/dev/mapper/rhel-root" {
		t.Errorf("Source = %q", m.Source)
	}
	if m.FSType != "ext4" {
		t.Errorf("FSType = %q, want ext4", m.FSType)
	}
	if m.MountOptions != "relatime,rw" {
		t.Errorf("MountOptions = %q, want relatime,rw", m.MountOptions)
	}
	if m.SuperOptions != "rw,seclabel" {
		t.Errorf("SuperOptions = %q, want rw,seclabel", m.SuperOptions)
	}
}

func TestParseMountinfoLineNoOptionalFields(t *testing.T) {
	// Lines where optional-fields block is empty (just the "-" separator).
	line := `38 26 0:33 / /sys/fs/cgroup ro,nosuid,nodev,noexec - tmpfs tmpfs ro,seclabel,size=4k`
	m := parseMountinfoLine(line)
	if m == nil {
		t.Fatalf("nil")
	}
	if m.MountPoint != "/sys/fs/cgroup" {
		t.Errorf("MountPoint = %q", m.MountPoint)
	}
	// Options should be sorted alphabetically.
	if m.MountOptions != "nodev,noexec,nosuid,ro" {
		t.Errorf("MountOptions = %q, want nodev,noexec,nosuid,ro (sorted)", m.MountOptions)
	}
}

func TestParseMountinfoLineCredentialsStripped(t *testing.T) {
	// CIFS mount with credentials= and password= options. Both must be dropped.
	line := `123 26 0:91 / /mnt/share rw,relatime shared:200 - cifs //server/share rw,vers=3.1.1,credentials=/etc/cifs.creds,username=guest`
	m := parseMountinfoLine(line)
	if m == nil {
		t.Fatalf("nil")
	}
	if strings.Contains(m.SuperOptions, "credentials") {
		t.Errorf("SuperOptions should not contain 'credentials': %q", m.SuperOptions)
	}
	if strings.Contains(m.SuperOptions, "/etc/cifs.creds") {
		t.Errorf("SuperOptions should not contain credential file path: %q", m.SuperOptions)
	}
	// username=guest is NOT a credential per our policy (it's an identifier);
	// keep it for diff visibility.
	if !strings.Contains(m.SuperOptions, "username=guest") {
		t.Errorf("SuperOptions should retain username=guest: %q", m.SuperOptions)
	}
}

func TestRedactAndSortOptions(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"rw,nosuid,nodev,noexec", "nodev,noexec,nosuid,rw"},
		{"rw,credentials=/etc/cifs.creds,vers=3.1.1", "rw,vers=3.1.1"},
		{"password=secret,rw", "rw"},
		{"CRED=foo,rw", "rw"}, // case-insensitive key match
		{"", ""},
		{"rw", "rw"},
	}
	for _, c := range cases {
		got := redactAndSortOptions(c.in)
		if got != c.want {
			t.Errorf("redactAndSortOptions(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestUnescapeMountField(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`/mnt/no-escape`, `/mnt/no-escape`},
		{`/mnt/with\040space`, `/mnt/with space`},
		{`/mnt/tab\011here`, "/mnt/tab\there"},
		{`/mnt/back\134slash`, `/mnt/back\slash`},
	}
	for _, c := range cases {
		got := unescapeMountField(c.in)
		if got != c.want {
			t.Errorf("unescapeMountField(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseMountinfoLineEscapedMountpoint(t *testing.T) {
	line := `42 26 0:99 / /mnt/with\040space rw - tmpfs tmpfs rw`
	m := parseMountinfoLine(line)
	if m == nil {
		t.Fatalf("nil")
	}
	if m.MountPoint != "/mnt/with space" {
		t.Errorf("MountPoint = %q, want '/mnt/with space'", m.MountPoint)
	}
}

func TestParseMountinfoLineMalformed(t *testing.T) {
	// Lines without the " - " separator or with too few fields must return nil
	// rather than panic or produce garbage.
	cases := []string{
		"",
		"too few fields here",
		"26 1 254:0 / / rw,relatime - ext4", // missing source + super_opts
	}
	for _, line := range cases {
		if m := parseMountinfoLine(line); m != nil {
			t.Errorf("expected nil for malformed line %q, got %+v", line, m)
		}
	}
}

func TestReadMountinfoFromFixture(t *testing.T) {
	f, err := os.CreateTemp("", "mountinfo-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	content := `26 1 254:0 / / rw,relatime shared:1 - ext4 /dev/mapper/rhel-root rw,seclabel
22 26 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
123 26 0:91 / /mnt/share rw,relatime shared:200 - cifs //server/share rw,vers=3.1.1,credentials=/etc/cifs.creds
`
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	f.Close()

	mounts, err := readMountinfoFrom(f.Name())
	if err != nil {
		t.Fatalf("readMountinfoFrom: %v", err)
	}
	if len(mounts) != 3 {
		t.Fatalf("got %d mounts, want 3", len(mounts))
	}

	// Sorted by mount point.
	wantPoints := []string{"/", "/mnt/share", "/sys"}
	gotPoints := []string{mounts[0].MountPoint, mounts[1].MountPoint, mounts[2].MountPoint}
	if !reflect.DeepEqual(gotPoints, wantPoints) {
		t.Errorf("mount points = %v, want %v (sorted)", gotPoints, wantPoints)
	}

	// CIFS mount should have credentials= stripped.
	cifs := mounts[1]
	if strings.Contains(cifs.SuperOptions, "credentials") {
		t.Errorf("CIFS SuperOptions still contains 'credentials': %q", cifs.SuperOptions)
	}
}

func TestReadMountinfoFromMissing(t *testing.T) {
	if _, err := readMountinfoFrom("/nonexistent/path/mountinfo"); err == nil {
		t.Error("expected error for missing file")
	}
}
