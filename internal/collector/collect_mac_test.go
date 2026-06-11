package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile is a small helper that creates path (and parents) with content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseSELinuxConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	writeFile(t, cfg, `# This file controls the state of SELinux
SELINUX=enforcing
# SELINUXTYPE can take one of three values:
SELINUXTYPE=targeted
`)
	mode, ptype := parseSELinuxConfig(cfg)
	if mode != "enforcing" {
		t.Errorf("mode = %q, want enforcing", mode)
	}
	if ptype != "targeted" {
		t.Errorf("policy type = %q, want targeted", ptype)
	}
}

func TestParseSELinuxConfigMissing(t *testing.T) {
	mode, ptype := parseSELinuxConfig(filepath.Join(t.TempDir(), "nope"))
	if mode != "" || ptype != "" {
		t.Errorf("missing config should yield empty strings, got %q/%q", mode, ptype)
	}
}

func TestReadSELinuxEnforcing(t *testing.T) {
	dir := t.TempDir()
	selinux := filepath.Join(dir, "selinux")
	cfg := filepath.Join(dir, "config")
	writeFile(t, filepath.Join(selinux, "enforce"), "1\n")
	writeFile(t, filepath.Join(selinux, "policyvers"), "33\n")
	writeFile(t, cfg, "SELINUX=enforcing\nSELINUXTYPE=targeted\n")

	m, err := readSELinuxFrom(selinux, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if m.System != "selinux" {
		t.Errorf("system = %q", m.System)
	}
	if m.Mode != "enforcing" {
		t.Errorf("mode = %q, want enforcing", m.Mode)
	}
	if m.ConfigMode != "enforcing" {
		t.Errorf("config_mode = %q", m.ConfigMode)
	}
	if m.PolicyType != "targeted" {
		t.Errorf("policy_type = %q", m.PolicyType)
	}
	if m.PolicyVersion != "33" {
		t.Errorf("policy_version = %q", m.PolicyVersion)
	}
}

func TestReadSELinuxPermissive(t *testing.T) {
	dir := t.TempDir()
	selinux := filepath.Join(dir, "selinux")
	cfg := filepath.Join(dir, "config")
	writeFile(t, filepath.Join(selinux, "enforce"), "0")
	writeFile(t, cfg, "SELINUX=enforcing\n") // runtime permissive, config enforcing

	m, err := readSELinuxFrom(selinux, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if m.Mode != "permissive" {
		t.Errorf("mode = %q, want permissive", m.Mode)
	}
	if m.ConfigMode != "enforcing" {
		t.Errorf("config_mode = %q, want enforcing (drift case)", m.ConfigMode)
	}
}

func TestReadSELinuxDisabledNoFs(t *testing.T) {
	// selinuxfs absent (no enforce file), config says disabled.
	dir := t.TempDir()
	selinux := filepath.Join(dir, "selinux") // never created
	cfg := filepath.Join(dir, "config")
	writeFile(t, cfg, "SELINUX=disabled\nSELINUXTYPE=targeted\n")

	m, err := readSELinuxFrom(selinux, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if m.Mode != "disabled" {
		t.Errorf("mode = %q, want disabled", m.Mode)
	}
	if m.ConfigMode != "disabled" {
		t.Errorf("config_mode = %q", m.ConfigMode)
	}
}

func TestParseAppArmorProfiles(t *testing.T) {
	in := strings.NewReader(`/usr/sbin/cupsd (enforce)
/usr/sbin/tcpdump (complain)
/usr/bin/man (enforce)
/usr/bin/man//man_filter (enforce)
docker-default (enforce)
garbage-without-mode
`)
	enforce, complain := parseAppArmorProfiles(in)
	if enforce != 4 {
		t.Errorf("enforce = %d, want 4", enforce)
	}
	if complain != 1 {
		t.Errorf("complain = %d, want 1", complain)
	}
}

func TestReadAppArmorEnforcing(t *testing.T) {
	dir := t.TempDir()
	profiles := filepath.Join(dir, "profiles")
	writeFile(t, profiles, "/usr/sbin/cupsd (enforce)\n/usr/sbin/tcpdump (complain)\n")

	m, err := readAppArmorFrom(profiles)
	if err != nil {
		t.Fatal(err)
	}
	if m.System != "apparmor" {
		t.Errorf("system = %q", m.System)
	}
	if m.Mode != "enforcing" {
		t.Errorf("mode = %q, want enforcing", m.Mode)
	}
	if m.EnforceCount != 1 || m.ComplainCount != 1 {
		t.Errorf("counts = enforce %d / complain %d, want 1/1", m.EnforceCount, m.ComplainCount)
	}
}

func TestReadAppArmorAllComplain(t *testing.T) {
	dir := t.TempDir()
	profiles := filepath.Join(dir, "profiles")
	writeFile(t, profiles, "/usr/sbin/tcpdump (complain)\n")

	m, err := readAppArmorFrom(profiles)
	if err != nil {
		t.Fatal(err)
	}
	if m.Mode != "permissive" {
		t.Errorf("mode = %q, want permissive (no enforce profiles)", m.Mode)
	}
}

func TestReadAppArmorMissingProfiles(t *testing.T) {
	// Module enabled but profiles file unreadable → disabled, not an error.
	m, err := readAppArmorFrom(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Mode != "disabled" {
		t.Errorf("mode = %q, want disabled", m.Mode)
	}
}

func TestApparmorIsEnabled(t *testing.T) {
	dir := t.TempDir()
	yes := filepath.Join(dir, "y")
	no := filepath.Join(dir, "n")
	writeFile(t, yes, "Y\n")
	writeFile(t, no, "N\n")
	if !apparmorIsEnabled(yes) {
		t.Error("Y should be enabled")
	}
	if apparmorIsEnabled(no) {
		t.Error("N should be disabled")
	}
	if apparmorIsEnabled(filepath.Join(dir, "missing")) {
		t.Error("missing file should be disabled")
	}
}

func TestCollectMACPrecedenceSELinux(t *testing.T) {
	dir := t.TempDir()
	selinux := filepath.Join(dir, "selinux")
	cfg := filepath.Join(dir, "config")
	apEnabled := filepath.Join(dir, "ap_enabled")
	apProfiles := filepath.Join(dir, "ap_profiles")
	writeFile(t, filepath.Join(selinux, "enforce"), "1\n")
	writeFile(t, cfg, "SELINUX=enforcing\n")
	// AppArmor also "enabled" — SELinux must win.
	writeFile(t, apEnabled, "Y\n")
	writeFile(t, apProfiles, "/x (enforce)\n")

	m, err := collectMACFrom(selinux, cfg, apEnabled, apProfiles)
	if err != nil {
		t.Fatal(err)
	}
	if m.System != "selinux" {
		t.Errorf("system = %q, want selinux (precedence)", m.System)
	}
}

func TestCollectMACAppArmor(t *testing.T) {
	dir := t.TempDir()
	selinux := filepath.Join(dir, "selinux") // absent
	cfg := filepath.Join(dir, "config")      // absent
	apEnabled := filepath.Join(dir, "ap_enabled")
	apProfiles := filepath.Join(dir, "ap_profiles")
	writeFile(t, apEnabled, "Y\n")
	writeFile(t, apProfiles, "/x (enforce)\n")

	m, err := collectMACFrom(selinux, cfg, apEnabled, apProfiles)
	if err != nil {
		t.Fatal(err)
	}
	if m.System != "apparmor" {
		t.Errorf("system = %q, want apparmor", m.System)
	}
	if m.EnforceCount != 1 {
		t.Errorf("enforce_count = %d, want 1", m.EnforceCount)
	}
}

func TestCollectMACNone(t *testing.T) {
	dir := t.TempDir()
	m, err := collectMACFrom(
		filepath.Join(dir, "selinux"),
		filepath.Join(dir, "config"),
		filepath.Join(dir, "ap_enabled"),
		filepath.Join(dir, "ap_profiles"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if m.System != "none" {
		t.Errorf("system = %q, want none", m.System)
	}
}
