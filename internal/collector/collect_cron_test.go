package collector

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseCronLineStandardWithUserField(t *testing.T) {
	line := "01 * * * * root run-parts /etc/cron.hourly"
	schedule, user, command := parseCronLine(line, true)
	if schedule != "01 * * * *" {
		t.Errorf("schedule = %q, want '01 * * * *'", schedule)
	}
	if user != "root" {
		t.Errorf("user = %q, want root", user)
	}
	if command != "run-parts /etc/cron.hourly" {
		t.Errorf("command = %q", command)
	}
}

func TestParseCronLineStandardNoUserField(t *testing.T) {
	// /var/spool/cron/<user> entries have no user field.
	line := "*/5 * * * * /home/alice/check.sh"
	schedule, user, command := parseCronLine(line, false)
	if schedule != "*/5 * * * *" {
		t.Errorf("schedule = %q", schedule)
	}
	if user != "" {
		t.Errorf("user = %q, want empty (filename supplies user)", user)
	}
	if command != "/home/alice/check.sh" {
		t.Errorf("command = %q", command)
	}
}

func TestParseCronLineShortcut(t *testing.T) {
	line := "@reboot root /opt/init.sh"
	schedule, user, command := parseCronLine(line, true)
	if schedule != "@reboot" {
		t.Errorf("schedule = %q, want @reboot", schedule)
	}
	if user != "root" {
		t.Errorf("user = %q", user)
	}
	if command != "/opt/init.sh" {
		t.Errorf("command = %q", command)
	}
}

func TestParseCronLineShortcutNoUserField(t *testing.T) {
	line := "@daily /home/alice/backup.sh"
	schedule, user, command := parseCronLine(line, false)
	if schedule != "@daily" {
		t.Errorf("schedule = %q", schedule)
	}
	if user != "" {
		t.Errorf("user = %q", user)
	}
	if command != "/home/alice/backup.sh" {
		t.Errorf("command = %q", command)
	}
}

func TestParseCronLineMalformed(t *testing.T) {
	cases := []string{
		"",
		"too few fields",
		"@",         // shortcut alone
		"@reboot",   // shortcut with no command
		"* * * * *", // schedule with no command (ok-ish, but command empty)
	}
	for _, line := range cases {
		schedule, _, command := parseCronLine(line, true)
		if schedule != "" && command != "" {
			t.Errorf("expected malformed for %q, got schedule=%q command=%q", line, schedule, command)
		}
	}
}

func TestIsCronEnvAssignment(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"SHELL=/bin/bash", true},
		{"MAILTO=root", true},
		{"PATH=/sbin:/bin:/usr/sbin:/usr/bin", true},
		{"FOO_BAR=baz", true},
		{"_LEADING_UNDERSCORE=ok", true},
		{"01 * * * * root cmd", false},
		{"@reboot root cmd", false},
		{"PATH /usr/bin", false}, // no '='
		{"=missing-key", false},
		{"1FOO=bad", false}, // env names cannot start with a digit
	}
	for _, c := range cases {
		got := isCronEnvAssignment(c.in)
		if got != c.want {
			t.Errorf("isCronEnvAssignment(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestReadCrontabFileSkipsCommentsAndEnv(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "crontab")
	content := `# this is a comment
SHELL=/bin/bash
MAILTO=root
PATH=/usr/bin

# Real job below
01 * * * * root run-parts /etc/cron.hourly
*/15 * * * * deploy /opt/run.sh
`
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	jobs, err := readCrontabFile(p, "", true)
	if err != nil {
		t.Fatalf("readCrontabFile: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("got %d jobs, want 2", len(jobs))
	}
	wantSchedules := []string{"01 * * * *", "*/15 * * * *"}
	wantUsers := []string{"root", "deploy"}
	for i, j := range jobs {
		if j.Schedule != wantSchedules[i] {
			t.Errorf("job[%d] schedule = %q, want %q", i, j.Schedule, wantSchedules[i])
		}
		if j.User != wantUsers[i] {
			t.Errorf("job[%d] user = %q, want %q", i, j.User, wantUsers[i])
		}
		if j.Source != p {
			t.Errorf("job[%d] source = %q, want %q", i, j.Source, p)
		}
	}
}

func TestReadCrontabFileRedactsCommandSecrets(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "crontab")
	content := `0 2 * * * root MYSQL_PASSWORD=hunter2 /opt/scripts/backup.sh
`
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	jobs, err := readCrontabFile(p, "", true)
	if err != nil {
		t.Fatalf("readCrontabFile: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("got %d jobs, want 1", len(jobs))
	}
	if !contains(jobs[0].Command, "<redacted>") {
		t.Errorf("command not redacted: %q", jobs[0].Command)
	}
	if contains(jobs[0].Command, "hunter2") {
		t.Errorf("password leaked into command: %q", jobs[0].Command)
	}
}

func TestReadCronFromAllSources(t *testing.T) {
	dir := t.TempDir()

	// /etc/crontab equivalent.
	crontab := filepath.Join(dir, "crontab")
	os.WriteFile(crontab, []byte("01 * * * * root run-parts /etc/cron.hourly\n"), 0644)

	// /etc/cron.d/* equivalent.
	cronD := filepath.Join(dir, "cron.d")
	os.MkdirAll(cronD, 0755)
	os.WriteFile(filepath.Join(cronD, "raid-check"), []byte("0 1 * * 0 root /usr/sbin/raid-check\n"), 0644)
	// editor backup file — must be skipped by shouldSkipCronInclude
	os.WriteFile(filepath.Join(cronD, "raid-check~"), []byte("BAD\n"), 0644)
	// dotted name — also skipped
	os.WriteFile(filepath.Join(cronD, "raid.bak"), []byte("BAD\n"), 0644)

	// /var/spool/cron/<user> equivalent.
	userDir := filepath.Join(dir, "spool")
	os.MkdirAll(userDir, 0755)
	os.WriteFile(filepath.Join(userDir, "alice"), []byte("@daily /home/alice/backup.sh\n"), 0600)

	jobs, err := readCronFrom(crontab, filepath.Join(cronD, "*"), userDir, "")
	if err != nil {
		t.Fatalf("readCronFrom: %v", err)
	}
	if len(jobs) != 3 {
		t.Fatalf("got %d jobs, want 3 (1 crontab + 1 cron.d + 1 user); jobs=%+v", len(jobs), jobs)
	}

	// Per-user crontab line has no user field — user comes from filename.
	var aliceJob CronJob
	for _, j := range jobs {
		if j.Source == filepath.Join(userDir, "alice") {
			aliceJob = j
			break
		}
	}
	if aliceJob.User != "alice" {
		t.Errorf("alice job user = %q, want alice", aliceJob.User)
	}
	if aliceJob.Schedule != "@daily" {
		t.Errorf("alice job schedule = %q", aliceJob.Schedule)
	}

	// Output must be sorted deterministically by Source path (alphabetical).
	sources := make([]string, len(jobs))
	for i, j := range jobs {
		sources[i] = j.Source
	}
	wantSources := []string{
		filepath.Join(cronD, "raid-check"),
		crontab,
		filepath.Join(userDir, "alice"),
	}
	if !reflect.DeepEqual(sources, wantSources) {
		t.Errorf("sources = %v, want %v (sorted)", sources, wantSources)
	}
}

func TestReadCronFromUnreadableUserDirIsNonFatal(t *testing.T) {
	// Production hosts ship /var/spool/cron mode 0700 root-only. Non-root snaps
	// must still get the world-readable /etc/cron.d/* entries; the unreadable
	// user-spool dir should be silently skipped, not propagate an error that
	// wipes out the partial result.
	dir := t.TempDir()

	// World-readable /etc/cron.d/* equivalent.
	cronD := filepath.Join(dir, "cron.d")
	os.MkdirAll(cronD, 0755)
	os.WriteFile(filepath.Join(cronD, "raid-check"), []byte("0 1 * * 0 root /usr/sbin/raid-check\n"), 0644)

	// Mode-0000 directory simulates the /var/spool/cron permission case.
	userDir := filepath.Join(dir, "spool")
	os.MkdirAll(userDir, 0000)
	defer os.Chmod(userDir, 0700) // restore so t.TempDir() can clean up

	jobs, err := readCronFrom("", filepath.Join(cronD, "*"), userDir, "")
	if err != nil {
		t.Fatalf("expected no error despite unreadable user dir, got %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("got %d jobs, want 1 (cron.d entry should survive permission error on user dir)", len(jobs))
	}
}

func TestReadCronFromMissingSourcesIsNotFatal(t *testing.T) {
	// All paths point at nonexistent locations — should return empty, not error.
	jobs, err := readCronFrom(
		"/nonexistent/crontab",
		"/nonexistent/cron.d/*",
		"/nonexistent/spool",
		"/nonexistent/spool/crontabs/*",
	)
	if err != nil {
		t.Errorf("expected no error for all-missing sources, got %v", err)
	}
	if len(jobs) != 0 {
		t.Errorf("expected 0 jobs, got %d", len(jobs))
	}
}

func TestShouldSkipCronInclude(t *testing.T) {
	cases := []struct {
		name string
		skip bool
	}{
		{"raid-check", false},
		{"my-job", false},
		{".hidden", true},
		{"backup~", true},
		{"file.bak", true},
		{"file.swp", true},
		{"", true},
	}
	for _, c := range cases {
		got := shouldSkipCronInclude(c.name)
		if got != c.skip {
			t.Errorf("shouldSkipCronInclude(%q) = %v, want %v", c.name, got, c.skip)
		}
	}
}
