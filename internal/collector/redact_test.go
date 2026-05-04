package collector

import "testing"

func TestRedactSecretsKeyValueAssignments(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"MYSQL_PASSWORD=foo backup.sh", "MYSQL_PASSWORD=<redacted> backup.sh"},
		{"DB_PASSWD=hunter2 /opt/run.sh", "DB_PASSWD=<redacted> /opt/run.sh"},
		{"API_TOKEN=abcd1234 curl x", "API_TOKEN=<redacted> curl x"},
		{"AWS_SECRET_ACCESS_KEY=xxx aws s3 cp", "AWS_SECRET_ACCESS_KEY=<redacted> aws s3 cp"},
		// Lowercase still matches (case-insensitive).
		{"db_password=secret cmd", "db_password=<redacted> cmd"},
		// Multiple secrets on one line — both must be redacted.
		{"USER_PASSWORD=a TOKEN=b cmd", "USER_PASSWORD=<redacted> TOKEN=<redacted> cmd"},
	}
	for _, c := range cases {
		got := redactSecrets(c.in)
		if got != c.want {
			t.Errorf("redactSecrets(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRedactSecretsAWSKey(t *testing.T) {
	in := "aws --access-key AKIAIOSFODNN7EXAMPLE s3 cp file s3://bucket/"
	got := redactSecrets(in)
	if got == in || !contains(got, "<redacted>") {
		t.Errorf("AWS key not redacted: %q", got)
	}
	if contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS key still present: %q", got)
	}
}

func TestRedactSecretsGitHubToken(t *testing.T) {
	cases := []string{
		"git push https://ghp_1234567890abcdefghijklmnopqrstuvwxyz123 origin main",
		"curl -u ghs_1234567890abcdefghijklmnopqrstuvwxyz456 ...",
	}
	for _, in := range cases {
		got := redactSecrets(in)
		if got == in {
			t.Errorf("token not redacted: %q", got)
		}
		if contains(got, "ghp_") || contains(got, "ghs_") {
			// Prefix may legitimately appear in URLs etc., but in these inputs
			// the prefix only existed in the token itself.
			if contains(got, "1234567890abcdefghijklmnopqrstuvwxyz") {
				t.Errorf("token body still present: %q", got)
			}
		}
	}
}

func TestRedactSecretsBearerToken(t *testing.T) {
	in := `curl -H "Authorization: Bearer abc.def.ghi" https://api`
	got := redactSecrets(in)
	if !contains(got, "Bearer <redacted>") && !contains(got, "bearer <redacted>") {
		t.Errorf("Bearer token not redacted: %q", got)
	}
	if contains(got, "abc.def.ghi") {
		t.Errorf("token still present: %q", got)
	}
}

func TestRedactSecretsPassesThroughInnocuousCommands(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"/usr/bin/run-parts /etc/cron.hourly",
		"backup.sh --output /var/backups/db.sql.gz",
		"systemctl restart nginx",
		// PATH= is not a secret — KEY= alone (no sensitive keyword) must not match.
		"PATH=/usr/bin /opt/run.sh",
		"SHELL=/bin/bash MAILTO=root /opt/run.sh",
	}
	for _, in := range cases {
		got := redactSecrets(in)
		if got != in {
			t.Errorf("redactSecrets(%q) = %q, want unchanged", in, got)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
