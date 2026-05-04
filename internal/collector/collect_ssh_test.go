package collector

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A known ed25519 public-key body (base64). The fingerprint is computed
// fresh in the test rather than hardcoded so future encoding tweaks
// (with-padding vs. raw) don't silently break the test.
const testEd25519Body = "AAAAC3NzaC1lZDI1NTE5AAAAIDg6yyZxAJtnL9oAjCBT2rfbk0KKjQfH3gpMtWzfdZP2"

func expectedFingerprint(t *testing.T, body string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func TestParseAuthorizedKeysLineSimple(t *testing.T) {
	line := "ssh-ed25519 " + testEd25519Body + " alice@laptop"
	k := parseAuthorizedKeysLine(line)
	if k == nil {
		t.Fatal("parseAuthorizedKeysLine returned nil")
	}
	if k.Type != "ssh-ed25519" {
		t.Errorf("Type = %q, want ssh-ed25519", k.Type)
	}
	if k.Comment != "alice@laptop" {
		t.Errorf("Comment = %q", k.Comment)
	}
	if k.Options != "" {
		t.Errorf("Options = %q, want empty", k.Options)
	}
	want := expectedFingerprint(t, testEd25519Body)
	if k.Fingerprint != want {
		t.Errorf("Fingerprint = %q, want %q", k.Fingerprint, want)
	}
}

func TestParseAuthorizedKeysLineNeverContainsBody(t *testing.T) {
	// The defining contract of the SSH collector: the public-key body must
	// NEVER appear in any field of the captured SSHKey value. Verify directly.
	line := "ssh-ed25519 " + testEd25519Body + " alice@laptop"
	k := parseAuthorizedKeysLine(line)
	if k == nil {
		t.Fatal("nil key")
	}
	for field, val := range map[string]string{
		"Type":        k.Type,
		"Fingerprint": k.Fingerprint,
		"Comment":     k.Comment,
		"Options":     k.Options,
	} {
		if strings.Contains(val, testEd25519Body) {
			t.Errorf("body leaked into field %s = %q", field, val)
		}
		// Also reject any 30+ char chunk of the body, in case partial leakage
		// happens via substring extraction.
		if len(val) > 30 && strings.Contains(testEd25519Body, val) {
			t.Errorf("partial body leak in field %s = %q", field, val)
		}
	}
}

func TestParseAuthorizedKeysLineWithOptions(t *testing.T) {
	line := `from="10.0.0.0/8",no-pty,command="bash -c 'echo hi'" ssh-ed25519 ` + testEd25519Body + ` deploy-bot`
	k := parseAuthorizedKeysLine(line)
	if k == nil {
		t.Fatal("nil")
	}
	if k.Type != "ssh-ed25519" {
		t.Errorf("Type = %q", k.Type)
	}
	if k.Comment != "deploy-bot" {
		t.Errorf("Comment = %q", k.Comment)
	}
	if !strings.Contains(k.Options, "from=") {
		t.Errorf("Options missing from= restriction: %q", k.Options)
	}
	if !strings.Contains(k.Options, "no-pty") {
		t.Errorf("Options missing no-pty: %q", k.Options)
	}
	if !strings.Contains(k.Options, `command="bash -c 'echo hi'"`) {
		t.Errorf("Options missing quoted command: %q", k.Options)
	}
}

func TestParseAuthorizedKeysLineRedactsCommandSecrets(t *testing.T) {
	// command= can carry inline credentials; redactSecrets must scrub them.
	line := `command="bash -c 'AWS_SECRET_ACCESS_KEY=hunter2 aws s3 cp x y'" ssh-ed25519 ` + testEd25519Body + ` ci`
	k := parseAuthorizedKeysLine(line)
	if k == nil {
		t.Fatal("nil")
	}
	if strings.Contains(k.Options, "hunter2") {
		t.Errorf("secret leaked into options: %q", k.Options)
	}
	if !strings.Contains(k.Options, "<redacted>") {
		t.Errorf("options not redacted: %q", k.Options)
	}
}

func TestParseAuthorizedKeysLineRSAType(t *testing.T) {
	// A short fake RSA body — only need valid base64 for the parser to compute
	// a fingerprint.
	body := base64.StdEncoding.EncodeToString([]byte("dummy-rsa-key-bytes"))
	line := "ssh-rsa " + body + " admin@bastion"
	k := parseAuthorizedKeysLine(line)
	if k == nil {
		t.Fatal("nil")
	}
	if k.Type != "ssh-rsa" {
		t.Errorf("Type = %q", k.Type)
	}
}

func TestParseAuthorizedKeysLineCertType(t *testing.T) {
	// OpenSSH user certificates are presented inside authorized_keys with
	// keytypes like ssh-ed25519-cert-v01@openssh.com. Must be recognized.
	line := "ssh-ed25519-cert-v01@openssh.com " + testEd25519Body + " alice"
	k := parseAuthorizedKeysLine(line)
	if k == nil || k.Type != "ssh-ed25519-cert-v01@openssh.com" {
		t.Errorf("got %+v, want type=ssh-ed25519-cert-v01@openssh.com", k)
	}
}

func TestParseAuthorizedKeysLineMalformed(t *testing.T) {
	cases := []string{
		"",
		"# comment-like",
		"ssh-rsa",                            // missing body
		"ssh-rsa not-base64-!@#$%",           // unparseable body
		"unknown-keytype " + testEd25519Body, // not in knownSSHKeyTypes
		`unterminated="quoted ssh-ed25519 ` + testEd25519Body, // bad options
	}
	for _, line := range cases {
		k := parseAuthorizedKeysLine(line)
		if k != nil {
			t.Errorf("expected nil for malformed line %q, got %+v", line, k)
		}
	}
}

func TestParseAuthorizedKeysLineMultiWordComment(t *testing.T) {
	line := "ssh-ed25519 " + testEd25519Body + " alice's laptop, primary"
	k := parseAuthorizedKeysLine(line)
	if k == nil {
		t.Fatal("nil")
	}
	if k.Comment != "alice's laptop, primary" {
		t.Errorf("Comment = %q (want full trailing remainder)", k.Comment)
	}
}

func TestScanQuotedTokenEnd(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"foo bar", 3},
		{`from="10.0.0.0/8" rest`, len(`from="10.0.0.0/8"`)},
		{`a,b="c d",e rest`, len(`a,b="c d",e`)},
		{"single-token", len("single-token")},
		{`"unterminated`, -1},
		{`"escaped \" quote" rest`, len(`"escaped \" quote"`)},
	}
	for _, c := range cases {
		got := scanQuotedTokenEnd(c.in)
		if got != c.want {
			t.Errorf("scanQuotedTokenEnd(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestReadAuthorizedKeysFileSkipsCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "authorized_keys")
	content := `# alice's primary key
ssh-ed25519 ` + testEd25519Body + ` alice@laptop

# legacy key, deprecated
ssh-rsa ` + base64.StdEncoding.EncodeToString([]byte("rsa-key-bytes")) + ` alice@desktop
`
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	keys, err := readAuthorizedKeysFile(p, "alice")
	if err != nil {
		t.Fatalf("readAuthorizedKeysFile: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	for _, k := range keys {
		if k.User != "alice" {
			t.Errorf("User = %q, want alice", k.User)
		}
		if k.Source != p {
			t.Errorf("Source = %q, want %q", k.Source, p)
		}
		if !strings.HasPrefix(k.Fingerprint, "SHA256:") {
			t.Errorf("Fingerprint missing SHA256 prefix: %q", k.Fingerprint)
		}
	}
}

func TestReadSSHKeysFromEndToEnd(t *testing.T) {
	dir := t.TempDir()

	// Build a fake /etc/passwd with two users whose home dirs we control.
	aliceHome := filepath.Join(dir, "home", "alice")
	bobHome := filepath.Join(dir, "home", "bob")
	for _, h := range []string{aliceHome, bobHome} {
		if err := os.MkdirAll(filepath.Join(h, ".ssh"), 0700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}

	// User with no home dir at all (e.g. systemd-coredump-style entry).
	passwd := filepath.Join(dir, "passwd")
	passwdContent := "alice:x:1000:1000::" + aliceHome + ":/bin/bash\n" +
		"bob:x:1001:1001::" + bobHome + ":/bin/bash\n" +
		"ghost:x:1002:1002::/nonexistent/path:/bin/bash\n"
	if err := os.WriteFile(passwd, []byte(passwdContent), 0644); err != nil {
		t.Fatalf("WriteFile passwd: %v", err)
	}

	// Alice has one key; bob has none (.ssh dir exists but file does not).
	aliceKeys := "ssh-ed25519 " + testEd25519Body + " alice@laptop\n"
	if err := os.WriteFile(filepath.Join(aliceHome, ".ssh", "authorized_keys"), []byte(aliceKeys), 0600); err != nil {
		t.Fatalf("WriteFile alice: %v", err)
	}

	keys, err := readSSHKeysFrom(passwd)
	if err != nil {
		t.Fatalf("readSSHKeysFrom: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1 (alice only)", len(keys))
	}
	if keys[0].User != "alice" {
		t.Errorf("User = %q, want alice", keys[0].User)
	}
	if keys[0].Type != "ssh-ed25519" {
		t.Errorf("Type = %q", keys[0].Type)
	}
	wantFP := expectedFingerprint(t, testEd25519Body)
	if keys[0].Fingerprint != wantFP {
		t.Errorf("Fingerprint = %q, want %q", keys[0].Fingerprint, wantFP)
	}
}

func TestReadSSHKeysFromUnreadableHomeIsBestEffort(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — chmod 0000 is bypassed; test only meaningful as a non-root user")
	}
	dir := t.TempDir()

	aliceHome := filepath.Join(dir, "home", "alice")
	bobHome := filepath.Join(dir, "home", "bob")
	os.MkdirAll(filepath.Join(aliceHome, ".ssh"), 0700)
	os.MkdirAll(filepath.Join(bobHome, ".ssh"), 0700)

	// Alice's authorized_keys is readable.
	os.WriteFile(filepath.Join(aliceHome, ".ssh", "authorized_keys"),
		[]byte("ssh-ed25519 "+testEd25519Body+" alice@laptop\n"), 0600)

	// Bob's authorized_keys is unreadable to other users.
	bobAK := filepath.Join(bobHome, ".ssh", "authorized_keys")
	os.WriteFile(bobAK, []byte("ssh-ed25519 "+testEd25519Body+" bob@laptop\n"), 0000)
	defer os.Chmod(bobAK, 0600) // ensure t.TempDir() can clean up

	passwd := filepath.Join(dir, "passwd")
	os.WriteFile(passwd, []byte(
		"alice:x:1000:1000::"+aliceHome+":/bin/bash\n"+
			"bob:x:1001:1001::"+bobHome+":/bin/bash\n"), 0644)

	keys, err := readSSHKeysFrom(passwd)
	if err != nil {
		t.Fatalf("expected best-effort success, got error: %v", err)
	}
	// Alice's key must be present — bob's permission error must not abort.
	found := false
	for _, k := range keys {
		if k.User == "alice" {
			found = true
		}
	}
	if !found {
		t.Errorf("alice's key was lost to bob's permission error; got keys=%+v", keys)
	}
}
