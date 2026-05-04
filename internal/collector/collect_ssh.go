package collector

// collect_ssh.go — v0.3 Phase C SSH authorized-keys collector.
//
// Walks every user listed in /etc/passwd, derives their home directory, and
// reads <home>/.ssh/authorized_keys and <home>/.ssh/authorized_keys2 if
// present. The base64 public-key body is hashed (SHA256) at collect time
// and discarded — only the fingerprint, key type, comment, and (redacted)
// options enter the chain. Per docs/V03_PLAN.md "PII / secrets redaction
// policy" Cat A: key material never lands in the snapshot.
//
// Per-user reads are best-effort: a permission-denied .ssh/authorized_keys
// (mode 0600 alice:alice when statedrift runs as a non-root non-alice user)
// is silently skipped, the same way Phase D handles /var/spool/cron.

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// knownSSHKeyTypes is the closed set of public-key algorithm names that may
// appear as the keytype field in authorized_keys. Used to disambiguate the
// (optional) options prefix from the keytype during line parsing.
//
// Source: openssh-portable's PROTOCOL.* and ssh-keys(5). Kept exhaustive
// rather than pattern-matching so novel non-OpenSSH formats fail closed.
var knownSSHKeyTypes = map[string]bool{
	"ssh-rsa":                                  true,
	"ssh-dss":                                  true,
	"ssh-ed25519":                              true,
	"ssh-ed448":                                true,
	"ecdsa-sha2-nistp256":                      true,
	"ecdsa-sha2-nistp384":                      true,
	"ecdsa-sha2-nistp521":                      true,
	"sk-ssh-ed25519@openssh.com":               true,
	"sk-ecdsa-sha2-nistp256@openssh.com":       true,
	"ssh-rsa-cert-v01@openssh.com":             true,
	"ssh-ed25519-cert-v01@openssh.com":         true,
	"ecdsa-sha2-nistp256-cert-v01@openssh.com": true,
	"ecdsa-sha2-nistp384-cert-v01@openssh.com": true,
	"ecdsa-sha2-nistp521-cert-v01@openssh.com": true,
}

// authorizedKeysFilenames are the per-user files we look for under .ssh/.
// AuthorizedKeysFile in sshd_config can override these; not honored in v0.3
// (documented limitation).
var authorizedKeysFilenames = []string{"authorized_keys", "authorized_keys2"}

// collectSSHKeys reads authorized_keys files for every user in /etc/passwd.
func collectSSHKeys() ([]SSHKey, error) {
	return readSSHKeysFrom(defaultPasswdPath)
}

// readSSHKeysFrom is the test-friendly form. Takes a passwd-format file path
// and walks the home directories of users listed there.
func readSSHKeysFrom(passwdPath string) ([]SSHKey, error) {
	users, err := readPasswdFrom(passwdPath)
	if err != nil {
		// Missing /etc/passwd is catastrophic — propagate. Permission denied
		// would be unusual (passwd is world-readable by convention).
		return nil, err
	}

	var keys []SSHKey
	seen := make(map[string]bool) // home dir → already scanned (multiple users may share /sbin/nologin etc., but the dir mapping dedupes)
	for _, u := range users {
		if u.Home == "" {
			continue
		}
		// Some passwd entries (e.g. systemd-coredump) point at non-existent
		// home dirs by design; skip silently.
		if _, err := os.Stat(u.Home); err != nil {
			if isExpectedFSAccessError(err) {
				continue
			}
			return nil, err
		}
		// Dedupe by home — distinct passwd entries occasionally share a dir
		// (rare, but happens with role accounts).
		if seen[u.Home] {
			continue
		}
		seen[u.Home] = true

		for _, name := range authorizedKeysFilenames {
			p := filepath.Join(u.Home, ".ssh", name)
			ks, err := readAuthorizedKeysFile(p, u.Name)
			if err != nil {
				if isExpectedFSAccessError(err) {
					continue
				}
				return nil, err
			}
			keys = append(keys, ks...)
		}
	}

	sort.Slice(keys, func(i, j int) bool {
		if keys[i].User != keys[j].User {
			return keys[i].User < keys[j].User
		}
		if keys[i].Source != keys[j].Source {
			return keys[i].Source < keys[j].Source
		}
		return keys[i].Fingerprint < keys[j].Fingerprint
	})
	return keys, nil
}

// readAuthorizedKeysFile parses one authorized_keys file for a known user.
// Comments and blank lines are skipped.
func readAuthorizedKeysFile(path, user string) ([]SSHKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var keys []SSHKey
	scanner := bufio.NewScanner(f)
	// authorized_keys lines can be very long — RSA-4096 public keys + cert
	// blobs sometimes exceed bufio's default 64 KiB.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k := parseAuthorizedKeysLine(line)
		if k == nil {
			continue
		}
		k.User = user
		k.Source = path
		keys = append(keys, *k)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

// parseAuthorizedKeysLine parses one authorized_keys line into an SSHKey
// with User and Source left empty (the caller fills those in). Returns nil
// for lines that don't have the expected shape.
//
// Format:
//
//	[options ]<keytype> <base64-body> [comment...]
//
// Where options, if present, is a single comma-separated token with no
// unquoted whitespace (quoted strings inside options may contain spaces).
// The keytype is one of a closed set (knownSSHKeyTypes), which is how we
// disambiguate the optional options prefix.
func parseAuthorizedKeysLine(line string) *SSHKey {
	rest := line
	options := ""

	// Pull off a leading options block, if any. Options are present iff the
	// first whitespace-delimited token is NOT a known keytype.
	first, after := splitFirstField(rest)
	if first == "" {
		return nil
	}
	if !knownSSHKeyTypes[first] {
		// First token is options. But options may contain quoted strings with
		// spaces, so respect quoting when finding the end.
		optsEnd := scanQuotedTokenEnd(rest)
		if optsEnd <= 0 || optsEnd >= len(rest) {
			return nil
		}
		options = rest[:optsEnd]
		rest = strings.TrimLeft(rest[optsEnd:], " \t")
		first, after = splitFirstField(rest)
		if !knownSSHKeyTypes[first] {
			return nil
		}
	}

	keyType := first
	body, comment := splitFirstField(after)
	if body == "" {
		return nil
	}

	// Decode the body, hash it, then drop the body. Padding rules: OpenSSH
	// emits standard base64 with padding, but some operators paste keys
	// without trailing `=`; accept both via RawStdEncoding fallback.
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(body)
		if err != nil {
			return nil
		}
	}
	sum := sha256.Sum256(raw)
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])

	return &SSHKey{
		Type:        keyType,
		Fingerprint: fingerprint,
		Comment:     comment,
		Options:     redactSecrets(options),
	}
}

// scanQuotedTokenEnd returns the index just past the first whitespace-
// delimited token in s, with double-quoted substrings treated as opaque
// (whitespace inside quotes does not terminate the token). Returns -1 on
// malformed input (unterminated quote).
//
// Used for the authorized_keys options prefix, which can legitimately
// contain quoted strings like `command="bash -c 'foo bar'"`.
func scanQuotedTokenEnd(s string) int {
	inQuote := false
	escape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && inQuote {
			escape = true
			continue
		}
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if !inQuote && (c == ' ' || c == '\t') {
			return i
		}
	}
	if inQuote {
		return -1
	}
	return len(s)
}
