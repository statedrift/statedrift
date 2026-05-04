package collector

// redact.go — reusable secret-pattern redactor for free-form command strings.
//
// Used by collect_cron.go on cron command bodies; designed to apply equally
// well to /proc/cmdline (planned v0.4) and any future free-text capture.
//
// Policy (per docs/V03_PLAN.md "PII / secrets redaction"):
//   - Drop the value of KEY=secret pairs where KEY name suggests a credential.
//   - Drop known token formats (AWS access keys, GitHub PATs, Bearer tokens).
//   - Replace dropped values with the literal string "<redacted>" so the
//     structure of the line survives for diff visibility, but the secret does
//     not enter the chain.
//
// Best-effort: novel secret formats will not be caught. When in doubt about a
// new pattern, prefer adding it here over leaking it.

import (
	"regexp"
	"strings"
)

// sensitiveKeyPattern matches inline KEY=value assignments where KEY suggests
// a credential. Case-insensitive on the key. The captured value runs to the
// next whitespace, semicolon, or pipe — whichever comes first in shell.
//
// Substring match on the key (e.g. "MYSQL_PASSWORD" matches "PASSWORD") so we
// catch common prefixed names without enumerating every variant.
var sensitiveKeyPattern = regexp.MustCompile(
	`(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|AUTH|CREDENTIAL|PRIVATE_KEY)[A-Z0-9_]*)=([^\s;|&]+)`,
)

// awsAccessKeyPattern matches AWS access key IDs (AKIA[0-9A-Z]{16}).
// Tightly bounded — false-positive risk is low.
var awsAccessKeyPattern = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)

// githubTokenPattern matches GitHub personal access tokens and similar.
// Prefix scheme defined in https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/ .
var githubTokenPattern = regexp.MustCompile(`\bgh[opsur]_[A-Za-z0-9]{36,}\b`)

// bearerPattern matches `Authorization: Bearer xxx` and variants. The scheme
// keyword is preserved; only the token is dropped.
var bearerPattern = regexp.MustCompile(`(?i)(bearer)\s+([A-Za-z0-9._\-]+)`)

// redactSecrets returns s with credential-bearing substrings replaced by
// `<redacted>` placeholders. Empty / whitespace-only input is returned
// verbatim.
func redactSecrets(s string) string {
	if strings.TrimSpace(s) == "" {
		return s
	}
	s = sensitiveKeyPattern.ReplaceAllString(s, "$1=<redacted>")
	s = awsAccessKeyPattern.ReplaceAllString(s, "<redacted>")
	s = githubTokenPattern.ReplaceAllString(s, "<redacted>")
	s = bearerPattern.ReplaceAllString(s, "$1 <redacted>")
	return s
}
