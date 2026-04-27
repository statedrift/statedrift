package hasher

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCanonicalJSONMatchesBashPipeline ensures the Go canonical-JSON encoder
// produces the same bytes (and therefore the same SHA-256) as the
// `jq -cS '.' | tr -d '\n' | sha256sum` pipeline used by the embedded
// verify.sh in audit bundles.
//
// If this diverges, an auditor running verify.sh against a real bundle will
// see false integrity breaks. The most likely cause is Go's default
// HTML-escaping of <, >, &, U+2028, U+2029 in string fields — jq does not
// escape these.
//
// Skipped if bash, jq, or sha256sum is not on PATH.
func TestCanonicalJSONMatchesBashPipeline(t *testing.T) {
	for _, tool := range []string{"bash", "jq", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH; parity test cannot run", tool)
		}
	}

	cases := []struct {
		name string
		in   map[string]interface{}
	}{
		{
			"plain ascii",
			map[string]interface{}{
				"hostname": "host1",
				"version":  "0.2.0",
			},
		},
		{
			"sorted nested",
			map[string]interface{}{
				"z": map[string]interface{}{"b": 2, "a": 1},
				"a": "first",
			},
		},
		{
			"empty containers",
			map[string]interface{}{
				"empty_map":   map[string]interface{}{},
				"empty_array": []interface{}{},
				"null_value":  nil,
			},
		},
		{
			"html-sensitive characters",
			map[string]interface{}{
				"lt":           "a<b",
				"gt":           "a>b",
				"amp":          "x&y",
				"all":          "<script>alert(1)&</script>",
				"line_sep":     "line break",
				"para_sep":     "para break",
				"quote":        `she said "hi"`,
				"backslash":    `C:\Users\test`,
				"tab_newline":  "tab\there\nnewline",
				"unicode_path": "naïve / résumé",
			},
		},
		{
			// Real /proc/net/snmp field names where case-folding flips the
			// relative order of two adjacent keys: ordinal puts D (0x44)
			// before a (0x61), so "ForwDatagrams" < "Forwarding"; a
			// case-insensitive sort reverses this. Go's sort.Strings and
			// jq -cS are both ordinal, so any reimplementation that uses
			// case-insensitive or culture-aware sort (e.g., PowerShell's
			// Sort-Object Name) will diverge here.
			"case-fold collision keys",
			map[string]interface{}{
				"DefaultTTL":    64,
				"ForwDatagrams": 0,
				"Forwarding":    1,
				"FragCreates":   0,
				"FragFails":     0,
				"InAddrErrors":  0,
				"InDelivers":    1000,
				"OutOctets":     123456,
				"OutRequests":   500,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			goHash, err := Hash(tc.in)
			if err != nil {
				t.Fatalf("Hash: %v", err)
			}

			// Write the input to a temp file as plain JSON (jq accepts any
			// formatting; it will re-canonicalize via -cS).
			plain, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			tmpFile := filepath.Join(t.TempDir(), "input.json")
			if err := os.WriteFile(tmpFile, plain, 0644); err != nil {
				t.Fatalf("write tmp: %v", err)
			}

			// Run the same pipeline embedded in verify.sh.
			cmd := exec.Command("bash", "-c",
				`jq -cS '.' "$1" | tr -d '\n' | sha256sum | awk '{print $1}'`,
				"bash", tmpFile)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("bash pipeline: %v", err)
			}
			bashHash := strings.TrimSpace(string(out))

			if goHash != bashHash {
				t.Errorf("hash divergence:\n  Go:   %s\n  bash: %s\n  input: %s",
					goHash, bashHash, string(plain))
			}
		})
	}
}
