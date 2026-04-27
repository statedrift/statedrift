// Package hasher computes deterministic SHA-256 hashes over canonical JSON snapshots.
package hasher

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
)

const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Hash computes the SHA-256 hash of the snapshot's canonical JSON representation.
// Canonical JSON: keys sorted at every level, compact encoding, no trailing whitespace.
//
// The on-the-wire byte stream MUST match what the embedded verify.sh
// pipeline (`jq -cS '.' | tr -d '\n' | sha256sum`) computes for the same
// snapshot file — see TestCanonicalJSONMatchesBashPipeline. The most
// surprising consequence is that string fields containing <, >, &, U+2028,
// or U+2029 must NOT be HTML-escaped, since jq does not escape them.
func Hash(v interface{}) (string, error) {
	canonical, err := CanonicalJSON(v)
	if err != nil {
		return "", fmt.Errorf("canonical json: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return fmt.Sprintf("%x", sum), nil
}

// CanonicalJSON produces deterministic JSON with sorted keys and compact encoding.
// This is critical: the same snapshot must always produce the same bytes,
// regardless of Go map iteration order.
func CanonicalJSON(v interface{}) ([]byte, error) {
	// First, marshal to get a generic representation
	data, err := marshalNoHTMLEscape(v)
	if err != nil {
		return nil, err
	}

	// Unmarshal into interface{} to normalize
	var generic interface{}
	if err := json.Unmarshal(data, &generic); err != nil {
		return nil, err
	}

	// Re-marshal with sorted keys
	return marshalSorted(generic)
}

// marshalSorted recursively marshals with sorted keys.
// Go's json.Marshal doesn't guarantee map key order, so we handle it manually.
func marshalSorted(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		return marshalSortedMap(val)
	case []interface{}:
		return marshalSortedArray(val)
	default:
		return marshalNoHTMLEscape(val)
	}
}

// lineSep and paraSep are the literal UTF-8 encodings of U+2028 and U+2029.
// json.Encoder hardcodes escaping for these two even with SetEscapeHTML(false),
// so we substitute the literal bytes back in to match jq's emit.
var (
	lineSepEscape  = []byte(`\u2028`)
	lineSepLiteral = []byte(" ")
	paraSepEscape  = []byte(`\u2029`)
	paraSepLiteral = []byte(" ")
)

// marshalNoHTMLEscape produces compact JSON without escaping <, >, &, U+2028,
// or U+2029. This matches jq's default output, which the embedded verify.sh
// re-canonicalization relies on.
//
// Go's encoding/json hardcodes U+2028/U+2029 escaping independently of
// SetEscapeHTML, so those two are unescaped post-encode. A literal ` `
// or ` ` in the encoder output can only come from Go escaping a real
// U+2028 / U+2029 char — a user-supplied string containing those six
// characters would have its leading backslash escaped to `\\u2028`, which
// doesn't match the substring being replaced.
func marshalNoHTMLEscape(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// json.Encoder appends a trailing newline; strip it for canonical bytes.
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	out = bytes.ReplaceAll(out, lineSepEscape, lineSepLiteral)
	out = bytes.ReplaceAll(out, paraSepEscape, paraSepLiteral)
	return out, nil
}

func marshalSortedMap(m map[string]interface{}) ([]byte, error) {
	// Sort keys
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build JSON manually to guarantee key order
	buf := []byte{'{'}
	for i, k := range keys {
		if i > 0 {
			buf = append(buf, ',')
		}

		// Marshal key
		keyBytes, err := marshalNoHTMLEscape(k)
		if err != nil {
			return nil, err
		}
		buf = append(buf, keyBytes...)
		buf = append(buf, ':')

		// Marshal value (recursively)
		valBytes, err := marshalSorted(m[k])
		if err != nil {
			return nil, err
		}
		buf = append(buf, valBytes...)
	}
	buf = append(buf, '}')
	return buf, nil
}

func marshalSortedArray(a []interface{}) ([]byte, error) {
	buf := []byte{'['}
	for i, item := range a {
		if i > 0 {
			buf = append(buf, ',')
		}
		itemBytes, err := marshalSorted(item)
		if err != nil {
			return nil, err
		}
		buf = append(buf, itemBytes...)
	}
	buf = append(buf, ']')
	return buf, nil
}

// Verify checks that a snapshot's prev_hash matches the given expected hash.
// Returns true if the chain link is valid.
func Verify(prevHash, expectedPrevHash string) bool {
	return prevHash == expectedPrevHash
}
