package hasher

import (
	"bytes"
	"encoding/json"
	"testing"
)

// FuzzCanonicalJSON drives arbitrary JSON through CanonicalJSON and asserts the
// two properties the hash chain depends on:
//
//   - no panic on any parseable input, and
//   - idempotency: re-canonicalizing already-canonical output is a fixed point.
//
// Idempotency is the load-bearing property. The whole tamper-evidence story
// rests on "the same logical snapshot always produces the same bytes," so if
// canonicalizing canonical JSON ever drifts (key ordering, number formatting,
// U+2028/U+2029 substitution, HTML-escape handling), two honest verifiers could
// disagree about whether a chain is intact. A fixed-point violation here is a
// silent integrity bug; this catches it.
func FuzzCanonicalJSON(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"b":1,"a":2}`,
		`{"z":{"y":[3,2,1]},"a":"x"}`,
		`[{"k":"v"},{"k":"w"}]`,
		`{"html":"<a>&</a>","sep":"  "}`,
		`{"n":1.5,"big":1e10,"neg":-0,"nested":{"":""}}`,
		`"just a string"`,
		`123`,
		`true`,
		`null`,
		`{"unicode":"héllo é ￿","emoji":"😀"}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Only consider inputs that are valid JSON; CanonicalJSON is defined
		// over decoded values, not arbitrary bytes.
		var generic interface{}
		if err := json.Unmarshal(data, &generic); err != nil {
			return
		}

		c1, err := CanonicalJSON(generic)
		if err != nil {
			t.Fatalf("CanonicalJSON on valid JSON returned error: %v (input=%q)", err, data)
		}

		// Output must itself be valid JSON.
		var reparsed interface{}
		if err := json.Unmarshal(c1, &reparsed); err != nil {
			t.Fatalf("CanonicalJSON output is not valid JSON: %v (output=%q)", err, c1)
		}

		// Idempotency / fixed point.
		c2, err := CanonicalJSON(reparsed)
		if err != nil {
			t.Fatalf("re-canonicalizing returned error: %v (c1=%q)", err, c1)
		}
		if !bytes.Equal(c1, c2) {
			t.Fatalf("CanonicalJSON not idempotent:\n  first:  %q\n  second: %q\n  input:  %q", c1, c2, data)
		}
	})
}

// FuzzHashDeterministic asserts Hash is a pure function of the canonical bytes:
// hashing the same decoded value twice yields the same digest. A regression
// here would make verification non-reproducible.
func FuzzHashDeterministic(f *testing.F) {
	f.Add([]byte(`{"a":1,"b":[2,3]}`))
	f.Add([]byte(`{"z":"y","x":{"w":"v"}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var generic interface{}
		if err := json.Unmarshal(data, &generic); err != nil {
			return
		}
		h1, err := Hash(generic)
		if err != nil {
			t.Fatalf("Hash error on valid JSON: %v", err)
		}
		h2, err := Hash(generic)
		if err != nil {
			t.Fatalf("Hash error on second call: %v", err)
		}
		if h1 != h2 {
			t.Fatalf("Hash not deterministic: %s != %s (input=%q)", h1, h2, data)
		}
	})
}
