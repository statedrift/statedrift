package hasher

import (
	"strings"
	"testing"
)

func TestHashDeterministic(t *testing.T) {
	input := map[string]interface{}{
		"key": "value",
		"num": 42,
	}
	h1, err := Hash(input)
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	h2, err := Hash(input)
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	if h1 != h2 {
		t.Errorf("Hash not deterministic: %q != %q", h1, h2)
	}
}

func TestHashDifferentInputs(t *testing.T) {
	h1, err := Hash(map[string]interface{}{"key": "a"})
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	h2, err := Hash(map[string]interface{}{"key": "b"})
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	if h1 == h2 {
		t.Error("different inputs produced same hash")
	}
}

func TestCanonicalJSONSortsKeysAtEveryLevel(t *testing.T) {
	nested := map[string]interface{}{
		"z": map[string]interface{}{
			"b": 2,
			"a": 1,
		},
		"a": "first",
	}
	data, err := CanonicalJSON(nested)
	if err != nil {
		t.Fatalf("CanonicalJSON() error: %v", err)
	}
	s := string(data)
	// "a" key must appear before "z" key at top level
	aPos := strings.Index(s, `"a"`)
	zPos := strings.Index(s, `"z"`)
	if aPos > zPos {
		t.Errorf("top-level keys not sorted: got %s", s)
	}
	// Inside nested object, "a" must appear before "b"
	nestedStart := strings.Index(s, `"z"`)
	inner := s[nestedStart:]
	innerAPos := strings.Index(inner, `"a"`)
	innerBPos := strings.Index(inner, `"b"`)
	if innerAPos > innerBPos {
		t.Errorf("nested keys not sorted: got %s", s)
	}
}

func TestCanonicalJSONEmptyMap(t *testing.T) {
	data, err := CanonicalJSON(map[string]interface{}{})
	if err != nil {
		t.Fatalf("CanonicalJSON() error: %v", err)
	}
	if string(data) != "{}" {
		t.Errorf("expected {}, got %s", string(data))
	}
}

func TestCanonicalJSONEmptyArray(t *testing.T) {
	data, err := CanonicalJSON([]interface{}{})
	if err != nil {
		t.Fatalf("CanonicalJSON() error: %v", err)
	}
	if string(data) != "[]" {
		t.Errorf("expected [], got %s", string(data))
	}
}

func TestCanonicalJSONNilValue(t *testing.T) {
	data, err := CanonicalJSON(nil)
	if err != nil {
		t.Fatalf("CanonicalJSON() error: %v", err)
	}
	if string(data) != "null" {
		t.Errorf("expected null, got %s", string(data))
	}
}

func TestCanonicalJSONMapInsertionOrderIrrelevant(t *testing.T) {
	// Build two maps with same keys/values but simulate different insertion orders
	// by using struct-to-map round-trip in different orders.
	// Go maps have non-deterministic iteration order, so two maps with same
	// content should produce identical canonical JSON.
	m1 := map[string]interface{}{
		"zebra":  "z",
		"apple":  "a",
		"mango":  "m",
		"banana": "b",
	}
	m2 := map[string]interface{}{
		"apple":  "a",
		"banana": "b",
		"mango":  "m",
		"zebra":  "z",
	}
	d1, err := CanonicalJSON(m1)
	if err != nil {
		t.Fatalf("CanonicalJSON() error: %v", err)
	}
	d2, err := CanonicalJSON(m2)
	if err != nil {
		t.Fatalf("CanonicalJSON() error: %v", err)
	}
	if string(d1) != string(d2) {
		t.Errorf("insertion order affected canonical JSON:\n  m1: %s\n  m2: %s", d1, d2)
	}
}

func TestGenesisHashIs64Zeros(t *testing.T) {
	if len(GenesisHash) != 64 {
		t.Errorf("GenesisHash length = %d, want 64", len(GenesisHash))
	}
	for _, c := range GenesisHash {
		if c != '0' {
			t.Errorf("GenesisHash contains non-zero char %q: %s", c, GenesisHash)
			break
		}
	}
}
