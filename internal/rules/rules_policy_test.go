package rules

import (
	"encoding/json"
	"os"
	"testing"
)

// ruleWith builds a minimal rule with the given match conditions, wide-open on
// the structural gates so the tests isolate value-condition behavior.
func ruleWith(match ...Condition) Rule {
	return Rule{
		ID:         "C_TEST",
		Name:       "test",
		Severity:   SeverityHigh,
		Section:    "kernel_params",
		ChangeType: "modified",
		Match:      match,
	}
}

func fires(t *testing.T, r Rule, c Change) bool {
	t.Helper()
	return containsRule(Evaluate([]Rule{r}, []Change{c}, false), r.ID)
}

func TestConditionOperators(t *testing.T) {
	c := Change{Section: "kernel_params", Type: "modified", Key: "net.ipv4.ip_forward",
		OldValue: "0", NewValue: "1"}

	cases := []struct {
		name string
		cond Condition
		want bool
	}{
		{"eq match", Condition{Field: "new", Op: "eq", Value: "1"}, true},
		{"eq miss", Condition{Field: "new", Op: "eq", Value: "0"}, false},
		{"ne match", Condition{Field: "new", Op: "ne", Value: "0"}, true},
		{"ne miss", Condition{Field: "new", Op: "ne", Value: "1"}, false},
		{"contains match", Condition{Op: "contains", Value: "1"}, true},
		{"contains miss", Condition{Op: "contains", Value: "9"}, false},
		{"prefix match", Condition{Field: "key", Op: "prefix", Value: "net.ipv4"}, true},
		{"prefix miss", Condition{Field: "key", Op: "prefix", Value: "net.ipv6"}, false},
		{"suffix match", Condition{Field: "key", Op: "suffix", Value: "ip_forward"}, true},
		{"suffix miss", Condition{Field: "key", Op: "suffix", Value: "rp_filter"}, false},
		{"regex match", Condition{Field: "key", Op: "regex", Value: `^net\.ipv4\..*forward$`}, true},
		{"regex miss", Condition{Field: "key", Op: "regex", Value: `^net\.ipv6\.`}, false},
		{"regex bad pattern no match", Condition{Field: "key", Op: "regex", Value: "("}, false},
		{"changed match", Condition{Op: "changed"}, true},
		{"unknown op no match", Condition{Op: "wat", Value: "1"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fires(t, ruleWith(tc.cond), c); got != tc.want {
				t.Errorf("op %q field %q value %q: fired=%v, want %v",
					tc.cond.Op, tc.cond.Field, tc.cond.Value, got, tc.want)
			}
		})
	}
}

func TestConditionChangedNoChange(t *testing.T) {
	// Same old/new → "changed" must not fire.
	c := Change{Section: "kernel_params", Type: "modified", Key: "k", OldValue: "1", NewValue: "1"}
	if fires(t, ruleWith(Condition{Op: "changed"}), c) {
		t.Error("changed condition fired when old == new")
	}
}

func TestConditionNumeric(t *testing.T) {
	c := Change{Section: "kernel_params", Type: "modified", Key: "threads", OldValue: "10", NewValue: "150"}

	cases := []struct {
		op    string
		value string
		want  bool
	}{
		{"gt", "100", true},
		{"gt", "150", false},
		{"gte", "150", true},
		{"lt", "200", true},
		{"lt", "150", false},
		{"lte", "150", true},
	}
	for _, tc := range cases {
		t.Run(tc.op+"_"+tc.value, func(t *testing.T) {
			if got := fires(t, ruleWith(Condition{Field: "new", Op: tc.op, Value: tc.value}), c); got != tc.want {
				t.Errorf("new=150 %s %s: fired=%v, want %v", tc.op, tc.value, got, tc.want)
			}
		})
	}
}

func TestConditionNumericNonNumericNoMatch(t *testing.T) {
	// Non-numeric operand on a numeric op must not match (and must not panic).
	c := Change{Section: "kernel_params", Type: "modified", Key: "mode", OldValue: "off", NewValue: "on"}
	if fires(t, ruleWith(Condition{Field: "new", Op: "gt", Value: "5"}), c) {
		t.Error("numeric op matched a non-numeric value")
	}
	if fires(t, ruleWith(Condition{Field: "new", Op: "gt", Value: "abc"}), c) {
		t.Error("numeric op matched a non-numeric comparand")
	}
}

func TestConditionFieldSelectors(t *testing.T) {
	c := Change{Section: "kernel_params", Type: "modified", Key: "thekey", OldValue: "oldv", NewValue: "newv"}
	if !fires(t, ruleWith(Condition{Field: "old", Op: "eq", Value: "oldv"}), c) {
		t.Error("field=old did not read OldValue")
	}
	if !fires(t, ruleWith(Condition{Field: "key", Op: "eq", Value: "thekey"}), c) {
		t.Error("field=key did not read Key")
	}
	// Empty field defaults to new.
	if !fires(t, ruleWith(Condition{Op: "eq", Value: "newv"}), c) {
		t.Error("empty field did not default to NewValue")
	}
}

func TestConditionsAreANDed(t *testing.T) {
	c := Change{Section: "kernel_params", Type: "modified", Key: "net.ipv4.ip_forward",
		OldValue: "0", NewValue: "1"}

	allPass := ruleWith(
		Condition{Field: "new", Op: "eq", Value: "1"},
		Condition{Field: "key", Op: "prefix", Value: "net.ipv4"},
	)
	if !fires(t, allPass, c) {
		t.Error("expected fire when all conditions pass")
	}

	oneFail := ruleWith(
		Condition{Field: "new", Op: "eq", Value: "1"},
		Condition{Field: "key", Op: "prefix", Value: "net.ipv6"}, // fails
	)
	if fires(t, oneFail, c) {
		t.Error("expected no fire when one condition fails (conditions are ANDed)")
	}
}

func TestEmptyMatchBehavesAsBefore(t *testing.T) {
	// A rule with no Match must fire purely on the structural gates, exactly as
	// pre-value-condition rules did.
	r := Rule{ID: "C_NOMATCH", Name: "n", Severity: SeverityLow,
		Section: "kernel_params", ChangeType: "modified"}
	c := Change{Section: "kernel_params", Type: "modified", Key: "anything", OldValue: "a", NewValue: "b"}
	if !fires(t, r, c) {
		t.Error("rule with empty Match did not behave as a plain structural rule")
	}
}

func TestConditionDoesNotBroadenStructuralGate(t *testing.T) {
	// Conditions narrow only: a matching value must not rescue a rule whose
	// section/type gate already fails.
	r := ruleWith(Condition{Field: "new", Op: "eq", Value: "1"})
	r.Section = "packages" // change is in kernel_params
	c := Change{Section: "kernel_params", Type: "modified", Key: "k", OldValue: "0", NewValue: "1"}
	if fires(t, r, c) {
		t.Error("condition broadened a match past the section gate")
	}
}

func TestConditionCounterStillExcluded(t *testing.T) {
	// Counter changes are excluded before conditions run.
	c := Change{Section: "kernel_params", Type: "modified", Key: "k",
		OldValue: "0", NewValue: "1", Counter: true}
	if fires(t, ruleWith(Condition{Field: "new", Op: "eq", Value: "1"}), c) {
		t.Error("counter change matched despite the counter exclusion")
	}
}

func TestLoadFileRuleWithMatchFires(t *testing.T) {
	// Round-trip: a custom rule with conditions loaded from a JSON file fires.
	custom := []Rule{{
		ID:         "C01_IP_FORWARD_ENABLED",
		Name:       "IP forwarding enabled",
		Severity:   SeverityHigh,
		Section:    "kernel_params",
		ChangeType: "modified",
		KeyPattern: "net.ipv4.ip_forward",
		Match:      []Condition{{Field: "new", Op: "eq", Value: "1"}},
	}}
	data, _ := json.Marshal(custom)

	f, err := os.CreateTemp("", "statedrift-policy-*.json")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())
	f.Write(data)
	f.Close()

	loaded, err := Load(f.Name())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	enabled := Change{Section: "kernel_params", Type: "modified", Key: "net.ipv4.ip_forward",
		OldValue: "0", NewValue: "1"}
	if !containsRule(Evaluate(loaded, []Change{enabled}, false), "C01_IP_FORWARD_ENABLED") {
		t.Error("loaded policy rule did not fire on ip_forward=1")
	}

	disabled := Change{Section: "kernel_params", Type: "modified", Key: "net.ipv4.ip_forward",
		OldValue: "1", NewValue: "0"}
	if containsRule(Evaluate(loaded, []Change{disabled}, false), "C01_IP_FORWARD_ENABLED") {
		t.Error("loaded policy rule fired on ip_forward=0 (condition not applied)")
	}
}
