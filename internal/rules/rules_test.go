package rules

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDefaultRulesNonEmpty(t *testing.T) {
	r := DefaultRules()
	if len(r) == 0 {
		t.Error("DefaultRules() returned empty slice")
	}
}

func TestDefaultRulesHaveRequiredFields(t *testing.T) {
	for _, r := range DefaultRules() {
		if r.ID == "" {
			t.Errorf("rule missing ID: %+v", r)
		}
		if r.Name == "" {
			t.Errorf("rule %s missing Name", r.ID)
		}
		if r.Severity == "" {
			t.Errorf("rule %s missing Severity", r.ID)
		}
	}
}

func TestEvaluateMatchesPackageAdded(t *testing.T) {
	ruleSet := DefaultRules()
	changes := []Change{
		{Section: "packages", Type: "added", Key: "malware", NewValue: "1.0"},
	}
	findings := Evaluate(ruleSet, changes, false)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for added package")
	}
	found := false
	for _, f := range findings {
		if f.Rule.ID == "R03_PACKAGE_ADDED" {
			found = true
		}
	}
	if !found {
		t.Error("expected R03_PACKAGE_ADDED in findings")
	}
}

func TestEvaluateSkipsCounterChanges(t *testing.T) {
	ruleSet := DefaultRules()
	changes := []Change{
		{Section: "network.interfaces", Type: "modified", Key: "eth0.stats.rx_bytes",
			OldValue: "100", NewValue: "200", Counter: true},
	}
	findings := Evaluate(ruleSet, changes, false)
	for _, f := range findings {
		if f.Rule.ID == "R09_NETWORK_INTERFACE_CHANGE" {
			t.Error("counter change should not trigger network interface rule")
		}
	}
}

func TestEvaluateProRuleSkippedWithoutLicense(t *testing.T) {
	ruleSet := DefaultRules()
	changes := []Change{
		{Section: "nic_drivers", Type: "modified", Key: "eth0.fw_version",
			OldValue: "1.0", NewValue: "2.0"},
	}
	findings := Evaluate(ruleSet, changes, false) // hasPro = false
	for _, f := range findings {
		if f.Rule.ID == "R11_NIC_FIRMWARE_CHANGED" {
			t.Error("Pro rule R11 should be skipped without license")
		}
	}
}

func TestEvaluateProRuleMatchesWithLicense(t *testing.T) {
	ruleSet := DefaultRules()
	changes := []Change{
		{Section: "nic_drivers", Type: "modified", Key: "eth0.fw_version",
			OldValue: "1.0", NewValue: "2.0"},
	}
	findings := Evaluate(ruleSet, changes, true) // hasPro = true
	found := false
	for _, f := range findings {
		if f.Rule.ID == "R11_NIC_FIRMWARE_CHANGED" {
			found = true
		}
	}
	if !found {
		t.Error("Pro rule R11 should match with license")
	}
}

func TestEvaluateBootIDTriggersCritical(t *testing.T) {
	ruleSet := DefaultRules()
	changes := []Change{
		{Section: "host", Type: "modified", Key: "boot_id",
			OldValue: "aaa", NewValue: "bbb"},
	}
	findings := Evaluate(ruleSet, changes, false)
	if len(findings) == 0 {
		t.Fatal("expected finding for boot_id change")
	}
	if findings[0].Rule.Severity != SeverityCritical {
		t.Errorf("first finding severity = %q, want critical", findings[0].Rule.Severity)
	}
}

func TestEvaluateSortedBySeverity(t *testing.T) {
	ruleSet := DefaultRules()
	changes := []Change{
		{Section: "packages", Type: "modified", Key: "nginx", OldValue: "1.0", NewValue: "1.1"}, // low
		{Section: "host", Type: "modified", Key: "boot_id", OldValue: "aaa", NewValue: "bbb"},   // critical
		{Section: "packages", Type: "added", Key: "backdoor", NewValue: "1.0"},                  // high
	}
	findings := Evaluate(ruleSet, changes, false)
	if len(findings) < 2 {
		t.Skip("not enough findings to check sort order")
	}
	for i := 1; i < len(findings); i++ {
		if SeverityRank(findings[i-1].Rule.Severity) > SeverityRank(findings[i].Rule.Severity) {
			t.Errorf("findings not sorted by severity at index %d: %s > %s",
				i, findings[i-1].Rule.Severity, findings[i].Rule.Severity)
		}
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	loaded, err := Load("/nonexistent/path/rules.json")
	if err != nil {
		t.Fatalf("Load() missing file should return nil error, got %v", err)
	}
	if len(loaded) != len(DefaultRules()) {
		t.Errorf("loaded %d rules, want %d (defaults)", len(loaded), len(DefaultRules()))
	}
}

func TestLoadFileOverridesDefault(t *testing.T) {
	override := []Rule{{
		ID:         "R01_NEW_LISTEN_PORT",
		Name:       "OVERRIDDEN",
		Severity:   SeverityLow,
		Section:    "listening_ports",
		ChangeType: "added",
	}}
	data, _ := json.Marshal(override)

	f, err := os.CreateTemp("", "statedrift-rules-*.json")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())
	f.Write(data)
	f.Close()

	loaded, err := Load(f.Name())
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	for _, r := range loaded {
		if r.ID == "R01_NEW_LISTEN_PORT" {
			if r.Name != "OVERRIDDEN" {
				t.Errorf("override not applied: Name = %q, want OVERRIDDEN", r.Name)
			}
			if r.Severity != SeverityLow {
				t.Errorf("override not applied: Severity = %q, want low", r.Severity)
			}
			return
		}
	}
	t.Error("R01_NEW_LISTEN_PORT not found in loaded rules")
}

func TestLoadFileAddsNewRule(t *testing.T) {
	extra := []Rule{{
		ID:         "CUSTOM_001",
		Name:       "My custom rule",
		Severity:   SeverityMedium,
		Section:    "services",
		ChangeType: "added",
	}}
	data, _ := json.Marshal(extra)

	f, err := os.CreateTemp("", "statedrift-rules-*.json")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())
	f.Write(data)
	f.Close()

	loaded, err := Load(f.Name())
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(loaded) != len(DefaultRules())+1 {
		t.Errorf("expected %d rules (defaults + 1 custom), got %d", len(DefaultRules())+1, len(loaded))
	}
}
