package diff

import "testing"

// TestValidSectionFilter pins the accept/reject behavior for --section
// filters: prefixes of known sections and dotted extensions are valid,
// typos are not.
func TestValidSectionFilter(t *testing.T) {
	valid := []string{
		"host", "network", "network.interfaces", "net",
		"kernel_params", "kernel_counters", "kernel",
		"harness", "harness.mcp", "harness.permissions",
		"dataplane", "dataplane.pf", "filesystem",
		"users", "firewall", "containers", "gpu",
	}
	for _, f := range valid {
		if !ValidSectionFilter(f) {
			t.Errorf("ValidSectionFilter(%q) = false, want true", f)
		}
	}

	// Typos and filters longer than any section name can never match a
	// Change and must be rejected.
	invalid := []string{
		"bogus", "kernelparams", "user_accounts", "harness.mpc",
		"network_interfaces", "Users", "harness,mcp",
		"filesystem./etc/passwd",
	}
	for _, f := range invalid {
		if ValidSectionFilter(f) {
			t.Errorf("ValidSectionFilter(%q) = true, want false", f)
		}
	}
}

// TestKnownSectionsCoverEmittedSections cross-checks that every section a
// Compare-produced Change carries is accepted by ValidSectionFilter, so the
// CLI can never reject a section name that actually appears in output.
func TestKnownSectionsCoverEmittedSections(t *testing.T) {
	for _, s := range KnownSections {
		if !ValidSectionFilter(s) {
			t.Errorf("known section %q rejected by ValidSectionFilter", s)
		}
	}
}
