package rules

import (
	"regexp"
	"testing"
)

// Tests for the v0.9 protective-control-removed class (R55-R60).
//
// Every test builds the Change literals the diff layer would actually emit —
// service_enablement values look like "enabled:multi-user.target", a disable
// arrives as a "removed" change and a mask as a "modified" one, and diffCron
// puts the job command in OldValue. Getting those shapes wrong is the way
// these rules would silently never fire in production while passing here.

// enabledChange is the change emitted when an enabled unit leaves the
// enablement layer — a `systemctl disable`, or the package being uninstalled.
func disableChange(unit string) Change {
	return Change{Section: "service_enablement", Type: "removed", Key: unit,
		OldValue: "enabled:multi-user.target", NewValue: ""}
}

// maskChange is the change emitted by `systemctl mask` on an enabled unit.
func maskChange(unit string) Change {
	return Change{Section: "service_enablement", Type: "modified", Key: unit,
		OldValue: "enabled:multi-user.target", NewValue: "masked"}
}

func TestEvaluateAuditDaemonDisabled(t *testing.T) {
	for _, c := range []Change{disableChange("auditd.service"), maskChange("auditd.service")} {
		findings := Evaluate(DefaultRules(), []Change{c}, false)
		if !fired(findings, "R55_AUDIT_DAEMON_DISABLED") {
			t.Errorf("expected R55 to fire on %s of auditd.service", c.Type)
		}
	}
}

func TestEvaluateAuditDaemonRuntimeEnablementLost(t *testing.T) {
	// `systemctl enable --runtime` records "enabled-runtime:"; losing that is
	// the same guardrail loss and must match unitWasEnabled too.
	c := Change{Section: "service_enablement", Type: "removed", Key: "auditd.service",
		OldValue: "enabled-runtime:multi-user.target", NewValue: ""}
	if !fired(Evaluate(DefaultRules(), []Change{c}, false), "R55_AUDIT_DAEMON_DISABLED") {
		t.Error("expected R55 to fire when runtime enablement is lost")
	}
}

func TestEvaluateMonitoringPackageRemoved(t *testing.T) {
	for _, pkg := range []string{"prometheus-node-exporter", "node_exporter", "netdata",
		"telegraf", "filebeat", "auditd", "rsyslog", "wazuh-agent", "datadog-agent"} {
		c := Change{Section: "packages", Type: "removed", Key: pkg, OldValue: "1.2.3"}
		if !fired(Evaluate(DefaultRules(), []Change{c}, false), "R56_MONITORING_PACKAGE_REMOVED") {
			t.Errorf("expected R56 to fire on removal of package %q", pkg)
		}
	}
}

func TestEvaluateMonitoringServiceDisabled(t *testing.T) {
	for _, unit := range []string{"node_exporter.service", "netdata.service",
		"telegraf.service", "rsyslog.service", "falco.service"} {
		if !fired(Evaluate(DefaultRules(), []Change{disableChange(unit)}, false),
			"R57_MONITORING_SERVICE_DISABLED") {
			t.Errorf("expected R57 to fire on disable of %q", unit)
		}
	}
}

func TestEvaluateProtectiveCronRemoved(t *testing.T) {
	// Shape matches diffCron: Key is the source, the command is in OldValue.
	c := Change{Section: "cron", Type: "removed", Key: "/etc/cron.d/backup",
		OldValue: `user=root schedule="0 2 * * *" cmd="/usr/local/bin/backup.sh /srv"`}
	if !fired(Evaluate(DefaultRules(), []Change{c}, false), "R58_PROTECTIVE_CRON_REMOVED") {
		t.Error("expected R58 to fire on removal of a backup cron job")
	}
}

func TestEvaluateSecuritySysctlLoosened(t *testing.T) {
	for _, key := range []string{"net.ipv4.conf.all.rp_filter", "net.ipv4.conf.eth0.rp_filter",
		"net.ipv4.tcp_syncookies", "kernel.randomize_va_space", "kernel.kptr_restrict",
		"kernel.dmesg_restrict", "kernel.yama.ptrace_scope", "fs.protected_symlinks"} {
		c := Change{Section: "kernel_params", Type: "modified", Key: key,
			OldValue: "1", NewValue: "0"}
		if !fired(Evaluate(DefaultRules(), []Change{c}, false), "R59_SECURITY_SYSCTL_LOOSENED") {
			t.Errorf("expected R59 to fire on %s -> 0", key)
		}
	}
}

func TestEvaluateFirewallServiceDisabled(t *testing.T) {
	for _, unit := range []string{"firewalld.service", "nftables.service", "ufw.service"} {
		if !fired(Evaluate(DefaultRules(), []Change{maskChange(unit)}, false),
			"R60_FIREWALL_SERVICE_DISABLED") {
			t.Errorf("expected R60 to fire on mask of %q", unit)
		}
	}
}

// --- negative cases: the whole point of the service_enablement section is that
// these do NOT fire. ---

// A service going inactive is a reboot, a deploy or a maintenance stop. It must
// not reach the protective-control rules at all — that noise is why the
// persistent enablement layer exists. (R06 still reports it at medium.)
func TestRuntimeServiceStopDoesNotFireControlRules(t *testing.T) {
	changes := []Change{
		{Section: "services", Type: "modified", Key: "auditd.service",
			OldValue: "active (running)", NewValue: "inactive (dead)"},
		{Section: "services", Type: "modified", Key: "firewalld.service",
			OldValue: "active (running)", NewValue: "inactive (dead)"},
		{Section: "services", Type: "removed", Key: "netdata.service",
			OldValue: "active (running)"},
	}
	findings := Evaluate(DefaultRules(), changes, false)
	for _, id := range []string{"R55_AUDIT_DAEMON_DISABLED", "R57_MONITORING_SERVICE_DISABLED",
		"R60_FIREWALL_SERVICE_DISABLED"} {
		if fired(findings, id) {
			t.Errorf("%s fired on a runtime stop; only persistent enablement loss may fire it", id)
		}
	}
}

// A control being restored (disabled -> enabled, or newly enabled) is the
// opposite direction and must be silent.
func TestControlRestoredDoesNotFire(t *testing.T) {
	changes := []Change{
		{Section: "service_enablement", Type: "added", Key: "auditd.service",
			OldValue: "", NewValue: "enabled:multi-user.target"},
		{Section: "service_enablement", Type: "modified", Key: "firewalld.service",
			OldValue: "masked", NewValue: "enabled:multi-user.target"},
	}
	findings := Evaluate(DefaultRules(), changes, false)
	if fired(findings, "R55_AUDIT_DAEMON_DISABLED") || fired(findings, "R60_FIREWALL_SERVICE_DISABLED") {
		t.Error("re-enabling a protective control must not fire a control-removed rule")
	}
}

// masked -> disabled: the guardrail was already off, so nothing was lost now.
func TestAlreadyOffUnitDoesNotFire(t *testing.T) {
	c := Change{Section: "service_enablement", Type: "removed", Key: "auditd.service",
		OldValue: "masked", NewValue: ""}
	if fired(Evaluate(DefaultRules(), []Change{c}, false), "R55_AUDIT_DAEMON_DISABLED") {
		t.Error("R55 fired on a unit that was already masked; only a loss from enabled counts")
	}
}

// A unit outside the control catalog is ordinary drift, not a guardrail loss.
func TestNonCatalogUnitDoesNotFire(t *testing.T) {
	findings := Evaluate(DefaultRules(), []Change{disableChange("nginx.service")}, false)
	for _, id := range []string{"R55_AUDIT_DAEMON_DISABLED", "R57_MONITORING_SERVICE_DISABLED",
		"R60_FIREWALL_SERVICE_DISABLED"} {
		if fired(findings, id) {
			t.Errorf("%s fired on nginx.service, which is not a protective control", id)
		}
	}
}

func TestNonSecuritySysctlDoesNotFireR59(t *testing.T) {
	changes := []Change{
		// Not a hardening param.
		{Section: "kernel_params", Type: "modified", Key: "net.core.somaxconn",
			OldValue: "128", NewValue: "0"},
		// A hardening param moving in the hardening direction.
		{Section: "kernel_params", Type: "modified", Key: "kernel.kptr_restrict",
			OldValue: "0", NewValue: "2"},
		// ip_forward loosens toward 1, so it is deliberately not in R59's catalog.
		{Section: "kernel_params", Type: "modified", Key: "net.ipv4.ip_forward",
			OldValue: "0", NewValue: "1"},
	}
	if fired(Evaluate(DefaultRules(), changes, false), "R59_SECURITY_SYSCTL_LOOSENED") {
		t.Error("R59 fired on a non-hardening or hardening-direction sysctl change")
	}
}

func TestOrdinaryCronRemovalDoesNotFireR58(t *testing.T) {
	c := Change{Section: "cron", Type: "removed", Key: "/etc/cron.d/report",
		OldValue: `user=deploy schedule="*/5 * * * *" cmd="/usr/local/bin/refresh-cache"`}
	if fired(Evaluate(DefaultRules(), []Change{c}, false), "R58_PROTECTIVE_CRON_REMOVED") {
		t.Error("R58 fired on an ordinary cron job removal")
	}
}

// A package unrelated to observability must not trip R56.
func TestOrdinaryPackageRemovalDoesNotFireR56(t *testing.T) {
	for _, pkg := range []string{"nginx", "curl", "python3-requests"} {
		c := Change{Section: "packages", Type: "removed", Key: pkg, OldValue: "1.0"}
		if fired(Evaluate(DefaultRules(), []Change{c}, false), "R56_MONITORING_PACKAGE_REMOVED") {
			t.Errorf("R56 fired on removal of %q", pkg)
		}
	}
}

// --- hygiene ---

func TestProtectiveControlRulesAreFreeTier(t *testing.T) {
	want := map[string]bool{
		"R55_AUDIT_DAEMON_DISABLED":       false,
		"R56_MONITORING_PACKAGE_REMOVED":  false,
		"R57_MONITORING_SERVICE_DISABLED": false,
		"R58_PROTECTIVE_CRON_REMOVED":     false,
		"R59_SECURITY_SYSCTL_LOOSENED":    false,
		"R60_FIREWALL_SERVICE_DISABLED":   false,
	}
	seen := 0
	for _, r := range DefaultRules() {
		if _, ok := want[r.ID]; ok {
			seen++
			if r.Pro {
				t.Errorf("%s should be free-tier, got Pro=true", r.ID)
			}
		}
	}
	if seen != len(want) {
		t.Errorf("found %d of the %d protective-control rules in DefaultRules", seen, len(want))
	}
}

// A regex that fails to compile makes matchCondition fail closed, so the rule
// would silently never fire — invisible in production and in every positive
// test above only because they happen to exercise it. Check every built-in.
func TestDefaultRuleRegexesCompile(t *testing.T) {
	for _, r := range DefaultRules() {
		for _, c := range r.Match {
			if c.Op != "regex" {
				continue
			}
			if _, err := regexp.Compile(c.Value); err != nil {
				t.Errorf("%s: regex %q does not compile: %v", r.ID, c.Value, err)
			}
		}
	}
}

// One event, one finding: the audit daemon has its own rule (R55), so it must
// not also trip the generic monitoring-service rule. Its *package* removal has
// no R55 equivalent, so R56 does cover it.
func TestAuditDaemonDoesNotDoubleFire(t *testing.T) {
	findings := Evaluate(DefaultRules(), []Change{disableChange("auditd.service")}, false)
	if !fired(findings, "R55_AUDIT_DAEMON_DISABLED") {
		t.Error("expected R55 on auditd disable")
	}
	if fired(findings, "R57_MONITORING_SERVICE_DISABLED") {
		t.Error("R57 also fired on auditd; the audit daemon belongs to R55 alone")
	}

	pkg := Change{Section: "packages", Type: "removed", Key: "auditd", OldValue: "3.0"}
	if !fired(Evaluate(DefaultRules(), []Change{pkg}, false), "R56_MONITORING_PACKAGE_REMOVED") {
		t.Error("expected R56 to cover removal of the auditd package")
	}
}
