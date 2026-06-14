package collector

// collect_firewall.go — firewall ruleset capture. Always-on when the capture
// allowlist permits.
//
// There is no readable /proc representation of the packet-filter ruleset, so
// this collector shells out to `nft` / `iptables-save` — the same approach
// the packages (dpkg/rpm), services (systemctl), and nic_drivers (ethtool)
// collectors already take. Reading the ruleset requires root; `statedrift
// snap` runs as root by design.
//
// v0.4 Phase N stored a SHA-256 of the canonicalized ruleset plus a rule
// count (drives R32/R33). v0.5 Phase O adds the parsed, ordered RuleList for
// per-rule diff. The rule text embeds Category B identifiers (IPs/CIDRs/ports),
// so the section is redacted at export — see internal/redact.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// iptablesCounter matches the "[packets:bytes]" counters on iptables-save
// chain-policy lines (e.g. ":INPUT ACCEPT [1234:5678]").
var iptablesCounter = regexp.MustCompile(`\[\d+:\d+\]`)

// nftCounter matches nftables inline "counter packets N bytes M" statements.
var nftCounter = regexp.MustCompile(`packets \d+ bytes \d+`)

// collectFirewall reports the identity of the host's firewall ruleset.
// Backend is determined by tool *presence*, with precedence nftables →
// iptables → none: on modern hosts iptables is iptables-nft and `nft list
// ruleset` is the authoritative superset, so preferring nft avoids
// double-counting. Crucially, presence (not ruleset non-emptiness) picks the
// backend — an emptied nft ruleset still reports Backend "nftables" with an
// empty hash, so a flush on a pure-nftables host is observable as a
// populated→empty transition rather than collapsing to "none". A
// present-but-failing tool (e.g. permission denied) returns an error so the
// caller records it; genuinely absent tooling yields Backend "none".
func collectFirewall() (*Firewall, error) {
	switch {
	case lookPath("nft"):
		out, err := exec.Command("nft", "list", "ruleset").Output()
		if err != nil {
			return nil, fmt.Errorf("nft list ruleset: %w", err)
		}
		canonical, rules := canonicalizeNftables(string(out))
		return &Firewall{
			Backend:     "nftables",
			RulesetHash: hashRuleset(canonical),
			Rules:       rules,
			RuleList:    parseNftablesRules(string(out)),
		}, nil

	case lookPath("iptables-save"):
		v4, err := exec.Command("iptables-save").Output()
		if err != nil {
			return nil, fmt.Errorf("iptables-save: %w", err)
		}
		var v6 []byte
		if lookPath("ip6tables-save") {
			if out6, err := exec.Command("ip6tables-save").Output(); err == nil {
				v6 = out6
			}
		}
		// Hash over the concatenated v4+v6 blob (Phase N behaviour, unchanged).
		canonical, rules := canonicalizeIptables(string(v4) + string(v6))
		ruleList := parseIptablesRules(string(v4), "ip4")
		ruleList = append(ruleList, parseIptablesRules(string(v6), "ip6")...)
		return &Firewall{
			Backend:     "iptables",
			RulesetHash: hashRuleset(canonical),
			Rules:       rules,
			RuleList:    ruleList,
		}, nil

	default:
		return &Firewall{Backend: "none"}, nil
	}
}

// parseIptablesRules extracts the ordered rules from one `iptables-save` /
// `ip6tables-save` output. `*table` lines set the current table; `-A CHAIN …`
// lines become rules located at (family+" "+table, CHAIN). family is "ip4" or
// "ip6" so a `-A INPUT` in each address family stays distinct. Counters and
// comments are stripped to match the ruleset hash. Returns nil for empty input.
func parseIptablesRules(raw, family string) []FirewallRule {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var rules []FirewallRule
	table := ""
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			table = family + " " + strings.TrimPrefix(line, "*")
			continue
		}
		if strings.HasPrefix(line, "-A ") || strings.HasPrefix(line, "-I ") {
			line = iptablesCounter.ReplaceAllString(line, "[0:0]")
			fields := strings.Fields(line)
			chain := ""
			if len(fields) >= 2 {
				chain = fields[1]
			}
			rules = append(rules, FirewallRule{Table: table, Chain: chain, Rule: line})
		}
	}
	return rules
}

// parseNftablesRules extracts the ordered rules from `nft list ruleset`.
// Brace-depth tracking sets the current table ("<family> <name>") and chain;
// statement lines inside a chain (depth ≥ 2) that are not the
// "type … policy …;" declaration become rules. Inline counters are zeroed to
// match the ruleset hash. Returns nil for empty input.
func parseNftablesRules(raw string) []FirewallRule {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var rules []FirewallRule
	table, chain := "", ""
	depth := 0
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		trimmed = nftCounter.ReplaceAllString(trimmed, "packets 0 bytes 0")

		switch {
		case depth == 0 && strings.HasPrefix(trimmed, "table ") && strings.HasSuffix(trimmed, "{"):
			// "table <family> <name> {"
			table = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "table "), "{"))
		case depth == 1 && strings.HasPrefix(trimmed, "chain ") && strings.HasSuffix(trimmed, "{"):
			// "chain <name> {"
			chain = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "chain "), "{"))
		case depth >= 2 && !strings.HasPrefix(trimmed, "type ") &&
			!strings.HasPrefix(trimmed, "}") && !strings.HasSuffix(trimmed, "{"):
			rules = append(rules, FirewallRule{Table: table, Chain: chain, Rule: trimmed})
		}
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if depth < 0 {
			depth = 0
		}
	}
	return rules
}

// lookPath reports whether name is an executable on PATH.
func lookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// canonicalizeIptables strips volatile content from `iptables-save` output so
// a stable ruleset hashes stably, and counts the rule lines. Volatile parts:
// the "# Generated … on <date>" comment header (and any comment) and the
// "[packets:bytes]" counters on chain-policy lines. Returns the canonical
// text and the count of rule lines (those starting with -A/-I).
func canonicalizeIptables(raw string) (string, int) {
	var out []string
	rules := 0
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = iptablesCounter.ReplaceAllString(line, "[0:0]")
		if strings.HasPrefix(line, "-A ") || strings.HasPrefix(line, "-I ") {
			rules++
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n"), rules
}

// canonicalizeNftables strips volatile content from `nft list ruleset` output
// and counts rule lines. Volatile parts: comment lines and inline "counter
// packets N bytes M" values. The rule count is an approximation — it counts
// non-structural lines inside chain bodies (brace depth ≥ 2) — and is used
// only for the emptied-to-zero flush signal, never for small deltas, so the
// approximation is harmless (a flush drives it unambiguously to zero).
func canonicalizeNftables(raw string) (string, int) {
	var out []string
	rules := 0
	depth := 0
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, " \t")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		line = nftCounter.ReplaceAllString(line, "packets 0 bytes 0")
		trimmed = strings.TrimSpace(line)

		// Count rules before adjusting depth: a rule is a statement line
		// inside a chain (depth ≥ 2) that is neither the "type … policy …;"
		// declaration, a closing brace, nor a sub-block opener.
		if depth >= 2 && !strings.HasPrefix(trimmed, "type ") &&
			!strings.HasPrefix(trimmed, "}") && !strings.HasSuffix(trimmed, "{") {
			rules++
		}
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if depth < 0 {
			depth = 0
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n"), rules
}

// hashRuleset returns the hex SHA-256 of the canonical ruleset text, or "" for
// an empty ruleset.
func hashRuleset(canonical string) string {
	if canonical == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}
