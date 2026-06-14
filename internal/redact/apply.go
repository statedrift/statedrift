package redact

import (
	"github.com/statedrift/statedrift/internal/collector"
)

// Type-tag prefixes. Kept short (≤ 6 chars) so the redacted JSON stays
// readable. The prefix is part of the HMAC input — see tag().
const (
	tagIP   = "ip"   // IPv4/IPv6 addresses, gateways, route destinations, listen addresses, connection endpoints
	tagMAC  = "mac"  // MAC addresses
	tagHost = "host" // hostname, machine_id, boot_id, DNS search domains, network mount sources
	tagUser = "user" // login names, group names, group members, ssh users, cron users
	tagPath = "path" // home directories, file paths that may embed a username
	tagText = "text" // free-text fields: GECOS, SSH key comment, sudoers line, systemd timer description/unit
	tagFW   = "fw"   // firewall rule text (embeds IPs/CIDRs/ports) — hashed whole, sudoers-style
)

// Apply walks snap in-place, replacing Category B identifier fields with
// deterministic tagged hashes per the Redactor's options. Cat A fields
// (which were stripped or pattern-redacted at collect time) are not
// touched; they pass through with their existing "<redacted>" placeholders
// intact.
//
// Apply tolerates missing or nil sub-structs, including pre-v0.4
// snapshots that lack Process tick fields and v0.1/v0.2 snapshots that
// lack the v0.3 security signal sections. A nil snap is a no-op.
//
// Determinism contract: given the same Redactor (same salt + options) and
// the same input snapshot, Apply produces byte-identical output across
// runs. This is what the bundle-integration phase relies on for the
// re-chained verify path.
func Apply(snap *collector.Snapshot, r *Redactor) {
	if snap == nil || r == nil || !r.opts.Any() {
		return
	}

	if r.opts.Network {
		applyNetwork(snap, r)
	}
	if r.opts.Hostnames {
		applyHostnames(snap, r)
	}
}

func applyNetwork(snap *collector.Snapshot, r *Redactor) {
	for i := range snap.Network.Interfaces {
		iface := &snap.Network.Interfaces[i]
		iface.MAC = r.tag(tagMAC, iface.MAC)
		iface.Addresses = r.tagSlice(tagIP, iface.Addresses)
	}

	for i := range snap.Network.Routes {
		rt := &snap.Network.Routes[i]
		rt.Destination = r.tag(tagIP, rt.Destination)
		rt.Gateway = r.tag(tagIP, rt.Gateway)
	}

	snap.Network.DNS.Nameservers = r.tagSlice(tagIP, snap.Network.DNS.Nameservers)

	for i := range snap.ListeningPorts {
		snap.ListeningPorts[i].Address = r.tag(tagIP, snap.ListeningPorts[i].Address)
	}

	for i := range snap.Connections {
		c := &snap.Connections[i]
		c.LocalAddr = r.tag(tagIP, c.LocalAddr)
		c.RemoteAddr = r.tag(tagIP, c.RemoteAddr)
	}

	for i := range snap.MulticastGroups {
		snap.MulticastGroups[i].Group = r.tag(tagIP, snap.MulticastGroups[i].Group)
	}

	// Firewall rule text embeds IPs/CIDRs/ports (Cat B). Rather than
	// regex-substituting the embedded addresses — fragile for IPv6/CIDR and a
	// redaction gap is a leak — each rule is hashed whole, sudoers-style (see
	// the tagText sudoers handling in applyHostnames). Table and chain names
	// are structural, not Cat B, so they stay clear; this keeps the redacted
	// view diffable by (table, chain) while guaranteeing no address leak. The
	// ruleset_hash field is already an opaque digest and needs no redaction.
	if snap.Firewall != nil {
		for i := range snap.Firewall.RuleList {
			snap.Firewall.RuleList[i].Rule = r.tag(tagFW, snap.Firewall.RuleList[i].Rule)
		}
	}
}

func applyHostnames(snap *collector.Snapshot, r *Redactor) {
	snap.Host.Hostname = r.tag(tagHost, snap.Host.Hostname)
	snap.Host.MachineID = r.tag(tagHost, snap.Host.MachineID)
	snap.Host.BootID = r.tag(tagHost, snap.Host.BootID)

	snap.Network.DNS.SearchDomains = r.tagSlice(tagHost, snap.Network.DNS.SearchDomains)

	for i := range snap.Users {
		u := &snap.Users[i]
		u.Name = r.tag(tagUser, u.Name)
		u.Home = r.tag(tagPath, u.Home)
		u.GECOS = r.tag(tagText, u.GECOS)
	}

	for i := range snap.Groups {
		g := &snap.Groups[i]
		g.Name = r.tag(tagUser, g.Name)
		g.Members = r.tagSlice(tagUser, g.Members)
	}

	for i := range snap.Sudoers {
		// Sudoers lines mix usernames, hostnames, and command paths in a
		// grammar we don't parse. Hash the whole normalized line as one
		// opaque blob — auditors lose per-rule readability, internal
		// responders retain the verbatim local chain. See V04_PLAN.md
		// Decision #2.
		snap.Sudoers[i].Line = r.tag(tagText, snap.Sudoers[i].Line)
	}

	for i := range snap.SSHKeys {
		k := &snap.SSHKeys[i]
		k.User = r.tag(tagUser, k.User)
		k.Comment = r.tag(tagText, k.Comment)
		// Source path embeds the username (e.g. /home/alice/.ssh/authorized_keys).
		k.Source = r.tag(tagPath, k.Source)
		// Type, Fingerprint, Options are not Cat B — leave alone.
	}

	for i := range snap.CronJobs {
		snap.CronJobs[i].User = r.tag(tagUser, snap.CronJobs[i].User)
	}

	for i := range snap.Mounts {
		m := &snap.Mounts[i]
		// Only network mount sources carry a Cat B identifier. Local
		// block devices (/dev/sda1) and pseudofs (tmpfs, proc, sysfs,
		// overlay, none) stay verbatim — they leak no host identity.
		if IsNetworkMountSource(m.Source) {
			m.Source = r.tag(tagHost, m.Source)
		}
	}

	for i := range snap.Timers {
		t := &snap.Timers[i]
		t.Description = r.tag(tagText, t.Description)
		t.Unit = r.tag(tagText, t.Unit)
	}
}
