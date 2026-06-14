// Package redact applies export-time Category B identifier redaction to a
// snapshot. It replaces operational identifiers (IPs, MACs, hostnames,
// usernames, mount sources, sudoers lines) with deterministic
// HMAC-SHA256-derived hashes so an audit bundle can be shipped to an
// external party without leaking the underlying values.
//
// This package is distinct from internal/collector/redact.go: that handles
// Category A secret-pattern redaction at *collect* time (passwords,
// AWS/GitHub tokens, etc.) and is a single-shot pattern matcher. This
// package handles Category B *export*-time redaction and is keyed by a
// per-bundle salt so that:
//
//   - The same value within a bundle hashes identically (route → gateway
//     references, users[].name → groups[].members cross-references survive).
//   - The same value across different bundles hashes differently (no
//     cross-bundle fingerprinting).
//
// All transformations are pure: given the same (snapshot, salt, options)
// triple, Apply produces byte-identical output. This is the load-bearing
// property the bundle integration in Phase H relies on for deterministic
// re-chaining.
package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// SaltSize is the recommended salt length in bytes. HMAC-SHA256 accepts any
// key length cryptographically, but 32 bytes matches the SHA-256 block /
// output size and is what the bundle integration generates via crypto/rand.
const SaltSize = 32

// hashHexLen is the truncation length for tagged values. 12 hex chars =
// 48 bits = 1-in-2.8e14 collision probability per pair, which is plenty for
// "is the same string identical within a snapshot" and keeps the redacted
// JSON readable. Increase if a customer reports collisions on a real
// snapshot.
const hashHexLen = 12

// Options selects which categories of identifiers Apply should redact.
// Both flags can be combined; passing the zero value is a no-op.
type Options struct {
	// Network, when true, redacts IP addresses, MAC addresses, route
	// destinations and gateways, DNS nameservers, listening-port
	// addresses, connection endpoints, and firewall rule text (hashed
	// whole; table/chain names stay clear).
	Network bool

	// Hostnames, when true, redacts the hostname / machine_id / boot_id
	// triple, DNS search domains, usernames (in users, groups, ssh_keys,
	// cron_jobs), home directories, GECOS strings, the network-source
	// half of mounts (//server/share, host:/export — local block devices
	// and pseudofs sources are left alone), whole sudoers lines, and
	// systemd timer free-text fields.
	Hostnames bool
}

// Any returns true if at least one redaction flag is set. Callers can use
// this to short-circuit the rechain path.
func (o Options) Any() bool { return o.Network || o.Hostnames }

// Redactor holds the per-bundle HMAC key and the active options. Construct
// one via NewRedactor and reuse it across every snapshot in a bundle so
// cross-snapshot references (e.g. an IP that appears in two consecutive
// snapshots) hash identically.
type Redactor struct {
	opts Options
	salt []byte
}

// NewRedactor returns a Redactor that hashes Cat B values with the given
// salt. The salt should typically be SaltSize bytes from crypto/rand;
// shorter or longer values are accepted (HMAC-SHA256 has no fixed key
// length) but a per-bundle 32-byte random salt is the documented default.
//
// The Redactor stores a reference to the salt slice — callers must not
// mutate it after construction.
func NewRedactor(opts Options, salt []byte) *Redactor {
	return &Redactor{opts: opts, salt: salt}
}

// Options returns the redaction options the Redactor was constructed with.
func (r *Redactor) Options() Options { return r.opts }

// HashHost returns the tagged hash for a hostname-class identifier. Used
// by the export path for fields outside the snapshot body (e.g. the
// manifest's hostname) so the redacted view is consistent across the
// whole bundle. Empty input returns empty output.
func (r *Redactor) HashHost(s string) string { return r.tag(tagHost, s) }

// tag computes a tagged HMAC for value under the given prefix. Empty values
// pass through unchanged: an empty Comm field or absent GECOS string means
// "not present," and replacing "" with a hash would mislead an auditor.
//
// The output format is "<prefix>:<12 hex chars>". The prefix is included
// in the HMAC input so that the same string under different prefixes
// hashes differently — preventing an auditor from cross-referencing, say,
// a username and a hostname that happen to share the same string.
func (r *Redactor) tag(prefix, value string) string {
	if value == "" {
		return ""
	}
	mac := hmac.New(sha256.New, r.salt)
	// Length-prefix the prefix so "ab"+"cd" cannot collide with "a"+"bcd".
	// Cheap insurance even though every prefix in this package is short
	// and known-distinct.
	mac.Write([]byte{byte(len(prefix))})
	mac.Write([]byte(prefix))
	mac.Write([]byte(value))
	sum := mac.Sum(nil)
	return prefix + ":" + hex.EncodeToString(sum)[:hashHexLen]
}

// tagSlice applies tag to every element of in, preserving order. A nil
// input produces a nil output (so JSON omitempty fields stay omitted).
func (r *Redactor) tagSlice(prefix string, in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = r.tag(prefix, v)
	}
	return out
}

// IsNetworkMountSource reports whether a mount source string identifies a
// network share (//server/share for SMB/CIFS, host:/export for NFS and
// similar). Local block devices (/dev/sda1) and pseudofs sources (tmpfs,
// proc, sysfs, none, overlay) return false and are left verbatim by Apply.
//
// Exposed for testing and for documentation purposes; the rule is one
// line and easy to extend if exotic schemes (ipfs://, custom FUSE
// drivers) need to be added.
func IsNetworkMountSource(source string) bool {
	if strings.HasPrefix(source, "//") {
		return true
	}
	// host:/path style — at least one ':' followed by a '/' somewhere
	// after it. Excludes ":memory:" or similar non-network literals.
	if i := strings.Index(source, ":/"); i > 0 {
		return true
	}
	return false
}
