package collector

import (
	"strings"
	"testing"
)

// The line parsers below consume untrusted input: lines from /proc, /sys, and
// the output of external tools (ip, rpm, iptables-save, nft). A malformed or
// hostile line must never panic the agent — that would be a remotely-influenced
// denial of service on a tool whose job is to keep running and recording. These
// fuzz targets assert exactly that: no input crashes the parser. Each also runs
// the parser twice and ignores the result; the harness's own crash detection is
// the oracle.

func FuzzParseMountinfoLine(f *testing.F) {
	f.Add("36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue")
	f.Add("")
	f.Add("- - - -")
	f.Add("garbage with - dash separator - and more")
	f.Fuzz(func(t *testing.T, line string) {
		_ = parseMountinfoLine(line)
	})
}

func FuzzParseRouteLine(f *testing.F) {
	f.Add("default via 192.168.1.1 dev eth0 proto dhcp metric 100")
	f.Add("10.0.0.0/24 dev eth1 scope link")
	f.Add("")
	f.Add("via via via dev dev")
	f.Fuzz(func(t *testing.T, line string) {
		_ = parseRouteLine(line)
	})
}

func FuzzParseModulesLine(f *testing.F) {
	f.Add("xfrm_user 45056 1 - Live 0xffffffffc0a2b000")
	f.Add("nf_conntrack 167936 3 nf_nat,nf_conntrack_netlink,xt_conntrack, Live 0x0")
	f.Add("")
	f.Add("a b c d e")
	f.Fuzz(func(t *testing.T, line string) {
		_ = parseModulesLine(line)
	})
}

func FuzzParseAuthorizedKeysLine(f *testing.F) {
	f.Add("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx user@host")
	f.Add("# a comment")
	f.Add("")
	f.Add("command=\"/bin/false\",no-pty ssh-rsa AAAA key")
	f.Add("not-a-valid-key-type blah")
	f.Fuzz(func(t *testing.T, line string) {
		_ = parseAuthorizedKeysLine(line)
	})
}

func FuzzParseCronLine(f *testing.F) {
	f.Add("*/5 * * * * root /usr/bin/backup.sh", true)
	f.Add("0 0 * * * /home/user/job.sh", false)
	f.Add("@reboot root /opt/start", true)
	f.Add("", false)
	f.Add("not enough fields", true)
	f.Fuzz(func(t *testing.T, line string, hasUserField bool) {
		_, _, _ = parseCronLine(line, hasUserField)
	})
}

func FuzzParseHexAddrPort(f *testing.F) {
	f.Add("0100007F:0050")
	f.Add("00000000000000000000000001000000:1F90")
	f.Add("")
	f.Add(":::::")
	f.Add("ZZZZ:GGGG")
	f.Fuzz(func(t *testing.T, s string) {
		_, _, _ = parseHexAddrPort(s)
	})
}

func FuzzParseIptablesRules(f *testing.F) {
	seed := strings.Join([]string{
		"*filter",
		":INPUT ACCEPT [0:0]",
		"-A INPUT -p tcp --dport 22 -j ACCEPT",
		"COMMIT",
	}, "\n")
	f.Add(seed, "ip4")
	f.Add("", "ip4")
	f.Add("*filter\n:INPUT\n", "ip6")
	f.Add("totally unrelated text", "ip4")
	f.Fuzz(func(t *testing.T, raw, family string) {
		_ = parseIptablesRules(raw, family)
	})
}

func FuzzParseCgroupForContainer(f *testing.F) {
	f.Add("0::/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope")
	f.Add("12:devices:/kubepods/besteffort/pod1234-5678/abc")
	f.Add("0::/user.slice/user-1000.slice/session-3.scope")
	f.Add("")
	f.Add(":::::\n::\ngarbage")
	f.Add("0::/" + strings.Repeat("a", 4096))
	f.Fuzz(func(t *testing.T, content string) {
		_, _, _ = parseCgroupForContainer(content)
	})
}

func FuzzParseNftablesRules(f *testing.F) {
	seed := strings.Join([]string{
		"table inet filter {",
		"  chain input {",
		"    type filter hook input priority 0; policy drop;",
		"    tcp dport 22 accept",
		"  }",
		"}",
	}, "\n")
	f.Add(seed)
	f.Add("")
	f.Add("table {{{ chain }}}")
	f.Add("} } } unbalanced { {")
	f.Fuzz(func(t *testing.T, raw string) {
		_ = parseNftablesRules(raw)
	})
}
