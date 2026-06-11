# v0.4 Phase N — Firewall rule hashing

Status: in progress. Branch `feat/v04-phase-n-firewall`.

The last of the two remaining v0.4 "Security completeness" themes (Phase M
MAC enforcement shipped in PR #8). Records the identity of the host's
firewall ruleset so that any change — and especially a flush — is caught as
drift, without storing the rules themselves.

## Decisions (locked — do not relitigate)

1. **Identity hash, not per-rule diff.** Per ROADMAP, v0.4 stores a SHA-256
   of the canonicalized ruleset plus a rule count. Rule-by-rule firewall diff
   is explicitly v0.5. Do not add per-rule structural diffing here.
2. **Hash, don't store the rules.** Firewall rules contain IPs, CIDRs, and
   ports — all Category B identifiers. Storing only the hash keeps them out of
   the chain entirely, so the section has **no Cat B fields** and is
   redaction-exempt. This is the whole point of "hashing" in the ROADMAP.
3. **Always-on, capture-gated** — section `"firewall"`, a peer of `mac` and
   the v0.3 security signals. Added to `allWatchSections` so `watch` monitors
   it too.
4. **Shell out, like packages/services/nic_drivers.** "stdlib only" forbids
   third-party Go modules, not subprocesses. `nft` / `iptables-save` are the
   only practical way to read the ruleset (no readable `/proc` form). Reading
   requires root; `snap` runs as root by design (same as sudoers).
5. **Backend precedence: nftables → iptables → none.** On modern hosts
   `iptables` is `iptables-nft` and `nft list ruleset` is the superset, so
   trying nft first avoids double-counting. Fall back to
   `iptables-save` + `ip6tables-save` (concatenated) only when nft yields no
   ruleset. `none` when neither tool is present / both empty.
6. **Rule count is a flush proxy, not an inventory.** R33 fires only on the
   strong signal — count dropped to 0 while the engine is still present
   (`iptables -F` / `nft flush ruleset`). An approximate nft count is fine
   because "emptied" is unambiguous regardless of counting precision; we never
   alarm on small count deltas.
7. **No `schema_version` bump.** `Firewall` is an additive, omitempty pointer
   field. `schema_version` stays `"0.4"`.

## Data model — `internal/collector/types.go`

```go
type Firewall struct {
    Backend     string `json:"backend"`                // "nftables" | "iptables" | "none"
    RulesetHash string `json:"ruleset_hash,omitempty"` // SHA-256 hex of canonicalized ruleset
    Rules       int    `json:"rules,omitempty"`        // canonical rule-line count (flush signal)
}
```

`Snapshot` gains `Firewall *Firewall \`json:"firewall,omitempty"\``.

## Collector — `internal/collector/collect_firewall.go`

`collectFirewall()` execs with precedence; pure helpers do the work and are
unit-tested without subprocesses:

- `nft list ruleset` → `canonicalizeNftables(raw) (canonical string, rules int)`
- `iptables-save` + `ip6tables-save` → `canonicalizeIptables(raw) (canonical, rules)`
- `hashRuleset(canonical) string` → SHA-256 hex, `""` for empty.

Canonicalization strips volatile content so a stable ruleset hashes stably:

- Drop comment lines (`#…`) — `iptables-save` emits a `# Generated … on <date>`
  header.
- Zero packet/byte counters: `[N:M]` → `[0:0]` (iptables policy lines) and
  `packets N bytes M` → `packets 0 bytes 0` (nft counter statements).
- Trim trailing whitespace; drop blank lines.

Rule count: iptables = lines starting with `-A`/`-I`; nft = non-structural
lines at brace depth ≥ 2 (proxy; used only for the emptied-to-zero signal).

## Diff — `internal/diff/diff.go`

`diffFirewall(old, new *Firewall, r *Result)` emits Section `"firewall"`
field changes plus synthetic rule keys:

- `flushed` — `old.Rules >= 5 && new.Rules == 0 && new.Backend != "none"`.
  The dominant event; suppresses `ruleset_changed`.
- `ruleset_changed` — `old.RulesetHash != new.RulesetHash` (both present),
  when not flushed.

Nil handling mirrors `diffMAC`: both nil → nothing; old nil → added field
changes, no alarm; new nil → removed, no alarm (absence ≠ disablement).

## Rules — `internal/rules/rules.go` (free tier)

| ID | Severity | Section | KeyPattern |
|----|----------|---------|------------|
| R32_FIREWALL_RULESET_CHANGED | Medium | firewall | `ruleset_changed` |
| R33_FIREWALL_FLUSHED | High | firewall | `flushed` |

## Wiring

- `collect.go::Collect` + `CollectPartial` — `captures(cfg, "firewall")` branch.
- `config.go` — `"firewall"` in `Default().Capture`, `knownCaptureSections`,
  `knownSectionNames`.
- `cmd/statedrift/main.go` — `"firewall"` in `allWatchSections`.
- `diff.go::Compare` — `diffFirewall(old.Firewall, new.Firewall, r)`.

## Tests

- `collect_firewall_test.go` — canonicalization of sample iptables-save and
  nft output (counter zeroing, comment/date stripping, rule counts), hash
  stability across counter-only changes, empty → none.
- `diff_firewall_test.go` — ruleset_changed, flushed (suppresses changed),
  nil transitions, no-change.
- `rules_firewall_test.go` — R32/R33 fire on their synthetic keys; free-tier.

## Docs

- `CHANGELOG.md` `[0.4.0]` — Phase N entry.
- `README.md` capture table; `docs/DESIGN.md` §4.2 + §4.5 (Cat B: none).

## Definition of done

`go vet ./...`, `go test ./...` green; `gofmt -w .` clean. PR off
`feat/v04-phase-n-firewall` into `main`. After this lands, **all v0.4
"Security completeness" themes are complete and v0.4.0 is releasable.**
