# v0.5 Phase O — Per-rule firewall diff

Status: in progress. Branch `feat/v05-phase-o-firewall-rules`. First v0.5 theme.

## Progress (2026-06-14)

- [x] Collector — `types.go` (`FirewallRule` + `RuleList`), `collect_firewall.go`
      (`parseIptablesRules`/`parseNftablesRules`), schema bump to 0.5
      (`SchemaVersionV05`/`SchemaVersionCurrent`).
- [x] Diff — `diffFirewall` extended (perRule gate suppresses ruleset_hash
      field-line; R32/R33 unchanged) + `diffFirewallRules` (added/removed/
      reordered, sorted chains). Tests in `diff_firewall_test.go`.
- [x] Collector tests — `collect_firewall_test.go`: parse iptables (single/
      multi-table, v4/v6 family tags, order, empty) and nft (multi-chain,
      counter zeroing, empty). 7 new tests.
- [x] Redaction — `tagFW = "fw"` in `apply.go`; `applyNetwork` hashes each
      `Firewall.RuleList[i].Rule` whole (sudoers-style), table/chain/ruleset_hash
      left clear; nil-Firewall guarded. `Options.Network` doc updated.
- [x] Redaction tests — `redact_test.go`: fixture gained a Firewall; rule in
      all-covered + no-leak lists; hostnames-only leaves it clear; determinism
      within bundle; nil-safe.
- [x] Docs — CHANGELOG `[0.5.0] Unreleased`; README collector table; DESIGN
      §4.2 firewall row + §4.5 firewall rows flipped to Cat B (mac stays
      exempt); ROADMAP per-rule firewall diff marked delivered.
- [ ] Commit + PR.

Phase N (v0.4) stored only a SHA-256 of the ruleset — enough to answer "did it
change / was it flushed?" but not "which rule changed?". Phase O stores the
parsed rules so the diff can show per-rule added / removed / reordered changes,
bringing firewall into line with the other network collectors (which already
store IPs and redact them at export).

## Decisions (locked — confirmed with user 2026-06-12)

1. **Store the parsed rules.** This deliberately reverses Phase N's
   "hash-only, no Cat B" stance. Per-rule diff is impossible without the
   rules. Firewall rules embed IPs/CIDRs/ports (Category B) — same as
   `connections`/`listening_ports`, which already store IPs and redact at
   export. So firewall now carries Cat B and is **redactable**, not exempt.
2. **Order-aware diff.** Firewall rules are first-match-wins; moving a DROP
   above an ACCEPT changes behaviour. The diff detects added / removed rules
   *and* per-chain reordering of the rules common to both snapshots. A
   modified rule surfaces as removed + added (rules are atomic; no partial
   "modified" — matches how cron uses full-tuple identity).
3. **Always-on.** `RuleList` is stored in every snapshot, like every other
   collector. Typical rulesets are tens of rules. No config opt-in.
4. **Free tier.** Per the freemium boundary (`project_roadmap_analysis`):
   diff and all collectors are free. ROADMAP's "Pro depth" for v0.5 refers to
   the *later* themes (customizable policy rules, smart firewall anomaly rules
   R34+, filesystem hash trees) — not the raw per-rule diff.
5. **Redaction = whole-rule hash, sudoers-style.** Under `--redact-network`,
   each rule's text is hashed as one opaque `fw:<hash>` blob rather than
   regex-substituting embedded IPs. Rationale: a redaction *gap* is a leak,
   and IPv6/CIDR regexes are fragile; for a compliance tool "guaranteed no
   leak" beats "prettier auditor diff". Direct precedent: sudoers lines
   (V04_PLAN Decision #2). Table/chain names stay clear (not Cat B). Same
   value hashes identically within a bundle, so auditors can still diff
   bundle-to-bundle structurally.
6. **`schema_version` bumps "0.4" → "0.5".** First v0.5 schema change, same
   as Phase F bumped "0.3" → "0.4". `rule_list` is additive/omitempty;
   pre-0.5 snapshots simply lack it. `SchemaVersionV05 = "0.5"`.
7. **Phase N signals preserved.** `ruleset_hash` and `rules` count stay, so
   R32 (ruleset_changed) and R33 (flushed) fire exactly as before. The
   `ruleset_hash` *field-change line* is suppressed in the diff when per-rule
   detail is available (the per-rule changes are the human-readable detail);
   it still emits in hash-only mode for pre-0.5 snapshots.

## Data model — `internal/collector/types.go`

```go
type FirewallRule struct {
    Table string `json:"table"` // "filter" / "inet filter" / "ip4 filter" / "ip6 filter"
    Chain string `json:"chain"` // "INPUT", "input", "DOCKER-USER", ...
    Rule  string `json:"rule"`  // canonical rule text, counters stripped
}

type Firewall struct {
    Backend     string         `json:"backend"`
    RulesetHash string         `json:"ruleset_hash,omitempty"`
    Rules       int            `json:"rules,omitempty"`
    RuleList    []FirewallRule `json:"rule_list,omitempty"` // NEW; order = on-host order
}
```

## Collector — `internal/collector/collect_firewall.go`

Keep `canonicalizeIptables`/`canonicalizeNftables` unchanged (hash stability
across the v0.4→v0.5 boundary — a stable ruleset must keep the same
`ruleset_hash`). Add parsers that populate `RuleList`:

- `parseIptablesRules(raw, family string) []FirewallRule` — `*table` sets the
  current table; `-A CHAIN …` lines become rules in `(family+" "+table, CHAIN)`
  with counters stripped. v4 and v6 parsed separately (`ip4`/`ip6`) so a
  `-A INPUT` in each stays distinct.
- `parseNftablesRules(raw string) []FirewallRule` — brace-depth tracking:
  `table <family> <name> {` and `chain <name> {` set context; statement lines
  at depth ≥ 2 (excluding the `type … policy …;` line) become rules.

Order is preserved as on-host (no sorting) — order *is* the signal.

## Diff — `internal/diff/diff.go`

Extend `diffFirewall`: when both snapshots carry a `RuleList`, suppress the
opaque `ruleset_hash` field-line and call `diffFirewallRules(old, new, r)`,
which groups by `(table, chain)` and per chain emits:

- `added` — `<table>/<chain>: <rule>` present in new, not old.
- `removed` — present in old, not new.
- `reordered` — the rules common to both changed relative order within the
  chain (`<table>/<chain>.reordered`, one per chain).

`ruleset_changed` (R32) and `flushed` (R33) still fire from the hash/count
path, unchanged. Chains iterate in sorted order for deterministic output.

## Redaction — `internal/redact/`

Add `tagFW = "fw"`. In `applyNetwork`, hash every `snap.Firewall.RuleList[i].Rule`
with `tagFW`. Table/chain untouched. `--redact-hostnames` alone does not touch
firewall (its Cat B is IPs = network).

## Tests

- `collect_firewall_test.go` — parse iptables (multi-table, v4/v6 family
  tags) and nft (multi-chain) into ordered `RuleList`; existing hash/count
  tests unchanged.
- `diff_firewall_test.go` — added/removed rules; per-chain reorder detection;
  modified = remove+add; hash-only mode still behaves as Phase N; existing
  tests unchanged.
- `redact_test.go` — rule text hashed under Network, table/chain preserved,
  identical-within-bundle determinism, no-leak (verbatim IP absent).

## Docs

- `CHANGELOG.md` — new `## [0.5.0] — Unreleased` section.
- `README.md` — note firewall now stores rules (redactable).
- `docs/DESIGN.md` §4.5 — flip the firewall row from "no Cat B — exempt" to
  Cat B (rule IPs) redacted by `--redact-network`; §4.6 if needed.
- `ROADMAP.md` — mark per-rule firewall diff delivered.

## Definition of done

`go vet ./...`, `go test ./...` green; `gofmt -w .` clean. PR off
`feat/v05-phase-o-firewall-rules` into `main`. VERSION stays `0.4.0` (latest
released tag — do not pre-bump). Opens the v0.5 line.
