# v0.5 — Customizable policy rules (richer value matcher)

Status: in progress. Branch `feat/v05-policy-rules`. Final v0.5 theme.

## What and why

Custom rules already work for free: `rules.Load()` merges a user `rules.json`
into `DefaultRules()` (override by ID, append new). But the matcher is thin —
it can only test `Section` (prefix), `ChangeType`, and `KeyPattern`
(`filepath.Match` glob on the change key). It **cannot inspect the change's
value**, so a user cannot express policies like "fire when `ip_forward`
becomes `1`" or "fire when a numeric threshold is exceeded".

This phase adds a **value-condition matcher** so users can author precise
policy rules. Decision (locked with user 2026-06-26): **fully free, no Pro
gating, no `LICENSE_SECRET` rotation.** Removes the Pro cliff entirely.

## Design (locked)

1. **Additive, backward-compatible.** New optional `match` field on `Rule`. A
   rule with no `match` behaves exactly as today. Existing rules.json files and
   all built-in rules are unaffected. No snapshot-schema change (rules are not
   part of the snapshot schema).
2. **Conditions are ANDed.** `match` is a list of `Condition`; all must pass,
   in addition to the existing Section/ChangeType/KeyPattern gates. Empty list
   = no value constraint.
3. **Conditions can only narrow.** They run *after* the existing matchers and
   never broaden a match. Counter changes are still excluded up front.
4. **No DSL, no expression parser.** Flat `{field, op, value}` triples — stays
   within the C-style-simplicity convention. stdlib only (`regexp`, `strconv`,
   `strings`).

### Condition shape

```go
type Condition struct {
    Field string `json:"field"` // "new" (default), "old", "key"
    Op    string `json:"op"`    // see operators
    Value string `json:"value"` // comparand; ignored by "changed"
}
```

`Field` selects the string under test:
- `new` (default / empty) → `Change.NewValue`
- `old` → `Change.OldValue`
- `key` → `Change.Key`

Operators (`Op`):
- `eq`, `ne` — exact string (in)equality
- `contains`, `prefix`, `suffix` — substring tests
- `regex` — `regexp.MatchString(value, field)`; bad pattern → no match
- `gt`, `lt`, `gte`, `lte` — numeric (`strconv.ParseFloat`); non-numeric → no match
- `changed` — `OldValue != NewValue` (value ignored; for "any modification")

Unknown `Op` → no match (fail-closed, so a typo can't silently fire).

### Example user rule

```json
[
  {
    "id": "C01_IP_FORWARD_ENABLED",
    "name": "IP forwarding enabled",
    "description": "net.ipv4.ip_forward flipped to 1 (host turned into a router).",
    "severity": "high",
    "section": "kernel_params",
    "change_type": "modified",
    "key_pattern": "net.ipv4.ip_forward",
    "match": [{"field": "new", "op": "eq", "value": "1"}]
  }
]
```

## Implementation

- `internal/rules/rules.go`
  - Add `Condition` type + `Match []Condition` field on `Rule` (json `match`).
  - In `matchesRule`, after existing gates pass, require every condition in
    `rule.Match` to pass (`matchCondition`).
  - Add `matchCondition(cond, c)` and a `fieldValue(field, c)` helper.
- No changes needed in main.go (Load/Evaluate signatures unchanged) or the
  diff→rules conversion (OldValue/NewValue already carried).

## Tests — `rules_policy_test.go`

- each operator: positive + negative (eq, ne, contains, prefix, suffix, regex,
  gt/lt/gte/lte numeric, changed).
- `field: old` and `field: key` selectors.
- multiple conditions ANDed (all-pass fires, one-fail doesn't).
- bad regex → no match (no panic); non-numeric gt → no match.
- unknown op → no match.
- backward-compat: a rule with empty/no `match` behaves as before.
- round-trip: a `match` rule loaded from a JSON file via `Load` fires.
- counter change still excluded even if conditions would match.

## Docs

- `CHANGELOG.md` `[0.5.0]` — customizable policy rules / value-condition matcher.
- `ROADMAP.md` — mark customizable policy rules delivered (free).
- `README.md` / `docs/DESIGN.md` — document the `match` field + operators if
  rules.json is documented there.
- `CLAUDE.md` (local) — note rules engine now supports value conditions.

## Definition of done

`go vet ./...`, `go test ./...` green; `gofmt -w .` clean. PR off
`feat/v05-policy-rules` into `main`. VERSION stays `0.4.0`. No license/secret
changes.

## Progress

- [x] Condition type + Match field + matcher (rules.go) — 11 operators across
      new/old/key, ANDed, fail-closed on unknown op / bad regex / non-numeric.
- [x] Tests (rules_policy_test.go) — every operator pos+neg, numeric, field
      selectors, AND, narrow-only, counter-excluded, empty-match compat,
      file round-trip via Load.
- [x] Docs — CHANGELOG [0.5.0] entry; DESIGN §7.3 match table + §9 free-tier
      reframe (policy now free, Pro = fleet/reporting); ROADMAP delivered +
      free-tier range. README needs no rule-schema edit (none documented there).
- [x] gofmt + vet + full `go test ./...` green (13/13 packages).
- [ ] Commit + PR
