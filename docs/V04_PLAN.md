# v0.4 Plan — Export-Time Redaction Flags

Status: Phase F (process forensics, R26–R28) landed 2026-05-05 on PR #5
(`feat/v04-phase-f-process`). This document plans the next v0.4 deliverable:
**`statedrift export --redact-network --redact-hostnames`**, the export-time
redaction flags promised in the v0.3 plan (V03_PLAN.md:608–617) and in
`docs/DESIGN.md` §4.5.

The remaining v0.4 themes — `statedrift baseline`, SELinux / AppArmor
enforcement state, firewall rule hashing — are tracked in `ROADMAP.md` and get
their own plan docs when their phase opens.

## Goal

Let an operator produce an audit bundle suitable for shipping to an external
auditor / support ticket / public bug report **without** leaking the Category
B operational identifiers (IPs, MACs, hostnames, usernames, mount sources,
sudoers lines) catalogued in DESIGN.md §4.5.

The bundle must remain a self-verifying tamper-evident artifact: an auditor
running `verify.sh` (or `verify.ps1`) on a redacted bundle must still get
INTEGRITY VERIFIED.

Non-goals: redacting the **local** chain (the chain is the load-bearing
internal forensics record — it stays verbatim), redacting Category A secrets
(those never enter the chain in the first place), or supporting a
"reversible" redaction with a key-escrow mechanism.

## Design — deterministic re-chaining

The naive approach — strip Cat B fields and hand back the resulting tarball —
breaks the chain: every redacted snapshot has a new hash, and the
`prev_hash` pointers no longer match. An auditor running `verify.sh` would
get a chain-broken error and have no way to distinguish "redacted by design"
from "tampered with."

The plan: **the redacted bundle is a new, internally-consistent chain
deterministically derived from the original.** Specifically:

1. Each Cat B field is replaced by a **bundle-scoped HMAC-SHA256 hash** of
   its original value, truncated to 12 hex chars and prefixed by a type tag
   (e.g. `ip:a3f1d2b9e0c4`, `host:7e8b2c5a91f0`, `user:1e0f9b3c4a2d`). The
   HMAC key is a 32-byte random salt generated per-bundle and stored in
   `manifest.json` alongside the redaction mode. **Same value within the
   bundle → same hash** (so `route → gateway` still parses, `users[].name`
   still cross-references `groups[].members`, etc.). **Same value across
   bundles → different hashes** (so an external observer can't accumulate a
   fingerprint across multiple bundles).

2. Each snapshot is re-serialized with the redacted values, re-hashed via
   the existing `hasher` package, and its `prev_hash` is updated to point at
   the previous redacted snapshot's new hash.

3. `manifest.json` gains a `redaction` section: the flags applied, the
   per-bundle salt (so an internal party with the original chain can
   reproduce the exact redacted output and confirm the operator did not
   substitute different snapshots under the cover of "redaction"), and the
   redacted `chain_root_hash` / `chain_head_hash`.

4. `verify.sh` and `verify.ps1` continue to verify the chain as written —
   no script changes needed, because the redacted bundle is itself a
   well-formed chain. The script's existing manifest cross-check continues
   to work against the redacted root/head.

The trust property is: **deterministic redaction**. Anyone with the
unredacted local chain plus the bundle's salt can reproduce the redacted
bundle byte-for-byte. An operator who tries to substitute a *different*
snapshot under the cover of redaction would have to break HMAC-SHA256 to
make the result match.

## Scope — two flags, one transform pipeline

| Flag | Targets (per DESIGN.md §4.5 inventory) |
|------|----------------------------------------|
| `--redact-network` | `network.interfaces.mac`, `network.interfaces.addresses`, `network.routes.gateway/destination`, `network.dns.nameservers/search_domains`, `listening_ports.address`, `connections.local_addr/remote_addr` |
| `--redact-hostnames` | `host.hostname`, `host.machine_id`, `host.boot_id`, `users[].name/home/gecos`, `groups[].name/members`, `ssh_keys[].user/comment`, `cron_jobs[].user`, `mounts[].source` (network sources only — `//server/share`, `nfs.example.com:/export`), `sudoers[].line` (whole-line hashed; see Phase H), `systemd_timers[].description/unit` (free-text) |

Both flags can be passed together. Either flag triggers the rechain path;
neither flag preserves today's behavior exactly.

`network.dns.search_domains` is a domain name, not an IP — bucket under
`--redact-hostnames`. `listening_ports.process` is a binary name (`sshd`,
`nginx`) which is operationally identifying but not personally so; leave it
alone in v0.4 and revisit if customers ask. `processes[].comm` likewise stays.

## Decisions to resolve before coding

1. **Salt persistence.** A per-bundle random salt means the same physical
   host produces different redacted hashes in two different bundles. That's
   the desired privacy property (no cross-bundle fingerprint), but it
   prevents an auditor receiving two bundles from cross-checking "is this
   the same host?" Acceptable trade-off for v0.4 — document in
   DESIGN.md §4.5 that cross-bundle correlation is intentionally not
   supported. If a customer needs it, ship a `--redaction-salt FILE` flag
   later that lets a fleet operator pin one salt across many bundles.

2. **Sudoers line — hash whole or token-by-token?** Token-by-token
   redaction (replacing only the username/host fields) requires a real
   sudoers parser to identify which tokens are identities. We don't have
   one and writing one to spec is out of scope. **Decision: hash the
   entire normalized line as one opaque value.** External auditors lose
   per-rule readability; internal incident responders still have the
   unredacted local chain. Documented limitation. The
   `Sudoers[].LineRedactionTODO` comment in V03_PLAN.md:564–570 is
   resolved by this decision.

3. **`mounts[].source` — when to hash?** `tmpfs`, `proc`, `sysfs`,
   `/dev/sda1` etc. are not Cat B. `//server/share`, `nfs:/export`,
   `s3://bucket/...`, `192.168.1.1:/export` are. **Decision: pattern-detect
   network sources** (contains `:` followed by `/`, or starts with `//`)
   and only hash those. Local-block-device and pseudofs sources stay
   verbatim. Pattern lives next to the network-redactor and is unit-tested.

4. **What about `processes[].pid`?** PIDs are ephemeral, not personally
   identifying, but they *are* fingerprinting (process startup order
   leaks deployment behavior). **Decision: leave PIDs alone in v0.4.**
   Promote to a `--redact-pids` flag later if anyone asks. Mention in the
   redaction policy doc as an acknowledged gap.

5. **Schema version bump?** The redacted snapshot is structurally
   identical to a v0.4 unredacted snapshot — same fields, just hashed
   values where strings used to be. **Decision: do not bump
   `schema_version`.** A redacted bundle's `schema_version` stays
   `"0.4"`; the `manifest.json` `redaction` section is the signal an
   auditor uses to know they're holding a redacted bundle.

## Phases

Each phase ships a complete unit: helpers + tests + integration, no
half-merged state. Mirrors v0.3's per-phase discipline.

### Phase G — redaction primitives + snapshot-level transform

- New package `internal/redact/` (separate from `internal/collector/redact.go`,
  which is the collect-time Cat A pattern redactor — different concern, do
  not merge).
- `redact.NewRedactor(opts Options) *Redactor` — holds the per-bundle salt
  and the option flags.
- `redact.Apply(snap *collector.Snapshot, r *Redactor)` — walks the
  snapshot in-place, replacing Cat B fields per the table above. Pure
  function; deterministic given the same `(snap, salt, opts)` triple.
- HMAC-SHA256 helper with type-tag prefix + 12-hex-char truncation.
- Tests:
  - Same input + same salt → same output (determinism).
  - Same value → same hash within a snapshot (cross-reference preservation:
    `users[].name` matches `groups[].members` after redaction).
  - Different salt → different hashes (per-bundle uniqueness).
  - Cat A redactor still applies (pattern redactor's output is not
    re-hashed at export time; `<redacted>` placeholders stay literal).
  - Each Cat B field listed in DESIGN.md §4.5 gets covered by at least one
    table-driven test case.
- No CLI changes in this phase. `make test` and `go vet ./...` green.

### Phase H — bundle integration + manifest changes + CLI flags

- `export.Bundle` gains a `RedactionOptions` parameter; existing call sites
  pass the zero value to preserve current behavior.
- When redaction is active, the bundle path:
  1. Generates a 32-byte random salt via `crypto/rand`.
  2. For each selected snapshot: clone, apply `redact.Apply`, re-marshal,
     re-hash, link to previous redacted snapshot's hash.
  3. Writes redacted snapshots into `chain/` with the same filenames as
     today (timestamp-based — collision-free because timestamps are
     preserved).
  4. Builds a `manifest.json` with the new `redaction` block:
     ```json
     "redaction": {
       "mode": ["network", "hostnames"],
       "salt": "<64 hex chars>",
       "tool_version": "0.4.0"
     }
     ```
     and the redacted root/head hashes.
  5. Self-verifies the redacted bundle exactly as today; the chain is
     internally consistent so this passes without changes to
     `VerifyBundle`.
- CLI:
  - `cmdExport` parses `--redact-network` and `--redact-hostnames`.
  - When either is set, the post-export hint changes to mention "redacted
    bundle" so an operator doesn't accidentally ship the wrong file.
  - The standard `Verifying chain before export...` step continues to run
    against the **unredacted local chain** (we want to know the local
    chain is healthy before we derive a redacted view from it).
- `verify.sh` and `verify.ps1`: **no changes required**. The redacted
  bundle's manifest cross-check works because the manifest's
  `chain_root_hash` / `chain_head_hash` describe the redacted chain that
  was actually written.
- Tests:
  - End-to-end: build a chain with known IPs / hostnames / users, export
    with both flags, untar, grep for the original values → 0 matches.
  - End-to-end: same chain exported twice with the same salt produces
    byte-identical bundles (modulo `manifest.created_at`).
  - End-to-end: verify.sh against a redacted bundle reports INTEGRITY
    VERIFIED.
  - Negative: verify.sh against a redacted bundle whose `manifest.salt`
    has been edited still detects the chain-root mismatch.
  - Cross-flag: passing only `--redact-network` leaves `users[].name`
    untouched and vice versa.

### Phase I — documentation + CHANGELOG + DESIGN.md update

- Update DESIGN.md §4.5 inventory: the trailing paragraph that says "v0.4
  will ship..." moves to "v0.4 ships..." and the table grows a "Redacted
  by" column listing which flag covers each field.
- Add a "Redaction modes" subsection documenting:
  - The trust model (deterministic redaction; salt is the integrity
    anchor).
  - Cross-bundle correlation is intentionally not supported.
  - PIDs, `processes[].comm`, `listening_ports.process` are deliberate
    non-coverage.
- Add CHANGELOG entries under `[0.4.0] — Unreleased`.
- README: one-line example under the export section.

## Known limitations (to record in DESIGN.md when Phase H lands)

- **Cross-bundle correlation deliberately broken.** Two bundles from the
  same host produce different redacted hashes. Acceptable per Decision #1.
- **Sudoers `Line` redaction is whole-line, not token-level.** External
  auditors see opaque hashes for every sudoers entry; internal responders
  retain the verbatim chain. Per Decision #2.
- **PIDs not redacted.** Process startup-order fingerprinting remains
  possible. Per Decision #4.
- **Pattern-based "is this a network mount source" heuristic.** Exotic
  schemes (e.g. `ipfs://...`, custom FUSE drivers with hostname-bearing
  source strings) may slip through and stay verbatim. The pattern lives
  in `internal/redact/` so adding cases is one PR.
- **`schema_version` does not signal redaction.** A consumer must inspect
  `manifest.redaction.mode` to know what's redacted. Per Decision #5.

## Manual tests (run before declaring redaction work complete)

Mirror the V03_PLAN.md per-phase manual-test discipline. Status legend:
✅ verified · ☐ recommended, not yet run.

### Smoke

1. ☐ **Genesis + redacted export round-trips.** Capture a few snapshots on
   the RHEL test host with realistic content (the same fixture used for
   v0.3's full sweep), export with both flags, untar, eyeball that
   `manifest.redaction` is present and that `chain/*.json` contains hashes
   in place of the live host's IP and hostname.
2. ☐ **Hash chain verifies.** `./verify.sh` inside the redacted bundle
   reports INTEGRITY VERIFIED.
3. ☐ **`verify.ps1` parity.** Same bundle on a Windows host (or via the
   CI `pwsh` 7.5+ install) reports the same.

### Negative

4. ☐ **No literal hostname / IP in tarball.** `tar xzOf bundle.tar.gz |
   grep -E "<live-hostname>|<live-ip>"` returns 0 matches.
5. ☐ **Salt-tamper detected.** Edit `manifest.json` to flip a hex char in
   `redaction.salt`, re-tar, run verify → manifest-mismatch error.

### Edge cases

6. ☐ **Cross-reference preservation.** Pick a username that appears in
   `users[].name`, `groups[].members`, and `ssh_keys[].user`. After
   redaction, all three fields show the same `user:...` hash.
7. ☐ **Local mount sources untouched.** A `/dev/sda1` mount source stays
   verbatim; a `//server/share` source becomes a `host:...` hash.
8. ☐ **Both flags individually.** `--redact-network` alone leaves
   `users[].name` alone; `--redact-hostnames` alone leaves
   `network.interfaces.addresses` alone.

### Cross-version

9. ☐ **Pre-v0.4 snapshot in chain.** A chain that includes v0.3 snapshots
   (no `Process.Threads` field, no `schema_version: "0.4"`) still exports
   cleanly under redaction. The redactor must be tolerant of missing
   fields.

## Recommended sequencing

1. **Phase G first (primitives + transform).** Pure-function, fully
   table-tested, no integration risk. Locks in the determinism contract
   that Phase H depends on.
2. **Phase H next (bundle integration).** Adds the manifest field, CLI
   flags, and end-to-end tests. The verify scripts are unchanged; this is
   the highest-risk phase because the rechain code touches the export
   hot path.
3. **Phase I (docs).** Land in the same PR as H; the redaction story is
   incomplete without the DESIGN.md update.
4. **Cut a v0.4 milestone release** once Phase F (already merged on PR #5
   pending merge) and Phases G–I land. Keep `statedrift baseline` and
   SELinux/firewall work on a separate branch sequence — those are
   independent of redaction and can ship in v0.4.x or v0.5 as scope dictates.

## Out of scope

- Reversible redaction with key escrow.
- Local-chain redaction (the local chain is forensic ground truth; never
  mutate).
- A `--redaction-salt FILE` flag for cross-bundle correlation (Decision #1
  follow-up if a customer asks).
- Token-level sudoers redaction (Decision #2 follow-up; needs a real
  sudoers parser).
- A `--redact-pids` flag (Decision #4 follow-up).
- Redacting `listening_ports.process` / `processes[].comm` binary names.
- Schema-version bump to signal redaction (Decision #5).

## Cross-references

- DESIGN.md §4.5 — identifier inventory; will gain a "Redacted by" column
  in Phase I.
- V03_PLAN.md:564–570 — the sudoers `Line` redaction TODO that this plan
  resolves via Decision #2.
- V03_PLAN.md:608–617 — the v0.3 out-of-scope list that committed to
  these flags for v0.4.
- ROADMAP.md — the broader v0.4 "security completeness" theme; redaction
  flags are one piece, baseline / SELinux / firewall are the others.
- `feedback_pii_redaction.md` (auto-memory) — the original Cat A vs Cat B
  policy the plan implements.
