# statedrift Security Model

## Threat model

Statedrift's goal is to make tampering with infrastructure snapshots **detectable**, not impossible. It assumes the host may be compromised and focuses on making retroactive edits to snapshot history provably visible.

### What statedrift protects against

| Attack | Detection method |
|--------|-----------------|
| Modifying any snapshot except the last | SHA-256 hash mismatch breaks the next `prev_hash` link — `verify` catches it |
| Modifying the last snapshot (without forging `head`) | `verify` cross-checks last snapshot hash against the `head` file |
| Deleting a snapshot from the middle of the chain | Missing link — `verify` catches it |
| Deleting snapshots from the tail | Undetectable locally — mitigated by off-host export before deletion |
| Inserting a fake snapshot between two real ones | `prev_hash` mismatch — `verify` catches it |
| Replaying an old snapshot as a newer one | Timestamp and hash chain position are both checked |
| Modifying an export bundle after creation | `verify.sh` recomputes all hashes from the bundle |

### What statedrift does NOT protect against

| Limitation | Notes |
|------------|-------|
| Root-level compromise before snapshotting | An attacker with root can collect false data at snapshot time |
| Replacing the statedrift binary itself | Use package manager verification or signed binaries |
| Chain rewrite by a sufficiently motivated attacker with root | They can recompute a consistent fake chain from scratch |
| Real-time integrity | Statedrift records state at snapshot intervals, not continuously |
| Modifying the last snapshot **and** the `head` file | See below |

### Atomic writes

Snapshot files and the `head` pointer are written atomically: data is first written to a temporary file in the same directory, then renamed into place. On Linux, `rename(2)` within the same filesystem is atomic — a crash mid-write leaves either the previous file or the new file, never a partial write at the destination path. This prevents a daemon killed during a snapshot from producing a corrupt chain entry.

### The tail-anchor limitation

Hash chains only protect the **interior**. The last snapshot has no successor to detect changes through a broken `prev_hash` link.

Statedrift partially mitigates this by cross-checking the last snapshot's computed hash against the `head` file (written atomically on every `snap`). Modifying the last snapshot without also forging `head` is caught by `statedrift verify`.

However, an attacker who controls both the snapshot file and the `head` file can evade this check. The same applies to deleting snapshots from the tail — the chain heals itself because the new last snapshot has no successor.

**The only reliable fix is external anchoring**: getting the head hash out of the attacker's reach before an incident occurs.

### Manual tail deletion

Deleting snapshot files from the **tail** (newest end) of the chain by hand is a specific case of this problem. The `head` file is not updated by `rm`, so it remains pointing at the deleted snapshot. The next `snap` or `daemon` run reads the stale `head` and chains from it — producing a new snapshot whose `prev_hash` references a file that no longer exists. `verify` detects the break at the first new snapshot.

**Do not use `rm` to remove recent snapshots.** There is currently no `statedrift` command for tail-trimming. The safe recovery path is:

```bash
sudo ./bin/statedrift init --force   # wipes chain and head, takes a fresh genesis snapshot
```

If retaining the older (pre-deletion) snapshots matters, export them first:

```bash
statedrift export --from <start> --to <yesterday> -o archive.tar.gz
sudo ./bin/statedrift init --force
```

Options, in increasing strength:
1. **Regular exports to write-once storage** — ship bundles to S3 with Object Lock, a WORM drive, or any append-only destination. An attacker cannot retroactively modify what has already been shipped.
2. **Periodic head hash logging** — POST the current head hash to a remote server or append it to a remote log after each snapshot. Even a simple cron job `statedrift log --json | tail -1 >> remote:/audit.log` works.
3. **Public transparency log** — future versions will support posting head hashes to a public timestamping service, providing cryptographic proof of existence at a point in time that no single party can revoke.

Statedrift is most useful when combined with:
- **Append-only filesystem flags**: `chattr +a /var/lib/statedrift/chain/` prevents deletion even by root (until the flag is removed, which is itself detectable)
- **Off-host export**: shipping bundles to external write-once storage (S3 with object lock, WORM drives) promptly after each snapshot window
- **External timestamping**: posting head hashes to a remote log after every snapshot

## Hash chain design

Every snapshot contains:

```json
{
  "snapshot_id": "snap-20260322-140000-a3f8c1",
  "timestamp": "2026-03-22T14:00:00Z",
  "prev_hash": "<SHA-256 of previous snapshot's canonical JSON>",
  ...
}
```

The chain works as follows:

1. The genesis snapshot has `prev_hash` equal to 64 hex zeros (GenesisHash)
2. Each subsequent snapshot contains the SHA-256 hash of its predecessor's canonical JSON
3. Canonical JSON sorts all object keys alphabetically at every nesting level, ensuring deterministic serialization
4. `statedrift verify` recomputes every hash and checks every `prev_hash` link

For a non-technical reader: think of it as a paper ledger where each page's header includes a checksum of the previous page. If anyone rewrites page 5, page 6's header no longer matches, and every page after that is flagged as suspicious.

## Canonical JSON

The hash is computed over a canonical JSON representation:

- All object keys sorted alphabetically (recursively)
- No extra whitespace
- UTF-8 encoding
- Consistent number formatting

This ensures that two equivalent data structures always hash to the same value, regardless of insertion order or serialization library.

## Export bundle security

The export bundle (`.tar.gz`) contains:

- All snapshot JSON files (unchanged from the store)
- `manifest.json` — metadata including expected hash of each snapshot and `chain_verified: true`
- `verify.sh` — standalone verification script using only `sha256sum` and `jq`

The bundle is verified before creation (chain check) and after creation (extract to temp dir, re-verify). An auditor receiving a bundle can run `./verify.sh` without any statedrift tooling.

### verify.sh security properties

- Uses only POSIX tools: `sha256sum`, `jq`, `find`, `sort`
- Reads hashes from `manifest.json` and recomputes them independently
- Checks each snapshot's `prev_hash` against the previous file's computed hash
- Returns exit code 0 (verified) or 1 (violation)

## Responsible disclosure

If you discover a security vulnerability in statedrift, please report it at:

**https://github.com/statedrift/statedrift/issues**

Use the label `security`. For sensitive reports, email the maintainers directly (see the GitHub profile).

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

We aim to acknowledge reports within 48 hours and provide a fix within 14 days for critical issues.

## Strengthening your deployment

### Append-only chain directory

```bash
# Prevent deletion/modification of snapshot files even by root
sudo chattr +a -R /var/lib/statedrift/chain/

# Verify the attribute is set
lsattr -d /var/lib/statedrift/chain/
```

Note: `chattr +a` can be removed by root. For stronger guarantees, use a hardware security module or remote write-once storage.

### Regular off-host exports

```bash
# Daily export to a write-once S3 bucket
statedrift export --from $(date -d yesterday +%Y-%m-%d) --to $(date -d yesterday +%Y-%m-%d) \
  -o /tmp/daily-export.tar.gz
aws s3 cp /tmp/daily-export.tar.gz s3://my-worm-bucket/statedrift/
```

### Systemd service hardening

The generated service file (`statedrift daemon --install`) uses sensible defaults. For additional hardening, consider adding to the `[Service]` section:

```ini
ProtectSystem=strict
ReadWritePaths=/var/lib/statedrift
PrivateTmp=true
NoNewPrivileges=true
```
