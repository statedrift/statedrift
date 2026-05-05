# Release Procedure

Step-by-step procedure for cutting a statedrift release. Written for v0.2.0;
the same flow applies to future versions with the version string bumped.

The release is a three-step pipeline:

1. **`make release`** — build & package locally (reversible)
2. **`git tag` + push** — create the immutable label
3. **`gh release create`** — publish artifacts to GitHub (one-way)

Steps 1 and 2 can be undone cheaply. Step 3 is effectively permanent because
`install.sh` resolves `/releases/latest` and starts handing the new version
to anyone running the install one-liner.

---

## Pre-flight checks

Run before step 1. All must be green.

```bash
git status                      # working tree clean
git log -1 --oneline            # confirm HEAD is the commit you want to ship
gh run list --limit 3           # latest CI on main is success
gofmt -l .                      # no output = clean
go vet ./...                    # no output = clean
go test ./...                   # all packages ok
```

Optional but recommended:

```bash
make test-docker-all            # integration tests in real containers
gh auth status                  # confirm logged in with write access
```

Confirm the version in `Makefile:5` (`VERSION := X.Y.Z`) matches the tag you
plan to cut. Mismatch means the binary self-reports a different version than
the GitHub release page shows.

Confirm the CHANGELOG has a `## [X.Y.Z] — YYYY-MM-DD` heading for this
version. The `make release` `awk` extractor on Makefile:78 keys off this
exact format; if the heading is missing or differs, `dist/release-notes-X.Y.Z.md`
will be empty and the GitHub release body will be blank.

---

## Step 1 — `make release`

**What it does** (Makefile:51–83):

1. `clean` — wipes `bin/` and `dist/`.
2. Cross-compiles two static binaries (`CGO_ENABLED=0`):
   - `linux-amd64`
   - `linux-arm64`
3. Bakes three values into each binary via `-ldflags -X`:
   - `Version` from `VERSION` in Makefile
   - `BuildDate` (UTC timestamp)
   - `licenseSecret` from the `LICENSE_SECRET` env var
     (default: `PLACEHOLDER_DEV_BUILD_DO_NOT_SHIP`)
4. Tars each binary with `README.md` + `LICENSE` into:
   - `dist/statedrift-X.Y.Z-linux-amd64.tar.gz`
   - `dist/statedrift-X.Y.Z-linux-arm64.tar.gz`
5. Generates `dist/sha256sums.txt` so users can verify downloads.
6. Extracts the per-version CHANGELOG slice into
   `dist/release-notes-X.Y.Z.md` for use as the GitHub release body.

**Run**:

```bash
make release
ls -lh dist/
```

**Verify before moving on**:

```bash
cd dist && sha256sum -c sha256sums.txt && cd ..   # checksums match tarballs
cat dist/release-notes-X.Y.Z.md                   # release notes are non-empty
```

**Considerations**:

- **`LICENSE_SECRET` is read from the environment at build time.** The
  Makefile defaults to the development placeholder when unset. Changing
  the secret across releases invalidates every license signed against
  the prior key, so rotation is a deliberate, infrequent event. Do not
  pass a non-default `LICENSE_SECRET` on a release build without first
  consulting `project_license_secret_rotation.md` for the rotation
  policy and timing.
- **Linux-only build is intentional** (the agent reads `/proc` and `/sys`).
  No Windows or macOS target.
- **No artifact signing (GPG / cosign).** Trust is the SHA256 file plus
  GitHub's TLS. Revisit if Pro customers ask for signed binaries.
- **Reversible**: `make clean` removes everything this step produced.

---

## Step 2 — `git tag` + push

**Run**:

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

**What this entails**:

- `-a` makes an **annotated tag** (carries author, date, message). GitHub
  treats annotated tags as first-class release objects.
- The tag points at whatever commit `HEAD` currently is. Re-confirm with
  `git log -1 --oneline` immediately before tagging.
- `git push origin main` does **not** push tags. Tags need their own push.

**Considerations**:

- **Tag string must equal the binary's baked-in `VERSION`.** A v0.2.1 tag on
  a binary that self-reports 0.2.0 confuses every user who runs
  `statedrift --version`.
- **Tags are effectively immutable in public.** Deleting and re-pushing is
  technically possible but breaks anyone who already cloned, cached, or
  starred the release. If a problem surfaces after step 3, cut a new patch
  version rather than retagging.
- If you spot a problem **between step 2 and step 3**, deletion is still
  cheap: `git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z`.

---

## Step 3 — `gh release create`

**Run**:

```bash
gh release create vX.Y.Z \
  dist/statedrift-X.Y.Z-linux-amd64.tar.gz \
  dist/statedrift-X.Y.Z-linux-arm64.tar.gz \
  dist/sha256sums.txt \
  --title "vX.Y.Z" \
  --notes-file dist/release-notes-X.Y.Z.md \
  --verify-tag
```

**What it does**:

- Uploads the three artifacts as release assets attached to the tag.
- Uses the per-version CHANGELOG slice as the release body (avoids dumping
  the entire CHANGELOG into the release page).
- Marks the release as "Latest" by default — this is what `install.sh`'s
  `/releases/latest` URL resolves to, so it goes live to the install
  one-liner immediately.
- `--verify-tag` refuses to publish if the tag isn't on the remote yet.
  Guardrail; not an error to work around.

**Optional flags**:

- `--draft` — creates the release as a draft so you can preview the page
  in the UI and click "Publish" manually. URL doesn't change between draft
  and final. Recommended for the very first release.
- `--prerelease` — for betas. Don't use for stable tags.
- `--discussion-category "Announcements"` — opens a tied discussion thread.

**Considerations**:

- **No rollback.** Deleting a release leaves mirrors, package managers, and
  anyone who downloaded between publish and delete with the artifacts.
  Treat publish as one-way.
- **Install one-liner goes live the moment this command succeeds.** Anyone
  running `curl … | sh` after this point gets the new version.

---

## Post-release

Not blocking, but do soon after each release:

- **Announce** wherever appropriate (Discussions tab, social, mailing list).

**Do NOT pre-bump `Makefile:5` `VERSION` after publish.** Convention
(see `project_github_release.md`): VERSION on `main` always equals the
**latest released** version, not the in-progress one. The bump happens
in the release commit itself, not as a separate post-release commit.
This avoids dev builds self-reporting as a not-yet-released version,
which would confuse bug reports and source-built users. If at some
future point the dev-build mismatch becomes annoying, use a `-dev`
suffix (e.g. `0.3.0-dev`) — never a bare next-version string.

One-time setups already complete (kept for reference):

- ✅ **Branch protection on `main`** applied 2026-05-04 after v0.3.0
  via `gh api PUT /repos/statedrift/statedrift/branches/main/protection`.
  Loose-solo-dev config: PR required (0 reviewers), required status
  checks `test` + `docker-build`, no force-push, no deletion, admin
  override retained. Future releases will need to land via PR rather
  than direct push to `main`.

---

## Release history

| Version | Tag commit | Shipped (UTC) | Notes |
|---|---|---|---|
| v0.2.0 | `af34f27` | 2026-04-29T00:34:26Z | First public release. Used `--draft` as a safety net: previewed in the UI, then promoted with `gh release edit v0.2.0 --draft=false`. |
| v0.3.0 | `d2a5a78` | 2026-05-04T22:34:56Z | Five always-on security-signal collectors (Phases A–E) and 12 new anomaly rules (R14–R25). Skipped `--draft`; pushed main, waited for CI green on the new commits, then tagged + published. |

`LICENSE_SECRET` rotation status is tracked in
`project_license_secret_rotation.md`. See `CHANGELOG.md` for per-release
feature lists.
