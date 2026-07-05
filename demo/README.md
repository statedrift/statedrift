# demo/

Tooling that renders the README's "See it work" GIF (`docs/demo.gif`).

- `demo.tape` — [VHS](https://github.com/charmbracelet/vhs) script. Runs the real
  `init → snap → drift → diff → analyze → verify → tamper-catch` story; nothing is
  faked. The staged drift (enable IP forwarding, add a user) is reverted in the
  tape's hidden cleanup block, against a throwaway store in `/tmp`.
- `Dockerfile.demo` — builds `statedrift` from this repo and layers it onto Charm's
  VHS image (vhs + ttyd + ffmpeg + fonts). Build context is the repo root.
- `run-demo.sh` — one command to render, isolated in a throwaway container.

## Render

```bash
./run-demo.sh            # Docker/Podman path (recommended, isolated)
./run-demo.sh --rebuild  # force an image rebuild
./run-demo.sh --native   # run vhs on the host (mutates the host — see the script)
```

The render is written locally to `demo/demo.gif` (git-ignored) and **published to
`docs/demo.gif`**, which is the copy the README embeds. Commit `docs/demo.gif` after
re-rendering, and keep the static transcript in `README.md` in sync with the tape's
real output.
