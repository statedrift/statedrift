#!/usr/bin/env bash
#
# run-demo.sh — render demo.tape to demo.gif.
#
# The tape (see demo.tape) runs the statedrift init → drift → diff → verify →
# tamper-catch story for real. Two of its steps are privileged and mutate
# machine state (`sysctl -w net.ipv4.ip_forward=1` and `useradd backdoor`),
# so the DEFAULT and recommended path renders inside a throwaway container
# where those mutations are isolated from your host and cleaned up with it.
#
#   ./run-demo.sh                # Docker/Podman path (recommended, isolated)
#   ./run-demo.sh --native       # run vhs on the host (mutates the host!)
#   ./run-demo.sh --rebuild      # force a rebuild of the demo image
#
# Missing software is detected and you are prompted before anything is
# installed. Nothing is installed without your say-so.
#
# Env overrides:
#   TAPE=demo.tape               tape file to render (relative to this script)
#   IMAGE=statedrift-demo:latest image tag to build/run
#   STATEDRIFT_SRC=..            path to the statedrift source repo (repo root)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAPE="${TAPE:-demo.tape}"
IMAGE="${IMAGE:-statedrift-demo:latest}"
STATEDRIFT_SRC="${STATEDRIFT_SRC:-$SCRIPT_DIR/..}"
MODE="auto"
REBUILD=0

# ── pretty output ─────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; C=$'\033[36m'; N=$'\033[0m'
else
  B=; G=; Y=; R=; C=; N=
fi
info()  { printf '%s==>%s %s\n' "$C" "$N" "$*"; }
ok()    { printf '%s ok%s  %s\n' "$G" "$N" "$*"; }
warn()  { printf '%swarn%s %s\n' "$Y" "$N" "$*" >&2; }
die()   { printf '%serror%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

# confirm "question" -> returns 0 on yes. Auto-no if not a TTY.
confirm() {
  local q="$1" a
  if [ ! -t 0 ]; then
    warn "not an interactive terminal; skipping: $q"
    return 1
  fi
  read -rp "$(printf '%s?%s %s [y/N] ' "$B" "$N" "$q")" a || return 1
  [[ "$a" =~ ^[Yy]$ || "$a" =~ ^[Yy][Ee][Ss]$ ]]
}

usage() {
  sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^#\s\?//'
  exit "${1:-0}"
}

# ── arg parsing ───────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --docker|--container) MODE="docker" ;;
    --native)             MODE="native" ;;
    --rebuild)            REBUILD=1 ;;
    -h|--help)            usage 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done

TAPE_PATH="$SCRIPT_DIR/$TAPE"
[ -f "$TAPE_PATH" ] || die "tape not found: $TAPE_PATH"

# Where does this tape write its output? (Output <file> line in the tape.)
OUT_FILE="$(awk '/^[[:space:]]*Output[[:space:]]/ {print $2; exit}' "$TAPE_PATH")"
OUT_FILE="${OUT_FILE:-demo.gif}"

# ── package-manager helpers ───────────────────────────────────────────────────
PKG=""
for p in dnf apt-get brew pacman zypper; do
  if command -v "$p" >/dev/null 2>&1; then PKG="$p"; break; fi
done

SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi

pkg_install() { # pkg_install <pkgname...>
  case "$PKG" in
    dnf|yum)  $SUDO "$PKG" install -y "$@" ;;
    apt-get)  $SUDO apt-get update && $SUDO apt-get install -y "$@" ;;
    brew)     brew install "$@" ;;
    pacman)   $SUDO pacman -S --noconfirm "$@" ;;
    zypper)   $SUDO zypper install -y "$@" ;;
    *) return 1 ;;
  esac
}

# ── container engine detection ────────────────────────────────────────────────
detect_engine() {
  if command -v docker >/dev/null 2>&1; then echo docker
  elif command -v podman >/dev/null 2>&1; then echo podman
  else echo ""; fi
}

# ══════════════════════════════════════════════════════════════════════════════
# Docker / Podman path
# ══════════════════════════════════════════════════════════════════════════════
run_docker() {
  local engine; engine="$(detect_engine)"
  if [ -z "$engine" ]; then
    warn "no container engine (docker/podman) found."
    if [ -n "$PKG" ] && confirm "install podman with $PKG now?"; then
      pkg_install podman || die "podman install failed"
      engine="$(detect_engine)"
    fi
    [ -n "$engine" ] || die "need docker or podman for the container path (or use --native)."
  fi
  info "container engine: $B$engine$N"

  if ! "$engine" info >/dev/null 2>&1; then
    die "$engine is installed but not usable (daemon down / no permission)."
  fi

  [ -f "$STATEDRIFT_SRC/go.mod" ] || die \
"statedrift source not found at: $STATEDRIFT_SRC
 The image builds the statedrift binary from that repo. Point STATEDRIFT_SRC at
 the veridyn checkout, e.g.:  STATEDRIFT_SRC=/path/to/veridyn ./run-demo.sh"

  # Build the image unless it already exists (or --rebuild given).
  if [ "$REBUILD" -eq 1 ] || ! "$engine" image inspect "$IMAGE" >/dev/null 2>&1; then
    info "building image $B$IMAGE$N (statedrift + VHS)…"
    "$engine" build -f "$SCRIPT_DIR/Dockerfile.demo" -t "$IMAGE" "$STATEDRIFT_SRC" \
      || die "image build failed"
    ok "image built"
  else
    info "reusing existing image $B$IMAGE$N (use --rebuild to force)"
  fi

  # --privileged gives the container its own writable network namespace so the
  # tape's `sysctl -w net.ipv4.ip_forward=…` works. It stays inside the
  # container: the host's sysctls and user database are never touched.
  info "rendering $B$TAPE$N → $B$OUT_FILE$N (this takes a few minutes)…"
  # :z relabels the bind mount for SELinux-enforcing hosts; it's a no-op where
  # SELinux is off or the container is unconfined (e.g. rootless podman here).
  "$engine" run --rm --privileged -v "$SCRIPT_DIR:/vhs:z" "$IMAGE" "$TAPE" \
    || die "render failed"

  # Under rootful Docker the container runs as real root, so the output lands
  # root-owned; reclaim it so it doesn't fight git/re-renders. Rootless podman
  # already maps it to the invoking user, so -O is true and this is skipped.
  local out="$SCRIPT_DIR/$OUT_FILE"
  if [ -f "$out" ] && [ ! -O "$out" ]; then
    $SUDO chown "$(id -u):$(id -g)" "$out" 2>/dev/null || true
  fi

  finish
}

# ══════════════════════════════════════════════════════════════════════════════
# Native path (runs vhs on the host — mutates the host!)
# ══════════════════════════════════════════════════════════════════════════════
ensure_statedrift() {
  command -v statedrift >/dev/null 2>&1 && { ok "statedrift present"; return; }
  warn "statedrift not on PATH."
  [ -f "$STATEDRIFT_SRC/go.mod" ] || die "statedrift source not found at $STATEDRIFT_SRC"
  if ! command -v go >/dev/null 2>&1; then
    confirm "install the Go toolchain (needed to build statedrift) with $PKG?" \
      && pkg_install golang || die "Go is required to build statedrift"
  fi
  confirm "build statedrift from $STATEDRIFT_SRC and install to /usr/local/bin?" \
    || die "statedrift is required"
  make -C "$STATEDRIFT_SRC" build || die "statedrift build failed"
  $SUDO install -m 0755 "$STATEDRIFT_SRC/bin/statedrift" /usr/local/bin/statedrift
  ok "installed statedrift to /usr/local/bin"
}

ensure_native_tool() { # ensure_native_tool <cmd> <pkg>
  local cmd="$1" pkg="$2"
  command -v "$cmd" >/dev/null 2>&1 && { ok "$cmd present"; return; }
  warn "$cmd not found."
  if [ "$cmd" = vhs ] && command -v go >/dev/null 2>&1; then
    if confirm "install vhs via 'go install charmbracelet/vhs@latest'?"; then
      go install github.com/charmbracelet/vhs@latest || die "vhs install failed"
      export PATH="$PATH:$(go env GOPATH)/bin"
      return
    fi
  fi
  if [ -n "$PKG" ] && confirm "install $cmd via $PKG (package: $pkg)?"; then
    pkg_install "$pkg" && return
    warn "$PKG could not install $pkg (may not be in your repos)."
  fi
  die "$cmd is required for the native path. Install it and re-run, or use the container path."
}

run_native() {
  warn "NATIVE mode runs the tape on THIS host as root."
  warn "It will briefly set net.ipv4.ip_forward=1 and create a 'backdoor' user;"
  warn "the tape's cleanup block reverts both, but the container path avoids"
  warn "touching your host at all. Ctrl-C now to switch to: ./run-demo.sh"
  confirm "continue with native mode?" || die "aborted"

  ensure_statedrift
  ensure_native_tool vhs vhs
  ensure_native_tool ffmpeg ffmpeg
  ensure_native_tool ttyd ttyd

  info "rendering $B$TAPE$N → $B$OUT_FILE$N as root (sudo)…"
  ( cd "$SCRIPT_DIR" && $SUDO --preserve-env=PATH vhs "$TAPE" ) || die "render failed"
  finish
}

finish() {
  local out="$SCRIPT_DIR/$OUT_FILE"
  if [ -f "$out" ]; then
    ok "wrote $B$out$N ($(du -h "$out" | cut -f1))"
  else
    die "render finished but $OUT_FILE was not produced"
  fi

  # Publish the default render to the committed location the README embeds
  # (docs/demo.gif). The tape writes into this script's dir (the VHS mount);
  # docs/demo.gif is what ships. Scoped to the default demo.gif so rendering
  # an alternate tape (TAPE=other.tape) never clobbers the published GIF.
  if [ "$(basename "$OUT_FILE")" = demo.gif ] && [ -d "$SCRIPT_DIR/../docs" ]; then
    cp "$out" "$SCRIPT_DIR/../docs/demo.gif"
    ok "published to $B$SCRIPT_DIR/../docs/demo.gif$N (commit this)"
  fi
}

# ── dispatch ──────────────────────────────────────────────────────────────────
case "$MODE" in
  docker) run_docker ;;
  native) run_native ;;
  auto)
    if [ -n "$(detect_engine)" ]; then
      run_docker
    else
      warn "no container engine found; falling back to native mode."
      run_native
    fi
    ;;
esac
