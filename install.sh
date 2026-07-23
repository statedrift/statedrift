#!/usr/bin/env bash
# install.sh — Download and install statedrift from GitHub Releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/statedrift/statedrift/main/install.sh | bash
#   bash install.sh                          # install latest release
#   bash install.sh --version 0.2.0          # install specific version
#   bash install.sh --prefix /usr/local/bin  # custom install prefix

set -euo pipefail

VERSION="${STATEDRIFT_VERSION:-}"
PREFIX="${STATEDRIFT_PREFIX:-/usr/local/bin}"
REPO="statedrift/statedrift"
BASE_URL="https://github.com/${REPO}/releases/download"

# Parse arguments.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="$2"
      shift 2
      ;;
    --prefix)
      PREFIX="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

# Resolve PREFIX to an absolute path now: the install step later cd's into a
# temp dir, where a relative --prefix would silently install (and be deleted
# by the EXIT trap).
case "$PREFIX" in
  /*) ;;
  *) PREFIX="$(pwd)/${PREFIX#./}" ;;
esac

# Required tools that have no fallback (curl/wget is checked separately later
# because either one works).
for tool in tar sha256sum; do
  if ! command -v "$tool" &>/dev/null; then
    echo "Error: required tool '$tool' is not installed." >&2
    exit 1
  fi
done

# Verify install destination is writable before downloading anything.
if [[ -d "$PREFIX" ]]; then
  if [[ ! -w "$PREFIX" ]]; then
    echo "Error: $PREFIX is not writable." >&2
    echo "Re-run with sudo, or pass --prefix to a writable directory (e.g. \$HOME/.local/bin)." >&2
    exit 1
  fi
  if [[ -e "${PREFIX}/statedrift" ]] && [[ ! -w "${PREFIX}/statedrift" ]]; then
    echo "Error: ${PREFIX}/statedrift exists and is not writable." >&2
    echo "Re-run with sudo, or pass --prefix to a writable directory (e.g. \$HOME/.local/bin)." >&2
    exit 1
  fi
else
  PARENT="$(dirname "$PREFIX")"
  if [[ ! -d "$PARENT" ]] || [[ ! -w "$PARENT" ]]; then
    echo "Error: cannot create $PREFIX (parent directory missing or not writable)." >&2
    echo "Re-run with sudo, or pass --prefix to a writable directory (e.g. \$HOME/.local/bin)." >&2
    exit 1
  fi
fi

# Detect architecture.
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64 | amd64)
    ARCH="amd64"
    ;;
  aarch64 | arm64)
    ARCH="arm64"
    ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    echo "Supported: x86_64 (amd64), aarch64 (arm64)" >&2
    exit 1
    ;;
esac

# Detect OS.
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [[ "$OS" != "linux" ]]; then
  echo "statedrift only supports Linux (detected: $OS)" >&2
  exit 1
fi

# Resolve the latest released version if the caller didn't pin one. Uses the
# stable /releases/latest redirect — GitHub redirects it to /releases/tag/vX.Y.Z
# so the effective URL gives us the version after the trailing /v.
if [[ -z "${VERSION}" ]]; then
  if ! command -v curl &>/dev/null; then
    echo "Error: auto-detecting the latest version requires curl." >&2
    echo "Install curl, or pass --version explicitly." >&2
    exit 1
  fi
  echo "Resolving latest release..."
  RESOLVED="$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    "https://github.com/${REPO}/releases/latest")"
  VERSION="${RESOLVED##*/v}"
  if [[ -z "${VERSION}" ]] || [[ "${VERSION}" == "${RESOLVED}" ]]; then
    echo "Error: failed to resolve latest version from ${RESOLVED}." >&2
    echo "Pass --version explicitly." >&2
    exit 1
  fi
  echo "  Latest: v${VERSION}"
fi

# Normalize: accept "v0.2.0" or "0.2.0" for --version / $STATEDRIFT_VERSION.
VERSION="${VERSION#v}"

TARBALL="statedrift-${VERSION}-${OS}-${ARCH}.tar.gz"
CHECKSUM_URL="${BASE_URL}/v${VERSION}/sha256sums.txt"
TARBALL_URL="${BASE_URL}/v${VERSION}/${TARBALL}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Installing statedrift v${VERSION} (${OS}/${ARCH})..."
echo ""

# Download tarball and checksums.
echo "Downloading ${TARBALL}..."
if command -v curl &>/dev/null; then
  curl -fsSL -o "${TMPDIR}/${TARBALL}" "${TARBALL_URL}"
  curl -fsSL -o "${TMPDIR}/sha256sums.txt" "${CHECKSUM_URL}"
elif command -v wget &>/dev/null; then
  wget -q -O "${TMPDIR}/${TARBALL}" "${TARBALL_URL}"
  wget -q -O "${TMPDIR}/sha256sums.txt" "${CHECKSUM_URL}"
else
  echo "Error: curl or wget is required" >&2
  exit 1
fi

# Verify checksum.
echo "Verifying checksum..."
cd "${TMPDIR}"
grep -F "${TARBALL}" sha256sums.txt | sha256sum --check
echo "  Checksum OK"

# Extract binary.
tar xzf "${TARBALL}"

# Install.
if [[ ! -d "$PREFIX" ]]; then
  echo "Creating directory: $PREFIX"
  mkdir -p "$PREFIX"
fi

INSTALL_PATH="${PREFIX}/statedrift"
cp statedrift "${INSTALL_PATH}"
chmod 755 "${INSTALL_PATH}"

echo ""
echo "statedrift installed to: ${INSTALL_PATH}"
echo ""
# Print the full install path in the quick start: sudo resets PATH to
# secure_path (which on RHEL excludes even /usr/local/bin), so a bare
# "sudo statedrift" is not copy-pasteable. All commands need sudo because
# a root init stores the config and chain under root-owned paths.
echo "Quick start:"
echo "  sudo ${INSTALL_PATH} init"
echo "  sudo ${INSTALL_PATH} snap        # run again after any change"
echo "  sudo ${INSTALL_PATH} diff HEAD~1 HEAD"
echo "  sudo ${INSTALL_PATH} verify"
echo ""
echo "No root? Use a home-directory store instead (drop sudo from every command):"
echo "  STATEDRIFT_STORE=\$HOME/.statedrift ${INSTALL_PATH} init"
echo ""
echo "Run '${INSTALL_PATH} help' for full usage."
