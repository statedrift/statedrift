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
if [[ -f "$INSTALL_PATH" ]] && [[ ! -w "$INSTALL_PATH" ]]; then
  echo "Error: $INSTALL_PATH is not writable. Try running with sudo." >&2
  exit 1
fi

cp statedrift "${INSTALL_PATH}"
chmod 755 "${INSTALL_PATH}"

echo ""
echo "statedrift installed to: ${INSTALL_PATH}"
echo ""
echo "Quick start:"
echo "  sudo statedrift init"
echo "  sudo statedrift snap"
echo "  statedrift log"
echo "  statedrift diff HEAD~1 HEAD"
echo ""
echo "Run 'statedrift help' for full usage."
