#!/bin/sh
# Copyright (c) 2026 Roman Zhuzhgov
# Licensed under the Apache License, Version 2.0
#
# Installer for the `iris` CLI: fetches the prebuilt binary for this
# platform from GitHub Releases, verifies its checksum, and installs it.
#
#   curl -fsSL https://raw.githubusercontent.com/mi11ione/iris/main/install.sh | sh
#
# Configuration (environment variables):
#   IRIS_VERSION      a specific release like 0.3.0 (default: latest)
#   IRIS_INSTALL_DIR  install directory (default: ~/.local/bin)

set -u

REPO="mi11ione/iris"
INSTALL_DIR="${IRIS_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${IRIS_VERSION:-latest}"

fail() {
    echo "install.sh: $1" >&2
    exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"

case "$(uname -s)" in
    Darwin) ASSET_PLATFORM="macos-universal" ;;
    Linux)
        case "$(uname -m)" in
            x86_64) ASSET_PLATFORM="linux-x86_64" ;;
            aarch64 | arm64) ASSET_PLATFORM="linux-aarch64" ;;
            *) fail "unsupported Linux architecture: $(uname -m)" ;;
        esac
        ;;
    *) fail "unsupported platform: $(uname -s) (macOS and Linux have prebuilt binaries; on other platforms build from source with \`swift build -c release --product iris\`)" ;;
esac

if [ "$VERSION" = "latest" ]; then
    BASE_URL="https://github.com/${REPO}/releases/latest/download"
else
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/iris-install.XXXXXX")" || fail "cannot create a temporary directory"
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM

echo "Fetching checksums (${VERSION})..."
curl -fsSL "${BASE_URL}/checksums.txt" -o "${WORK_DIR}/checksums.txt" ||
    fail "cannot download checksums.txt from ${BASE_URL} (does the release exist?)"

ASSET="$(sed -n "s/^[0-9a-f]\{64\}  \(iris-.*-${ASSET_PLATFORM}\.tar\.gz\)$/\1/p" "${WORK_DIR}/checksums.txt" | head -n 1)"
[ -n "$ASSET" ] || fail "no ${ASSET_PLATFORM} asset listed in checksums.txt"

echo "Downloading ${ASSET}..."
curl -fsSL "${BASE_URL}/${ASSET}" -o "${WORK_DIR}/${ASSET}" || fail "download failed"

echo "Verifying checksum..."
EXPECTED="$(sed -n "s/^\([0-9a-f]\{64\}\)  ${ASSET}\$/\1/p" "${WORK_DIR}/checksums.txt")"
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL="$(sha256sum "${WORK_DIR}/${ASSET}" | cut -d' ' -f1)"
else
    ACTUAL="$(shasum -a 256 "${WORK_DIR}/${ASSET}" | cut -d' ' -f1)"
fi
[ "$EXPECTED" = "$ACTUAL" ] || fail "checksum mismatch for ${ASSET} (expected ${EXPECTED}, got ${ACTUAL})"

tar -xzf "${WORK_DIR}/${ASSET}" -C "$WORK_DIR" || fail "extraction failed"
[ -f "${WORK_DIR}/iris" ] || fail "archive did not contain the iris binary"

mkdir -p "$INSTALL_DIR" || fail "cannot create ${INSTALL_DIR}"
install -m 0755 "${WORK_DIR}/iris" "${INSTALL_DIR}/iris" 2>/dev/null ||
    { cp "${WORK_DIR}/iris" "${INSTALL_DIR}/iris" && chmod 0755 "${INSTALL_DIR}/iris"; } ||
    fail "cannot install to ${INSTALL_DIR}"

echo "Installed: ${INSTALL_DIR}/iris"
"${INSTALL_DIR}/iris" --version || fail "installed binary failed to run"

case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        echo ""
        echo "Note: ${INSTALL_DIR} is not on your PATH. Add it with:"
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        ;;
esac
