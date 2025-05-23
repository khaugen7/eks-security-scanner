#!/usr/bin/env bash

set -e

REPO="khaugen7/eks-security-scanner"
BINARY="eks-scanner"
VERSION="${1:-latest}"

# Detect OS
OS="$(uname | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

# Normalize architecture name
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Handle latest version fetch
if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
fi

FILENAME="${BINARY}-${OS}-${ARCH}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/${FILENAME}"

echo "Downloading $BINARY version $VERSION for $OS/$ARCH..."
curl -L "$DOWNLOAD_URL" -o "$FILENAME"

chmod +x "$FILENAME"
sudo mv "$FILENAME" /usr/local/bin/$BINARY

echo "$BINARY installed to /usr/local/bin/$BINARY"
echo "You can now run: $BINARY --help"
