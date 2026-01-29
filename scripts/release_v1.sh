#!/usr/bin/env bash
set -euo pipefail

VERSION="1.0.0"

if [[ -n "${1:-}" ]]; then
  VERSION="$1"
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git not found" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found" >&2
  exit 1
fi

echo "Releasing Chrontainer ${VERSION}"

git status -sb

# Tag release (edit as needed)
# git tag -a "v${VERSION}" -m "Release v${VERSION}"

# Build multi-arch image locally
# docker build -t ghcr.io/rsousa88/chrontainer:${VERSION} -t ghcr.io/rsousa88/chrontainer:latest .

# Push to GHCR (requires login)
# docker push ghcr.io/rsousa88/chrontainer:${VERSION}
# docker push ghcr.io/rsousa88/chrontainer:latest

echo "Done. Uncomment steps above to execute the release."
