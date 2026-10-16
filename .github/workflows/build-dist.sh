#!/usr/bin/env bash
# Cross-compile the release binaries into dist/ and write SHA-256 checksums.
# Shared by the release workflow (on a v* tag) and the CI dist job (every push,
# as a dry run), so a release can never be the first time a target is built.
#
# Usage: build-dist.sh <version>
#   version  embedded with -X main.version; e.g. v0.1.0, or a commit SHA
set -euo pipefail

version="${1:?usage: build-dist.sh <version>}"
targets=(
  linux/amd64
  linux/arm64
  darwin/amd64
  darwin/arm64
  windows/amd64
  windows/arm64
)

# The runner image may lack zip; Python's zipfile is the fallback.
zipdir() {
  if command -v zip >/dev/null; then
    zip -qr "$1" "$2"
  elif command -v python3 >/dev/null; then
    python3 -m zipfile -c "$1" "$2"
  else
    echo "::error::packaging the Windows archives needs zip or python3 on the runner" >&2
    exit 1
  fi
}

rm -rf dist
mkdir -p dist
for target in "${targets[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  name="trustsmith_${version}_${goos}_${goarch}"
  ext=""
  if [ "$goos" = "windows" ]; then ext=".exe"; fi
  stage="dist/$name"
  mkdir -p "$stage"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath \
    -ldflags "-s -w -X main.version=$version" \
    -o "$stage/trustsmith$ext" ./cmd/trustsmith
  cp LICENSE README.md "$stage/"
  if [ "$goos" = "windows" ]; then
    (cd dist && zipdir "$name.zip" "$name")
  else
    tar -C dist -czf "dist/$name.tar.gz" "$name"
  fi
  rm -rf "$stage"
done

(cd dist && sha256sum -- *.tar.gz *.zip > SHA256SUMS)
cat dist/SHA256SUMS
