#!/usr/bin/env bash
# CLI smoke test: the real binary inspects a valid certificate (exit 0) and an
# expired one (exit 3). Shared by the self-hosted and GitHub-hosted test jobs.
set -euo pipefail

ext=""
if [ "${RUNNER_OS:-}" = "Windows" ]; then ext=".exe"; fi
go build -o "bin/trustsmith$ext" ./cmd/trustsmith
"bin/trustsmith$ext" inspect testdata/certs/leaf.pem
set +e
"bin/trustsmith$ext" inspect testdata/certs/expired.pem > /dev/null
code=$?
set -e
if [ "$code" -ne 3 ]; then
  echo "::error::inspecting an expired certificate must exit 3, got $code"
  exit 1
fi

# match: a key and its certificate (exit 0), and a key that is not its (exit 3).
vectors=internal/fingerprint/testdata/vectors
"bin/trustsmith$ext" match "$vectors/ecdsa-p256/cert.pem" "$vectors/ecdsa-p256/key.pem" > /dev/null
set +e
"bin/trustsmith$ext" match "$vectors/rsa-2048/cert.pem" "$vectors/ecdsa-p256/key.pem" > /dev/null
code=$?
set -e
if [ "$code" -ne 3 ]; then
  echo "::error::matching a key against a certificate it does not belong to must exit 3, got $code"
  exit 1
fi
