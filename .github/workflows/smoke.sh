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

# The local CA: create one, issue from it, and inspect the result against it.
tmp="$(mktemp -d)"
"bin/trustsmith$ext" ca init --dir "$tmp/ca" --permit-dns example.internal > /dev/null
"bin/trustsmith$ext" ca issue --ca-dir "$tmp/ca" --dns app.example.internal --out "$tmp/app" > /dev/null
"bin/trustsmith$ext" inspect "$tmp/app.pem" --roots "$tmp/ca/ca.pem" --purpose tls-server --hostname app.example.internal --fail-on info > /dev/null
set +e
"bin/trustsmith$ext" ca issue --ca-dir "$tmp/ca" --dns bank.example.com --out "$tmp/bank" > /dev/null 2>&1
code=$?
set -e
if [ "$code" -ne 1 ] || [ -e "$tmp/bank.key" ]; then
  echo "::error::issuing outside the CA's name constraints must exit 1 and write nothing, got $code"
  exit 1
fi
rm -rf "$tmp"
