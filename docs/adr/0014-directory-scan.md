# ADR-0014: Scanning a directory for certificates

- Status: accepted
- Date: 2026-10-16
- Implemented in: `internal/app/scansvc`, `internal/cli` (`scan.go`)

## Context

The first question about certificates on a real machine is rarely "explain
this file". It is "which certificates are on this server, and which one
expires first?" Answering it with `inspect` means knowing every path in
advance. The roadmap's inventory is the long-term answer; this slice is the
smallest useful step towards it: one explicit command, one directory, the same
inspection of every certificate file found, sorted by expiry.

It is also the shape a fleet integration needs. Sybil's agent can run
`trustsmith scan /etc/ssl --output json` on each host and report the result,
which is how "what expires this month, and where" becomes one query across a
fleet (docs/integrations/sybil.md). That integration is not built; the JSON
contract it would rest on is.

## Decision

### Command

`trustsmith scan <directory|file> [--output text|json] [--fail-on <severity>]
[--expiring-within <days>]`.

- Every certificate file found is inspected by `inspectsvc` with the default
  options, exactly as `trustsmith inspect <file>` would. There is one
  inspection code path (ADR-0001); the scan only selects files and arranges
  results.
- Output lists every certificate soonest-expiring first (ties by file, then
  entry), with days remaining and its most severe finding. Findings that do
  not belong to a listed certificate (a malformed block, a key block reported
  by label, trailing data) are listed separately with their file and entry.
- `--expiring-within N` lists only certificates whose `days_remaining` is at
  most N (so expired ones always appear). It filters the list only: findings,
  counts and `--fail-on` still cover every certificate scanned.
- Exit codes are inspect's: 0, 1 operational error (the path cannot be read at
  all), 2 usage error, 3 findings reached `--fail-on` (default `critical`).

### Which files are read

- **Only under the path named.** A symbolic link inside it is never followed
  (counted as skipped), so a scan cannot leave the directory. The path itself
  may be a link, which is followed once because the user named it.
- **Regular files only**; devices, sockets and pipes are passed over.
- **Selection by content, then name.** A file containing PEM certificate
  armour is inspected whatever it is called (nginx and HAProxy setups name
  them freely). A file without armour is considered only when its extension
  is `.der`, `.cer`, `.crt` or `.cert`, and inspected only when it frames as a
  DER certificate. Everything else, private keys included, is passed over
  without being decoded.
- **Bounded.** Files over 8 MiB (inspect's input limit) are skipped and
  counted; the scan stops after 100,000 files and says the list is incomplete.
- **Unreadable entries** (permission denied, a file removed mid-walk) are
  listed with the operating system's reason and do not stop the scan.
- Nothing is written, nothing is sent, and no system trust store is used.

### What it does not claim

Trust is not evaluated: no roots are supplied and none are inferred, so the
summary says so in every output (`"trust": "not_evaluated"` in JSON). A root
CA found in `/etc/ssl/certs` is listed by what it contains, not reported as
trusted. Certificates are counted twice when they appear in two files; the
distinct count by `x509-cert-sha256` is reported alongside.

### JSON

`trustsmith.scan/v1`, versioned under ADR-0003's rules: `schema`,
`scanned_at`, `path`, `overview` (files examined, certificate files,
certificates, distinct certificates, skipped links and large files,
`limit_reached`, finding count, highest severity, `trust`), `expiring_within`
(null without the filter), `certificates[]` (file, entry, `x509-cert-sha256`,
kind, identifies, issuer as stated, `validity` shaped as `summary.validity` in
`trustsmith.inspect/v1`, findings as code and severity), `problems[]` and
`errors[]`. Full findings with evidence and remediation stay in
`trustsmith inspect --output json <file>`.

## Not in this slice

- `--roots`, `--purpose` and `--hostname` for a scan; ownership of files;
  following links on request; scanning archives, PKCS #12 or Java keystores;
  discovering endpoints on the network; remembering results between scans.

## Consequences

- SECURITY.md no longer says Trustsmith never reads directories: it reads the
  one it is told to, under the rules above.
