# ADR-0012: A local private CA

- Status: accepted
- Date: 2026-10-16
- Implemented in: `internal/issuance`, `internal/app/casvc`, `internal/cli` (`ca.go`)

## Context

Trustsmith's roadmap starts with explaining certificates (ADR-0003 to
ADR-0010) and continues with a private CA. The everyday need is narrow and
common: a team wants TLS for internal services, test environments or a home
lab, without a public CA and without learning `openssl ca`. Tools that do this
today either issue for any name with an unconstrained root (a stolen key then
lets an attacker impersonate any site to every machine that trusts it), or
leave the user to verify the result by hand.

Sybil's secrets service, Aegis, deliberately has no PKI engine (a decision
recorded in its own positioning). This is where certificates are issued
instead. Aegis is unchanged by this ADR.

This slice adds the first two verbs: create a CA, issue a certificate.

## Decision

### Commands

- `trustsmith ca init [--dir trustsmith-ca] [--name ...] [--org ...]
  [--key-type ecdsa-p256|ecdsa-p384|rsa-3072] [--days 1825]
  [--permit-dns <domain>]... [--permit-ip <cidr>]...` creates the directory
  (mode 0700) with `ca.pem` (0644) and `ca.key` (0600).
- `trustsmith ca issue [--ca-dir trustsmith-ca] --dns <name>... --ip <addr>...
  [--use server|client|both] [--days 90] [--key-type ...] [--out <path>]`
  writes `<out>.pem` and `<out>.key`. `--out` defaults to the first name, with
  `*` written `_wildcard` and IPv6 colons as dashes.
- Exit codes: 0 done, 1 operational error (including a refused request or an
  existing file), 2 usage error.

### What the CA is

- **A root that signs end entities only.** `basicConstraints` CA:TRUE with
  pathLenConstraint 0, key usage keyCertSign and cRLSign, a SHA-256-based
  subject key identifier (RFC 7093 method 1). No intermediates: there is
  nothing to rotate between the root and a leaf, and a leaf key can never sign.
- **Name constraints, when asked, mean what they say.** `--permit-dns` and
  `--permit-ip` produce a critical name constraints extension. RFC 5280 leaves
  a name type without a permitted subtree unconstrained, so a CA restricted to
  `example.internal` alone could still certify any IP address. Trustsmith
  closes the other type: DNS-only constraints exclude all of IPv4 and IPv6;
  IP-only constraints permit only the RFC 6761 reserved domain `invalid`.
  Email and URI names are not constrained, and the CA never issues them.
  A test signs out-of-constraint certificates with the CA key directly, as a
  thief would, and checks that validation fails.
- **Without constraints, the output says so**: "this CA can certify any name;
  trust it only where that is acceptable".
- **Validity**: 5 years by default, at most 20.

### What a leaf is

- Names only in subject alternative names; the Common Name repeats the first
  name for people. At least one DNS name or IP address is required.
- DNS names must be lower-case LDH A-labels; a wildcard only as the whole
  left-most label of a name with at least two further labels. Upper case,
  internationalised names in U-label form and inner wildcards are refused, not
  normalised, so the certificate contains exactly what was typed.
- `basicConstraints` CA:FALSE, key usage digitalSignature (plus
  keyEncipherment for RSA keys), extended key usage serverAuth, clientAuth or
  both, authority key identifier set to the CA's.
- 90 days by default, at most 397 (the CA/Browser Forum limit, so lifetime is
  never the reason software rejects it). Every certificate starts five minutes
  before issuance, for relying parties whose clocks lag.
- 128-bit random positive serial numbers.

### Refuse, never adjust

A request that would outlive the CA, fall outside its constraints, or use an
invalid name is refused with a message naming the problem. Nothing is
silently shortened or rewritten, so what is issued is always what was asked.

### Proven before written

`ca issue` signs the certificate in memory, then inspects it with
`inspectsvc` exactly as `trustsmith inspect <out>.pem --roots <ca>/ca.pem
--purpose <purpose> --hostname <name>` would, once per requested purpose and
name (a wildcard is checked through a concrete name under it). It requires all
three independent answers: trust verified against the CA as the only anchor,
the purpose suitable, the name matched. Only then are the files written. This
reuses the one inspection code path (ADR-0001) instead of adding a second
notion of "valid".

### Keys and files

- Keys are generated from `crypto/rand` (wired in `cmd/trustsmith` like the
  clock) and stored as **unencrypted PKCS #8 PEM**, like mkcert. Encryption at
  rest (a passphrase, or an OS keychain) is a later slice; until then the
  output and the help say to protect the directory as a private key.
- Files are created with `O_EXCL`: Trustsmith never overwrites a key or a
  certificate. The key is written first; if the certificate cannot be
  written, the new key is removed, so a failure never leaves an orphan key.
- On Windows the permission bits map to the read-only attribute only; the key
  file inherits the directory's ACL. The documentation says so.
- `ca issue` checks that `ca.key` belongs to `ca.pem` and that `ca.pem` is a
  CA certificate before signing anything.

### Boundaries (enforced by `internal/archtest`)

- `internal/issuance` is the only production package that calls
  `x509.CreateCertificate`, generates keys (`ecdsa`/`rsa`/`ed25519`
  `GenerateKey`) or marshals private keys. It imports no other Trustsmith
  package and nothing from `os`, `os/exec`, `net/http`, `io/fs`, `syscall` or
  `database/sql`; `net` is allowed for its IP address types only.
- `internal/app/casvc` is the only production package that opens files for
  writing (`os.OpenFile`, `os.WriteFile`, `os.Create`).
- The time and the randomness source are inputs, as everywhere else.

## Not in this slice

- Encrypted keys, hardware tokens, OS keychains.
- Intermediates, CRLs, OCSP, revocation of any kind. A compromised local CA is
  recovered by replacing it and removing it from trust stores.
- Installing the root into system or browser trust stores. Trustsmith never
  touches trust stores; it says which file to trust.
- Issuing from a CSR, renewal, an inventory of issued certificates, ACME.
- JSON output for `ca` commands. The issued certificate can be inspected with
  `trustsmith inspect --output json`.

## Consequences

- Trustsmith now holds secret material, so `SECURITY.md` describes what it
  writes and where.
- The CLI stays the authoritative interface for this secret-bearing operation
  (ADR-0001).
- A later Sybil integration can renew certificates on the hosts that use them
  by calling the same service, then prove the new one is served with
  `trustsmith inspect host:port` before retiring the old one.
