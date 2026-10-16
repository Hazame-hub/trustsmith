# ADR-0013: Does this key belong to this certificate?

- Status: accepted
- Date: 2026-10-16
- Implemented in: `internal/keyfacts`, `internal/app/matchsvc`, `internal/cli` (`match.go`)

## Context

"Key values mismatch", "private key does not match public key", "x509: private
key does not match public key": deploying a certificate with the wrong key is
one of the most common certificate failures, and the usual check is a pair of
`openssl` commands whose moduli or hashes the user compares by eye, differently
for RSA and EC keys. Answering it needs the private key file, which
`trustsmith inspect` deliberately never decodes (ADR-0001, SECURITY.md).

## Decision

### Command

`trustsmith match <certificate-file> <private-key-file> [--output text|json]`.

- The certificate file is read like `inspect` reads a file (PEM, DER, bundles;
  8 MiB limit). Every parseable certificate in it is compared; the answer names
  the first entry that matches.
- Exit codes: 0 the key belongs to a certificate in the file; 3 it belongs to
  none (the same code `inspect` uses for findings, so scripts gate the same
  way); 1 operational error; 2 usage error.

### How keys are compared

- By the ADR-0002 `x509-spki-sha256` key identity, which is canonical across
  encodings. The key's identity is computed from the public key derived from
  the private key; the certificate's is the one `inspect` already reports. One
  rule covers every algorithm ADR-0002 identifies (RSA, ECDSA, Ed25519,
  ML-DSA), with no per-algorithm comparison code.
- A certificate whose key has no ADR-0002 identity (unsupported or malformed)
  is `unverifiable`, never `does_not_match`: Trustsmith claims only what it
  checked.

### What is read from a key file

- Exactly one unencrypted private key: PEM `PRIVATE KEY` (PKCS #8),
  `RSA PRIVATE KEY` (PKCS #1), `EC PRIVATE KEY` (SEC 1), or DER PKCS #8.
  `EC PARAMETERS` and `CERTIFICATE` blocks next to it are skipped, because
  OpenSSL and combined PEM files put them there. Any other block refuses the
  file. Two keys are ambiguous and refused.
- **Encrypted keys are refused** (`ENCRYPTED PRIVATE KEY`, or a legacy
  `Proc-Type: 4,ENCRYPTED` header). Trustsmith never prompts for, or accepts, a
  passphrase in this version.
- A corrupt key block is reported as unreadable, not as "no key": `pem.Decode`
  silently skips blocks it cannot decode, so the presence of a key label is
  checked separately.

### What is never done with the private key

- `keyfacts` returns a `Key` holding the format, the algorithm, the curve or
  size, and the public identity. The private value is dropped when `Parse`
  returns; it is never rendered, logged, stored or compared. A test checks that
  no part of the key file's body appears in either output format.
- Go offers no reliable way to zero key material, so the private value lives in
  memory until the garbage collector reclaims it. This is stated rather than
  hidden.

### Boundaries (enforced by `internal/archtest`)

- `keyfacts` is a domain package: no filesystem, network or interface code.
- `x509.ParsePKCS8PrivateKey`, `ParsePKCS1PrivateKey` and `ParseECPrivateKey`
  appear in production code only in `keyfacts` and in `issuance` (which loads
  the local CA's own key, ADR-0012).
- `inspect` is unchanged: it still reports private key blocks by label and
  never decodes them.
- `keyfacts.Parse` is a fuzz target.

### JSON

`trustsmith.match/v1`, versioned under ADR-0003's rules:

```json
{
  "schema": "trustsmith.match/v1",
  "certificate_file": "...",
  "key": {"file": "...", "format": "pkcs8|pkcs1|sec1", "algorithm": "ECDSA",
          "detail": "P-256", "bits": 256, "x509-spki-sha256": "..."},
  "certificates": [{"entry": 0, "x509-cert-sha256": "...", "subject": "...",
                    "x509-spki-sha256": "...", "state": "matches|does_not_match|unverifiable",
                    "detail": "..."}],
  "matched": 0
}
```

`matched` is null when no certificate matches.

## Not in this slice

- Encrypted keys and passphrases, PKCS #12 files, hardware keys.
- Certificate signing requests as the public side. Once ADR-0011's CSR
  inspection lands, a CSR's key identity can be compared the same way.
- Proving possession by signing a challenge: the comparison is of public keys,
  which is exactly what a TLS server's key-pair check does.

## Consequences

- Trustsmith now decodes private keys outside the local CA, in one package,
  and SECURITY.md says so.
- Sybil can run the same check on a host before a certificate is deployed
  there, using the JSON result.
