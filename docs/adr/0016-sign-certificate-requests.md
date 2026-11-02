# ADR-0016: Signing certificate requests with the local CA

- Status: accepted
- Date: 2026-11-01
- Implemented in: `internal/issuance` (`CheckSubjectKey`), `internal/app/casvc`
  (`Sign`, `ParseCSR`, `Stage`), `internal/cli` (`ca sign`), `pkg/ca`

## Context

`trustsmith ca issue` (ADR-0012) creates the key and the certificate together
and writes both. That fits a laptop or a home lab, but not a managed machine:
the key then exists wherever the CA runs and has to be copied to the machine
that serves it. Every copy is a place it can leak from.

The usual answer is a certificate signing request: the machine creates its own
key, sends only the request, and receives only the certificate. Trustsmith can
already explain a request (ADR-0011). Sybil wants to renew a service's
certificate this way, from a CA it holds as a secret, without the key ever
leaving the machine.

## Decision

### Command

`trustsmith ca sign [--ca-dir trustsmith-ca] --csr <file> [--dns <name>]...
[--ip <addr>]... [--use server|client|both] [--days 90] [--out <path>]`
writes `<out>.pem` and nothing else. `--out` defaults to the first certified
name, as for `ca issue`. Exit codes are those of `ca issue`.

### What is taken from the request, and what is not

- **The public key**, after the request's self-signature verifies. A request
  whose signature does not verify proves nothing about who holds the key and
  is refused.
- **The key must be one the CA would create or accept**: RSA of at least 2048
  bits, ECDSA on P-256, P-384 or P-521, or Ed25519. Anything else is refused
  with the reason, not signed.
- **The names**, only when the command names none: `--dns` and `--ip` replace
  the request's subject alternative names entirely. Either way the names go
  through the same checks as `ca issue` (syntax, wildcards, the CA's name
  constraints).
- **Nothing else.** The subject, and every extension the request asks for
  (basic constraints, key usages, anything), is ignored. The CA decides what
  it certifies; the leaf profile is exactly ADR-0012's. A request asking to be
  a CA gets an end-entity certificate.

### Proven before written

The certificate is inspected exactly as an issued one is (ADR-0012): trusted
by the CA as the only anchor, suitable for its purpose, identifying every
certified name. If any check fails, nothing is written. An existing file is
never replaced.

### pkg/ca

Callers that hold a CA in memory (Sybil keeps it as a secret) get two
functions: `Init(InitOptions) (CA, error)` and `Sign(CA, csr, SignOptions)
([]byte, error)`. Following ADR-0015 they run the `ca init` and `ca sign`
commands in process, in an owner-only temporary directory removed before they
return, so the library refuses and proves exactly as the CLI does and never
does something the command cannot. The CA is written into that directory by
`casvc.Stage`, which keeps every private key write in the one package the
architecture tests allow, and refuses a key that does not belong to its
certificate before anything is signed.

`runcli` now gives commands `crypto/rand.Reader`; the clock remains the
caller's.

## Consequences

- A machine renewing its certificate never sends its key anywhere. The CA key
  still lives wherever the CA runs; protecting it is unchanged from ADR-0012.
- No revocation, no intermediates, no PKCS #12: a signed certificate is as
  short-lived as an issued one (90 days by default), and renewal, not
  revocation, is how it is replaced.
- The Go API of `pkg/ca` (two functions, three structs) is covered by semantic
  versioning like `pkg/inspect` and `pkg/scan`.

## Alternatives considered

- **Copy the request's extensions, filtered.** Every filter is a policy to get
  wrong; ignoring them all makes the leaf profile one fixed, tested thing.
- **Sign in memory in `pkg/ca` without the CLI.** Simpler, but it would be a
  second signing path the CLI's tests do not cover, against ADR-0015.
