# Trustsmith

**Understand your certificates before they break something.**

Trustsmith is a local-first certificate and private-PKI workbench. It explains
certificate files and TLS endpoints in plain language, says exactly what it
checked and what it did not, and gives a fix for every problem it finds. It is
built for people who are not PKI experts, without taking the advanced path
away from those who are.

Trustsmith is open source (Apache-2.0) and stands on its own. It is also the
certificate half of [Sybil](#part-of-the-sybil-family): Sybil knows your
infrastructure, Trustsmith knows its certificates.

> **Status: early development.** Three commands exist: `trustsmith inspect`,
> for certificate files and TLS endpoints, `trustsmith ca`, a local private CA,
> and `trustsmith match`, for keys and certificates. Everything else in the
> roadmap (inventory, renewal, discovery, a local UI) is not built yet.

## Quick start

```console
$ go install github.com/Hazame-hub/trustsmith/cmd/trustsmith@latest
$ trustsmith inspect example.com:443
$ trustsmith inspect server.pem --roots company-roots.pem --hostname api.example.com
```

Release archives for Linux, macOS and Windows (amd64 and arm64), with a
`SHA256SUMS` file, are attached to each [GitHub release](https://github.com/Hazame-hub/trustsmith/releases).

What it looks like:

```console
$ trustsmith inspect expired.pem
Inspected expired.pem (PEM, 1 entry) at 2026-10-16 01:40:14 UTC

[0] TLS server certificate
    Identifies     expired.example.test
    Issuer         CN=Trustsmith Test Intermediate CA,O=Trustsmith Tests
                   no matching issuer candidate found in this input
    Valid          no, expired on 2026-06-01 00:00:00 UTC
    Key            ECDSA P-256
    Signature      ECDSA-SHA256
    Chain          not validated against trust anchors (none supplied; see --roots)
    ...

Findings (1)
  CRITICAL  entry 0  Certificate has expired [cert.expired]
            The inspection time is after the certificate's notAfter date. Software that validates certificates will reject it.
            Evidence: not_after=2026-06-01T00:00:00Z
            Fix: Renew or replace the certificate, then deploy the replacement everywhere the old one is used.
$ echo $?
3
```

The exit code makes it a CI gate: `trustsmith inspect --fail-on warning cert.pem`
fails the build on any warning, and `--output json` gives scripts a versioned,
[schema-described](docs/schema/trustsmith.inspect.v1.schema.json) result.
## What works today

`trustsmith inspect` explains a certificate file, or the certificates a TLS
server presents:

- **Inputs:** PEM certificates, DER certificates, PEM bundles, standard
  input (`-`), and TLS endpoints (`host:port`, `[IPv6]:port`,
  `tls://host:port`; port 443 by default).
- **What it tells you:** what the certificate is for, what it identifies, who it
  says issued it, whether it is valid now, when it expires, its key and
  signature algorithms, and obvious problems with suggested fixes.
- **Issuer relationships inside the input:** for a bundle, which certificate's
  key verifies which certificate's signature, and which matching certificates
  could not be confirmed ([ADR-0004](docs/adr/0004-issuer-relationships.md)).
  This is a signature check only; it is not a trust decision.
- **Certification paths inside the input:** the paths those verified
  relationships form, and whether the issuers along them are CA certificates
  allowed to sign certificates (basic constraints, key usage, path length),
  plus the validity of every certificate on the path
  ([ADR-0005](docs/adr/0005-included-certification-paths.md)). A path that
  reaches a self-signed certificate is "complete in this input", which is not
  the same as trusted: no certificate in the input is used as a trust anchor.
- **Trust against roots you supply:** `--roots <file>` validates the input
  against trust anchors you provide, using Go's crypto/x509 verifier
  ([ADR-0006](docs/adr/0006-explicit-trust-anchors.md)). Only the supplied
  certificates are anchors: certificates in the inspected file never are, and
  no system trust store is used. Without `--roots`, trust is not evaluated.
- **Suitability for a purpose you name:** `--purpose tls-server` (or
  `tls-client`, `code-signing`, `email`) reports whether the certificate's own
  extended key usage and key usage permit that purpose and, with `--roots`,
  whether Go validates the chain for it
  ([ADR-0007](docs/adr/0007-explicit-certificate-purpose.md)). The default,
  `any`, asserts no application purpose. Host names are never checked.
- **Host name identity:** `--hostname api.example.com` (or an IP address)
  reports whether the certificate's subject alternative names identify that
  name, using Go's crypto/x509 matching; the Common Name is never used
  ([ADR-0008](docs/adr/0008-hostname-identity.md)). It implies no purpose.
  Internationalised names are first converted to their A-label (`xn--`) form
  with an explicit, pinned IDNA profile.
- **Fingerprints** follow [ADR-0002](docs/adr/0002-public-key-identity.md):
  `x509-cert-sha256` for the certificate, `x509-spki-sha256` (a canonical,
  cross-file key identity), and `x509-spki-encoded-sha256` (the key as encoded,
  for pins).
- **TLS endpoints:** Trustsmith connects to the endpoint, completes one TLS
  handshake under the explicit `modern` policy (TLS 1.2 with ECDHE and AEAD
  suites, and TLS 1.3), keeps the certificates the server presented and closes
  the connection ([ADR-0009](docs/adr/0009-tls-endpoint-acquisition.md)).
  - The handshake is **not authenticated**. Completing it does not mean the
    certificates are trusted, identify the host, suit a purpose or are secure.
  - Those questions are answered separately, exactly as for a file: an endpoint
    implies `--purpose tls-server` and `--hostname` set to its host, unless you
    pass either explicitly.
  - No application data is sent and no HTTP is spoken. There is no fallback to
    weaker protocol versions or cipher suites.
  - `--probe-policy compatible` additionally offers the TLS 1.2 ECDHE AES-CBC-SHA
    suites and the P-521 group ([ADR-0010](docs/adr/0010-compatible-probe-policy.md)).
    It is chosen explicitly, never used as a fallback, and reports which of
    those parameters, if any, were actually negotiated.
- **Output:** friendly text by default, `--advanced` for technical details, or
  `--output json` for the versioned `trustsmith.inspect/v1` schema.

### A local private CA

`trustsmith ca` issues TLS certificates for internal services
([ADR-0012](docs/adr/0012-local-private-ca.md)):

```console
$ trustsmith ca init --permit-dns example.internal --permit-ip 10.0.0.0/8
$ trustsmith ca issue --dns app.example.internal --ip 10.1.2.3
```

- **Constrained by default when you ask.** `--permit-dns` and `--permit-ip`
  put critical name constraints in the root, so even a stolen CA key cannot
  produce a certificate that validates for `bank.example.com`. Naming only DNS
  domains also closes IP addresses, and the reverse.
- **Proven before written.** `ca issue` inspects the new certificate against
  the CA, for its purpose and every requested name, with the same code as
  `trustsmith inspect`. Nothing is written unless all of it passes.
- **Refuses rather than adjusts.** A certificate that would outlive its CA,
  last more than 397 days or name something outside the constraints is refused
  with the reason.
- **Never overwrites** a key or certificate, and never touches a trust store:
  it tells you which file to trust.
- Root: ECDSA P-256 by default (`--key-type ecdsa-p384` or `rsa-3072`),
  5 years, signs end-entity certificates only. Leaves: 90 days by default,
  `--use server|client|both`, wildcards as the left-most label. Keys are
  unencrypted PKCS #8 files with owner-only permissions; protect the CA
  directory accordingly.

### Does this key belong to this certificate?

`trustsmith match cert.pem key.pem` answers the question behind "key values
mismatch" for every algorithm at once, by comparing ADR-0002 key identities
([ADR-0013](docs/adr/0013-key-certificate-match.md)). In a bundle it names
the entry that matches. Exit code 0 means it matches, 3 that it matches
nothing. Only unencrypted keys are read, and nothing about the private key
except its public identity is ever printed.

```console
$ trustsmith match fullchain.pem privkey.pem
$ trustsmith match server.pem server.key --output json
```

File inspection works offline. The only network connection Trustsmith ever
makes is to an endpoint you name. Other PEM blocks in a file, including private
keys, are reported by their label and never decoded.

```console
$ trustsmith inspect testdata/certs/leaf.pem
$ trustsmith inspect --advanced bundle.pem
$ trustsmith inspect --output json cert.der
$ cat bundle.pem | trustsmith inspect -
$ trustsmith inspect bundle.pem --roots company-roots.pem
$ trustsmith inspect server.pem --purpose tls-server --roots company-roots.pem
$ trustsmith inspect server.pem --hostname api.example.com
$ trustsmith inspect api.example.com:443 --roots company-roots.pem
$ trustsmith inspect tls://[2001:db8::1]:8443 --output json
$ trustsmith inspect legacy.example.com:443 --probe-policy compatible
```

Not yet supported: system or platform trust stores, revocation, private keys, CSRs, PKCS#12, STARTTLS and legacy TLS
diagnostics, and public WebPKI policy checks.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | no finding at or above `--fail-on` (default `critical`) |
| 1 | operational error, for example an unreadable file, an unusable `--roots` file, or a TLS endpoint from which no certificate was acquired |
| 2 | usage error |
| 3 | findings reached `--fail-on` (`info`, `warning`, `critical`; `never` disables) |

## Building from source

Requires Go 1.27.

```console
$ go build -o bin/trustsmith ./cmd/trustsmith
$ go test ./...
```

With [Task](https://taskfile.dev): `task build`, `task test`, `task lint`,
`task fuzz:short`, `task golden:update`, `task fixtures`, `task dist`
(cross-compiles every release target into `dist/`).

## Design documents

- [ADR-0001: stack, layout and boundaries](docs/adr/0001-stack-and-boundaries.md)
- [ADR-0002: certificate and public-key identity](docs/adr/0002-public-key-identity.md)
- [ADR-0003: findings, inspect output and exit codes](docs/adr/0003-findings.md)
- [ADR-0004: issuer relationships inside one input](docs/adr/0004-issuer-relationships.md)
- [ADR-0005: structural certification paths inside one input](docs/adr/0005-included-certification-paths.md)
- [ADR-0006: explicitly supplied trust anchors](docs/adr/0006-explicit-trust-anchors.md)
- [ADR-0007: explicit certificate-purpose validation](docs/adr/0007-explicit-certificate-purpose.md)
- [ADR-0008: explicit host name identity](docs/adr/0008-hostname-identity.md)
- [ADR-0009: minimal TLS endpoint acquisition](docs/adr/0009-tls-endpoint-acquisition.md)
- [ADR-0010: explicit compatible TLS probe policy](docs/adr/0010-compatible-probe-policy.md)
- [ADR-0012: a local private CA](docs/adr/0012-local-private-ca.md)
- [ADR-0013: does this key belong to this certificate?](docs/adr/0013-key-certificate-match.md)

## JSON output

`--output json` emits `trustsmith.inspect/v1`. Its JSON Schema,
[docs/schema/trustsmith.inspect.v1.schema.json](docs/schema/trustsmith.inspect.v1.schema.json),
is generated from the CLI's contract types and every JSON golden file is
validated against it, so it cannot drift from what the binary prints. Fields
may be added within v1; consumers must ignore properties they do not know.
Finding codes are append-only ([ADR-0003](docs/adr/0003-findings.md)), so a
script can key on `cert.expired` or `name.hostname_mismatch` safely.

## Part of the Sybil family

[Sybil](https://github.com/Hazame-hub) is an infrastructure platform that
takes a machine from intent to a verified live state and then watches it for
drift. Its secrets service, Aegis, knows which host holds which credential and
records every read. Certificates are the part of that picture Aegis
deliberately leaves out, and they are what Trustsmith is for.

Trustsmith does not need Sybil, and never will: every feature works from the
command line, offline, with nothing to sign up for. When you run more than a
handful of machines, Sybil is where Trustsmith's results are meant to go, to
add what a local tool cannot. None of this is built yet; the JSON contract it
will rest on is:

- **Every certificate on every host, in one place.** The Sybil agent running
  the same inspection on each machine and reporting the `trustsmith.inspect/v1`
  result, so "what expires this month, and where is it deployed" becomes one
  query instead of an SSH session per server.
- **Expiry and mismatches on the infrastructure timeline**, next to the
  deployments and drift that caused them.
- **Renewal that closes the loop**: replace the certificate on the machine that
  uses it, then prove the new one is served before the old one is retired.

See [docs/integrations/sybil.md](docs/integrations/sybil.md) for how the two
fit together and which parts exist today.

## Contributing

Bug reports, fixtures for certificates Trustsmith misreads, and pull requests
are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities
privately, as described in [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE).
