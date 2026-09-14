# Trustsmith

Trustsmith is a local-first certificate and private-PKI workbench. It aims to
make everyday certificate work understandable to people who are not PKI
experts, without taking the advanced path away from those who are.

> **Status: early development.** The only command implemented so far is
> `trustsmith inspect`, for certificate files and TLS endpoints. Everything else in the roadmap
> (private CA, inventory, renewal, discovery, a local UI) is not built yet.

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
- **Output:** friendly text by default, `--advanced` for technical details, or
  `--output json` for the versioned `trustsmith.inspect/v1` schema.

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

## Building

Requires Go 1.27.

```console
$ go build -o bin/trustsmith ./cmd/trustsmith
$ go test ./...
```

With [Task](https://taskfile.dev): `task build`, `task test`, `task lint`,
`task fuzz:short`, `task golden:update`, `task fixtures`.

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

## License

[Apache License 2.0](LICENSE).
