# Trustsmith

Trustsmith is a local-first certificate and private-PKI workbench. It aims to
make everyday certificate work understandable to people who are not PKI
experts, without taking the advanced path away from those who are.

> **Status: early development.** The only command implemented so far is
> `trustsmith inspect` for certificate files. Everything else in the roadmap
> (private CA, inventory, renewal, discovery, a local UI) is not built yet.

## What works today

`trustsmith inspect` explains a certificate file:

- **Inputs:** PEM certificates, DER certificates, PEM bundles, and standard
  input (`-`).
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
- **Fingerprints** follow [ADR-0002](docs/adr/0002-public-key-identity.md):
  `x509-cert-sha256` for the certificate, `x509-spki-sha256` (a canonical,
  cross-file key identity), and `x509-spki-encoded-sha256` (the key as encoded,
  for pins).
- **Output:** friendly text by default, `--advanced` for technical details, or
  `--output json` for the versioned `trustsmith.inspect/v1` schema.

It works offline and makes no network connections. Other PEM blocks in a file,
including private keys, are reported by their label and never decoded.

```console
$ trustsmith inspect testdata/certs/leaf.pem
$ trustsmith inspect --advanced bundle.pem
$ trustsmith inspect --output json cert.der
$ cat bundle.pem | trustsmith inspect -
$ trustsmith inspect bundle.pem --roots company-roots.pem
```

Not yet supported: system or platform trust stores, host name and purpose
(extended key usage) validation, revocation, private keys, CSRs, PKCS#12, TLS
endpoint probing, and public WebPKI policy checks.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | no finding at or above `--fail-on` (default `critical`) |
| 1 | operational error, for example an unreadable file or an unusable `--roots` file |
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

## License

[Apache License 2.0](LICENSE).
