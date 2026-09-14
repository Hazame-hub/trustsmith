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
```

Not yet supported: chain verification (always reported as "not checked"),
private keys, CSRs, PKCS#12, TLS endpoint probing, and public WebPKI policy
checks.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | no finding at or above `--fail-on` (default `critical`) |
| 1 | operational error, for example an unreadable file |
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

## License

[Apache License 2.0](LICENSE).
