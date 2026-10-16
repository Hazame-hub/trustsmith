# Changelog

All notable changes to Trustsmith. Each released version has a `## vX.Y.Z`
section; the release workflow publishes that section as the release notes.

## Unreleased

### Added

- `trustsmith inspect` for PEM certificates, DER certificates, PEM bundles,
  standard input and TLS endpoints (`host:port`, `[IPv6]:port`,
  `tls://host:port`).
- Issuer relationships and certification paths inside one input
  (ADR-0004, ADR-0005).
- Validation against explicitly supplied trust anchors with `--roots`
  (ADR-0006); no system trust store is ever used.
- `--purpose` (ADR-0007) and `--hostname` (ADR-0008) evaluations.
- Minimal, unauthenticated TLS endpoint acquisition with the `modern` probe
  policy (ADR-0009) and the explicit `compatible` policy (ADR-0010).
- `--output json` with the versioned `trustsmith.inspect/v1` contract and its
  generated JSON Schema in `docs/schema/`.
- `trustsmith ca init` and `ca issue`: a local private CA with name
  constraints; every issued certificate is checked before it is written
  (ADR-0012).
- `trustsmith match cert key`: does this unencrypted private key belong to
  this certificate, or to which entry of a bundle (ADR-0013).
- Release archives for Linux, macOS and Windows on amd64 and arm64, with
  SHA-256 checksums.
